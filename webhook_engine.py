"""
CodeShield AI - Webhook Delivery Engine.

Provides async webhook delivery with:
- Exponential backoff retry mechanism
- HMAC-SHA256 signature verification
- Multiple event types
- Delivery logging and retry tracking
- Circuit breaker pattern for failing endpoints
- Event payload templates
"""

import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import uuid4

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


class WebhookEventType(str, Enum):
    """Supported webhook event types."""

    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    VULNERABILITY_FOUND = "vulnerability.found"
    VULNERABILITY_FIXED = "vulnerability.fixed"
    POLICY_VIOLATION = "policy.violation"
    POLICY_PASSED = "policy.passed"


class DeliveryStatus(str, Enum):
    """Status of a webhook delivery attempt."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    EXHAUSTED = "exhausted"


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class WebhookEndpoint:
    """Configuration for a webhook endpoint."""

    id: str = field(default_factory=lambda: str(uuid4())[:8])
    url: str = ""
    secret: Optional[str] = None
    events: List[str] = field(default_factory=lambda: ["scan.completed"])
    headers: Dict[str, str] = field(default_factory=dict)
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""
    timeout_seconds: int = 30
    max_retries: int = 5
    retry_delays: List[int] = field(default_factory=lambda: [1, 2, 4, 8, 16])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "events": self.events,
            "headers": self.headers,
            "active": self.active,
            "created_at": self.created_at.isoformat(),
            "description": self.description,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
        }


@dataclass
class DeliveryLogEntry:
    """Log entry for a webhook delivery attempt."""

    delivery_id: str
    endpoint_id: str
    event_type: str
    status: DeliveryStatus
    attempt_number: int
    request_body: str = ""
    response_status: Optional[int] = None
    response_body: str = ""
    error_message: str = ""
    duration_ms: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "endpoint_id": self.endpoint_id,
            "event_type": self.event_type,
            "status": self.status.value,
            "attempt_number": self.attempt_number,
            "response_status": self.response_status,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class CircuitBreaker:
    """Circuit breaker for a webhook endpoint."""

    endpoint_id: str
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    failure_threshold: int = 5
    recovery_timeout_seconds: int = 60
    half_open_max_requests: int = 3

    def record_success(self) -> None:
        """Record a successful delivery."""
        self.success_count += 1
        self.failure_count = 0
        self.last_success_time = datetime.now(timezone.utc)

        if self.state == CircuitState.HALF_OPEN:
            if self.success_count >= self.half_open_max_requests:
                self.state = CircuitState.CLOSED
                self.success_count = 0
                logger.info("Circuit breaker closed for endpoint %s", self.endpoint_id)
        elif self.state == CircuitState.OPEN:
            self.state = CircuitState.HALF_OPEN
            self.success_count = 1

    def record_failure(self) -> None:
        """Record a failed delivery."""
        self.failure_count += 1
        self.last_failure_time = datetime.now(timezone.utc)

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.success_count = 0
            logger.warning(
                "Circuit breaker opened for endpoint %s (half-open test failed)",
                self.endpoint_id,
            )
        elif self.state == CircuitState.CLOSED and self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker opened for endpoint %s after %d failures",
                self.endpoint_id,
                self.failure_count,
            )

    def can_execute(self) -> bool:
        """Check if a request can be executed."""
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self.last_failure_time:
                elapsed = (
                    datetime.now(timezone.utc) - self.last_failure_time
                ).total_seconds()
                if elapsed >= self.recovery_timeout_seconds:
                    self.state = CircuitState.HALF_OPEN
                    self.failure_count = 0
                    self.success_count = 0
                    logger.info(
                        "Circuit breaker half-open for endpoint %s",
                        self.endpoint_id,
                    )
                    return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return self.success_count < self.half_open_max_requests
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": (
                self.last_failure_time.isoformat() if self.last_failure_time else None
            ),
            "last_success_time": (
                self.last_success_time.isoformat() if self.last_success_time else None
            ),
        }


class WebhookEngine:
    """
    Async webhook delivery engine for CodeShield AI.

    Features:
    - Reliable delivery with exponential backoff retries
    - HMAC-SHA256 payload signing
    - Circuit breaker pattern for resilience
    - Comprehensive delivery logging
    - Event payload templating
    """

    # Event payload templates
    PAYLOAD_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "scan.started": {
            "event": "scan.started",
            "description": "A new security scan has started",
        },
        "scan.completed": {
            "event": "scan.completed",
            "description": "Security scan completed with results",
        },
        "scan.failed": {
            "event": "scan.failed",
            "description": "Security scan failed to complete",
        },
        "vulnerability.found": {
            "event": "vulnerability.found",
            "description": "New vulnerability detected",
        },
        "vulnerability.fixed": {
            "event": "vulnerability.fixed",
            "description": "Vulnerability has been fixed",
        },
        "policy.violation": {
            "event": "policy.violation",
            "description": "Security policy was violated",
        },
        "policy.passed": {
            "event": "policy.passed",
            "description": "All security policies passed",
        },
    }

    def __init__(self) -> None:
        """Initialize the webhook engine."""
        self.endpoints: Dict[str, WebhookEndpoint] = {}
        self.delivery_log: List[DeliveryLogEntry] = []
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._max_log_entries = 10000
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
                timeout=httpx.Timeout(30.0),
            )
        return self._http_client

    def register_endpoint(self, endpoint: WebhookEndpoint) -> str:
        """
        Register a new webhook endpoint.

        Args:
            endpoint: Webhook endpoint configuration

        Returns:
            Endpoint ID
        """
        if not endpoint.id:
            endpoint.id = str(uuid4())[:8]
        self.endpoints[endpoint.id] = endpoint
        self.circuit_breakers[endpoint.id] = CircuitBreaker(endpoint_id=endpoint.id)
        logger.info("Registered webhook endpoint: %s -> %s", endpoint.id, endpoint.url)
        return endpoint.id

    def unregister_endpoint(self, endpoint_id: str) -> bool:
        """Unregister a webhook endpoint."""
        if endpoint_id not in self.endpoints:
            return False
        del self.endpoints[endpoint_id]
        self.circuit_breakers.pop(endpoint_id, None)
        logger.info("Unregistered webhook endpoint: %s", endpoint_id)
        return True

    def get_endpoint(self, endpoint_id: str) -> Optional[WebhookEndpoint]:
        """Get a webhook endpoint by ID."""
        return self.endpoints.get(endpoint_id)

    def list_endpoints(self, active_only: bool = False) -> List[WebhookEndpoint]:
        """List all registered endpoints."""
        endpoints = list(self.endpoints.values())
        if active_only:
            endpoints = [e for e in endpoints if e.active]
        return endpoints

    async def deliver_event(
        self,
        event_type: WebhookEventType,
        payload: Dict[str, Any],
        endpoint_id: Optional[str] = None,
        specific_url: Optional[str] = None,
    ) -> List[DeliveryLogEntry]:
        """
        Deliver a webhook event.

        Args:
            event_type: Type of event
            payload: Event data payload
            endpoint_id: Optional specific endpoint to deliver to
            specific_url: Optional specific URL to deliver to

        Returns:
            List of delivery log entries
        """
        results: List[DeliveryLogEntry] = []

        if specific_url:
            # Deliver to a specific URL (test delivery)
            temp_endpoint = WebhookEndpoint(
                url=specific_url,
                events=[event_type.value],
            )
            entry = await self._deliver_to_endpoint(temp_endpoint, event_type, payload)
            results.append(entry)
        elif endpoint_id:
            # Deliver to specific endpoint
            endpoint = self.endpoints.get(endpoint_id)
            if endpoint and endpoint.active:
                entry = await self._deliver_to_endpoint(endpoint, event_type, payload)
                results.append(entry)
        else:
            # Deliver to all endpoints subscribed to this event
            for endpoint in self.endpoints.values():
                if endpoint.active and event_type.value in endpoint.events:
                    entry = await self._deliver_to_endpoint(
                        endpoint, event_type, payload
                    )
                    results.append(entry)

        return results

    async def _deliver_to_endpoint(
        self,
        endpoint: WebhookEndpoint,
        event_type: WebhookEventType,
        payload: Dict[str, Any],
    ) -> DeliveryLogEntry:
        """Deliver an event to a single endpoint with retries."""
        delivery_id = str(uuid4())[:12]
        cb = self.circuit_breakers.get(endpoint.id)

        # Check circuit breaker
        if cb and not cb.can_execute():
            logger.warning(
                "Circuit breaker open for endpoint %s, skipping delivery %s",
                endpoint.id,
                delivery_id,
            )
            return DeliveryLogEntry(
                delivery_id=delivery_id,
                endpoint_id=endpoint.id,
                event_type=event_type.value,
                status=DeliveryStatus.FAILED,
                attempt_number=0,
                error_message="Circuit breaker is open",
            )

        # Build payload
        full_payload = self._build_payload(event_type, payload)
        body = json.dumps(full_payload, default=str)

        # Generate signature
        signature = self._generate_signature(body, endpoint.secret)

        # Build headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CodeShield-AI-Webhook/1.0",
            "X-Webhook-ID": delivery_id,
            "X-Webhook-Event": event_type.value,
            "X-Webhook-Timestamp": str(int(time.time())),
            **endpoint.headers,
        }
        if signature:
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        # Attempt delivery with retries
        last_entry = None
        for attempt in range(1, endpoint.max_retries + 1):
            if attempt > 1:
                delay = endpoint.retry_delays[min(attempt - 2, len(endpoint.retry_delays) - 1)]
                logger.info(
                    "Retrying delivery %s in %ds (attempt %d/%d)",
                    delivery_id,
                    delay,
                    attempt,
                    endpoint.max_retries,
                )
                await asyncio.sleep(delay)

            entry = await self._attempt_delivery(
                endpoint, delivery_id, event_type, body, headers, attempt
            )
            last_entry = entry

            if entry.status == DeliveryStatus.DELIVERED:
                if cb:
                    cb.record_success()
                break
            else:
                if cb:
                    cb.record_failure()
                if attempt < endpoint.max_retries:
                    entry.status = DeliveryStatus.RETRYING

        if last_entry and last_entry.status != DeliveryStatus.DELIVERED:
            last_entry.status = DeliveryStatus.EXHAUSTED

        # Add to log
        if last_entry:
            self._add_log_entry(last_entry)

        return last_entry or DeliveryLogEntry(
            delivery_id=delivery_id,
            endpoint_id=endpoint.id,
            event_type=event_type.value,
            status=DeliveryStatus.FAILED,
            attempt_number=0,
            error_message="Delivery failed",
        )

    async def _attempt_delivery(
        self,
        endpoint: WebhookEndpoint,
        delivery_id: str,
        event_type: WebhookEventType,
        body: str,
        headers: Dict[str, str],
        attempt: int,
    ) -> DeliveryLogEntry:
        """Attempt a single delivery."""
        start_time = time.time()
        entry = DeliveryLogEntry(
            delivery_id=delivery_id,
            endpoint_id=endpoint.id,
            event_type=event_type.value,
            status=DeliveryStatus.PENDING,
            attempt_number=attempt,
            request_body=body[:1000],  # Truncate for log
            signature=headers.get("X-Webhook-Signature", ""),
        )

        try:
            client = await self._get_client()
            response = await client.post(
                endpoint.url,
                content=body,
                headers=headers,
                timeout=endpoint.timeout_seconds,
            )

            duration_ms = int((time.time() - start_time) * 1000)
            entry.duration_ms = duration_ms
            entry.response_status = response.status_code
            entry.response_body = response.text[:500]  # Truncate

            if response.status_code >= 200 and response.status_code < 300:
                entry.status = DeliveryStatus.DELIVERED
                logger.info(
                    "Webhook delivered: %s -> %s (HTTP %d, %dms)",
                    delivery_id,
                    endpoint.url,
                    response.status_code,
                    duration_ms,
                )
            else:
                entry.status = DeliveryStatus.FAILED
                entry.error_message = f"HTTP {response.status_code}: {response.text[:200]}"
                logger.warning(
                    "Webhook delivery failed: %s -> %s (HTTP %d)",
                    delivery_id,
                    endpoint.url,
                    response.status_code,
                )

        except httpx.TimeoutException:
            entry.status = DeliveryStatus.FAILED
            entry.duration_ms = int((time.time() - start_time) * 1000)
            entry.error_message = "Request timeout"
        except httpx.ConnectError as e:
            entry.status = DeliveryStatus.FAILED
            entry.error_message = f"Connection error: {str(e)}"
        except Exception as e:
            entry.status = DeliveryStatus.FAILED
            entry.error_message = f"Unexpected error: {str(e)}"

        return entry

    @staticmethod
    def _build_payload(
        event_type: WebhookEventType, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build the full webhook payload."""
        template = WebhookEngine.PAYLOAD_TEMPLATES.get(
            event_type.value, {"event": event_type.value}
        )

        return {
            "version": "1.0",
            "event": template["event"],
            "description": template.get("description", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }

    @staticmethod
    def _generate_signature(payload: str, secret: Optional[str]) -> str:
        """Generate HMAC-SHA256 signature for a payload."""
        if not secret:
            return ""
        return hmac.new(
            secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify_signature(payload: str, signature: str, secret: str) -> bool:
        """
        Verify a webhook payload signature.

        Args:
            payload: Raw payload string
            signature: Signature to verify (without 'sha256=' prefix)
            secret: Shared secret

        Returns:
            True if signature is valid
        """
        expected = WebhookEngine._generate_signature(payload, secret)
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected, signature.replace("sha256=", ""))

    def _add_log_entry(self, entry: DeliveryLogEntry) -> None:
        """Add a delivery log entry, maintaining max size."""
        self.delivery_log.append(entry)
        if len(self.delivery_log) > self._max_log_entries:
            self.delivery_log = self.delivery_log[-self._max_log_entries // 2 :]

    def get_delivery_log(
        self,
        endpoint_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[DeliveryLogEntry]:
        """
        Get delivery log entries with filtering.

        Args:
            endpoint_id: Filter by endpoint
            event_type: Filter by event type
            limit: Maximum entries to return
            offset: Number of entries to skip

        Returns:
            Filtered list of log entries
        """
        entries = self.delivery_log

        if endpoint_id:
            entries = [e for e in entries if e.endpoint_id == endpoint_id]
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]

        # Sort by timestamp descending
        entries = sorted(entries, key=lambda e: e.timestamp, reverse=True)

        return entries[offset : offset + limit]

    def get_circuit_breaker_status(
        self, endpoint_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get circuit breaker status for endpoints."""
        if endpoint_id:
            cb = self.circuit_breakers.get(endpoint_id)
            return cb.to_dict() if cb else {}
        return {eid: cb.to_dict() for eid, cb in self.circuit_breakers.items()}

    async def close(self) -> None:
        """Close the webhook engine and cleanup resources."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()

    def to_dict(self) -> Dict[str, Any]:
        """Get engine status as dictionary."""
        return {
            "endpoints_registered": len(self.endpoints),
            "endpoints_active": sum(1 for e in self.endpoints.values() if e.active),
            "total_deliveries": len(self.delivery_log),
            "circuit_breakers": {
                eid: cb.to_dict() for eid, cb in self.circuit_breakers.items()
            },
        }
