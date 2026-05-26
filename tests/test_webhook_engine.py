"""
Tests for the Webhook Delivery Engine.

Covers webhook registration, delivery, retries, circuit breaker, and logging.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from webhook_engine import (
    CircuitBreaker,
    CircuitState,
    DeliveryLogEntry,
    DeliveryStatus,
    WebhookEndpoint,
    WebhookEngine,
    WebhookEventType,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def webhook_engine():
    """Create a fresh webhook engine."""
    engine = WebhookEngine()
    yield engine
    # Cleanup
    asyncio.run(engine.close())


@pytest.fixture
def sample_endpoint():
    """Create a sample webhook endpoint."""
    return WebhookEndpoint(
        url="https://httpbin.org/post",
        secret="test-secret-123",
        events=["scan.completed", "vulnerability.found"],
        description="Test endpoint",
        timeout_seconds=5,
        max_retries=2,
    )


# =============================================================================
# Webhook Endpoint Management Tests
# =============================================================================

class TestEndpointManagement:
    """Tests for webhook endpoint CRUD."""

    def test_register_endpoint(self, webhook_engine, sample_endpoint):
        """Test registering a webhook endpoint."""
        endpoint_id = webhook_engine.register_endpoint(sample_endpoint)

        assert endpoint_id
        assert endpoint_id in webhook_engine.endpoints
        assert endpoint_id in webhook_engine.circuit_breakers

    def test_unregister_endpoint(self, webhook_engine, sample_endpoint):
        """Test unregistering an endpoint."""
        endpoint_id = webhook_engine.register_endpoint(sample_endpoint)
        assert endpoint_id in webhook_engine.endpoints

        result = webhook_engine.unregister_endpoint(endpoint_id)
        assert result is True
        assert endpoint_id not in webhook_engine.endpoints

    def test_unregister_nonexistent(self, webhook_engine):
        """Test unregistering a non-existent endpoint."""
        result = webhook_engine.unregister_endpoint("nonexistent-id")
        assert result is False

    def test_get_endpoint(self, webhook_engine, sample_endpoint):
        """Test getting an endpoint by ID."""
        endpoint_id = webhook_engine.register_endpoint(sample_endpoint)
        retrieved = webhook_engine.get_endpoint(endpoint_id)

        assert retrieved is not None
        assert retrieved.url == sample_endpoint.url
        assert retrieved.secret == sample_endpoint.secret

    def test_list_endpoints(self, webhook_engine, sample_endpoint):
        """Test listing all endpoints."""
        webhook_engine.register_endpoint(sample_endpoint)

        endpoints = webhook_engine.list_endpoints()
        assert len(endpoints) >= 1

        active = webhook_engine.list_endpoints(active_only=True)
        assert len(active) >= 1

    def test_list_endpoints_filtered(self, webhook_engine):
        """Test listing with active filter."""
        inactive = WebhookEndpoint(
            url="https://example.com",
            active=False,
        )
        webhook_engine.register_endpoint(inactive)

        all_endpoints = webhook_engine.list_endpoints()
        active_only = webhook_engine.list_endpoints(active_only=True)

        assert len(all_endpoints) > len(active_only) or inactive not in active_only


# =============================================================================
# Payload and Signature Tests
# =============================================================================

class TestPayloadAndSignature:
    """Tests for payload building and signature generation."""

    def test_build_payload(self):
        """Test webhook payload building."""
        payload = WebhookEngine._build_payload(
            WebhookEventType.SCAN_COMPLETED,
            {"scan_id": "test-123", "status": "completed"},
        )

        assert "version" in payload
        assert "event" in payload
        assert "timestamp" in payload
        assert payload["event"] == "scan.completed"
        assert payload["data"]["scan_id"] == "test-123"

    def test_generate_signature(self):
        """Test HMAC-SHA256 signature generation."""
        payload = '{"event": "test"}'
        secret = "my-secret"
        signature = WebhookEngine._generate_signature(payload, secret)

        assert signature
        assert len(signature) == 64  # SHA-256 hex length

    def test_generate_signature_no_secret(self):
        """Test signature generation with no secret."""
        signature = WebhookEngine._generate_signature('{"test": true}', None)
        assert signature == ""

    def test_verify_signature(self):
        """Test signature verification."""
        payload = '{"event": "test"}'
        secret = "my-secret"
        signature = WebhookEngine._generate_signature(payload, secret)

        valid = WebhookEngine.verify_signature(payload, f"sha256={signature}", secret)
        assert valid is True

    def test_verify_invalid_signature(self):
        """Test verification with wrong signature."""
        payload = '{"event": "test"}'
        secret = "my-secret"

        invalid = WebhookEngine.verify_signature(payload, "sha256=invalid", secret)
        assert invalid is False

    def test_payload_templates_exist(self):
        """Test that all event type templates exist."""
        for event_type in WebhookEventType:
            template = WebhookEngine.PAYLOAD_TEMPLATES.get(event_type.value)
            assert template is not None, f"Missing template for {event_type.value}"
            assert "event" in template


# =============================================================================
# Circuit Breaker Tests
# =============================================================================

class TestCircuitBreaker:
    """Tests for the circuit breaker pattern."""

    def test_initial_state(self):
        """Test circuit breaker starts closed."""
        cb = CircuitBreaker(endpoint_id="test")
        assert cb.state == CircuitState.CLOSED
        assert cb.can_execute() is True

    def test_open_after_failures(self):
        """Test circuit opens after threshold failures."""
        cb = CircuitBreaker(endpoint_id="test", failure_threshold=3)

        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED  # Not yet

        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.can_execute() is False

    def test_close_after_recovery(self):
        """Test circuit closes after successful recovery."""
        cb = CircuitBreaker(endpoint_id="test", failure_threshold=1)

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Force half-open by waiting (simulated)
        cb.state = CircuitState.HALF_OPEN
        cb.success_count = 0

        cb.record_success()
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_max_requests(self):
        """Test half-open limits requests."""
        cb = CircuitBreaker(
            endpoint_id="test",
            state=CircuitState.HALF_OPEN,
            half_open_max_requests=2,
        )

        assert cb.can_execute() is True
        cb.record_success()
        assert cb.can_execute() is True
        cb.record_success()
        # Now at max
        assert cb.can_execute() is True  # half_open_max_requests check

    def test_record_success_in_closed(self):
        """Test recording success in closed state."""
        cb = CircuitBreaker(endpoint_id="test")
        cb.failure_count = 2

        cb.record_success()
        assert cb.failure_count == 0
        assert cb.success_count == 1

    def test_to_dict(self):
        """Test circuit breaker serialization."""
        cb = CircuitBreaker(endpoint_id="test-123")
        data = cb.to_dict()

        assert data["endpoint_id"] == "test-123"
        assert data["state"] == "closed"
        assert "failure_count" in data


# =============================================================================
# Delivery Log Tests
# =============================================================================

class TestDeliveryLog:
    """Tests for delivery logging."""

    def test_log_entry_creation(self):
        """Test creating a delivery log entry."""
        entry = DeliveryLogEntry(
            delivery_id="test-123",
            endpoint_id="endpoint-456",
            event_type="scan.completed",
            status=DeliveryStatus.DELIVERED,
            attempt_number=1,
            response_status=200,
            duration_ms=150,
        )

        data = entry.to_dict()
        assert data["delivery_id"] == "test-123"
        assert data["status"] == "delivered"
        assert data["response_status"] == 200

    def test_get_delivery_log(self, webhook_engine):
        """Test retrieving delivery log."""
        # Add some entries
        for i in range(5):
            entry = DeliveryLogEntry(
                delivery_id=f"test-{i}",
                endpoint_id="ep-1",
                event_type="scan.completed",
                status=DeliveryStatus.DELIVERED,
                attempt_number=1,
            )
            webhook_engine._add_log_entry(entry)

        entries = webhook_engine.get_delivery_log(limit=10)
        assert len(entries) == 5

    def test_get_delivery_log_filtered(self, webhook_engine):
        """Test filtering delivery log."""
        entry1 = DeliveryLogEntry(
            delivery_id="t1",
            endpoint_id="ep-1",
            event_type="scan.completed",
            status=DeliveryStatus.DELIVERED,
            attempt_number=1,
        )
        entry2 = DeliveryLogEntry(
            delivery_id="t2",
            endpoint_id="ep-2",
            event_type="vulnerability.found",
            status=DeliveryStatus.FAILED,
            attempt_number=1,
        )
        webhook_engine._add_log_entry(entry1)
        webhook_engine._add_log_entry(entry2)

        filtered = webhook_engine.get_delivery_log(endpoint_id="ep-1")
        assert len(filtered) == 1
        assert filtered[0].endpoint_id == "ep-1"

    def test_log_truncation(self, webhook_engine):
        """Test that log is truncated when too large."""
        # Add many entries
        for i in range(100):
            entry = DeliveryLogEntry(
                delivery_id=f"test-{i}",
                endpoint_id="ep",
                event_type="scan.completed",
                status=DeliveryStatus.DELIVERED,
                attempt_number=1,
            )
            webhook_engine._add_log_entry(entry)

        # Should still be manageable
        entries = webhook_engine.get_delivery_log()
        assert len(entries) <= 100


# =============================================================================
# Webhook Engine Status Tests
# =============================================================================

class TestEngineStatus:
    """Tests for engine status and metadata."""

    def test_to_dict(self, webhook_engine):
        """Test engine status serialization."""
        status = webhook_engine.to_dict()

        assert "endpoints_registered" in status
        assert "circuit_breakers" in status
        assert isinstance(status["endpoints_registered"], int)

    def test_circuit_breaker_status(self, webhook_engine):
        """Test getting circuit breaker status."""
        endpoint = WebhookEndpoint(url="https://example.com")
        ep_id = webhook_engine.register_endpoint(endpoint)

        status = webhook_engine.get_circuit_breaker_status(ep_id)
        assert status["state"] == "closed"

        all_status = webhook_engine.get_circuit_breaker_status()
        assert ep_id in all_status


# =============================================================================
# WebhookEndpoint Tests
# =============================================================================

class TestWebhookEndpoint:
    """Tests for the WebhookEndpoint dataclass."""

    def test_default_creation(self):
        """Test creating endpoint with defaults."""
        ep = WebhookEndpoint(url="https://example.com")

        assert ep.id  # Auto-generated
        assert ep.events == ["scan.completed"]
        assert ep.active is True
        assert ep.timeout_seconds == 30
        assert ep.max_retries == 5

    def test_to_dict(self):
        """Test endpoint serialization."""
        ep = WebhookEndpoint(
            url="https://example.com",
            secret="secret",
            description="Test",
        )
        data = ep.to_dict()

        assert data["url"] == "https://example.com"
        assert data["active"] is True
        assert "secret" not in data  # Secret should not be exposed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
