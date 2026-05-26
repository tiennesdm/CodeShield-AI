"""
Enterprise SIEM Integration

Supports:
- Splunk HEC (HTTP Event Collector)
- Datadog Logs API
- Elastic Security
- CEF (Common Event Format) export
- Syslog export (RFC 5424)

Usage:
    siem = SIEMIntegrationEngine()
    siem.configure_splunk("https://splunk.corp.com:8088", "token-abc123")
    siem.configure_datadog("api-key-123", "app-key-456")
    await siem.send_scan_event("scan.completed", scan_data)
    cef_events = siem.export_cef(scan_results)
"""

from __future__ import annotations

import json
import socket
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SIEMConfig(BaseModel):
    """Configuration for a SIEM integration."""
    provider: str  # splunk, datadog, elastic, syslog
    enabled: bool = True
    endpoint_url: Optional[str] = None
    api_key: Optional[str] = None
    index: str = "main"  # Splunk index / Elastic index
    source: str = "codeshield"
    sourcetype: str = "json"
    host: str = "codeshield-ai"
    # Syslog-specific
    syslog_host: Optional[str] = None
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # udp, tcp
    syslog_facility: int = 16  # local0
    # Additional headers
    headers: Dict[str, str] = Field(default_factory=dict)
    # CEF-specific
    cef_device_vendor: str = "CodeShield"
    cef_device_product: str = "AI Security Platform"
    cef_device_version: str = "1.0.0"

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        data = self.model_dump()
        if mask_secrets and data.get("api_key"):
            data["api_key"] = "***" + data["api_key"][-4:]
        return data


class SIEMEvent(BaseModel):
    """A normalized SIEM event."""
    event_type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: int = 5  # 0-10 scale
    source: str = "codeshield"
    host: str = "codeshield-ai"
    message: str = ""
    fields: Dict[str, Any] = Field(default_factory=dict)

    def to_splunk_hec(self) -> Dict[str, Any]:
        """Format for Splunk HEC."""
        return {
            "time": self.timestamp.timestamp(),
            "event": {
                "type": self.event_type,
                "severity": self.severity,
                "message": self.message,
                **self.fields,
            },
            "sourcetype": "json",
            "source": self.source,
            "host": self.host,
        }

    def to_datadog_log(self) -> Dict[str, Any]:
        """Format for Datadog Logs API."""
        return {
            "ddsource": self.source,
            "ddtags": f"env:production,source:codeshield,event_type:{self.event_type}",
            "hostname": self.host,
            "message": json.dumps({
                "type": self.event_type,
                "severity": self.severity,
                "message": self.message,
                "timestamp": self.timestamp.isoformat(),
                **self.fields,
            }),
            "service": "codeshield",
        }

    def to_elastic_doc(self) -> Dict[str, Any]:
        """Format for Elastic Security."""
        return {
            "@timestamp": self.timestamp.isoformat(),
            "event": {
                "kind": "event",
                "category": ["vulnerability"],
                "type": [self.event_type],
                "severity": self.severity,
            },
            "observer": {
                "vendor": "CodeShield",
                "product": "AI Security Platform",
                "version": "1.0.0",
            },
            "message": self.message,
            **self.fields,
        }

    def to_cef(self, config: SIEMConfig) -> str:
        """Format as CEF (Common Event Format) string."""
        # CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extensions
        timestamp_ms = int(self.timestamp.timestamp() * 1000)
        extensions = " ".join(
            f"{k}={json.dumps(v) if isinstance(v, (dict, list)) else v}"
            for k, v in self.fields.items()
        )

        return (
            f"CEF:0|{config.cef_device_vendor}|{config.cef_device_product}|"
            f"{config.cef_device_version}|{self.event_type}|{self.message}|"
            f"{min(10, max(0, self.severity))}|rt={timestamp_ms} "
            f"{extensions}"
        )

    def to_syslog(self, config: SIEMConfig) -> str:
        """Format as RFC 5424 Syslog message."""
        # PRI = facility * 8 + severity
        # Facility 16 = local0
        severity = min(7, max(0, 10 - self.severity))  # Map 0-10 to syslog 0-7
        pri = config.syslog_facility * 8 + severity
        timestamp = self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        structured_data = "-"
        if self.fields:
            pairs = " ".join(f'{k}="{v}"' for k, v in self.fields.items())
            structured_data = f"[codeshield@32473 {pairs}]"

        msg = json.dumps({
            "type": self.event_type,
            "message": self.message,
            "severity": self.severity,
            **self.fields,
        })

        return f"<{pri}>1 {timestamp} {self.host} codeshield - - {structured_data} {msg}"


class SIEMIntegrationEngine:
    """
    Enterprise SIEM Integration Engine.

    Sends security events to Splunk, Datadog, Elastic, or via CEF/Syslog.
    """

    # Severity mapping from CodeShield severity to 0-10 scale
    SEVERITY_MAP = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 1,
    }

    def __init__(self) -> None:
        self._configs: Dict[str, SIEMConfig] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_splunk(
        self,
        hec_url: str,
        hec_token: str,
        index: str = "security",
        sourcetype: str = "json",
    ) -> SIEMConfig:
        """Configure Splunk HTTP Event Collector."""
        config = SIEMConfig(
            provider="splunk",
            endpoint_url=hec_url.rstrip("/") + "/services/collector/event",
            api_key=hec_token,
            index=index,
            sourcetype=sourcetype,
            headers={"Authorization": f"Splunk {hec_token}"},
        )
        self._configs["splunk"] = config
        return config

    def configure_datadog(
        self,
        api_key: str,
        app_key: Optional[str] = None,
        site: str = "datadoghq.com",
    ) -> SIEMConfig:
        """Configure Datadog Logs API."""
        config = SIEMConfig(
            provider="datadog",
            endpoint_url=f"https://http-intake.logs.{site}/v1/input",
            api_key=api_key,
            headers={
                "DD-API-KEY": api_key,
                **({"DD-APPLICATION-KEY": app_key} if app_key else {}),
            },
        )
        self._configs["datadog"] = config
        return config

    def configure_elastic(
        self,
        elasticsearch_url: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index: str = "security-codeshield",
    ) -> SIEMConfig:
        """Configure Elastic Security integration."""
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        config = SIEMConfig(
            provider="elastic",
            endpoint_url=elasticsearch_url.rstrip("/"),
            api_key=api_key,
            index=index,
            headers=headers,
        )
        if username and password:
            import base64
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            config.headers["Authorization"] = f"Basic {credentials}"

        self._configs["elastic"] = config
        return config

    def configure_syslog(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        facility: int = 16,
    ) -> SIEMConfig:
        """Configure Syslog export."""
        config = SIEMConfig(
            provider="syslog",
            syslog_host=host,
            syslog_port=port,
            syslog_protocol=protocol,
            syslog_facility=facility,
        )
        self._configs["syslog"] = config
        return config

    def get_config(self, provider: str) -> Optional[SIEMConfig]:
        return self._configs.get(provider)

    # ------------------------------------------------------------------
    # Event Sending
    # ------------------------------------------------------------------

    async def send_event(
        self,
        event: SIEMEvent,
        providers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send an event to configured SIEM providers."""
        results: Dict[str, Any] = {}
        targets = providers or list(self._configs.keys())

        for provider_name in targets:
            config = self._configs.get(provider_name)
            if not config or not config.enabled:
                continue

            try:
                if provider_name == "splunk":
                    results["splunk"] = await self._send_splunk(event, config)
                elif provider_name == "datadog":
                    results["datadog"] = await self._send_datadog(event, config)
                elif provider_name == "elastic":
                    results["elastic"] = await self._send_elastic(event, config)
                elif provider_name == "syslog":
                    results["syslog"] = await self._send_syslog(event, config)
            except Exception as e:
                results[provider_name] = {"error": str(e)}

        return results

    async def send_scan_event(
        self,
        event_type: str,
        scan_data: Dict[str, Any],
        providers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send a scan-related event to SIEM."""
        stats = scan_data.get("stats", {})
        total_vulns = stats.get("total", 0)
        risk_score = scan_data.get("risk_score", 0)

        severity = 5
        if total_vulns > 0:
            severity = min(10, max(1, total_vulns // 2 + risk_score // 20))

        event = SIEMEvent(
            event_type=event_type,
            severity=severity,
            message=f"CodeShield scan {event_type}: {scan_data.get('name', 'unknown')}",
            fields={
                "scan_id": scan_data.get("scan_id"),
                "scan_name": scan_data.get("name"),
                "total_vulnerabilities": total_vulns,
                "critical": stats.get("critical", 0),
                "high": stats.get("high", 0),
                "medium": stats.get("medium", 0),
                "low": stats.get("low", 0),
                "risk_score": risk_score,
                "source_type": scan_data.get("source_type"),
                "languages": scan_data.get("languages", []),
                "tools_used": scan_data.get("tools_used", []),
            },
        )
        return await self.send_event(event, providers)

    async def send_vulnerability_event(
        self,
        vulnerability: Dict[str, Any],
        event_type: str = "vulnerability.detected",
        providers: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send a vulnerability detection event to SIEM."""
        sev = (vulnerability.get("severity") or "INFO").upper()
        severity = self.SEVERITY_MAP.get(sev, 5)

        event = SIEMEvent(
            event_type=event_type,
            severity=severity,
            message=f"Vulnerability detected: {vulnerability.get('title', 'Unknown')}",
            fields={
                "vulnerability_id": vulnerability.get("id"),
                "scan_id": vulnerability.get("scan_id"),
                "title": vulnerability.get("title"),
                "severity": sev,
                "category": vulnerability.get("category"),
                "cwe_id": vulnerability.get("cwe_id"),
                "file_path": vulnerability.get("file_path"),
                "line_number": vulnerability.get("line_number"),
                "tool_source": vulnerability.get("tool_source"),
                "cvss_score": vulnerability.get("cvss_score"),
            },
        )
        return await self.send_event(event, providers)

    # ------------------------------------------------------------------
    # CEF Export
    # ------------------------------------------------------------------

    def export_cef(
        self,
        scan_results: List[Dict[str, Any]],
    ) -> List[str]:
        """Export scan results as CEF events."""
        config = self._configs.get("cef")
        if not config:
            config = SIEMConfig(provider="cef")

        events: List[str] = []
        for scan in scan_results:
            event = SIEMEvent(
                event_type="scan.completed",
                severity=min(10, max(1, scan.get("risk_score", 0) // 10)),
                message=f"Scan completed: {scan.get('name', 'unknown')}",
                fields={
                    "scan_id": scan.get("scan_id"),
                    "total_vulnerabilities": scan.get("stats", {}).get("total", 0),
                    "risk_score": scan.get("risk_score"),
                },
            )
            events.append(event.to_cef(config))

        for scan in scan_results:
            for vuln in scan.get("vulnerabilities", []):
                sev_str = (vuln.get("severity") or "INFO").upper()
                event = SIEMEvent(
                    event_type="vulnerability.detected",
                    severity=self.SEVERITY_MAP.get(sev_str, 5),
                    message=f"Vulnerability: {vuln.get('title', 'Unknown')}",
                    fields={
                        "vuln_id": vuln.get("id"),
                        "scan_id": vuln.get("scan_id"),
                        "severity": sev_str,
                        "category": vuln.get("category"),
                        "cwe_id": vuln.get("cwe_id"),
                        "file_path": vuln.get("file_path"),
                    },
                )
                events.append(event.to_cef(config))

        return events

    # ------------------------------------------------------------------
    # Syslog Export
    # ------------------------------------------------------------------

    def export_syslog(
        self,
        scan_results: List[Dict[str, Any]],
    ) -> List[str]:
        """Export scan results as Syslog messages."""
        config = self._configs.get("syslog")
        if not config:
            config = SIEMConfig(provider="syslog")

        messages: List[str] = []
        for scan in scan_results:
            event = SIEMEvent(
                event_type="scan.completed",
                severity=min(10, max(1, scan.get("risk_score", 0) // 10)),
                message=f"Scan completed: {scan.get('name')}",
                fields={
                    "scan_id": scan.get("scan_id"),
                    "total_vulns": scan.get("stats", {}).get("total", 0),
                },
            )
            messages.append(event.to_syslog(config))

        return messages

    # ------------------------------------------------------------------
    # Internal Send Methods
    # ------------------------------------------------------------------

    async def _send_splunk(self, event: SIEMEvent, config: SIEMConfig) -> Dict[str, Any]:
        """Send event to Splunk HEC."""
        payload = event.to_splunk_hec()
        payload["index"] = config.index

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            config.endpoint_url or "",
            data=data,
            headers={**config.headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return {"status": resp.status, "response": resp.read().decode()[:200]}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "error": e.read().decode()[:500]}
        except Exception as e:
            return {"error": str(e)}

    async def _send_datadog(self, event: SIEMEvent, config: SIEMConfig) -> Dict[str, Any]:
        """Send event to Datadog Logs API."""
        payload = event.to_datadog_log()
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            config.endpoint_url or "",
            data=data,
            headers={**config.headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return {"status": resp.status, "response": resp.read().decode()[:200]}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "error": e.read().decode()[:500]}
        except Exception as e:
            return {"error": str(e)}

    async def _send_elastic(self, event: SIEMEvent, config: SIEMConfig) -> Dict[str, Any]:
        """Send event to Elastic Security."""
        doc = event.to_elastic_doc()
        index_name = f"{config.index}-{event.timestamp.strftime('%Y.%m.%d')}"
        url = f"{config.endpoint_url}/{index_name}/_doc"
        data = json.dumps(doc).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={**config.headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return {"status": resp.status, "response": resp.read().decode()[:200]}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "error": e.read().decode()[:500]}
        except Exception as e:
            return {"error": str(e)}

    async def _send_syslog(self, event: SIEMEvent, config: SIEMConfig) -> Dict[str, Any]:
        """Send event via Syslog."""
        message = event.to_syslog(config)
        host = config.syslog_host or "localhost"
        port = config.syslog_port

        try:
            if config.syslog_protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                sock.sendall((message + "\n").encode())
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message.encode(), (host, port))
                sock.close()
            return {"status": "sent", "bytes": len(message)}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Provider Management
    # ------------------------------------------------------------------

    def list_providers(self) -> List[Dict[str, Any]]:
        """List configured SIEM providers."""
        return [
            {"name": name, **config.to_dict(mask_secrets=True)}
            for name, config in self._configs.items()
        ]

    def remove_provider(self, name: str) -> bool:
        """Remove a SIEM provider configuration."""
        if name in self._configs:
            del self._configs[name]
            return True
        return False


# Singleton
_siem_engine: Optional[SIEMIntegrationEngine] = None


def get_siem_engine() -> SIEMIntegrationEngine:
    """Get or create the global SIEM engine."""
    global _siem_engine
    if _siem_engine is None:
        _siem_engine = SIEMIntegrationEngine()
    return _siem_engine
