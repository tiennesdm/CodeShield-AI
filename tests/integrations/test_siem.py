"""
Tests for integrations.siem module.
"""

import pytest

from integrations.siem import (
    SIEMIntegrationEngine, SIEMConfig, SIEMEvent,
    get_siem_engine,
)


class TestSIEMIntegrationEngine:
    def setup_method(self):
        self.siem = SIEMIntegrationEngine()

    def test_configure_splunk(self):
        config = self.siem.configure_splunk(
            hec_url="https://splunk.corp.com:8088",
            hec_token="test-token-123",
            index="security",
        )
        assert config.provider == "splunk"
        assert config.index == "security"
        assert config.api_key == "test-token-123"

    def test_configure_datadog(self):
        config = self.siem.configure_datadog(
            api_key="dd-api-key",
            app_key="dd-app-key",
        )
        assert config.provider == "datadog"
        assert config.api_key == "dd-api-key"

    def test_configure_elastic(self):
        config = self.siem.configure_elastic(
            elasticsearch_url="https://elastic.corp.com:9200",
            api_key="elastic-api-key",
            index="security-codeshield",
        )
        assert config.provider == "elastic"
        assert config.index == "security-codeshield"

    def test_configure_syslog(self):
        config = self.siem.configure_syslog(
            host="syslog.corp.com",
            port=514,
            protocol="udp",
        )
        assert config.provider == "syslog"
        assert config.syslog_host == "syslog.corp.com"
        assert config.syslog_port == 514

    def test_get_config(self):
        self.siem.configure_splunk("https://s.com", "token")
        config = self.siem.get_config("splunk")
        assert config is not None
        assert config.provider == "splunk"

    def test_list_providers(self):
        self.siem.configure_splunk("https://s.com", "t1")
        self.siem.configure_datadog("k1", "k2")
        providers = self.siem.list_providers()
        assert len(providers) == 2

    def test_remove_provider(self):
        self.siem.configure_splunk("https://s.com", "t")
        assert self.siem.remove_provider("splunk") is True
        assert self.siem.get_config("splunk") is None
        assert self.siem.remove_provider("nonexistent") is False

    def test_export_cef(self):
        scan_results = [
            {
                "scan_id": "s1", "name": "Scan 1", "risk_score": 75,
                "stats": {"total": 10, "critical": 1, "high": 3, "medium": 4, "low": 2},
                "tools_used": ["semgrep"],
                "vulnerabilities": [
                    {"id": "v1", "title": "SQLi", "severity": "HIGH", "category": "Injection",
                     "cwe_id": "CWE-89", "file_path": "app.py", "scan_id": "s1"},
                ],
            },
        ]
        events = self.siem.export_cef(scan_results)
        assert len(events) >= 2  # scan event + vulnerability event
        assert all("CEF:0|CodeShield" in e for e in events)

    def test_export_syslog(self):
        scan_results = [
            {
                "scan_id": "s1", "name": "Scan 1", "risk_score": 50,
                "stats": {"total": 5, "critical": 0, "high": 1, "medium": 2, "low": 2},
                "tools_used": ["bandit"],
                "vulnerabilities": [],
            },
        ]
        messages = self.siem.export_syslog(scan_results)
        assert len(messages) >= 1
        assert all("<" in m for m in messages)  # PRI field

    def test_siem_event_to_splunk(self):
        event = SIEMEvent(
            event_type="test.event", severity=5,
            message="Test message", fields={"key": "value"},
        )
        splunk_format = event.to_splunk_hec()
        assert splunk_format["event"]["type"] == "test.event"
        assert splunk_format["event"]["severity"] == 5

    def test_siem_event_to_datadog(self):
        event = SIEMEvent(
            event_type="test.event", severity=3,
            message="Test message", fields={"scan_id": "s1"},
        )
        dd_format = event.to_datadog_log()
        assert "ddsource" in dd_format
        assert "codeshield" in dd_format["ddtags"]

    def test_siem_event_to_elastic(self):
        event = SIEMEvent(
            event_type="vulnerability.detected", severity=8,
            message="High severity vuln", fields={"cwe_id": "CWE-89"},
        )
        elastic_format = event.to_elastic_doc()
        assert "@timestamp" in elastic_format
        assert elastic_format["event"]["severity"] == 8

    def test_siem_event_to_cef(self):
        event = SIEMEvent(
            event_type="scan.completed", severity=5,
            message="Scan done", fields={"scan_id": "s1"},
        )
        config = SIEMConfig(provider="cef")
        cef_string = event.to_cef(config)
        assert "CEF:0|CodeShield|AI Security Platform" in cef_string
        assert "scan.completed" in cef_string

    def test_siem_event_to_syslog(self):
        event = SIEMEvent(
            event_type="scan.completed", severity=5,
            message="Scan done", fields={"scan_id": "s1"},
        )
        config = SIEMConfig(provider="syslog")
        syslog_msg = event.to_syslog(config)
        assert "<" in syslog_msg
        assert "codeshield" in syslog_msg

    def test_singleton(self):
        e1 = get_siem_engine()
        e2 = get_siem_engine()
        assert e1 is e2
