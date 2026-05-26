"""
Tests for integrations.notifications module.
"""

import pytest

from integrations.notifications import (
    NotificationEngine, NotificationConfig, get_notification_engine,
)


class TestNotificationEngine:
    def setup_method(self):
        self.notifier = NotificationEngine()

    def test_configure_slack(self):
        config = self.notifier.configure_slack(
            webhook_url="https://hooks.slack.com/services/T123/B456/xxx",
            channel="#security-alerts",
            username="CodeShield Bot",
        )
        assert config.channel == "slack"
        assert config.slack_webhook_url == "https://hooks.slack.com/services/T123/B456/xxx"
        assert config.slack_channel == "#security-alerts"

    def test_configure_teams(self):
        config = self.notifier.configure_teams(
            webhook_url="https://outlook.office.com/webhook/xxx",
        )
        assert config.channel == "teams"

    def test_configure_smtp(self):
        config = self.notifier.configure_smtp(
            host="smtp.corp.com",
            port=587,
            username="security@corp.com",
            password="app-password",
            from_address="security@corp.com",
            recipients=["team@corp.com", "admin@corp.com"],
        )
        assert config.channel == "email"
        assert config.smtp_host == "smtp.corp.com"
        assert len(config.recipients) == 2

    def test_add_email_recipient(self):
        self.notifier.configure_smtp(host="smtp.corp.com", recipients=[])
        self.notifier.add_email_recipient("new@corp.com")
        assert "new@corp.com" in self.notifier._configs["email"].recipients

    def test_meets_threshold(self):
        assert self.notifier._meets_threshold("CRITICAL", "LOW") is True
        assert self.notifier._meets_threshold("HIGH", "MEDIUM") is True
        assert self.notifier._meets_threshold("MEDIUM", "HIGH") is False
        assert self.notifier._meets_threshold("INFO", "LOW") is False

    def test_build_scan_slack_blocks(self):
        scan_data = {
            "name": "Frontend Scan",
            "scan_id": "s-123",
            "risk_score": 65,
            "stats": {"critical": 1, "high": 3, "medium": 5, "low": 2},
            "tools_used": ["semgrep", "bandit"],
        }
        blocks = self.notifier._build_scan_slack_blocks(scan_data)
        assert len(blocks) >= 3
        assert blocks[0]["type"] == "header"

    def test_build_vuln_slack_blocks(self):
        vuln = {
            "title": "SQL Injection", "severity": "CRITICAL",
            "file_path": "app.py", "line_number": 42,
            "category": "Injection", "cwe_id": "CWE-89",
            "cvss_score": 9.8, "tool_source": "semgrep",
        }
        blocks = self.notifier._build_vuln_slack_blocks(vuln)
        assert len(blocks) >= 2
        assert blocks[0]["type"] == "header"

    def test_build_scan_teams_card(self):
        scan_data = {
            "name": "Backend Scan",
            "scan_id": "s-456",
            "risk_score": 45,
            "stats": {"critical": 0, "high": 2, "medium": 4, "low": 3},
            "tools_used": ["bandit"],
        }
        card = self.notifier._build_scan_teams_card(scan_data)
        assert card["@type"] == "MessageCard"
        assert "summary" in card

    def test_build_vuln_teams_card(self):
        vuln = {
            "title": "XSS", "severity": "HIGH",
            "file_path": "index.js", "line_number": 15,
            "category": "XSS", "cwe_id": "CWE-79",
            "cvss_score": 7.5, "tool_source": "eslint",
        }
        card = self.notifier._build_vuln_teams_card(vuln)
        assert card["@type"] == "MessageCard"
        assert "facts" in card["sections"][0]

    def test_build_email_html(self):
        html = self.notifier._build_email_html("Test alert message", "HIGH")
        assert "HIGH" in html
        assert "Test alert message" in html
        assert "<html>" in html
        assert "</html>" in html

    def test_severity_colors(self):
        assert self.notifier.SEVERITY_COLORS["CRITICAL"] == "#DC2626"
        assert self.notifier.SEVERITY_COLORS["HIGH"] == "#EA580C"
        assert self.notifier.SEVERITY_COLORS["MEDIUM"] == "#D97706"

    def test_config_to_dict_masks_secrets(self):
        config = self.notifier.configure_slack(
            webhook_url="https://hooks.slack.com/secret",
        )
        data = config.to_dict(mask_secrets=True)
        assert "secret" not in data.get("slack_webhook_url", "")

    def test_singleton(self):
        e1 = get_notification_engine()
        e2 = get_notification_engine()
        assert e1 is e2
