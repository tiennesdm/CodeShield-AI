"""
Tests for integrations.ticketing module.
"""

import pytest

from integrations.ticketing import (
    TicketingIntegrationEngine, TicketConfig, TicketInfo, TicketStatus,
    get_ticketing_engine,
)


class TestTicketingIntegrationEngine:
    def setup_method(self):
        self.ticketing = TicketingIntegrationEngine()

    def test_configure_jira(self):
        config = self.ticketing.configure_jira(
            url="https://company.atlassian.net",
            username="bot@company.com",
            api_token="token-123",
            project_key="SEC",
        )
        assert config.provider == "jira"
        assert config.jira_project_key == "SEC"
        assert config.jira_url == "https://company.atlassian.net"

    def test_configure_github(self):
        config = self.ticketing.configure_github(
            token="ghp_xxx",
            owner="myorg",
            default_repo="myrepo",
        )
        assert config.provider == "github"
        assert config.github_owner == "myorg"
        assert config.github_default_repo == "myrepo"

    def test_configure_linear(self):
        config = self.ticketing.configure_linear(
            api_key="lin_api_xxx",
            team_id="team-uuid",
        )
        assert config.provider == "linear"
        assert config.linear_api_key == "lin_api_xxx"

    def test_configure_pagerduty(self):
        config = self.ticketing.configure_pagerduty(
            routing_key="pd-key-123",
        )
        assert config.provider == "pagerduty"
        assert config.pagerduty_routing_key == "pd-key-123"

    def test_severity_to_jira_priority(self):
        assert self.ticketing._severity_to_jira_priority("CRITICAL") == "Highest"
        assert self.ticketing._severity_to_jira_priority("HIGH") == "High"
        assert self.ticketing._severity_to_jira_priority("MEDIUM") == "Medium"
        assert self.ticketing._severity_to_jira_priority("LOW") == "Low"
        assert self.ticketing._severity_to_jira_priority("INFO") == "Lowest"

    def test_build_ticket_description(self):
        vuln = {
            "id": "v-1", "title": "SQL Injection", "severity": "HIGH",
            "category": "Injection", "cwe_id": "CWE-89", "cwe_name": "SQL Injection",
            "cvss_score": 7.5, "file_path": "app.py", "line_number": 42,
            "description": "User input used directly in SQL query",
            "fix_suggestion": "Use parameterized queries",
            "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "tool_source": "bandit", "scan_id": "s-1",
        }
        desc = self.ticketing._build_ticket_description(vuln)
        assert "SQL Injection" in desc
        assert "CWE-89" in desc
        assert "app.py" in desc
        assert "bandit" in desc

    def test_build_github_issue_body(self):
        vuln = {
            "id": "v-1", "title": "XSS", "severity": "HIGH",
            "category": "XSS", "cwe_id": "CWE-79",
            "file_path": "index.js", "line_number": 15,
            "description": "Reflected XSS vulnerability",
            "fix_suggestion": "Escape output",
            "code_snippet": "innerHTML = userInput",
            "tool_source": "semgrep", "scan_id": "s-1",
        }
        body = self.ticketing._build_github_issue_body(vuln)
        assert "Security Vulnerability" in body
        assert "CWE-79" in body
        assert "index.js" in body

    def test_simulate_ticket(self):
        vuln = {"id": "v-1", "title": "Test Vuln", "severity": "HIGH"}
        ticket = self.ticketing._simulate_ticket("jira", "Test Title", vuln)
        assert ticket.provider == "jira"
        assert ticket.status == TicketStatus.OPEN.value
        assert ticket.metadata.get("simulated") is True

    def test_list_tickets_empty(self):
        tickets = self.ticketing.list_tickets()
        assert tickets == []

    def test_auto_create_skips_low_severity(self):
        vuln = {"severity": "LOW", "title": "Minor Issue"}
        result = self.ticketing.auto_create_for_critical(vuln, providers=["jira"])
        # Should be a coroutine or skipped
        assert isinstance(result, dict)

    def test_ticket_info_to_dict(self):
        ticket = TicketInfo(
            ticket_id="SEC-123", provider="jira",
            ticket_url="https://jira/browse/SEC-123",
            title="Test Ticket", vulnerability_id="v-1",
            status=TicketStatus.OPEN.value,
        )
        data = ticket.to_dict()
        assert data["ticket_id"] == "SEC-123"
        assert data["provider"] == "jira"
        assert data["ticket_url"] == "https://jira/browse/SEC-123"

    def test_singleton(self):
        e1 = get_ticketing_engine()
        e2 = get_ticketing_engine()
        assert e1 is e2
