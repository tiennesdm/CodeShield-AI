"""
Enterprise Notification Integration

Supports:
- Slack: Block Kit formatted messages
- Microsoft Teams: Adaptive Cards
- Email: HTML templates per severity
- PagerDuty: Incident creation for critical

Usage:
    notifier = NotificationEngine()
    notifier.configure_slack(webhook_url="https://hooks.slack.com/...")
    notifier.configure_teams(webhook_url="https://outlook.office.com/...")
    notifier.configure_smtp(host="smtp.company.com", from_addr="security@company.com")
    
    await notifier.notify_scan_completed(scan_data)
    await notifier.notify_vulnerability_found(critical_vuln)
    await notifier.notify_sla_breach(sla_record)
"""

from __future__ import annotations

import json
import smtplib
import urllib.request
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NotificationConfig(BaseModel):
    """Configuration for a notification channel."""
    channel: str  # slack, teams, email, pagerduty
    enabled: bool = True
    # Slack
    slack_webhook_url: Optional[str] = None
    slack_channel: Optional[str] = None
    slack_username: str = "CodeShield AI"
    slack_icon_emoji: str = ":shield:"
    # Teams
    teams_webhook_url: Optional[str] = None
    # Email
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    from_address: str = "security@codeshield.ai"
    # Recipients
    recipients: List[str] = Field(default_factory=list)  # Email addresses or user IDs
    severity_threshold: str = "LOW"  # Only notify for this severity and above

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        data = self.model_dump()
        if mask_secrets:
            for key in ["slack_webhook_url", "teams_webhook_url", "smtp_password"]:
                if data.get(key):
                    data[key] = "***"
        return data


class NotificationEngine:
    """
    Enterprise Notification Engine.

    Sends formatted notifications via Slack, Teams, Email, and PagerDuty.
    Supports severity-based routing and HTML email templates.
    """

    SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    SEVERITY_COLORS = {
        "CRITICAL": "#DC2626",
        "HIGH": "#EA580C",
        "MEDIUM": "#D97706",
        "LOW": "#65A30D",
        "INFO": "#2563EB",
    }
    SEVERITY_EMOJI = {
        "CRITICAL": "\U0001F6A8",  # 🚨
        "HIGH": "\u26A0\uFE0F",      # ⚠️
        "MEDIUM": "\U0001F7E1",      # 🟡
        "LOW": "\U0001F7E2",         # 🟢
        "INFO": "\U0001F535",         # 🔵
    }

    def __init__(self) -> None:
        self._configs: Dict[str, NotificationConfig] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_slack(
        self,
        webhook_url: str,
        channel: Optional[str] = None,
        username: str = "CodeShield AI",
        severity_threshold: str = "LOW",
    ) -> NotificationConfig:
        """Configure Slack webhook notifications."""
        config = NotificationConfig(
            channel="slack",
            slack_webhook_url=webhook_url,
            slack_channel=channel,
            slack_username=username,
            severity_threshold=severity_threshold,
        )
        self._configs["slack"] = config
        return config

    def configure_teams(
        self,
        webhook_url: str,
        severity_threshold: str = "LOW",
    ) -> NotificationConfig:
        """Configure Microsoft Teams webhook notifications."""
        config = NotificationConfig(
            channel="teams",
            teams_webhook_url=webhook_url,
            severity_threshold=severity_threshold,
        )
        self._configs["teams"] = config
        return config

    def configure_smtp(
        self,
        host: str,
        port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_address: str = "security@codeshield.ai",
        recipients: Optional[List[str]] = None,
        use_tls: bool = True,
        severity_threshold: str = "LOW",
    ) -> NotificationConfig:
        """Configure email (SMTP) notifications."""
        config = NotificationConfig(
            channel="email",
            smtp_host=host,
            smtp_port=port,
            smtp_username=username,
            smtp_password=password,
            smtp_use_tls=use_tls,
            from_address=from_address,
            recipients=recipients or [],
            severity_threshold=severity_threshold,
        )
        self._configs["email"] = config
        return config

    def add_email_recipient(self, email: str) -> None:
        """Add an email recipient."""
        if "email" in self._configs:
            if email not in self._configs["email"].recipients:
                self._configs["email"].recipients.append(email)

    # ------------------------------------------------------------------
    # Notification Dispatch
    # ------------------------------------------------------------------

    async def send_notification(
        self,
        message: str,
        severity: str = "INFO",
        channels: Optional[List[str]] = None,
        blocks: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send a notification to configured channels.

        Args:
            message: The notification message
            severity: Severity level for filtering
            channels: Specific channels, or None for all configured
            blocks: Optional structured payload (Slack Block Kit, etc.)
        """
        results: Dict[str, Any] = {}
        targets = channels or list(self._configs.keys())

        for channel_name in targets:
            config = self._configs.get(channel_name)
            if not config or not config.enabled:
                continue
            if not self._meets_threshold(severity, config.severity_threshold):
                continue

            try:
                if channel_name == "slack":
                    results["slack"] = await self._send_slack(message, config, blocks)
                elif channel_name == "teams":
                    results["teams"] = await self._send_teams(message, config, blocks)
                elif channel_name == "email":
                    results["email"] = await self._send_email(message, severity, config)
            except Exception as e:
                results[channel_name] = {"error": str(e)}

        return results

    async def notify_scan_completed(
        self,
        scan_data: Dict[str, Any],
        channels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send scan completion notification."""
        stats = scan_data.get("stats", {})
        risk = scan.get("risk_score", 0)
        total = stats.get("total", 0)
        critical = stats.get("critical", 0)
        high = stats.get("high", 0)

        severity = "INFO" if total == 0 else "MEDIUM" if critical == 0 and high == 0 else "HIGH"
        if critical > 0:
            severity = "CRITICAL"
        elif high > 0:
            severity = "HIGH"

        emoji = self.SEVERITY_EMOJI.get(severity, "")
        message = (
            f"{emoji} Scan Completed: *{scan_data.get('name', 'Unknown')}*\n"
            f"Risk Score: {risk} | Total: {total} | "
            f"Critical: {critical} | High: {high} | "
            f"Medium: {stats.get('medium', 0)} | Low: {stats.get('low', 0)}"
        )

        slack_blocks = self._build_scan_slack_blocks(scan_data)
        teams_card = self._build_scan_teams_card(scan_data)

        return await self.send_notification(
            message=message,
            severity=severity,
            channels=channels,
            blocks={"slack": slack_blocks, "teams": teams_card},
        )

    async def notify_vulnerability_found(
        self,
        vulnerability: Dict[str, Any],
        channels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send vulnerability detection notification."""
        sev = (vulnerability.get("severity") or "INFO").upper()
        emoji = self.SEVERITY_EMOJI.get(sev, "")
        message = (
            f"{emoji} *{sev}* Vulnerability Detected\n"
            f"*{vulnerability.get('title', 'Unknown')}*\n"
            f"File: `{vulnerability.get('file_path', 'unknown')}:{vulnerability.get('line_number', 'N/A')}`\n"
            f"Category: {vulnerability.get('category', 'Unknown')} | "
            f"CWE: {vulnerability.get('cwe_id', 'N/A')} | "
            f"Tool: {vulnerability.get('tool_source', 'Unknown')}"
        )

        slack_blocks = self._build_vuln_slack_blocks(vulnerability)
        teams_card = self._build_vuln_teams_card(vulnerability)

        return await self.send_notification(
            message=message,
            severity=sev,
            channels=channels,
            blocks={"slack": slack_blocks, "teams": teams_card},
        )

    async def notify_sla_breach(
        self,
        sla_record: Dict[str, Any],
        channels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send SLA breach notification."""
        sev = (sla_record.get("severity") or "HIGH").upper()
        hours = sla_record.get("hours_overdue", 0)
        message = (
            f"{self.SEVERITY_EMOJI.get(sev, '')} SLA BREACH: {sev} vulnerability "
            f"*{sla_record.get('title', 'Unknown')}* is "
            f"*{hours:.1f} hours* overdue!\n"
            f"Deadline was: {sla_record.get('sla_deadline', 'N/A')}\n"
            f"Assigned to: {sla_record.get('assigned_to', 'Unassigned')}"
        )
        return await self.send_notification(message, sev, channels)

    async def notify_policy_violation(
        self,
        policy_name: str,
        violation_details: Dict[str, Any],
        channels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Send policy violation notification."""
        severity = violation_details.get("severity", "HIGH")
        message = (
            f"{self.SEVERITY_EMOJI.get(severity, '')} Policy Violation: *{policy_name}*\n"
            f"{violation_details.get('message', 'Security policy was violated')}\n"
            f"Scan: {violation_details.get('scan_name', 'N/A')} | "
            f"Rule: {violation_details.get('rule_name', 'N/A')}"
        )
        return await self.send_notification(message, severity, channels)

    # ------------------------------------------------------------------
    # Slack Block Kit
    # ------------------------------------------------------------------

    async def _send_slack(
        self,
        message: str,
        config: NotificationConfig,
        blocks: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a Slack message via webhook."""
        if not config.slack_webhook_url:
            return {"error": "Slack webhook URL not configured"}

        payload: Dict[str, Any] = {
            "username": config.slack_username,
            "icon_emoji": config.slack_icon_emoji,
            "text": message,
        }
        if config.slack_channel:
            payload["channel"] = config.slack_channel

        # Use Block Kit if provided
        if blocks and "slack" in blocks:
            slack_blocks = blocks["slack"]
            if isinstance(slack_blocks, list):
                payload["blocks"] = slack_blocks

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            config.slack_webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return {"status": resp.status, "response": resp.read().decode()[:200]}
        except Exception as e:
            return {"error": str(e)}

    def _build_scan_slack_blocks(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build Slack Block Kit blocks for a scan notification."""
        stats = scan_data.get("stats", {})
        risk = scan_data.get("risk_score", 0)
        color = self.SEVERITY_COLORS.get("HIGH" if risk > 50 else "MEDIUM", "#D97706")

        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"\U0001F6E1\uFE0F Scan Completed: {scan_data.get('name', 'Unknown')}",
                },
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Risk Score:* {risk}/100"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Critical:*\n{stats.get('critical', 0)}"},
                    {"type": "mrkdwn", "text": f"*High:*\n{stats.get('high', 0)}"},
                    {"type": "mrkdwn", "text": f"*Medium:*\n{stats.get('medium', 0)}"},
                    {"type": "mrkdwn", "text": f"*Low:*\n{stats.get('low', 0)}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Scan ID: `{scan_data.get('scan_id', 'N/A')}` | Tools: {', '.join(scan_data.get('tools_used', []))}"},
                ],
            },
        ]

    def _build_vuln_slack_blocks(self, vulnerability: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build Slack Block Kit blocks for a vulnerability notification."""
        sev = (vulnerability.get("severity") or "MEDIUM").upper()
        color = self.SEVERITY_COLORS.get(sev, "#D97706")

        return [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{self.SEVERITY_EMOJI.get(sev, '')} {sev}: {vulnerability.get('title', 'Unknown')}"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*File:* `{vulnerability.get('file_path', 'unknown')}:{vulnerability.get('line_number', 'N/A')}`\n"
                        f"*Category:* {vulnerability.get('category', 'Unknown')}\n"
                        f"*CWE:* {vulnerability.get('cwe_id', 'N/A')}\n"
                        f"*Tool:* {vulnerability.get('tool_source', 'Unknown')}\n"
                        f"*CVSS:* {vulnerability.get('cvss_score', 'N/A')}"
                    ),
                },
            },
        ]

    # ------------------------------------------------------------------
    # Microsoft Teams Adaptive Cards
    # ------------------------------------------------------------------

    async def _send_teams(
        self,
        message: str,
        config: NotificationConfig,
        blocks: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a Teams message via webhook."""
        if not config.teams_webhook_url:
            return {"error": "Teams webhook URL not configured"}

        if blocks and "teams" in blocks:
            payload = blocks["teams"]
        else:
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": message,
                "themeColor": "0078D7",
                "sections": [{"activityTitle": "CodeShield AI", "text": message}],
            }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            config.teams_webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return {"status": resp.status}
        except Exception as e:
            return {"error": str(e)}

    def _build_scan_teams_card(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build Teams Adaptive Card for scan notification."""
        stats = scan_data.get("stats", {})
        risk = scan_data.get("risk_score", 0)
        color = self.SEVERITY_COLORS.get("HIGH" if risk > 50 else "MEDIUM", "#D97706")

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": f"Scan: {scan_data.get('name', 'Unknown')}",
            "sections": [
                {
                    "activityTitle": f"\U0001F6E1\uFE0F Scan Completed: {scan_data.get('name', 'Unknown')}",
                    "facts": [
                        {"name": "Risk Score:", "value": f"{risk}/100"},
                        {"name": "Critical:", "value": str(stats.get("critical", 0))},
                        {"name": "High:", "value": str(stats.get("high", 0))},
                        {"name": "Medium:", "value": str(stats.get("medium", 0))},
                        {"name": "Low:", "value": str(stats.get("low", 0))},
                        {"name": "Scan ID:", "value": scan_data.get("scan_id", "N/A")},
                    ],
                },
            ],
        }

    def _build_vuln_teams_card(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Build Teams Adaptive Card for vulnerability notification."""
        sev = (vulnerability.get("severity") or "MEDIUM").upper()
        color = self.SEVERITY_COLORS.get(sev, "#D97706")

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": f"{sev}: {vulnerability.get('title', 'Unknown')}",
            "sections": [
                {
                    "activityTitle": f"{self.SEVERITY_EMOJI.get(sev, '')} {sev}: {vulnerability.get('title', 'Unknown')}",
                    "facts": [
                        {"name": "File:", "value": f"{vulnerability.get('file_path', 'unknown')}:{vulnerability.get('line_number', 'N/A')}"},
                        {"name": "Category:", "value": vulnerability.get("category", "Unknown")},
                        {"name": "CWE:", "value": vulnerability.get("cwe_id", "N/A")},
                        {"name": "CVSS:", "value": str(vulnerability.get("cvss_score", "N/A"))},
                        {"name": "Tool:", "value": vulnerability.get("tool_source", "Unknown")},
                    ],
                },
            ],
        }

    # ------------------------------------------------------------------
    # Email Notifications
    # ------------------------------------------------------------------

    async def _send_email(
        self,
        message: str,
        severity: str,
        config: NotificationConfig,
    ) -> Dict[str, Any]:
        """Send an email notification."""
        if not config.smtp_host or not config.recipients:
            return {"error": "SMTP not configured or no recipients"}

        subject = f"[CodeShield AI] [{severity}] Security Alert"
        html_body = self._build_email_html(message, severity)

        try:
            server = smtplib.SMTP(config.smtp_host, config.smtp_port)
            if config.smtp_use_tls:
                server.starttls()
            if config.smtp_username and config.smtp_password:
                server.login(config.smtp_username, config.smtp_password)

            for recipient in config.recipients:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = config.from_address
                msg["To"] = recipient
                msg.attach(MIMEText(message, "plain"))
                msg.attach(MIMEText(html_body, "html"))
                server.sendmail(config.from_address, [recipient], msg.as_string())

            server.quit()
            return {"sent": len(config.recipients)}
        except Exception as e:
            return {"error": str(e)}

    def _build_email_html(self, message: str, severity: str) -> str:
        """Build HTML email body with severity-specific styling."""
        color = self.SEVERITY_COLORS.get(severity, "#2563EB")
        emoji = self.SEVERITY_EMOJI.get(severity, "")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
                .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background-color: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-radius: 0 0 8px 8px; }}
                .severity {{ font-size: 24px; font-weight: bold; }}
                .message {{ font-size: 16px; line-height: 1.5; margin-top: 15px; }}
                .footer {{ font-size: 12px; color: #6b7280; margin-top: 20px; text-align: center; }}
                .timestamp {{ font-size: 14px; opacity: 0.8; }}
            </style>
        </head>
        <body>
            <div class="header">
                <div class="severity">{emoji} {severity} - CodeShield AI Security Alert</div>
                <div class="timestamp">{now}</div>
            </div>
            <div class="content">
                <div class="message">{message.replace(chr(10), "<br>")}</div>
            </div>
            <div class="footer">
                Sent by CodeShield AI Security Platform<br>
                <a href="#">View Dashboard</a> | <a href="#">Manage Notifications</a>
            </div>
        </body>
        </html>
        """

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _meets_threshold(event_severity: str, threshold: str) -> bool:
        """Check if event severity meets the notification threshold."""
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get(event_severity.upper(), 0) >= order.get(threshold.upper(), 0)


# Singleton
_notification_engine: Optional[NotificationEngine] = None


def get_notification_engine() -> NotificationEngine:
    """Get or create the global notification engine."""
    global _notification_engine
    if _notification_engine is None:
        _notification_engine = NotificationEngine()
    return _notification_engine
