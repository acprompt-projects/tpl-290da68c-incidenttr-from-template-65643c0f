import json
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class NotificationChannel:
    name: str = "base"

    async def send(self, incident: Dict[str, Any]) -> bool:
        raise NotImplementedError


class SlackChannel(NotificationChannel):
    name = "slack"

    def __init__(self, webhook_url: str, channel: Optional[str] = None):
        self.webhook_url = webhook_url
        self.channel = channel

    def _build_payload(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        severity_colors = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#36A64F",
            "info": "#808080",
        }
        color = severity_colors.get(incident.get("severity", "info"), "#808080")
        fields = [
            {"title": k, "value": str(v), "short": len(str(v)) < 25}
            for k, v in incident.items()
            if k not in ("title", "description", "severity") and v is not None
        ]
        payload: Dict[str, Any] = {
            "attachments": [
                {
                    "color": color,
                    "title": f"[{incident.get('severity', 'info').upper()}] {incident.get('title', 'Untitled Incident')}",
                    "text": incident.get("description", ""),
                    "fields": fields,
                    "footer": "Incident Triage Service",
                    "ts": incident.get("created_at", 0),
                }
            ]
        }
        if self.channel:
            payload["channel"] = self.channel
        return payload

    async def send(self, incident: Dict[str, Any]) -> bool:
        payload = self._build_payload(incident)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.webhook_url, json=payload)
                if resp.status_code == 200 and resp.text == "ok":
                    logger.info("Slack notification sent for incident %s", incident.get("id"))
                    return True
                logger.warning("Slack returned %s: %s", resp.status_code, resp.text)
                return False
        except Exception:
            logger.exception("Failed to send Slack notification for incident %s", incident.get("id"))
            return False


class PagerDutyChannel(NotificationChannel):
    name = "pagerduty"

    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self.routing_key = routing_key
        self.api_url = api_url

    def _build_payload(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }
        return {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": incident.get("dedup_key", incident.get("id")),
            "payload": {
                "summary": incident.get("title", "Untitled Incident"),
                "severity": severity_map.get(incident.get("severity", "info"), "info"),
                "source": incident.get("source", "incident-triage"),
                "component": incident.get("category", "unknown"),
                "group": incident.get("group"),
                "class": incident.get("class"),
                "custom_details": {
                    k: v
                    for k, v in incident.items()
                    if k not in ("id", "title", "description", "severity", "dedup_key")
                },
            },
        }

    async def send(self, incident: Dict[str, Any]) -> bool:
        payload = self._build_payload(incident)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.api_url, json=payload)
                if resp.status_code in (200, 202):
                    logger.info("PagerDuty alert sent for incident %s", incident.get("id"))
                    return True
                body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
                logger.warning("PagerDuty returned %s: %s", resp.status_code, body)
                return False
        except Exception:
            logger.exception("Failed to send PagerDuty alert for incident %s", incident.get("id"))
            return False


class EmailChannel(NotificationChannel):
    name = "email"

    def __init__(
        self,
        recipients: list[str],
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        sender: str = "incidents@example.com",
        use_tls: bool = False,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.recipients = recipients
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.use_tls = use_tls
        self.username = username
        self.password = password

    async def send(self, incident: Dict[str, Any]) -> bool:
        severity = incident.get("severity", "info").upper()
        subject = f"[{severity}] {incident.get('title', 'Untitled Incident')}"
        body_lines = [f"{k}: {v}" for k, v in incident.items() if v is not None]
        body_lines.insert(0, incident.get("description", ""))
        body = "\n".join(body_lines)
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.sender, self.recipients, msg.as_string())
            logger.info("Email sent for incident %s", incident.get("id"))
            return True
        except Exception:
            logger.exception("Failed to send email for incident %s", incident.get("id"))
            return False