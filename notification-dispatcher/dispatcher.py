import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from channels import EmailChannel, NotificationChannel, PagerDutyChannel, SlackChannel

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class RateLimitRule:
    max_events: int
    window_seconds: float

    def allows(self, key: str, timestamps: List[float], now: float) -> bool:
        cutoff = now - self.window_seconds
        recent = [t for t in timestamps if t > cutoff]
        return len(recent) < self.max_events


@dataclass
class RoutingRule:
    channels: List[str]
    min_severity: str = "low"
    categories: Optional[Set[str]] = None
    rate_limit: Optional[RateLimitRule] = None

    def matches(self, incident: Dict[str, Any]) -> bool:
        severity = incident.get("severity", "info")
        if SEVERITY_LEVELS.get(severity, 0) < SEVERITY_LEVELS.get(self.min_severity, 0):
            return False
        if self.categories and incident.get("category") not in self.categories:
            return False
        return True


class RateLimiter:
    def __init__(self):
        self._timestamps: Dict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, key: str, rule: Optional[RateLimitRule]) -> bool:
        if rule is None:
            return True
        now = time.monotonic()
        async with self._lock:
            cutoff = now - rule.window_seconds
            self._timestamps[key] = [t for t in self._timestamps[key] if t > cutoff]
            if len(self._timestamps[key]) >= rule.max_events:
                return False
            self._timestamps[key].append(now)
            return True


DEFAULT_ROUTING: Dict[str, RoutingRule] = {
    "critical_all": RoutingRule(
        channels=["slack", "pagerduty", "email"],
        min_severity="critical",
        rate_limit=RateLimitRule(max_events=30, window_seconds=60),
    ),
    "high_security": RoutingRule(
        channels=["slack", "pagerduty"],
        min_severity="high",
        categories={"security", "availability"},
        rate_limit=RateLimitRule(max_events=20, window_seconds=60),
    ),
    "high_other": RoutingRule(
        channels=["slack"],
        min_severity="high",
        rate_limit=RateLimitRule(max_events=30, window_seconds=60),
    ),
    "medium": RoutingRule(
        channels=["slack"],
        min_severity="medium",
        rate_limit=RateLimitRule(max_events=60, window_seconds=60),
    ),
    "low_info": RoutingRule(
        channels=["slack"],
        min_severity="low",
        rate_limit=RateLimitRule(max_events=120, window_seconds=60),
    ),
}


class NotificationDispatcher:
    def __init__(
        self,
        channels: Optional[Dict[str, NotificationChannel]] = None,
        routing_rules: Optional[Dict[str, RoutingRule]] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.channels: Dict[str, NotificationChannel] = channels or {}
        self.routing_rules = routing_rules or DEFAULT_ROUTING
        self.rate_limiter = rate_limiter or RateLimiter()
        self._cache: Dict[str, float] = {}

    def register_channel(self, channel: NotificationChannel) -> None:
        self.channels[channel.name] = channel

    def _resolve_channels(self, incident: Dict[str, Any]) -> Dict[str, RoutingRule]:
        matched: Dict[str, RoutingRule] = {}
        for rule_name, rule in sorted(
            self.routing_rules.items(),
            key=lambda x: SEVERITY_LEVELS.get(x[1].min_severity, 0),
            reverse=True,
        ):
            if rule.matches(incident):
                for ch in rule.channels:
                    if ch not in matched:
                        matched[ch] = rule
        return matched

    async def dispatch(self, incident: Dict[str, Any]) -> Dict[str, bool]:
        incident_id = incident.get("id", "unknown")
        dedup_key = incident.get("dedup_key", incident_id)

        now = time.monotonic()
        if dedup_key in self._cache and (now - self._cache[dedup_key]) < 60:
            logger.debug("Skipping duplicate dispatch for %s", dedup_key)
            return {}

        channel_rules = self._resolve_channels(incident)
        results: Dict[str, bool] = {}

        for channel_name, rule in channel_rules.items():
            channel = self.channels.get(channel_name)
            if channel is None:
                logger.warning("Channel %s not registered, skipping", channel_name)
                results[channel_name] = False
                continue

            rate_key = f"{channel_name}:{dedup_key}"
            allowed = await self.rate_limiter.check(rate_key, rule.rate_limit)
            if not allowed:
                logger.warning("Rate limited channel %s for incident %s", channel_name, incident_id)
                results[channel_name] = False
                continue

            try:
                success = await channel.send(incident)
                results[channel_name] = success
            except Exception:
                logger.exception("Error sending to %s for incident %s", channel_name, incident_id)
                results[channel_name] = False

        if any(results.values()):
            self._cache[dedup_key] = now

        return results


def build_dispatcher_from_config(config: Dict[str, Any]) -> NotificationDispatcher:
    channels: Dict[str, NotificationChannel] = {}
    slack_cfg = config.get("slack", {})
    if slack_cfg.get("webhook_url"):
        channels["slack"] = SlackChannel(
            webhook_url=slack_cfg["webhook_url"],
            channel=slack_cfg.get("channel"),
        )

    pd_cfg = config.get("pagerduty", {})
    if pd_cfg.get("routing_key"):
        channels["pagerduty"] = PagerDutyChannel(
            routing_key=pd_cfg["routing_key"],
            api_url=pd_cfg.get("api_url", "https://events.pagerduty.com/v2/enqueue"),
        )

    email_cfg = config.get("email", {})
    if email_cfg.get("recipients"):
        channels["email"] = EmailChannel(
            recipients=email_cfg["recipients"],
            smtp_host=email_cfg.get("smtp_host", "localhost"),
            smtp_port=email_cfg.get("smtp_port", 25),
            sender=email_cfg.get("sender", "incidents@example.com"),
            use_tls=email_cfg.get("use_tls", False),
            username=email_cfg.get("username"),
            password=email_cfg.get("password"),
        )

    custom_rules: Optional[Dict[str, RoutingRule]] = None
    if "routing_rules" in config:
        custom_rules = {}
        for name, rc in config["routing_rules"].items():
            rl = None
            if "rate_limit" in rc:
                rl = RateLimitRule(**rc["rate_limit"])
            custom_rules[name] = RoutingRule(
                channels=rc["channels"],
                min_severity=rc.get("min_severity", "low"),
                categories=set(rc["categories"]) if "categories" in rc else None,
                rate_limit=rl,
            )

    return NotificationDispatcher(channels=channels, routing_rules=custom_rules)