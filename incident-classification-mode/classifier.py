===
import yaml
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "reasons": self.reasons,
        }


DEFAULT_THRESHOLDS = {
    "affected_hosts_pct": {"p1": 50, "p2": 25, "p3": 10},
    "error_rate_pct": {"p1": 25, "p2": 10, "p3": 5},
    "latency_ms": {"p1": 5000, "p2": 2000, "p3": 1000},
    "auth_failure_rate_pct": {"p1": 30, "p2": 15, "p3": 5},
    "packet_loss_pct": {"p1": 20, "p2": 10, "p3": 3},
}

CATEGORY_KEYWORDS = {
    Category.INFRA: [
        "cpu", "memory", "disk", "host", "node", "server", "vm", "pod",
        "container", "kube", "deployment", "replicaset", "daemonset",
        "out_of_memory", "oom", "evicted", "pressure", "threshold",
    ],
    Category.APP: [
        "error", "exception", "traceback", "5xx", "500", "timeout",
        "latency", "slow", "hang", "crash", "restart", "oom_kill",
        "liveness", "readiness", "probe", "response_time", "throughput",
    ],
    Category.SECURITY: [
        "auth", "unauthorized", "forbidden", "breach", "intrusion",
        "malware", "exploit", "vulnerability", "cve", "brute", "force",
        "suspicious", "anomaly", "phishing", "credential", "access_denied",
        "certificate", "tls", "encryption", "firewall",
    ],
    Category.NETWORK: [
        "dns", "packet_loss", "latency_spike", "connection_refused",
        "tcp", "udp", "bandwidth", "throughput_network", "route",
        "interface", "switch", "router", "load_balancer", "upstream",
        "downstream", "icmp", "packet", "drop", "subnet",
    ],
}

CATEGORY_SIGNAL_KEYS = {
    Category.INFRA: ["cpu_pct", "memory_pct", "disk_pct", "affected_hosts_pct"],
    Category.APP: ["error_rate_pct", "latency_ms", "restart_count"],
    Category.SECURITY: ["auth_failure_rate_pct", "suspicious_event_count"],
    Category.NETWORK: ["packet_loss_pct", "dns_failure_pct", "connection_refused_count"],
}


class IncidentClassifier:
    def __init__(self, thresholds: Optional[dict] = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    @classmethod
    def from_yaml(cls, path: str | Path) -> "IncidentClassifier":
        with open(path) as f:
            cfg = yaml.safe_load(f)
        return cls(thresholds=cfg.get("thresholds", DEFAULT_THRESHOLDS))

    def classify(self, incident: dict) -> TriageLabel:
        severity = self._determine_severity(incident)
        category, cat_conf = self._determine_category(incident)
        sev_conf = self._severity_confidence(incident, severity)
        reasons = self._build_reasons(incident, severity, category)
        confidence = (sev_conf + cat_conf) / 2
        return TriageLabel(
            severity=severity, category=category,
            confidence=confidence, reasons=reasons,
        )

    def _determine_severity(self, inc: dict) -> Severity:
        score = 0
        th = self.thresholds

        affected = inc.get("affected_hosts_pct", 0)
        if affected >= th["affected_hosts_pct"]["p1"]:
            score += 3
        elif affected >= th["affected_hosts_pct"]["p2"]:
            score += 2
        elif affected >= th["affected_hosts_pct"]["p3"]:
            score += 1

        error_rate = inc.get("error_rate_pct", 0)
        if error_rate >= th["error_rate_pct"]["p1"]:
            score += 3
        elif error_rate >= th["error_rate_pct"]["p2"]:
            score += 2
        elif error_rate >= th["error_rate_pct"]["p3"]:
            score += 1

        auth_fail = inc.get("auth_failure_rate_pct", 0)
        if auth_fail >= th["auth_failure_rate_pct"]["p1"]:
            score += 3
        elif auth_fail >= th["auth_failure_rate_pct"]["p2"]:
            score += 2
        elif auth_fail >= th["auth_failure_rate_pct"]["p3"]:
            score += 1

        pkt_loss = inc.get("packet_loss_pct", 0)
        if pkt_loss >= th["packet_loss_pct"]["p1"]:
            score += 3
        elif pkt_loss >= th["packet_loss_pct"]["p2"]:
            score += 2
        elif pkt_loss >= th["packet_loss_pct"]["p3"]:
            score += 1

        if inc.get("is_customer_facing", False) and score >= 3:
            score += 2
        if inc.get("repeated_occurrences", 0) >= 5:
            score += 1

        # Priority escalation: explicit override
        if inc.get("force_severity"):
            return Severity(inc["force_severity"])

        if score >= 7:
            return Severity.P1
        if score >= 4:
            return Severity.P2
        if score >= 2:
            return Severity.P3
        return Severity.P4

    def _determine_category(self, inc: dict) -> tuple[Category, float]:
        title = inc.get("title", "").lower()
        description = inc.get("description", "").lower()
        text = f"{title} {description}"
        alert_type = inc.get("alert_type", "").lower()

        scores: dict[Category, float] = {}
        for cat, keywords in CATEGORY_KEYWORDS.items():
            match_count = sum(1 for kw in keywords if kw in text or kw in alert_type)
            signal_keys = CATEGORY_SIGNAL_KEYS[cat]
            signal_score = sum(
                1 for k in signal_keys if inc.get(k, 0) > 0
            )
            scores[cat] = match_count + signal_score * 2

        if inc.get("category"):
            try:
                explicit = Category(inc["category"])
                scores[explicit] = scores.get(explicit, 0) + 10
            except ValueError:
                pass

        total = sum(scores.values()) or 1
        best = max(scores, key=lambda c: scores[c])
        best_score = scores[best]
        confidence = min(best_score / max(total, 1), 1.0) if best_score > 0 else 0.3
        return best, confidence

    def _severity_confidence(self, inc: dict, sev: Severity) -> float:
        signal_count = sum(
            1 for k in ("affected_hosts_pct", "error_rate_pct",
                        "auth_failure_rate_pct", "packet_loss_pct")
            if inc.get(k, 0) > 0
        )
        if sev == Severity.P1:
            return min(0.5 + signal_count * 0.12, 1.0)
        if sev == Severity.P2:
            return min(0.55 + signal_count * 0.1, 0.95)
        if sev == Severity.P3:
            return min(0.5 + signal_count * 0.08, 0.85)
        return 0.4 if signal_count == 0 else 0.6

    def _build_reasons(self, inc: dict, sev: Severity, cat: Category) -> list[str]:
        reasons: list[str] = []
        th = self.thresholds
        if inc.get("affected_hosts_pct", 0) >= th["affected_hosts_pct"]["p2"]:
            reasons.append(f"High affected hosts: {inc['affected_hosts_pct']}%")
        if inc.get("error_rate_pct", 0) >= th["error_rate_pct"]["p2"]:
            reasons.append(f"High error rate: {inc['error_rate_pct']}%")
        if inc.get("auth_failure_rate_pct", 0) >= th["auth_failure_rate_pct"]["p2"]:
            reasons.append(f"High auth failure rate: {inc['auth_failure_rate_pct']}%")
        if inc.get("packet_loss_pct", 0) >= th["packet_loss_pct"]["p2"]:
            reasons.append(f"High packet loss: {inc['packet_loss_pct']}%")
        if inc.get("is_customer_facing"):
            reasons.append("Customer-facing impact")
        if inc.get("repeated_occurrences", 0) >= 5:
            reasons.append(f"Repeated occurrences: {inc['repeated_occurrences']}")
        cat_kw = CATEGORY_KEYWORDS[cat]
        matched = [kw for kw in cat_kw if kw in inc.get("title", "").lower()
                   or kw in inc.get("alert_type", "").lower()]
        if matched:
            reasons.append(f"Category keywords matched: {', '.join(matched[:3])}")
        if not reasons:
            reasons.append(f"Classified as {sev.value}/{cat.value} by default scoring")
        return reasons