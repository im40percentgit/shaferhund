"""
Alert clustering for Shaferhund.

Groups incoming alerts into 5-minute windows keyed on (source, src_ip, rule_id).
When a cluster exceeds max_alerts (50), it is split into a new cluster.

Design:
- In-memory dict of open clusters, flushed to SQLite when window closes
  or cluster is full.
- Window boundary is checked on each new alert; clusters older than
  window_seconds are closed and returned for triage.
- Thread-safe via a simple lock (background tailer + FastAPI run in the
  same asyncio event loop, so the GIL is sufficient for dict ops, but
  an explicit lock makes the contract clear).

@decision DEC-CLUSTER-001
@title In-memory clusterer with SQLite persistence
@status accepted
@rationale Hot path stays in memory; SQLite write happens only on cluster
           close. Keeps latency low for the 60s poll cycle. At target
           scale (<100 endpoints) a single dict is plenty.

@decision DEC-CLUSTER-002
@title Cluster key includes source to prevent cross-source alert merging
@status accepted
@rationale Wazuh and Suricata can both fire on the same src_ip + rule_id
           combination. Merging those into one cluster would produce
           nonsensical AI triage output. Including source in the key
           (source:src_ip:rule_id) guarantees clusters are always
           single-source, preserving semantic meaning for downstream triage.
"""

import hashlib
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class Alert:
    """Parsed alert ready for clustering."""

    id: str
    rule_id: int
    src_ip: str
    severity: int
    raw: dict
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "wazuh"


@dataclass
class Cluster:
    """An open (in-progress) cluster of related alerts."""

    id: str
    src_ip: str
    rule_id: int
    window_start: datetime
    source: str = "wazuh"
    alerts: list[Alert] = field(default_factory=list)

    @property
    def window_end(self) -> datetime:
        return self.alerts[-1].timestamp if self.alerts else self.window_start

    @property
    def alert_count(self) -> int:
        return len(self.alerts)


def _cluster_key(source: str, src_ip: str, rule_id: int) -> str:
    """Stable string key for the open-clusters dict.

    Includes source so Wazuh and Suricata alerts sharing the same
    src_ip + rule_id never merge into the same cluster (DEC-CLUSTER-002).
    """
    return f"{source}:{src_ip}:{rule_id}"


def _new_cluster_id(src_ip: str, rule_id: int, window_start: datetime) -> str:
    """Deterministic cluster ID: short hash of key + window start epoch."""
    raw = f"{src_ip}:{rule_id}:{window_start.timestamp()}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


class AlertClusterer:
    """Groups alerts into time-windowed clusters.

    Usage::

        clusterer = AlertClusterer(window_seconds=300, max_alerts=50)
        closed = clusterer.add(alert)   # may return 0-N closed clusters
        expired = clusterer.flush_expired()  # call periodically
    """

    def __init__(self, window_seconds: int = 300, max_alerts: int = 50) -> None:
        self.window_seconds = window_seconds
        self.max_alerts = max_alerts
        self._open: dict[str, Cluster] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, alert: Alert) -> list[Cluster]:
        """Add an alert to its cluster. Returns any clusters that were closed.

        A cluster closes when:
        1. The new alert arrives after the window has expired (time boundary).
        2. The cluster already has max_alerts alerts (size boundary).

        In case 1 the old cluster is returned and a new one is opened.
        In case 2 the full cluster is returned and a new one is opened.
        """
        closed: list[Cluster] = []
        key = _cluster_key(alert.source, alert.src_ip, alert.rule_id)

        with self._lock:
            existing = self._open.get(key)

            if existing is not None:
                age = (alert.timestamp - existing.window_start).total_seconds()
                if age > self.window_seconds:
                    # Window expired — close existing, open fresh
                    closed.append(existing)
                    del self._open[key]
                    existing = None
                elif existing.alert_count >= self.max_alerts:
                    # Cluster full — close and split
                    closed.append(existing)
                    del self._open[key]
                    existing = None

            if existing is None:
                cluster = Cluster(
                    id=_new_cluster_id(alert.src_ip, alert.rule_id, alert.timestamp),
                    src_ip=alert.src_ip,
                    rule_id=alert.rule_id,
                    window_start=alert.timestamp,
                    source=alert.source,
                )
                self._open[key] = cluster

            self._open[key].alerts.append(alert)

        return closed

    def flush_expired(self, now: Optional[datetime] = None) -> list[Cluster]:
        """Return and remove all clusters whose window has expired.

        Call this periodically (e.g., every poll cycle) to drain clusters
        that received no new alerts but whose window has elapsed.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        expired: list[Cluster] = []
        with self._lock:
            to_remove = [
                key
                for key, cluster in self._open.items()
                if (now - cluster.window_start).total_seconds() > self.window_seconds
            ]
            for key in to_remove:
                expired.append(self._open.pop(key))

        if expired:
            log.debug("Flushed %d expired clusters", len(expired))
        return expired

    def flush_all(self) -> list[Cluster]:
        """Return and remove all open clusters regardless of age.

        Used at shutdown or for testing.
        """
        with self._lock:
            clusters = list(self._open.values())
            self._open.clear()
        return clusters

    @property
    def open_count(self) -> int:
        """Number of currently open (in-window) clusters."""
        with self._lock:
            return len(self._open)


def parse_wazuh_alert(raw: dict) -> Optional[Alert]:
    """Extract structured fields from a raw Wazuh alerts.json line.

    Returns None if the alert is missing required fields or below severity
    threshold (caller applies the threshold filter, but this handles
    structural validation).

    Wazuh alert JSON structure (relevant fields)::

        {
          "id": "1680000000.12345",
          "rule": {"id": "5501", "level": 7, ...},
          "data": {"srcip": "192.168.1.1", ...},
          ...
        }
    """
    try:
        alert_id = raw.get("id") or raw.get("_id")
        if not alert_id:
            return None

        rule = raw.get("rule", {})
        rule_id = int(rule.get("id", 0))
        severity = int(rule.get("level", 0))

        # src_ip: check common Wazuh locations
        data = raw.get("data", {})
        src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or raw.get("agent", {}).get("ip", "unknown")
        )

        return Alert(
            id=str(alert_id),
            rule_id=rule_id,
            src_ip=str(src_ip),
            severity=severity,
            raw=raw,
        )
    except (KeyError, ValueError, TypeError) as exc:
        log.warning("Failed to parse alert: %s — %s", exc, str(raw)[:120])
        return None
