"""
Clustering tests (4 tests).

Tests:
  1. Basic clustering: two alerts with same src_ip+rule_id land in same cluster.
  2. Window split: alert arriving after window_seconds opens a new cluster.
  3. Max-size split: cluster with max_alerts+1 alerts splits into two clusters.
  4. Multi-source disjoint: same src_ip+rule_id from wazuh and suricata → 2 clusters.

@decision DEC-CLUSTER-001
@title In-memory clusterer with SQLite persistence
@status accepted
@rationale Tests verify the three critical cluster boundary conditions:
           same-window grouping, time-based window split, and size-based
           split. No mocks — tests run against the real AlertClusterer.

@decision DEC-CLUSTER-002
@title Cluster key includes source to prevent cross-source alert merging
@status accepted
@rationale test_multi_source_disjoint_clustering verifies that identical
           src_ip + rule_id from different sources (wazuh vs suricata)
           always produce distinct clusters, never merged.
"""

from datetime import datetime, timezone, timedelta

from agent.cluster import Alert, AlertClusterer


def _alert(alert_id: str, src_ip: str, rule_id: int, severity: int = 7,
           ts: datetime = None, source: str = "wazuh") -> Alert:
    if ts is None:
        ts = datetime.now(timezone.utc)
    return Alert(
        id=alert_id,
        rule_id=rule_id,
        src_ip=src_ip,
        severity=severity,
        raw={"id": alert_id, "rule": {"id": str(rule_id), "level": severity}},
        timestamp=ts,
        source=source,
    )


def test_basic_clustering():
    """Two alerts with same src_ip+rule_id end up in the same open cluster."""
    clusterer = AlertClusterer(window_seconds=300, max_alerts=50)

    a1 = _alert("a1", "10.0.0.1", 1001)
    a2 = _alert("a2", "10.0.0.1", 1001)

    closed1 = clusterer.add(a1)
    closed2 = clusterer.add(a2)

    # Neither alert should close the cluster — it's still within the window
    assert closed1 == []
    assert closed2 == []
    assert clusterer.open_count == 1

    # Flush everything to inspect
    all_clusters = clusterer.flush_all()
    assert len(all_clusters) == 1
    assert all_clusters[0].alert_count == 2
    assert all_clusters[0].src_ip == "10.0.0.1"
    assert all_clusters[0].rule_id == 1001


def test_window_split():
    """An alert arriving after window_seconds closes the old cluster and opens a new one."""
    clusterer = AlertClusterer(window_seconds=300, max_alerts=50)

    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=301)  # just past the 5-min window

    a1 = _alert("a1", "10.0.0.1", 1001, ts=t0)
    a2 = _alert("a2", "10.0.0.1", 1001, ts=t1)

    closed_after_a1 = clusterer.add(a1)
    closed_after_a2 = clusterer.add(a2)

    # a1 opens a cluster; a2 triggers window expiry, closing the first cluster
    assert closed_after_a1 == []
    assert len(closed_after_a2) == 1

    closed_cluster = closed_after_a2[0]
    assert closed_cluster.alert_count == 1
    assert closed_cluster.alerts[0].id == "a1"

    # A new cluster should now be open for a2
    assert clusterer.open_count == 1
    remaining = clusterer.flush_all()
    assert remaining[0].alerts[0].id == "a2"


def test_max_size_split():
    """A cluster receiving max_alerts+1 alerts splits into two clusters."""
    max_alerts = 5
    clusterer = AlertClusterer(window_seconds=300, max_alerts=max_alerts)

    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    closed_clusters = []

    for i in range(max_alerts + 1):
        ts = t0 + timedelta(seconds=i)  # all within window
        alert = _alert(f"a{i}", "10.0.0.2", 2002, ts=ts)
        closed = clusterer.add(alert)
        closed_clusters.extend(closed)

    # Exactly one cluster should have been closed (the full one)
    assert len(closed_clusters) == 1
    assert closed_clusters[0].alert_count == max_alerts

    # One new cluster open with the overflow alert
    assert clusterer.open_count == 1
    remaining = clusterer.flush_all()
    assert remaining[0].alert_count == 1


def test_multi_source_disjoint_clustering():
    """Wazuh and Suricata alerts with identical src_ip+rule_id form 2 clusters.

    This is the acceptance test for DEC-CLUSTER-002: the cluster key
    (source, src_ip, rule_id) must keep sources disjoint even when the
    IP and rule are identical.
    """
    clusterer = AlertClusterer(window_seconds=300, max_alerts=50)

    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    wazuh_alert = _alert("w1", "192.168.1.10", 5501, ts=t0, source="wazuh")
    suricata_alert = _alert("s1", "192.168.1.10", 5501, ts=t0, source="suricata")

    clusterer.add(wazuh_alert)
    clusterer.add(suricata_alert)

    # Both clusters must be open — no merging across sources
    assert clusterer.open_count == 2

    all_clusters = clusterer.flush_all()
    assert len(all_clusters) == 2

    sources = {c.source for c in all_clusters}
    assert sources == {"wazuh", "suricata"}

    # Each cluster holds exactly one alert from its respective source
    for cluster in all_clusters:
        assert cluster.alert_count == 1
        assert cluster.alerts[0].source == cluster.source
