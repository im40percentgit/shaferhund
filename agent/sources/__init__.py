"""Alert source parsers for Shaferhund.

Each sub-module exposes a parse_*_alert(line: dict) -> Optional[dict] function
that normalises a raw log line into the shared alert shape consumed by the
Alert Normaliser (Wave B, issue #6).
"""
