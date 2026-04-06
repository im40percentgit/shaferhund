"""
validate_fixtures.py — Verify that benign.pcap and malicious.pcap are
well-formed libpcap files with the expected content.

@decision DEC-SURICATA-001
@title Suricata 7 + pcap-replay via tcpreplay (no NIC tap)
@status accepted
@rationale Fixture validation uses pure stdlib struct parsing — no scapy,
  no root, no external tools — so it runs cleanly in any CI environment.

Run from the repo root or from tests/pcap-fixtures/:
    python3 tests/pcap-fixtures/validate_fixtures.py

Exit 0 on success, non-zero on failure.
"""

import struct
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PCAP_MAGIC   = 0xa1b2c3d4
LINKTYPE_ETH = 1
EICAR_MARKER = b"X5O!P%@AP[4\\"


def parse_pcap(path: str) -> list[bytes]:
    """Parse a libpcap file and return the list of raw frame payloads."""
    with open(path, "rb") as fh:
        raw = fh.read()

    offset = 0
    # Global header: 24 bytes
    magic, vmaj, vmin, _, _, snaplen, network = struct.unpack_from("<IHHiIII", raw, offset)
    assert magic == PCAP_MAGIC,   f"{path}: bad magic 0x{magic:08x} (expected 0x{PCAP_MAGIC:08x})"
    assert network == LINKTYPE_ETH, f"{path}: linktype={network}, expected 1 (Ethernet)"
    offset += 24

    frames = []
    while offset < len(raw):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from("<IIII", raw, offset)
        offset += 16
        frame = raw[offset: offset + incl_len]
        assert len(frame) == incl_len, f"{path}: truncated record at offset {offset}"
        frames.append(frame)
        offset += incl_len

    return frames


def check_benign(path: str) -> None:
    frames = parse_pcap(path)
    assert len(frames) >= 1, f"{path}: no frames"
    all_data = b"".join(frames)
    assert b"Hello, world!" in all_data, f"{path}: expected 'Hello, world!' payload not found"
    assert EICAR_MARKER not in all_data, f"{path}: EICAR marker must NOT appear in benign pcap"
    print(f"  benign.pcap  : {len(frames)} frames, Hello-world payload present, EICAR absent — OK")


def check_malicious(path: str) -> None:
    frames = parse_pcap(path)
    assert len(frames) >= 1, f"{path}: no frames"
    all_data = b"".join(frames)
    assert EICAR_MARKER in all_data, f"{path}: EICAR marker not found (SIDs 2000356/2000357 won't fire)"
    print(f"  malicious.pcap: {len(frames)} frames, EICAR marker present — OK")


def check_size(path: str, limit_kb: int = 200) -> None:
    size = os.path.getsize(path)
    assert size <= limit_kb * 1024, f"{path}: {size} bytes exceeds {limit_kb} KB limit"
    print(f"  {os.path.basename(path)}: {size} bytes (limit {limit_kb} KB) — OK")


def main() -> None:
    benign_path    = os.path.join(SCRIPT_DIR, "benign.pcap")
    malicious_path = os.path.join(SCRIPT_DIR, "malicious.pcap")

    for p in (benign_path, malicious_path):
        if not os.path.exists(p):
            print(f"FAIL: {p} does not exist — run generate_fixtures.py first", file=sys.stderr)
            sys.exit(1)

    print("Checking sizes:")
    check_size(benign_path)
    check_size(malicious_path)

    print("Checking benign.pcap:")
    check_benign(benign_path)

    print("Checking malicious.pcap:")
    check_malicious(malicious_path)

    print("\nAll fixture validations passed.")


if __name__ == "__main__":
    main()
