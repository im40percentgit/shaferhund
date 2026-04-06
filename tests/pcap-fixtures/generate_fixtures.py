"""
generate_fixtures.py — Build minimal but spec-compliant pcap fixtures.

@decision DEC-SURICATA-001
@title Suricata 7 + pcap-replay via tcpreplay (no NIC tap)
@status accepted
@rationale Pcap fixtures are hand-crafted using raw struct packing so they
  carry zero external dependencies (no scapy, no tcpdump, no root).
  The EICAR test string in malicious.pcap triggers Suricata ET Open SIDs
  2000356/2000357 without executing any harmful code.  Both files stay well
  under 200 KB so they are safe to commit to version control.

Writes benign.pcap and malicious.pcap into the same directory as this script.

These are libpcap format files (magic 0xa1b2c3d4, link type 1 = Ethernet).
Each file contains a small number of Ethernet/IP/TCP packets with a complete
HTTP transaction so Suricata can parse them as a flow.

malicious.pcap contains an HTTP response body with the EICAR test string.
Suricata's ET Open rules include:
  SID 2000356  "ET POLICY EICAR test string in HTTP response"
  SID 2000357  "ET POLICY EICAR test string in HTTP request body"
which fire on the X5O!P%@... pattern without executing any code.

benign.pcap contains a plain HTTP 200 OK with innocuous "Hello, world!" body.

Both files are well under 200 KB.
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# libpcap global header
# ---------------------------------------------------------------------------
PCAP_MAGIC    = 0xa1b2c3d4  # little-endian timestamp precision: microseconds
PCAP_VER_MAJ  = 2
PCAP_VER_MIN  = 4
PCAP_THISZONE = 0
PCAP_SIGFIGS  = 0
PCAP_SNAPLEN  = 65535
PCAP_NETWORK  = 1  # LINKTYPE_ETHERNET

def pcap_global_header() -> bytes:
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC, PCAP_VER_MAJ, PCAP_VER_MIN,
        PCAP_THISZONE, PCAP_SIGFIGS, PCAP_SNAPLEN, PCAP_NETWORK,
    )

def pcap_record(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data

# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def eth_header(src_mac: bytes, dst_mac: bytes, etype: int = 0x0800) -> bytes:
    """6-byte dst + 6-byte src + 2-byte ethertype."""
    return dst_mac + src_mac + struct.pack(">H", etype)

def ip_header(src_ip: bytes, dst_ip: bytes, proto: int, payload_len: int) -> bytes:
    """Minimal IPv4 header (no options), 20 bytes."""
    version_ihl = (4 << 4) | 5          # IPv4, IHL=5 (20 bytes)
    dscp_ecn    = 0
    total_len   = 20 + payload_len      # IP header + payload
    ident       = 0x1234
    flags_frag  = 0x4000                # Don't Fragment
    ttl         = 64
    checksum    = 0                     # leave 0; Suricata accepts this
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl, dscp_ecn, total_len,
        ident, flags_frag,
        ttl, proto, checksum,
        src_ip, dst_ip,
    )
    return hdr

def tcp_header(
    sport: int, dport: int, seq: int, ack: int,
    flags: int, payload_len: int,
) -> bytes:
    """Minimal TCP header (no options), 20 bytes."""
    data_offset = (5 << 4)  # 5 * 4 = 20 bytes, no options
    window      = 65535
    checksum    = 0
    urgent      = 0
    hdr = struct.pack(
        ">HHIIBBHHH",
        sport, dport, seq, ack,
        data_offset, flags, window, checksum, urgent,
    )
    return hdr

def build_tcp_packet(
    src_mac: bytes, dst_mac: bytes,
    src_ip: bytes,  dst_ip: bytes,
    sport: int,     dport: int,
    seq: int,       ack: int,
    flags: int,
    payload: bytes,
) -> bytes:
    tcp_hdr  = tcp_header(sport, dport, seq, ack, flags, len(payload))
    tcp_data = tcp_hdr + payload
    ip_hdr   = ip_header(src_ip, dst_ip, 6, len(tcp_data))
    eth_hdr  = eth_header(src_mac, dst_mac)
    return eth_hdr + ip_hdr + tcp_data


# Fake MAC addresses
CLIENT_MAC = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
SERVER_MAC = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])

# Fake IP addresses (RFC 5737 documentation range)
CLIENT_IP = bytes([192, 0, 2, 1])
SERVER_IP = bytes([192, 0, 2, 2])

# TCP flag constants
SYN  = 0x02
ACK  = 0x10
PSHA = 0x18  # PSH+ACK

def build_http_exchange(
    ts_base: int,
    request_payload: bytes,
    response_payload: bytes,
) -> list[tuple[int, int, bytes]]:
    """
    Build a minimal 5-packet TCP exchange:
      1. SYN      client → server
      2. SYN-ACK  server → client
      3. ACK      client → server
      4. PSH+ACK  client → server  (HTTP GET)
      5. PSH+ACK  server → client  (HTTP 200 response)

    Returns list of (ts_sec, ts_usec, raw_frame) tuples.
    """
    sport = 54321
    dport = 80

    packets = []

    # 1. SYN
    pkt = build_tcp_packet(
        CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
        sport, dport,
        seq=1000, ack=0, flags=SYN, payload=b"",
    )
    packets.append((ts_base, 0, pkt))

    # 2. SYN-ACK
    pkt = build_tcp_packet(
        SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
        dport, sport,
        seq=2000, ack=1001, flags=SYN | ACK, payload=b"",
    )
    packets.append((ts_base, 1000, pkt))

    # 3. ACK
    pkt = build_tcp_packet(
        CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
        sport, dport,
        seq=1001, ack=2001, flags=ACK, payload=b"",
    )
    packets.append((ts_base, 2000, pkt))

    # 4. HTTP GET (PSH+ACK)
    pkt = build_tcp_packet(
        CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP,
        sport, dport,
        seq=1001, ack=2001, flags=PSHA, payload=request_payload,
    )
    packets.append((ts_base, 3000, pkt))

    # 5. HTTP 200 response (PSH+ACK)
    pkt = build_tcp_packet(
        SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP,
        dport, sport,
        seq=2001, ack=1001 + len(request_payload), flags=PSHA,
        payload=response_payload,
    )
    packets.append((ts_base, 4000, pkt))

    return packets


# ---------------------------------------------------------------------------
# HTTP payloads
# ---------------------------------------------------------------------------

BENIGN_REQUEST = (
    b"GET /hello HTTP/1.1\r\n"
    b"Host: 192.0.2.2\r\n"
    b"User-Agent: curl/7.88.1\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)

BENIGN_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 13\r\n"
    b"\r\n"
    b"Hello, world!"
)

# EICAR test string — harmless sequence that security tools recognise as
# a test signature.  No actual malware; safe to store in source control.
# See https://www.eicar.org/download-anti-malware-testfile/
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

MALICIOUS_REQUEST = (
    b"GET /eicar.com HTTP/1.1\r\n"
    b"Host: 192.0.2.2\r\n"
    b"User-Agent: curl/7.88.1\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)

MALICIOUS_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Disposition: attachment; filename=eicar.com\r\n"
    b"Content-Length: "
    + str(len(EICAR)).encode()
    + b"\r\n\r\n"
    + EICAR
)


# ---------------------------------------------------------------------------
# Write pcap files
# ---------------------------------------------------------------------------

def write_pcap(path: str, packet_list: list[tuple[int, int, bytes]]) -> None:
    with open(path, "wb") as fh:
        fh.write(pcap_global_header())
        for ts_sec, ts_usec, data in packet_list:
            fh.write(pcap_record(ts_sec, ts_usec, data))


def main() -> None:
    benign_packets   = build_http_exchange(1712000000, BENIGN_REQUEST,    BENIGN_RESPONSE)
    malicious_packets = build_http_exchange(1712000010, MALICIOUS_REQUEST, MALICIOUS_RESPONSE)

    benign_path   = os.path.join(SCRIPT_DIR, "benign.pcap")
    malicious_path = os.path.join(SCRIPT_DIR, "malicious.pcap")

    write_pcap(benign_path,    benign_packets)
    write_pcap(malicious_path, malicious_packets)

    benign_size   = os.path.getsize(benign_path)
    malicious_size = os.path.getsize(malicious_path)
    print(f"Written {benign_path}   ({benign_size} bytes)")
    print(f"Written {malicious_path} ({malicious_size} bytes)")
    assert benign_size   < 200 * 1024, "benign.pcap exceeds 200 KB limit"
    assert malicious_size < 200 * 1024, "malicious.pcap exceeds 200 KB limit"
    print("Size assertions passed.")


if __name__ == "__main__":
    main()
