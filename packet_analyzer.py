from __future__ import annotations

import argparse
import socket
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PacketSummary:
    timestamp: float
    source: str
    destination: str
    protocol: str
    frame_bytes: int


@dataclass
class FlowStats:
    packets: int = 0
    frame_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


def read_pcap(path: Path):
    """Yield classic PCAP records from an Ethernet capture; no live capture."""
    with path.open("rb") as capture:
        header = capture.read(24)
        if len(header) != 24:
            raise ValueError("File is too short to be a classic PCAP capture.")

        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
            b"\xa1\xb2\xc3\xd4": (">", 1e-6),
            b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
            b"\xa1\xb2\x3c\x4d": (">", 1e-9),
        }
        if magic not in formats:
            raise ValueError("Unsupported capture format. Use a classic .pcap file (not pcapng).")

        endian, fractional_scale = formats[magic]
        major, minor, _zone, _sigfigs, _snaplen, link_type = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4):
            raise ValueError(f"Unsupported PCAP version {major}.{minor}; expected 2.4.")
        if link_type != 1:
            raise ValueError("This beginner demo currently supports Ethernet captures only.")

        while True:
            record_header = capture.read(16)
            if not record_header:
                return
            if len(record_header) != 16:
                raise ValueError("Capture ends in an incomplete packet header.")
            seconds, fraction, captured_length, _original_length = struct.unpack(endian + "IIII", record_header)
            if captured_length > 16 * 1024 * 1024:
                raise ValueError("Packet record is unexpectedly large; refusing to read it.")
            frame = capture.read(captured_length)
            if len(frame) != captured_length:
                raise ValueError("Capture ends in an incomplete packet.")
            yield seconds + fraction * fractional_scale, frame


def parse_frame(timestamp: float, frame: bytes) -> PacketSummary | None:
    """Extract network and transport headers only; never expose payload bytes."""
    if len(frame) < 14:
        return None

    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ether_type in (0x8100, 0x88A8, 0x9100):  # Common VLAN tags
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4

    if ether_type == 0x0800:  # IPv4
        if len(frame) < offset + 20:
            return None
        first = frame[offset]
        if first >> 4 != 4:
            return None
        ip_header_length = (first & 0x0F) * 4
        if ip_header_length < 20 or len(frame) < offset + ip_header_length:
            return None
        protocol_number = frame[offset + 9]
        source = socket.inet_ntop(socket.AF_INET, frame[offset + 12:offset + 16])
        destination = socket.inet_ntop(socket.AF_INET, frame[offset + 16:offset + 20])
        fragment_field = struct.unpack_from("!H", frame, offset + 6)[0]
        first_fragment = (fragment_field & 0x1FFF) == 0
        transport_offset = offset + ip_header_length
    elif ether_type == 0x86DD:  # IPv6 base header (extension chains are summarized generically)
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
            return None
        protocol_number = frame[offset + 6]
        source = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        destination = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        transport_offset = offset + 40
        first_fragment = True
    else:
        return None

    names = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
    protocol = names.get(protocol_number, f"IP-{protocol_number}")
    if protocol in ("TCP", "UDP") and first_fragment and len(frame) >= transport_offset + 4:
        source_port, destination_port = struct.unpack_from("!HH", frame, transport_offset)
        source = f"{source}:{source_port}"
        destination = f"{destination}:{destination_port}"

    return PacketSummary(timestamp, source, destination, protocol, len(frame))


def analyze_capture(path: Path) -> tuple[list[PacketSummary], int]:
    packets: list[PacketSummary] = []
    skipped = 0
    for timestamp, frame in read_pcap(path):
        summary = parse_frame(timestamp, frame)
        if summary is None:
            skipped += 1
        else:
            packets.append(summary)
    return packets, skipped


def report(packets: list[PacketSummary], skipped: int, top: int) -> str:
    if not packets:
        return "No supported IPv4/IPv6 Ethernet packets were found."

    protocols = Counter(packet.protocol for packet in packets)
    flows: dict[tuple[str, str, str], FlowStats] = {}
    for packet in packets:
        key = (packet.protocol, packet.source, packet.destination)
        stats = flows.setdefault(key, FlowStats(first_seen=packet.timestamp, last_seen=packet.timestamp))
        stats.packets += 1
        stats.frame_bytes += packet.frame_bytes
        stats.first_seen = min(stats.first_seen, packet.timestamp)
        stats.last_seen = max(stats.last_seen, packet.timestamp)

    lines = [
        "Offline Packet Summary",
        "======================",
        f"Supported packets: {len(packets)}",
        f"Skipped non-IP or malformed frames: {skipped}",
        "Protocol counts: " + ", ".join(f"{name} {count}" for name, count in protocols.most_common()),
        "",
        f"Top {min(top, len(flows))} directional flows (captured frame bytes):",
    ]
    ordered = sorted(flows.items(), key=lambda item: (-item[1].frame_bytes, item[0]))[:top]
    for (protocol, source, destination), stats in ordered:
        lines.append(
            f"  {protocol:6} {source} -> {destination} | "
            f"{stats.packets} packets | {stats.frame_bytes} bytes"
        )
    lines += ["", "Payload contents are not displayed or decoded."]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize headers from a local classic Ethernet PCAP file; no live sniffing."
    )
    parser.add_argument("capture", type=Path, help="path to an offline .pcap file")
    parser.add_argument("--top", type=int, default=10, help="maximum number of flows to show (default: 10)")
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top must be at least 1")
    if not args.capture.is_file():
        parser.error(f"capture file not found: {args.capture}")

    try:
        packets, skipped = analyze_capture(args.capture)
    except (OSError, ValueError, struct.error) as exc:
        parser.error(str(exc))
    print(report(packets, skipped, args.top))


if __name__ == "__main__":
    main()
