import socket
import struct
from pathlib import Path


def ipv4_tcp_frame(source: str, destination: str, source_port: int, destination_port: int, body: bytes) -> bytes:
    tcp = struct.pack("!HHIIHHHH", source_port, destination_port, 1, 0, (5 << 12) | 0x18, 8192, 0, 0) + body
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0,
        socket.inet_aton(source), socket.inet_aton(destination)
    )
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + tcp


def ipv4_udp_frame(source: str, destination: str, source_port: int, destination_port: int, body: bytes) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(body), 0) + body
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 2, 0x4000, 64, 17, 0,
        socket.inet_aton(source), socket.inet_aton(destination)
    )
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + udp


def main() -> None:
    # TEST-NET addresses and fabricated contents: no real traffic or user data.
    frames = [
        ipv4_tcp_frame("192.0.2.10", "198.51.100.20", 51514, 443, b"synthetic demo payload"),
        ipv4_tcp_frame("192.0.2.10", "198.51.100.20", 51514, 443, b"another demo packet"),
        ipv4_tcp_frame("198.51.100.20", "192.0.2.10", 443, 51514, b"demo reply"),
        ipv4_udp_frame("192.0.2.10", "198.51.100.53", 53000, 53, b"fake DNS example"),
    ]
    path = Path(__file__).with_name("demo_capture.pcap")
    with path.open("wb") as capture:
        capture.write(bytes.fromhex("d4c3b2a1"))
        capture.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            capture.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
            capture.write(frame)
    print(f"Created a synthetic, offline demo capture: {path}")


if __name__ == "__main__":
    main()
