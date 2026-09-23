# Offline Network Packet Analyzer

A beginner-friendly Python tool for summarizing **offline** Ethernet PCAP files. It reports IP addresses, TCP/UDP ports, protocol counts, packet counts, and captured frame bytes. It does not sniff live traffic, inject packets, or display packet payloads.

## Real-world use case

A junior support or network engineer receives an approved packet capture from a test environment because a service request is timing out. This tool helps answer first questions—who is talking to whom, which protocols and ports appear, and how much traffic is present—before opening a larger analysis tool. Use only captures you are authorized to inspect.

## Try the synthetic demo

The sample generator uses fabricated packet data and documentation-only TEST-NET IP addresses:

```powershell
py make_demo_capture.py
py packet_analyzer.py demo_capture.pcap
```

To read an approved capture you already have:

```powershell
py packet_analyzer.py path\to\your-capture.pcap --top 15
```

The analyzer reads classic PCAP with Ethernet link type. It currently skips non-IP frames and malformed frames; it does not support pcapng or fully decode IPv6 extension-header chains.

## How it works

1. Reads the PCAP record headers and Ethernet frames from a file on disk.
2. Identifies IPv4 or IPv6 network headers and TCP/UDP ports when present.
3. Groups packets into directional flows and reports packet counts and captured frame sizes.
4. Never prints payload contents.

## Interview-ready explanation

> “I built a small offline PCAP summarizer for first-pass troubleshooting. It reads packet headers, groups traffic into directional flows, and shows protocol and byte counts without exposing payloads. I kept it offline-only and generated a synthetic capture so the demo does not require sniffing anyone’s network.”

Good follow-up topics for an interview: handling malformed input, supporting pcapng, parsing IPv6 extension headers, and adding tests with fabricated packet fixtures.

## Limitations

This is an educational first-pass summary, not a replacement for Wireshark or a full intrusion-detection system. Counts and addresses alone do not prove that traffic is safe or malicious. Do not upload workplace or personal captures to this repository.
