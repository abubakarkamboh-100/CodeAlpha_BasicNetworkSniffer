"""CodeAlpha Task 1 — Basic Network Sniffer.
Only capture traffic on devices/networks you own or are authorized to inspect.
"""
import argparse
import csv
from datetime import datetime
from pathlib import Path

FIELDS = ["time", "source", "destination", "protocol", "source_port",
          "destination_port", "length", "payload_preview_hex"]

def summarize(packet):
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw
    network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
    src = network.src if network else "N/A"
    dst = network.dst if network else "N/A"
    protocol, sport, dport = "OTHER", "", ""
    if TCP in packet:
        protocol, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        protocol, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"
    payload = bytes(packet[Raw].load)[:16].hex() if Raw in packet else ""
    return [datetime.now().isoformat(timespec="seconds"), src, dst,
            protocol, sport, dport, len(packet), payload]

def show(row):
    timestamp, src, dst, proto, sport, dport, size, payload = row
    ports = f" | ports {sport}:{dport}" if sport != "" else ""
    print(f"{timestamp} | {src} -> {dst} | {proto}{ports} | {size} bytes | payload(hex): {payload}")

def run_demo(write):
    # Offline demonstration packets; no network is accessed.
    samples = [
        ["2026-10-17T12:00:01", "192.0.2.10", "198.51.100.20", "TCP", 51000, 443, 60, ""],
        ["2026-10-17T12:00:02", "192.0.2.10", "198.51.100.53", "UDP", 52000, 53, 72, "64656d6f"],
        ["2026-10-17T12:00:03", "198.51.100.20", "192.0.2.10", "ICMP", "", "", 84, ""],
    ]
    print("DEMO MODE — synthetic example packets, NOT a live network capture")
    for row in samples:
        write(row)

def main():
    parser = argparse.ArgumentParser(description="Authorized network sniffer with offline demo")
    parser.add_argument("--interface", help="Capture interface, e.g. eth0")
    parser.add_argument("--count", type=int, default=20, help="Live packet limit (default: 20)")
    parser.add_argument("--output", default="packets.csv", help="CSV output")
    parser.add_argument("--demo", action="store_true", help="Offline demonstration; no network access")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be at least 1")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)
        def write(row):
            writer.writerow(row)
            f.flush()
            show(row)
        if args.demo:
            run_demo(write)
        else:
            try:
                from scapy.all import sniff
            except ImportError:
                parser.error("Scapy not installed. Run: pip install -r requirements.txt")
            print("LIVE CAPTURE — authorized networks only; Ctrl+C to stop")
            try:
                sniff(iface=args.interface, count=args.count,
                      prn=lambda packet: write(summarize(packet)), store=False)
            except KeyboardInterrupt:
                print("Stopped by user.")
            except PermissionError:
                parser.error("Packet capture needs elevated privileges (try sudo).")
    print(f"Results saved to: {output}")

if __name__ == "__main__":
    main()
