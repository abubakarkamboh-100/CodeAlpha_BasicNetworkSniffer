# CodeAlpha Cyber Security — Task 1: Basic Network Sniffer

**Prepared by:** Muhammad Abubakar  
**Project:** Python packet sniffer using Scapy

## What it does
Captures authorized network traffic and shows source/destination IP addresses, protocol (TCP/UDP/ICMP), ports, packet size, and up to 16 bytes of payload in hex. Saves metadata as a local CSV.

## Quick demo (no installation or network permissions required)
```bash
python3 network_sniffer.py --demo --output examples/demo_packets.csv
```
The screenshot in `screenshots/demo_output.png` and example CSV are **synthetic offline demonstrations**, NOT evidence of live packet capture. Documentation example IP addresses are used.

## Real capture on Ubuntu / WSL
```bash
sudo apt update
sudo apt install -y python3-venv libpcap-dev
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/python network_sniffer.py --count 20
```
Optional: `--interface eth0`. See interfaces with `ip link`. On WSL, only traffic visible to the WSL virtual interface can be captured.

## Submission
This ZIP contains code, documentation, example output, and a clearly labeled **demo** screenshot. For evidence of a real capture, run the live command on your own authorized network and replace/add your own genuine screenshot. Do not publish real payloads, private IP logs, passwords, or other sensitive capture data.

## Files
- `network_sniffer.py` — executable program
- `requirements.txt` — Python dependency
- `examples/demo_packets.csv` — synthetic sample output
- `screenshots/demo_output.png` — offline demo screenshot
- `.gitignore` — excludes live capture files
