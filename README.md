# Network Packet Sniffer

A simple IP packet sniffer that captures TCP or ICMP traffic on a specified interface and prints basic header information, with an option to dump ASCII payload data. 
## Features

- Captures raw IPv4 packets using a raw socket.
- Supports **TCP** or **ICMP** protocol filtering via command-line flag. 
- Prints a concise header line: protocol, source IP, and destination IP. 
- Optional ASCII dump of packet payload, replacing non-printable bytes with dots. 

## Requirements

- Python 3
- Root/administrator privileges to open raw sockets. 
- A valid local IP address to bind for sniffing. 

## Usage

```bash
python3 sniffer.py --ip <IP_ADDRESS> --proto <tcp|ICMP> [--data]
```

- `--ip`: IP address to sniff on (e.g. `192.168.1.10`).
- `--proto`: Protocol to sniff, `tcp` or `ICMP`.
- `--data`: If provided, prints ASCII payload for each packet.

Example:

```bash
sudo python3 sniffer.py --ip 192.168.1.10 --proto tcp --data
```