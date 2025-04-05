# PRODIGY_CS_05
A Python-based packet sniffer with a graphical user interface (GUI) built using Scapy and Tkinter. This tool captures network packets, displays detailed packet information, and provides real-time statistics about captured traffic.

## Features
- Real-time packet capturing with customizable filters
- Detailed packet information display including:
  - Source and destination IP addresses
  - Protocol type (TCP/UDP/ICMP)
  - Port numbers (for TCP/UDP)
  - Full payload display (UTF-8 decoded or hex)
- Real-time statistics showing:
  - Top protocols
  - Top source IPs
  - Top destination IPs
- Option to save captured packets to a .pcap file
- User-friendly GUI with:
  - Interface selection
  - Filter configuration
  - Start/Stop controls
  - Clear display option
  - Scrollable packet and statistics views
 
## Requirements
- Python 3.x
- Scapy (`pip install scapy`)
- Tkinter (usually included with Python)
- Administrative/root privileges to capture packets

## Configuration Options
- Interface: Network interface to capture from (leave blank for default)
- Filter: BPF filter string (e.g., "tcp port 80", "icmp")
- Output File: Path to save captured packets in .pcap format

## Example Filters
- `tcp` - Capture only TCP packets
- `udp` - Capture only UDP packets
- `icmp` - Capture only ICMP packets
- `host 192.168.1.1` - Capture packets to/from specific IP
- `port 80` - Capture packets to/from port 80

## Technical Details
- Uses Scapy for packet capturing and analysis
- Implements multi-threading for non-blocking GUI operation
- Thread-safe statistics collection using locks
- Queue-based packet display system
- Supports TCP, UDP, and ICMP protocol analysis

## Limitations
- Requires administrative privileges to run
- May need adjustment for different network environments
- Basic error handling for common scenarios
- Limited to IP-based protocols in the detailed view

## Troubleshooting
- Permission Error: Run with sudo/admin privileges
- No interfaces shown: Check network adapter status
- No packets captured: Verify interface selection and filters
