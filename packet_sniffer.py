from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime
import threading
import queue
from collections import Counter
import tkinter as tk
from tkinter import ttk, messagebox

class PacketSniffer:
    def __init__(self, interface=None, filter="", output_file=None, packet_queue=None, stop_event=None):
        """Initialize the packet sniffer with optional parameters"""
        self.interface = interface
        self.filter = filter
        self.output_file = output_file
        self.packets = []
        self.protocol_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.lock = threading.Lock()
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.packet_count = 0

    def packet_handler(self, packet):
        """Process each captured packet and display relevant information"""
        self.packet_count += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Update statistics
        if packet.haslayer(IP):
            protocol = packet[IP].proto
            with self.lock:
                self.protocol_counts[protocol] += 1
                self.src_ip_counts[packet[IP].src] += 1
                self.dst_ip_counts[packet[IP].dst] += 1
        
        # Put packet info into queue for GUI
        if self.packet_queue:
            packet_info = self.format_packet_info(packet, timestamp)
            self.packet_queue.put(packet_info)
        
        # Collect packet if output_file is set
        if self.output_file:
            self.packets.append(packet)

    def format_packet_info(self, packet, timestamp):
        """Format packet information into a string, displaying full payload"""
        lines = []
        lines.append(f"[Packet #{self.packet_count}] - {timestamp}")
        lines.append("-" * 50)
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            lines.append(f"Source IP: {src_ip}")
            lines.append(f"Destination IP: {dst_ip}")
            protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            protocol_name = protocol_map.get(protocol, f"Unknown ({protocol})")
            lines.append(f"Protocol: {protocol_name}")
            
            if packet.haslayer(TCP):
                lines.append(f"Source Port: {packet[TCP].sport}")
                lines.append(f"Destination Port: {packet[TCP].dport}")
                lines.append(f"TCP Flags: {packet[TCP].flags}")
            elif packet.haslayer(UDP):
                lines.append(f"Source Port: {packet[UDP].sport}")
                lines.append(f"Destination Port: {packet[UDP].dport}")
            elif packet.haslayer(ICMP):
                lines.append(f"ICMP Type: {packet[ICMP].type}")
                lines.append(f"ICMP Code: {packet[ICMP].code}")
            
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    # Decode as UTF-8 and show full payload
                    payload_decoded = payload.decode('utf-8')
                    lines.append(f"Payload: {payload_decoded}")
                except:
                    # If not UTF-8, show full payload in hex
                    lines.append(f"Payload (hex): {payload.hex()}")
        else:
            lines.append("Non-IP packet captured")
            lines.append(f"Summary: {packet.summary()}")
        
        return "\n".join(lines)

    def start_sniffing(self):
        """Start the packet sniffing process"""
        try:
            print("Starting packet sniffer...")
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self.packet_handler,
                stop_filter=lambda p: self.stop_event.is_set() if self.stop_event else False
            )
        except PermissionError:
            print("Error: Please run with admin privileges")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.output_file and self.packets:
                print(f"Saving {len(self.packets)} packets to {self.output_file}")
                wrpcap(self.output_file, self.packets)

    def get_statistics(self):
        """Return current statistics"""
        with self.lock:
            return {
                'protocol_counts': self.protocol_counts.most_common(5),
                'src_ip_counts': self.src_ip_counts.most_common(5),
                'dst_ip_counts': self.dst_ip_counts.most_common(5)
            }

class SnifferGUI(tk.Tk):
    def __init__(self, sniffer):
        """Initialize the enhanced GUI"""
        super().__init__()
        self.title("Packet Sniffer")
        self.geometry("900x700")
        self.sniffer = sniffer
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.sniffer.packet_queue = self.packet_queue
        self.sniffer.stop_event = self.stop_event
        
        # Main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="5")
        config_frame.pack(fill=tk.X, pady=5)

        # Interface selection
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.interface_combo = ttk.Combobox(config_frame, values=get_if_list())
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.interface_combo.set(self.sniffer.interface or "")

        # Filter input
        ttk.Label(config_frame, text="Filter (e.g., 'tcp', 'host 192.168.1.1'):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.filter_entry = ttk.Entry(config_frame)
        self.filter_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.filter_entry.insert(0, self.sniffer.filter)

        # Output file input
        ttk.Label(config_frame, text="Output File (*.pcap):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.output_entry = ttk.Entry(config_frame)
        self.output_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.output_entry.insert(0, self.sniffer.output_file or "")
        ttk.Label(config_frame, text="Packets saved in .pcap format").grid(row=2, column=2, padx=5, pady=5, sticky="w")

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        self.btn_start = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        self.btn_stop = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        self.btn_clear = ttk.Button(control_frame, text="Clear Display", command=self.clear_display)
        self.btn_clear.pack(side=tk.LEFT, padx=5)

        # Packet display
        packet_frame = ttk.LabelFrame(main_frame, text="Captured Packets", padding="5")
        packet_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.text_packets = tk.Text(packet_frame, height=20, width=100)
        self.packet_scroll = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.text_packets.yview)
        self.text_packets.configure(yscrollcommand=self.packet_scroll.set)
        self.text_packets.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.packet_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Statistics display
        stats_frame = ttk.LabelFrame(main_frame, text="Real-Time Statistics", padding="5")
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.text_stats = tk.Text(stats_frame, height=10, width=100)
        self.stats_scroll = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=self.text_stats.yview)
        self.text_stats.configure(yscrollcommand=self.stats_scroll.set)
        self.text_stats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.stats_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=5)

        # Schedule updates
        self.update_packets()
        self.update_statistics()

    def start_sniffing(self):
        """Start sniffing in a separate thread"""
        self.sniffer.interface = self.interface_combo.get() or None
        self.sniffer.filter = self.filter_entry.get()
        output_file = self.output_entry.get()
        if output_file and not output_file.endswith('.pcap'):
            output_file += '.pcap'
        self.sniffer.output_file = output_file
        
        if not self.sniffer.interface:
            messagebox.showwarning("Warning", "Please select a network interface.")
            return
        
        self.stop_event.clear()
        self.sniffer_thread = threading.Thread(target=self.sniffer.start_sniffing)
        self.sniffer_thread.start()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status_var.set(f"Sniffing on {self.sniffer.interface}...")

    def stop_sniffing(self):
        """Stop the sniffing process"""
        self.stop_event.set()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_var.set(f"Stopped. Packets saved to {self.sniffer.output_file} (.pcap format)" if self.sniffer.output_file else "Stopped.")

    def clear_display(self):
        """Clear the packet and statistics display"""
        self.text_packets.delete(1.0, tk.END)
        self.text_stats.delete(1.0, tk.END)
        self.status_var.set("Display cleared.")

    def update_packets(self):
        """Update the packet display from the queue"""
        while not self.packet_queue.empty():
            packet_info = self.packet_queue.get()
            self.text_packets.insert(tk.END, packet_info + "\n\n")
            self.text_packets.see(tk.END)
        self.after(100, self.update_packets)

    def update_statistics(self):
        """Update the statistics display"""
        stats = self.sniffer.get_statistics()
        stats_text = "Top Protocols:\n"
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        for proto, count in stats['protocol_counts']:
            stats_text += f"{protocol_map.get(proto, str(proto))}: {count}\n"
        stats_text += "\nTop Source IPs:\n"
        for ip, count in stats['src_ip_counts']:
            stats_text += f"{ip}: {count}\n"
        stats_text += "\nTop Destination IPs:\n"
        for ip, count in stats['dst_ip_counts']:
            stats_text += f"{ip}: {count}\n"
        self.text_stats.delete(1.0, tk.END)
        self.text_stats.insert(tk.END, stats_text)
        self.after(1000, self.update_statistics)

def main():
    """Main function to set up and run the sniffer"""
    sniffer = PacketSniffer()
    gui = SnifferGUI(sniffer)
    gui.mainloop()

if __name__ == "__main__":
    main()