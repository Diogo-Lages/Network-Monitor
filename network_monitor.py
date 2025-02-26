import psutil
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.all import sniff, Raw
from datetime import datetime
import threading
import time
import platform
import socket
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import requests


# ANSI Color Codes
RESTART = '\033[0m'
B = '\033[0;30m'
R = '\033[0;31m'
G = '\033[0;32m'
Y = '\033[0;33m'
BLU = '\033[0;34m'
P = '\033[0;35m'
C = '\033[0;36m'
W = '\033[0;37m'

IP_ADDRESS = "127.0.0.1"


def get_ip_address():
    system = platform.system()
    if system == "Windows":
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    else:
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
            if ip_address.startswith("127."):
                ip_address = socket.gethostbyname(socket.getfqdn())
        except socket.gaierror:
            ip_address = "Unable to get IP address"
    return ip_address


def get_process_name_by_port(port):
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port or (conn.raddr and conn.raddr.port == port):
                if conn.pid:
                    try:
                        return psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        pass
        return "Unknown"
    except Exception as e:
        print(f"Error retrieving process name: {e}")
        return "Unknown"


class GeoIPLookup:
    def __init__(self, api_key=None):
        self.api_key = api_key

    def lookup(self, ip):
        try:
            response = requests.get(f"http://api.ipstack.com/{ip}", params={"access_key": self.api_key})
            if response.status_code == 200:
                data = response.json()
                country = data.get("country_name", "Unknown")
                city = data.get("city", "Unknown")
                isp = data.get("connection", {}).get("isp", "Unknown")
                return f"{country}, {city} | ISP: {isp}"
            return "Unknown Location"
        except Exception as e:
            print(f"Error during GeoIP lookup: {e}")
            return "Error during lookup"


class NetworkMonitorApp:
    def __init__(self, root, api_key=None):
        self.root = root
        self.root.title("Network Monitor")
        self.root.geometry("1200x800")

        # Treeview for packet details
        self.tree = ttk.Treeview(
            root,
            columns=("Time", "Source", "Destination", "Protocol", "Port", "Process", "Size", "Location"),
            show="headings",
        )
        self.tree.heading("Time", text="Timestamp")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Process", text="Process")
        self.tree.heading("Size", text="Size (Bytes)")
        self.tree.heading("Location", text="Location")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar for Treeview
        self.scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=self.tree.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Buttons
        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=10)
        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Filter Frame
        self.filter_frame = tk.Frame(root)
        self.filter_frame.pack(pady=10)
        tk.Label(self.filter_frame, text="Filter by IP:").grid(row=0, column=0)
        self.ip_filter = tk.Entry(self.filter_frame)
        self.ip_filter.grid(row=0, column=1)
        tk.Label(self.filter_frame, text="Filter by Port:").grid(row=0, column=2)
        self.port_filter = tk.Entry(self.filter_frame)
        self.port_filter.grid(row=0, column=3)
        tk.Label(self.filter_frame, text="Filter by Protocol:").grid(row=0, column=4)
        self.protocol_filter = ttk.Combobox(
            self.filter_frame, values=["TCP", "UDP", "ICMP", "DNS", "HTTP", "FTP", "SMTP", "SNMP", "IMAP"]
        )
        self.protocol_filter.grid(row=0, column=5)
        self.apply_filter_button = tk.Button(self.filter_frame, text="Apply Filters", command=self.apply_filters)
        self.apply_filter_button.grid(row=0, column=6)
        self.reset_filter_button = tk.Button(self.filter_frame, text="Reset Filters", command=self.reset_filters)
        self.reset_filter_button.grid(row=0, column=7)

        # Auto Scroll Toggle
        self.auto_scroll = True
        self.toggle_scroll_button = tk.Button(root, text="Disable Auto Scroll", command=self.toggle_auto_scroll)
        self.toggle_scroll_button.pack(pady=10)

        # Bandwidth Graph
        self.figure = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, master=root)
        self.canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        # GeoIP Lookup
        self.geoip_lookup = GeoIPLookup(api_key=api_key)
        self.running = False
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        self.timestamps = []
        self.bandwidth_in = []
        self.bandwidth_out = []

    def packet_callback(self, packet):
        if not self.running:
            return

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            protocol = "N/A"
            port = "N/A"
            size = len(packet)

            if proto == 6:
                protocol = "TCP"
                if packet.haslayer(TCP):
                    port = packet[TCP].sport
                    process_name = get_process_name_by_port(packet[TCP].sport)
            elif proto == 17:
                protocol = "UDP"
                if packet.haslayer(UDP):
                    port = packet[UDP].sport
                    process_name = get_process_name_by_port(packet[UDP].sport)
            elif proto == 1:
                protocol = "ICMP"
                process_name = "System"
            elif packet.haslayer(DNS):
                protocol = "DNS"
                process_name = "System"
            elif packet.haslayer(Raw) and b"HTTP" in bytes(packet[Raw]):
                protocol = "HTTP"
                process_name = "System"
            elif packet.haslayer(TCP) and packet[TCP].dport == 21:
                protocol = "FTP"
                process_name = "System"
            elif packet.haslayer(TCP) and packet[TCP].dport == 25:
                protocol = "SMTP"
                process_name = "System"
            elif packet.haslayer(UDP) and packet[UDP].dport == 161:
                protocol = "SNMP"
                process_name = "System"
            elif packet.haslayer(TCP) and packet[TCP].dport == 143:
                protocol = "IMAP"
                process_name = "System"
            else:
                process_name = "Unknown"

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            location = self.geoip_lookup.lookup(dst_ip)

            # Insert into treeview
            item_id = self.tree.insert(
                "", tk.END, values=(timestamp, src_ip, dst_ip, protocol, port, process_name, size, location)
            )
            if self.auto_scroll:
                self.tree.see(item_id)

            # Update bandwidth stats
            if src_ip == IP_ADDRESS:
                self.total_bytes_out += size
            else:
                self.total_bytes_in += size
            self.update_bandwidth_graph()

    def start_monitoring(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_monitoring(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def start_sniffing(self):
        sniff(prn=self.packet_callback, filter="ip", store=0)

    def update_bandwidth_graph(self):
        self.timestamps.append(time.time())
        self.bandwidth_in.append(self.total_bytes_in / 1024)
        self.bandwidth_out.append(self.total_bytes_out / 1024)

        if len(self.timestamps) > 10:
            self.timestamps.pop(0)
            self.bandwidth_in.pop(0)
            self.bandwidth_out.pop(0)

        self.ax.clear()
        self.ax.plot(self.timestamps, self.bandwidth_in, label="Inbound (KB)", color="blue")
        self.ax.plot(self.timestamps, self.bandwidth_out, label="Outbound (KB)", color="red")
        self.ax.set_title("Real-Time Bandwidth Usage")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Data (KB)")
        self.ax.legend()
        self.ax.grid(True)
        self.canvas.draw()

    def apply_filters(self):
        ip_filter = self.ip_filter.get().strip().lower()
        port_filter = self.port_filter.get().strip().lower()
        protocol_filter = self.protocol_filter.get().strip().lower()

        for child in self.tree.get_children():
            values = self.tree.item(child, "values")
            src_ip, dst_ip, protocol, port = (
                values[1].lower(),
                values[2].lower(),
                values[3].lower(),
                values[4].lower(),
            )

            if (
                (not ip_filter or ip_filter in src_ip or ip_filter in dst_ip)
                and (not port_filter or port_filter == port)
                and (not protocol_filter or protocol_filter == protocol)
            ):
                self.tree.reattach(child, "", 0)
            else:
                self.tree.detach(child)

    def reset_filters(self):
        for child in self.tree.get_children():
            self.tree.reattach(child, "", 0)

    def toggle_auto_scroll(self):
        self.auto_scroll = not self.auto_scroll
        if self.auto_scroll:
            self.toggle_scroll_button.config(text="Disable Auto Scroll")
        else:
            self.toggle_scroll_button.config(text="Enable Auto Scroll")


if __name__ == "__main__":
    IP_ADDRESS = get_ip_address()
    GEOIP_API_KEY = ""  # Replace with your actual API key
    root = tk.Tk()
    app = NetworkMonitorApp(root, api_key=GEOIP_API_KEY)
    root.mainloop()
