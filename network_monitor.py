import tkinter as tk
from tkinter import ttk, messagebox
#import customtkinter as ctk #Removed
from modules.packet_analyzer import PacketAnalyzer
from modules.data_manager import DataManager
from scapy.all import sniff
import threading
import platform
import socket
from datetime import datetime
import time
import requests
import os

# Add your ipapi.com API key here
# Sign up at https://ipapi.com/ to get your free API key
IPAPI_KEY = os.environ.get('IPAPI_KEY', "YOUR_API_KEY") #Using environment variable if available, otherwise default to YOUR_API_KEY

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitor")
        self.root.geometry("1200x800")

        # Initialize components
        self.packet_analyzer = PacketAnalyzer()
        self.data_manager = DataManager()

        self.setup_ui()
        self.running = False
        self.auto_scroll = True
        self.ip_address = self.get_ip_address()
        self.ip_location_cache = {}

    def setup_ui(self):
        try:
            # Configure style
            style = ttk.Style()
            style.configure("Treeview", background="white", foreground="black", fieldbackground="white")
            style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))

            # Main container
            main_frame = ttk.Frame(self.root)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            # Control Panel
            control_frame = ttk.Frame(main_frame)
            control_frame.pack(fill=tk.X, padx=5, pady=5)

            # Capture controls
            self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_monitoring)
            self.start_button.pack(side=tk.LEFT, padx=5)

            self.stop_button = ttk.Button(control_frame, text="Stop Capture",
                                        command=self.stop_monitoring, state=tk.DISABLED)
            self.stop_button.pack(side=tk.LEFT, padx=5)

            # Vertical separator
            ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)

            # Filter section
            filter_frame = ttk.Frame(control_frame)
            filter_frame.pack(side=tk.LEFT, padx=5, pady=5)

            ttk.Label(filter_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
            self.protocol_filter = ttk.Combobox(filter_frame,
                values=["All", "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "FTP", "SMTP",
                       "SSH", "TELNET", "RDP", "SMB", "NTP", "SNMP", "Other"],
                width=10)
            self.protocol_filter.set("All")
            self.protocol_filter.pack(side=tk.LEFT, padx=5)
            self.protocol_filter.bind('<<ComboboxSelected>>', self.apply_filters)

            ttk.Label(filter_frame, text="IP:").pack(side=tk.LEFT, padx=5)
            self.ip_filter = ttk.Entry(filter_frame, width=20)
            self.ip_filter.pack(side=tk.LEFT, padx=5)
            self.ip_filter.bind('<Return>', self.apply_filters)

            clear_button = ttk.Button(filter_frame, text="Clear Filters", command=self.clear_filters)
            clear_button.pack(side=tk.LEFT, padx=5)

            # Vertical separator
            ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)

            # Auto-scroll toggle
            self.scroll_var = tk.BooleanVar(value=True)
            self.scroll_toggle = ttk.Checkbutton(control_frame, text="Auto-scroll",
                                               variable=self.scroll_var,
                                               command=self.toggle_auto_scroll)
            self.scroll_toggle.pack(side=tk.LEFT, padx=10)

            # Export section (right side)
            export_frame = ttk.Frame(control_frame)
            export_frame.pack(side=tk.RIGHT, padx=10, pady=5)

            ttk.Label(export_frame, text="Export:").pack(side=tk.LEFT, padx=5)
            for format in ['CSV', 'JSON', 'HTML']:
                btn = ttk.Button(export_frame, text=format,
                               command=lambda f=format: self.export_data(f.lower()))
                btn.pack(side=tk.LEFT, padx=2)

            # Packet list frame
            packet_frame = ttk.Frame(main_frame)
            packet_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Create Treeview
            self.tree = ttk.Treeview(packet_frame,
                columns=("Time", "Source", "Destination", "Protocol", "Size", "Location", "Service"),
                show="headings")

            # Configure columns
            columns = {
                "Time": 150,
                "Source": 150,
                "Destination": 150,
                "Protocol": 100,
                "Size": 80,
                "Location": 150,
                "Service": 150
            }

            for col, width in columns.items():
                self.tree.heading(col, text=col)
                self.tree.column(col, width=width)

            # Add scrollbar
            scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.tree.yview)
            self.tree.configure(yscrollcommand=scrollbar.set)

            self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        except Exception as e:
            messagebox.showerror("Setup Error", f"Error during UI setup: {str(e)}")

    def get_ip_location_and_service(self, ip):
        if ip in self.ip_location_cache:
            return self.ip_location_cache[ip]

        try:
            if IPAPI_KEY == "YOUR_API_KEY":
                return "API Key Required", "Unknown"

            response = requests.get(
                f"https://api.ipapi.com/api/{ip}",
                params={'access_key': IPAPI_KEY}
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('success', False):
                    location = f"{data.get('city', 'Unknown')}, {data.get('country_name', 'Unknown')}"

                    # Basic service detection
                    service = "Unknown"
                    org = data.get('connection', {}).get('isp', '').lower()

                    if any(s in org for s in ['github', 'discord', 'google', 'amazon', 'facebook']):
                        service = next(s.title() for s in ['github', 'discord', 'google', 'amazon', 'facebook'] if s in org)
                    else:
                        service = data.get('connection', {}).get('isp', 'Unknown').split()[0]

                    result = (location, service)
                    self.ip_location_cache[ip] = result
                    return result
            return "Location Unavailable", "Unknown"
        except Exception as e:
            print(f"Location lookup error: {str(e)}")
            return "Error", "Unknown"

    def packet_callback(self, packet):
        if not self.running:
            return

        try:
            analysis = self.packet_analyzer.analyze_packet(packet)
            if not analysis:
                return

            # Get location and service info
            dst_location, dst_service = self.get_ip_location_and_service(analysis.get('dst_ip', 'unknown'))

            # Check if packet matches current filters before adding
            matches_filter = True
            protocol_filter = self.protocol_filter.get()
            ip_filter = self.ip_filter.get().strip()

            if protocol_filter != "All" and analysis['protocol'] != protocol_filter:
                matches_filter = False
            if ip_filter and ip_filter not in analysis.get('src_ip', '') and ip_filter not in analysis.get('dst_ip', ''):
                matches_filter = False

            # Only insert if matches current filters
            if matches_filter:
                item = self.tree.insert("", tk.END, values=(
                    analysis['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    analysis.get('src_ip', 'unknown'),
                    analysis.get('dst_ip', 'unknown'),
                    analysis['protocol'],
                    analysis['size'],
                    dst_location,
                    dst_service
                ))

                # Auto-scroll if enabled
                if self.scroll_var.get():
                    self.tree.see(item)

            # Save to database regardless of filters
            self.data_manager.save_packet_data({
                **analysis,
                'location': dst_location,
                'service': dst_service
            })

        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def apply_filters(self, event=None):
        self.tree.configure(cursor="watch")
        self.root.update_idletasks()

        try:
            items = self.tree.get_children()
            visible_items = []

            # Collect items that match the filter
            for item in items:
                if self.should_show_item(item):
                    visible_items.append((item, self.tree.item(item)))
                self.tree.detach(item)

            # Reattach matching items
            for item, values in visible_items:
                self.tree.reattach(item, "", "end")

        finally:
            self.tree.configure(cursor="")

    def should_show_item(self, item):
        values = self.tree.item(item)['values']
        if not values:
            return False

        protocol_filter = self.protocol_filter.get()
        ip_filter = self.ip_filter.get().strip()

        protocol_match = protocol_filter == "All" or values[3] == protocol_filter
        ip_match = not ip_filter or ip_filter in values[1] or ip_filter in values[2]

        return protocol_match and ip_match

    def clear_filters(self):
        self.protocol_filter.set("All")
        self.ip_filter.delete(0, tk.END)

        # Show all items
        for item in self.tree.get_children():
            self.tree.reattach(item, "", "end")

    def toggle_auto_scroll(self):
        self.auto_scroll = self.scroll_var.get()

    def start_monitoring(self):
        self.running = True
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)

        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_monitoring(self):
        self.running = False
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)

    def capture_packets(self):
        try:
            sniff(prn=self.packet_callback, store=0)
        except Exception as e:
            print(f"Error in packet capture: {str(e)}")
            self.stop_monitoring()

    def export_data(self, format):
        try:
            filename = self.data_manager.export_data(format)
            messagebox.showinfo("Export Complete", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting data: {str(e)}")

    def get_ip_address(self):
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except Exception as e:
            print(f"Error getting IP address: {str(e)}")
            return "127.0.0.1"

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = NetworkMonitorApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Critical error: {str(e)}")