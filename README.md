# Network Monitor

## Description
Network Monitor is a Python-based application designed to capture, analyze, and visualize real-time network traffic. It provides detailed insights into network packets, including source/destination IPs, protocols, ports, process names, packet sizes, and geographical locations of remote IPs. Additionally, it features a real-time bandwidth graph for monitoring traffic usage.

---

## Requirements

To use this tool, you need the following:

- **Python 3.6+**
- Required Python packages:
  - `psutil`
  - `scapy`
  - `tkinter` (usually included with Python)
  - `matplotlib`
  - `requests`

You can install the required packages using `pip`:

```bash
pip install psutil scapy matplotlib requests
```

---

## Features

- Real-time packet capture and analysis.
- Displays packet details such as:
  - Source/Destination IP addresses
  - Protocol (TCP, UDP, ICMP, DNS, HTTP, FTP, SMTP, SNMP, IMAP)
  - Port numbers
  - Associated process names
  - Packet size (in bytes)
  - Geographical location of remote IPs
- Real-time bandwidth usage graph for inbound and outbound traffic.
- Filtering capabilities by:
  - IP address
  - Port number
  - Protocol type
- Auto-scroll toggle for the packet list view.
- GeoIP lookup for identifying the country, city, and ISP of remote IP addresses.

---

## Installation

1. Clone the repository or download the source code:

   ```bash
   git clone https://github.com/Diogo-Lages/network-monitor.git
   cd network-monitor
   ```

2. Install the required dependencies:

   ```bash
   pip install psutil scapy matplotlib requests
   ```

3. Replace the `GEOIP_API_KEY` placeholder in the script with your actual API key from [ipstack](https://ipstack.com/) or another GeoIP provider.

   ```python
   GEOIP_API_KEY = "your_api_key_here"
   ```

---

## Usage

1. Run the script:

   ```bash
   python network_monitor.py
   ```

2. Click the **Start Monitoring** button to begin capturing packets.
3. Use the filters to narrow down the displayed packets by IP, port, or protocol.
4. Toggle auto-scroll to control how the packet list updates.
5. Stop monitoring at any time by clicking the **Stop Monitoring** button.

---

## License

This project is licensed under the [MIT License](LICENSE). Feel free to modify and distribute the code as per the terms of the license.

---

