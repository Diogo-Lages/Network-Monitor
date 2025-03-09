# Network-Monitor

A simple desktop application to monitor and analyze network traffic in real-time. This tool captures packets, analyzes their details, and provides visualizations and export options for further analysis.

## Features

- **Real-Time Packet Capture**: Capture and analyze network packets in real-time.
- **Packet Filtering**: Filter packets by protocol (e.g., TCP, UDP, ICMP) or IP address.
- **Location & Service Detection**: Automatically detect the location and service associated with destination IPs using an external API.
- **Data Export**: Export captured data in CSV, JSON, or HTML formats for offline analysis.
- **System Monitoring**: Monitor CPU, memory, and network usage with warnings for high resource utilization.
- **Visualizations**: View real-time bandwidth usage, protocol distribution, and system performance graphs.
- **Auto-Scroll**: Automatically scroll through captured packets for continuous monitoring.
- **Dark/Light Theme**: Toggle between light and dark themes for better usability.

## Requirements

- Python 3.x
- Required Libraries:
  - `scapy`
  - `psutil`
  - `requests`
  - `pandas`
  - `plotly`
  - `matplotlib`
  - `tkinter` (usually included with Python)
- An API key from [ipapi.com](https://ipapi.com/) for location and service detection (optional but recommended).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Diogo-Lages/Network-Monitor.git
   cd Network-Monitor
   ```

2. Install the required libraries manually:
   - Install each library using `pip`:
     ```bash
     pip install scapy psutil requests pandas plotly matplotlib
     ```

3. Set up your API key:
   - Sign up at [ipapi.com](https://ipapi.com/) to get your free API key.
   - Add the API key to your environment variables as `IPAPI_KEY` or replace `"YOUR_API_KEY"` in the code.

4. Run the application:
   ```bash
   python network_monitor.py
   ```

## Usage

1. **Start Monitoring**:
   - Click the "Start Capture" button to begin monitoring network traffic.
   - Captured packets will appear in the table below.

2. **Apply Filters**:
   - Use the "Protocol" dropdown to filter packets by protocol (e.g., TCP, UDP).
   - Enter an IP address in the "IP" field to filter packets by source or destination IP.

3. **Export Data**:
   - Click the export buttons (CSV, JSON, HTML) to save the captured data to a file.

4. **View Visualizations**:
   - Explore real-time bandwidth usage, protocol distribution, and system performance graphs.

5. **Stop Monitoring**:
   - Click the "Stop Capture" button to stop monitoring.

## Code Structure

- **`modules/data_manager.py`**: Handles database operations and data exports.
- **`modules/packet_analyzer.py`**: Analyzes captured packets and extracts details like protocol, size, and encryption status.
- **`modules/system_monitor.py`**: Monitors system resources (CPU, memory, disk, network).
- **`modules/visualizer.py`**: Creates visualizations for bandwidth usage, protocol distribution, and system performance.
- **`network_monitor.py`**: The main application file that ties everything together and provides the GUI.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
