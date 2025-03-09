import psutil
import time
from datetime import datetime

class SystemMonitor:
    def __init__(self):
        self.cpu_threshold = 80
        self.memory_threshold = 80
        self.historical_data = {
            'timestamps': [],
            'cpu_usage': [],
            'memory_usage': [],
            'network_io': []
        }

    def get_system_stats(self):
        stats = {
            'timestamp': datetime.now(),
            'cpu_usage': psutil.cpu_percent(interval=1),
            'memory_usage': psutil.virtual_memory().percent,
            'network_io': psutil.net_io_counters()._asdict(),
            'disk_usage': psutil.disk_usage('/').percent,
            'network_interfaces': self.get_network_interfaces(),
            'warnings': []
        }

        if stats['cpu_usage'] > self.cpu_threshold:
            stats['warnings'].append(f"High CPU usage: {stats['cpu_usage']}%")
        if stats['memory_usage'] > self.memory_threshold:
            stats['warnings'].append(f"High memory usage: {stats['memory_usage']}%")

        self.update_historical_data(stats)

        return stats

    def get_network_interfaces(self):
        interfaces = {}
        for iface, stats in psutil.net_if_stats().items():
            interfaces[iface] = {
                'is_up': stats.isup,
                'speed': stats.speed,
                'mtu': stats.mtu,
                'io_stats': psutil.net_io_counters(pernic=True).get(iface, None)
            }
        return interfaces

    def update_historical_data(self, stats):
        self.historical_data['timestamps'].append(stats['timestamp'])
        self.historical_data['cpu_usage'].append(stats['cpu_usage'])
        self.historical_data['memory_usage'].append(stats['memory_usage'])
        self.historical_data['network_io'].append(stats['network_io'])

        max_entries = 3600
        if len(self.historical_data['timestamps']) > max_entries:
            for key in self.historical_data:
                self.historical_data[key] = self.historical_data[key][-max_entries:]

    def get_historical_data(self):
        return self.historical_data
