from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.tls.all import TLS
import pyshark
from datetime import datetime

class PacketAnalyzer:
    def __init__(self):
        self.protocol_stats = {
            'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0,
            'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SMTP': 0,
            'IMAP': 0, 'POP3': 0, 'SSH': 0, 'TELNET': 0,
            'RDP': 0, 'SMB': 0, 'NTP': 0, 'SNMP': 0,
            'Other': 0
        }
        self.port_to_protocol = {
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            161: 'SNMP',
            389: 'LDAP',
            445: 'SMB',
            3389: 'RDP',
            123: 'NTP'
        }

    def analyze_packet(self, packet):
        analysis = {
            'timestamp': datetime.now(),
            'size': len(packet),
            'protocol': 'Unknown',
            'is_encrypted': False,
            'security_alerts': []
        }

        if packet.haslayer(IP):
            analysis['src_ip'] = packet[IP].src
            analysis['dst_ip'] = packet[IP].dst

            if packet.haslayer(TCP):
                sport, dport = packet[TCP].sport, packet[TCP].dport
                analysis['protocol'] = self._determine_tcp_protocol(sport, dport)
                self.protocol_stats[analysis['protocol']] += 1

            elif packet.haslayer(UDP):
                sport, dport = packet[UDP].sport, packet[UDP].dport
                analysis['protocol'] = self._determine_udp_protocol(sport, dport)
                self.protocol_stats[analysis['protocol']] += 1

            elif packet.haslayer(ICMP):
                analysis['protocol'] = 'ICMP'
                self.protocol_stats['ICMP'] += 1

            else:
                analysis['protocol'] = 'Other'
                self.protocol_stats['Other'] += 1

        return analysis

    def _determine_tcp_protocol(self, sport, dport):
        for port in [sport, dport]:
            if port in self.port_to_protocol:
                return self.port_to_protocol[port]
        return 'TCP'

    def _determine_udp_protocol(self, sport, dport):
        for port in [sport, dport]:
            if port in self.port_to_protocol:
                return self.port_to_protocol[port]
            elif port == 53:
                return 'DNS'
        return 'UDP'

    def get_protocol_stats(self):
        return self.protocol_stats

    def reset_stats(self):
        for key in self.protocol_stats:
            self.protocol_stats[key] = 0