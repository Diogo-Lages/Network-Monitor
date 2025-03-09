import sqlite3
import json
from datetime import datetime
import os
import pandas as pd
import plotly.express as px

class DataManager:
    def __init__(self, db_path='network_monitor.db'):
        self.db_path = db_path
        self.initialize_database()

    def initialize_database(self):
        """Initialize SQLite database and create necessary tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('DROP TABLE IF EXISTS packets')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                size INTEGER,
                location TEXT,
                service TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def save_packet_data(self, packet_data):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO packets (
                timestamp, src_ip, dst_ip, protocol, 
                size, location, service
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data['timestamp'],
            packet_data.get('src_ip', 'unknown'),
            packet_data.get('dst_ip', 'unknown'),
            packet_data['protocol'],
            packet_data['size'],
            packet_data.get('location', 'Unknown'),
            packet_data.get('service', 'Unknown')
        ))

        conn.commit()
        conn.close()

    def export_data(self, format='csv', start_time=None, end_time=None):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if not start_time:
            start_time = '1970-01-01'
        if not end_time:
            end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        cursor.execute('''
            SELECT timestamp, src_ip, dst_ip, protocol, size, location, service
            FROM packets 
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp DESC
        ''', (start_time, end_time))

        data = cursor.fetchall()
        columns = ['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Size (bytes)', 'Location', 'Service']

        conn.close()

        if not data:
            raise ValueError("No data available for export")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == 'csv':
            filename = f'network_data_{timestamp}.csv'
            df = pd.DataFrame(data, columns=columns)
            df.to_csv(filename, index=False)

        elif format == 'json':
            filename = f'network_data_{timestamp}.json'
            json_data = [dict(zip(columns, row)) for row in data]
            with open(filename, 'w') as f:
                json.dump(json_data, f, indent=2)

        elif format == 'html':
            filename = f'network_data_{timestamp}.html'
            df = pd.DataFrame(data, columns=columns)

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Network Monitor Report</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="container mt-5">
                <h1>Network Monitor Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <div class="row mt-4">
                    <div class="col-12">
                        <h2>Captured Packets</h2>
                        {df.to_html(classes='table table-striped table-hover', index=False)}
                    </div>
                </div>
            </body>
            </html>
            """

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)

        else:
            raise ValueError(f"Unsupported export format: {format}")

        return filename

    def get_historical_data(self, hours=1):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM system_stats 
            WHERE timestamp >= datetime('now', '-' || ? || ' hours')
            ORDER BY timestamp
        ''', (hours,))

        data = cursor.fetchall()
        conn.close()

        return data

__all__ = ['DataManager']