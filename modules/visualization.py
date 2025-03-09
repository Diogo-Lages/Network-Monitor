import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
from datetime import datetime, timedelta

class Visualizer:
    def __init__(self):
        self.figures = {}
        self.current_theme = 'light'
        self.color_schemes = {
            'light': {
                'background': 'white',
                'text': 'black',
                'grid': '#e0e0e0',
                'colors': ['#2196F3', '#FF5722', '#4CAF50', '#9C27B0']
            },
            'dark': {
                'background': '#2d2d2d',
                'text': 'white',
                'grid': '#404040',
                'colors': ['#64B5F6', '#FF8A65', '#81C784', '#BA68C8']
            }
        }

    def create_bandwidth_graph(self, figure, data, frame):
        figure.clear()
        ax = figure.add_subplot(111)

        colors = self.color_schemes[self.current_theme]['colors']

        if data['timestamps'] and data['bandwidth_in'] and data['bandwidth_out']:
            ax.plot(data['timestamps'], data['bandwidth_in'],
                    label="Inbound", color=colors[0])
            ax.plot(data['timestamps'], data['bandwidth_out'],
                    label="Outbound", color=colors[1])

        ax.set_title("Real-Time Bandwidth Usage")
        ax.set_xlabel("Time")
        ax.set_ylabel("Data (KB/s)")
        ax.legend()
        ax.grid(True, color=self.color_schemes[self.current_theme]['grid'])

        ax.set_facecolor(self.color_schemes[self.current_theme]['background'])
        figure.patch.set_facecolor(self.color_schemes[self.current_theme]['background'])

        ax.tick_params(colors=self.color_schemes[self.current_theme]['text'])
        ax.xaxis.label.set_color(self.color_schemes[self.current_theme]['text'])
        ax.yaxis.label.set_color(self.color_schemes[self.current_theme]['text'])
        ax.title.set_color(self.color_schemes[self.current_theme]['text'])

        return FigureCanvasTkAgg(figure, master=frame)

    def create_protocol_distribution(self, protocol_stats, frame):
        fig = plt.Figure(figsize=(6, 4))
        ax = fig.add_subplot(111)

        non_zero_items = {k: v for k, v in protocol_stats.items() if v > 0}

        if non_zero_items:
            labels = list(non_zero_items.keys())
            sizes = list(non_zero_items.values())
        else:
            labels = ['No Data']
            sizes = [1]

        colors = self.color_schemes[self.current_theme]['colors'][:len(labels)]

        ax.pie(sizes, labels=labels, colors=colors, autopct=lambda pct: f'{pct:.1f}%' if pct > 5 else '')
        ax.set_title("Protocol Distribution")

        fig.patch.set_facecolor(self.color_schemes[self.current_theme]['background'])
        ax.set_facecolor(self.color_schemes[self.current_theme]['background'])

        return FigureCanvasTkAgg(fig, master=frame)

    def create_system_performance_graph(self, system_stats, frame):
        fig = plt.Figure(figsize=(6, 4))
        ax = fig.add_subplot(111)

        colors = self.color_schemes[self.current_theme]['colors']

        timestamps = system_stats.get('timestamps', [])
        cpu_usage = system_stats.get('cpu_usage', [])
        memory_usage = system_stats.get('memory_usage', [])

        if timestamps and cpu_usage and memory_usage:
            ax.plot(timestamps, cpu_usage, label="CPU", color=colors[0])
            ax.plot(timestamps, memory_usage, label="Memory", color=colors[1])

        ax.set_title("System Performance")
        ax.set_xlabel("Time")
        ax.set_ylabel("Usage %")
        ax.legend()
        ax.grid(True, color=self.color_schemes[self.current_theme]['grid'])

        ax.set_facecolor(self.color_schemes[self.current_theme]['background'])
        fig.patch.set_facecolor(self.color_schemes[self.current_theme]['background'])

        return FigureCanvasTkAgg(fig, master=frame)

    def create_network_heatmap(self, connection_data, frame):
        fig = plt.Figure(figsize=(8, 6))
        ax = fig.add_subplot(111)

        hours = 24
        days = 7
        matrix = np.zeros((hours, days))

        if connection_data:
            pass

        im = ax.imshow(matrix, cmap='YlOrRd')

        ax.set_title("Network Activity Heatmap")
        ax.set_xlabel("Day of Week")
        ax.set_ylabel("Hour of Day")

        fig.colorbar(im)

        ax.set_facecolor(self.color_schemes[self.current_theme]['background'])
        fig.patch.set_facecolor(self.color_schemes[self.current_theme]['background'])

        return FigureCanvasTkAgg(fig, master=frame)

    def toggle_theme(self):
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.update_all_visualizations()

    def update_all_visualizations(self):
        pass