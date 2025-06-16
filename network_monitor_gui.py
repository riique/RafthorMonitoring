import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
                            QComboBox, QProgressBar, QSplitter, QTextEdit, QTabWidget)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QBrush
from scapy.all import sniff, DNS, DNSQR, conf
from datetime import datetime
from collections import defaultdict
import time
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class NetworkMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Monitor")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2c3e50;
            }
            QWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
                font-family: 'Segoe UI';
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1c6da8;
            }
            QPushButton:disabled {
                background-color: #34495e;
            }
            QTableWidget {
                background-color: #34495e;
                gridline-color: #7f8c8d;
                border: none;
            }
            QHeaderView::section {
                background-color: #2c3e50;
                padding: 4px;
                border: 1px solid #7f8c8d;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid #7f8c8d;
                background: #34495e;
            }
            QTabBar::tab {
                background: #2c3e50;
                color: #ecf0f1;
                padding: 8px;
                border: 1px solid #7f8c8d;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #3498db;
                color: white;
            }
            QTextEdit {
                background-color: #34495e;
                border: 1px solid #7f8c8d;
                border-radius: 4px;
            }
            QProgressBar {
                border: 1px solid #7f8c8d;
                border-radius: 4px;
                text-align: center;
                background-color: #34495e;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                width: 10px;
            }
        """)
        
        self.access_data = defaultdict(list)
        self.monitoring = False
        self.sniff_thread = None
        
        self.init_ui()
        
    def init_ui(self):
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Top control panel
        control_layout = QHBoxLayout()
        
        # Interface selection
        control_layout.addWidget(QLabel("Network Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItem(r"\Device\NPF_{91F02426-BDBA-41B2-882D-F0112F80FCBD}")
        self.interface_combo.setFixedWidth(300)
        control_layout.addWidget(self.interface_combo)
        
        # Buttons
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 30)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedWidth(200)
        control_layout.addWidget(self.progress_bar)
        
        # Add stretch to push everything left
        control_layout.addStretch()
        
        main_layout.addLayout(control_layout)
        
        # Splitter for main content
        splitter = QSplitter(Qt.Vertical)
        
        # Create tabs for different views
        self.tabs = QTabWidget()
        
        # Real-time logs tab
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.tabs.addTab(self.log_widget, "Live Logs")
        
        # Traffic visualization tab
        self.visualization_tab = QWidget()
        viz_layout = QVBoxLayout(self.visualization_tab)
        
        # Create matplotlib figure
        self.figure = Figure(figsize=(10, 6), dpi=100)
        self.canvas = FigureCanvas(self.figure)
        viz_layout.addWidget(self.canvas)
        
        self.tabs.addTab(self.visualization_tab, "Traffic Analysis")
        
        splitter.addWidget(self.tabs)
        
        # Table for results
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Device", "Website", "Access Count", "Time Spent (s)"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        
        splitter.addWidget(self.table)
        splitter.setSizes([600, 200])
        
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready to start monitoring")
        
        # Timer for progress bar
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        
        # Timer for updating visualization
        self.viz_timer = QTimer()
        self.viz_timer.timeout.connect(self.update_visualization)
        
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_widget.append(f"[{timestamp}] {message}")
        
    def start_monitoring(self):
        iface = self.interface_combo.currentText()
        self.log_message(f"Starting monitoring on interface: {iface}")
        self.log_message("Monitoring DNS traffic for all devices...")
        
        # Configure interface
        conf.iface = iface
        conf.promisc = True
        
        # Start sniffing in a separate thread
        self.monitoring = True
        self.sniff_thread = SniffThread()
        self.sniff_thread.packet_received.connect(self.process_packet)
        self.sniff_thread.start()
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.timer.start(1000)  # Update every second
        self.viz_timer.start(5000)  # Update visualization every 5 seconds
        self.status_bar.showMessage("Monitoring network traffic...")
        
    def stop_monitoring(self):
        self.monitoring = False
        if self.sniff_thread and self.sniff_thread.isRunning():
            self.sniff_thread.stop()
            
        # Update UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.timer.stop()
        self.viz_timer.stop()
        self.generate_report()
        self.status_bar.showMessage("Monitoring stopped. Report generated.")
        
    def update_progress(self):
        value = self.progress_bar.value() + 1
        if value > 30:
            self.stop_monitoring()
        else:
            self.progress_bar.setValue(value)
            
    def update_visualization(self):
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        # Prepare data for visualization
        devices = defaultdict(int)
        sites = defaultdict(int)
        
        for key, timestamps in self.access_data.items():
            device, site = key.split(" - ", 1)
            devices[device] += len(timestamps)
            sites[site] += len(timestamps)
        
        # Plot device activity
        if devices:
            ax.clear()
            ax.bar(devices.keys(), devices.values(), color='#3498db')
            ax.set_title('Network Activity by Device')
            ax.set_xlabel('Device IP')
            ax.set_ylabel('DNS Requests')
            ax.tick_params(axis='x', rotation=45)
            self.canvas.draw()
        
    def process_packet(self, pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            qname = pkt.getlayer(DNSQR).qname.decode('utf-8').rstrip('.')
            if pkt.haslayer('IP'):
                src_ip = pkt['IP'].src
            elif pkt.haslayer('IPv6'):
                src_ip = pkt['IPv6'].src
            else:
                src_ip = 'Unknown'
            timestamp = datetime.now()
            key = f"{src_ip} - {qname}"
            self.access_data[key].append(timestamp)
            
            # Update UI with live packet info
            time_str = timestamp.strftime("%H:%M:%S")
            self.log_message(f"{src_ip} accessed: {qname}")
            
    def generate_report(self):
        # Clear table
        self.table.setRowCount(0)
        
        # Populate table with results
        row = 0
        for key, timestamps in self.access_data.items():
            device, site = key.split(" - ", 1)
            
            # Calculate total time
            total_time = 0
            if len(timestamps) > 1:
                for i in range(len(timestamps)-1):
                    delta = (timestamps[i+1] - timestamps[i]).total_seconds()
                    if delta < 60:  # Ignore long intervals
                        total_time += delta
            
            # Add to table
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(device))
            self.table.setItem(row, 1, QTableWidgetItem(site))
            self.table.setItem(row, 2, QTableWidgetItem(str(len(timestamps))))
            self.table.setItem(row, 3, QTableWidgetItem(f"{total_time:.2f}"))
            
            # Color code based on access count
            if len(timestamps) > 10:
                for col in range(4):
                    self.table.item(row, col).setBackground(QBrush(QColor('#e74c3c')))
            elif len(timestamps) > 5:
                for col in range(4):
                    self.table.item(row, col).setBackground(QBrush(QColor('#f39c12')))
            
            row += 1
        
        # Sort by access count descending
        self.table.sortItems(2, Qt.DescendingOrder)
        self.log_message(f"Report generated with {row} entries")

class SniffThread(QThread):
    packet_received = pyqtSignal(object)
    _running = True
    
    def run(self):
        filter_str = "(udp port 53) or (tcp port 80) or (tcp port 853) or (tcp port 443 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x00010000)"
        sniff(prn=self.handle_packet, store=0, timeout=30, filter=filter_str, promisc=True)
    
    def handle_packet(self, pkt):
        if self._running:
            self.packet_received.emit(pkt)
    
    def stop(self):
        self._running = False

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set application font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    monitor = NetworkMonitor()
    monitor.show()
    sys.exit(app.exec_())
