import sys
import re
import requests
import psutil
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTextEdit, 
                             QPushButton, QVBoxLayout, QHBoxLayout, 
                             QWidget, QFileDialog, QListWidget, QLabel, QLineEdit)
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression, Qt, QTimer

# --- THE SECURITY BRAIN (Syntax Highlighter) ---
class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        self.rules = []
        
        # IP Addresses -> Blue & Bold
        ip_format = QTextCharFormat()
        ip_format.setForeground(QColor("#3498db"))
        ip_format.setFontWeight(QFont.Weight.Bold)
        self.rules.append((QRegularExpression(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), ip_format))

        # Security Threats -> Bright Red
        error_format = QTextCharFormat()
        error_format.setForeground(QColor("#e74c3c"))
        error_format.setFontWeight(QFont.Weight.Bold)
        self.rules.append((QRegularExpression(r'(?i)failed|denied|unauthorized|critical|401|403|invalid'), error_format))

        # Success Codes -> Green
        success_format = QTextCharFormat()
        success_format.setForeground(QColor("#2ecc71"))
        self.rules.append((QRegularExpression(r'(?i)success|accepted|200 OK'), success_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            match_iterator = pattern.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), fmt)

# --- THE MAIN SOC WINDOW ---
class LogIDE(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Log Analyzer v3.0 - SOC & LIVE MONITOR")
        self.resize(1200, 800)

        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        
        # --- TOP CONTROL BAR ---
        top_bar = QHBoxLayout()
        self.btn_open = QPushButton("📂 Load Log File")
        self.btn_open.setFixedHeight(45)
        self.btn_open.clicked.connect(self.load_file)
        
        self.btn_live = QPushButton("📡 Go LIVE")
        self.btn_live.setCheckable(True)
        self.btn_live.setFixedHeight(45)
        self.btn_live.toggled.connect(self.toggle_live_mode)
        self.btn_live.setStyleSheet("background-color: #2c3e50; color: white;")

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Filter logs or search IP...")
        self.search_bar.setFixedHeight(45)
        self.search_bar.returnPressed.connect(self.filter_logs)
        
        top_bar.addWidget(self.btn_open, 1)
        top_bar.addWidget(self.btn_live, 1)
        top_bar.addWidget(self.search_bar, 2)
        
        self.text_area = QTextEdit()
        self.text_area.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas';")
        self.highlighter = LogHighlighter(self.text_area.document())
        
        left_layout.addLayout(top_bar)
        left_layout.addWidget(self.text_area)

        # --- RIGHT SIDEBAR ---
        right_layout = QVBoxLayout()
        
        self.threat_panel = QLabel("<b>SOC DASHBOARD</b><br>Analyze a log or go Live...")
        self.threat_panel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.threat_panel.setWordWrap(True)
        self.threat_panel.setStyleSheet("""
            background-color: #34495e; color: white; 
            padding: 15px; border-radius: 10px; border: 2px solid #2c3e50;
        """)
        right_layout.addWidget(self.threat_panel)

        right_layout.addWidget(QLabel("<br><b>Detected Network Nodes:</b>"))
        self.ip_list = QListWidget()
        self.ip_list.itemClicked.connect(self.on_ip_clicked)
        right_layout.addWidget(self.ip_list)

        main_layout.addLayout(left_layout, stretch=4)
        main_layout.addLayout(right_layout, stretch=1)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
        
        # State & Timers
        self.full_log_content = ""
        self.live_timer = QTimer()
        self.live_timer.timeout.connect(self.update_live_traffic)

    # --- LOGIC FUNCTIONS ---

    def toggle_live_mode(self, checked):
        if checked:
            self.btn_live.setText("🔴 STOP LIVE")
            self.btn_live.setStyleSheet("background-color: #c0392b; color: white;")
            self.text_area.clear()
            self.text_area.append("📡 Starting Live Packet Inspection...")
            self.live_timer.start(2000)
        else:
            self.btn_live.setText("📡 Go LIVE")
            self.btn_live.setStyleSheet("background-color: #2c3e50; color: white;")
            self.live_timer.stop()

    def update_live_traffic(self):
        live_ips = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    live_ips.add(conn.raddr.ip)
            
            new_ips = sorted(list(live_ips))
            if len(new_ips) != self.ip_list.count():
                self.ip_list.clear()
                self.ip_list.addItems(new_ips)
            
            self.text_area.append(f"Network Scan: {len(new_ips)} active connections detected.")
        except Exception as e:
            self.text_area.append(f"System Error: {e}")

    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Log", "", "Log Files (*.log *.txt)")
        if file_path:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.full_log_content = f.read()
                self.text_area.setPlainText(self.full_log_content)
                self.update_stats(self.full_log_content)

    def filter_logs(self):
        query = self.search_bar.text().lower()
        content = self.text_area.toPlainText() if not self.full_log_content else self.full_log_content
        lines = content.splitlines()
        filtered = [l for l in lines if query in l.lower()]
        self.text_area.setPlainText("\n".join(filtered))

    def on_ip_clicked(self, item):
        ip = item.text()
        self.search_bar.setText(ip)
        self.filter_logs()
        
        # 1. Threat Score (Behavioral Analysis)
        pattern = fr"(?i){re.escape(ip)}.*(failed|denied|invalid|unauthorized)"
        threat_count = len(re.findall(pattern, self.full_log_content))
        
        if threat_count > 15:
            risk, color = "CRITICAL 🚨", "#c0392b"
        elif threat_count > 5:
            risk, color = "SUSPICIOUS ⚠️", "#f39c12"
        else:
            risk, color = "SAFE ✅", "#27ae60"

        # 2. Geo-IP (Location Intelligence)
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
            loc = f"{res.get('city')}, {res.get('country')}" if res.get('status') == 'success' else "Private/Internal"
            isp = res.get('isp', 'Unknown ISP')
        except:
            loc, isp = "Offline", "N/A"

        # Update Sidebar Dashboard
        self.threat_panel.setText(f"""
            <div style='text-align: center;'>
                <b style='font-size: 14px;'>{ip}</b><br>
                <span style='font-size: 18px; color: {color};'><b>{risk}</b></span><br><br>
                <b>Location:</b> {loc}<br>
                <b>ISP:</b> {isp}<br>
                <b>Log Incidents:</b> {threat_count}
            </div>
        """)
        self.threat_panel.setStyleSheet(f"background-color: #2c3e50; border: 3px solid {color}; border-radius: 10px; color: white; padding: 10px;")

    def update_stats(self, content):
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
        unique_ips = sorted(list(set(ips)))
        self.ip_list.clear()
        self.ip_list.addItems(unique_ips)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LogIDE()
    window.show()
    sys.exit(app.exec())