# # ui_main.py
# import os
# import sys
# from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
#                                QLabel, QLineEdit, QPushButton, QTabWidget, 
#                                QTextEdit, QTextBrowser, QProgressBar, QFileDialog,
#                                QGroupBox, QCheckBox, QGridLayout, QScrollArea, QFrame)
# from PySide6.QtCore import Qt, QThread, Signal, QObject, QPropertyAnimation, QEasingCurve
# from PySide6.QtGui import QPixmap, QFont, QPalette, QColor
# from scanner import AnonScanner
# from datetime import datetime

# class ScanWorker(QObject):
#     log_signal = Signal(str)
#     progress_signal = Signal(int)
#     status_signal = Signal(str)
#     summary_signal = Signal(str)
#     report_signal = Signal(str)
#     finished_signal = Signal()
    
#     def __init__(self, target, shodan_key, censys_id, censys_secret, modules):
#         super().__init__()
#         self.target = target
#         self.shodan_key = shodan_key
#         self.censys_id = censys_id
#         self.censys_secret = censys_secret
#         self.modules = modules
        
#     def run(self):
#         try:
#             scanner = AnonScanner(
#                 target=self.target,
#                 shodan_key=self.shodan_key,
#                 censys_id=self.censys_id,
#                 censys_secret=self.censys_secret,
#                 log_callback=self.log_signal.emit,
#                 progress_callback=self.progress_signal.emit,
#                 status_callback=self.status_signal.emit,
#                 enabled_modules=self.modules
#             )
            
#             results = scanner.run_scan()
            
#             summary = scanner.generate_summary(results)
#             self.summary_signal.emit(summary)
            
#             report_html = scanner.generate_html_report(results)
#             self.report_signal.emit(report_html)
            
#         except Exception as e:
#             self.log_signal.emit(f"[ERROR] Critical failure: {str(e)}")
#             self.status_signal.emit("Scan failed")
#         finally:
#             self.finished_signal.emit()

# class AnonScanWindow(QMainWindow):
#     def __init__(self):
#         super().__init__()
#         self.report_html = ""
#         self.scan_thread = None
#         self.worker = None
#         self.init_ui()
        
#     def init_ui(self):
#         self.setWindowTitle("Anon Scan - Advanced Reconnaissance Tool")
#         self.setMinimumSize(1200, 800)
        
#         # Dark red theme
#         self.setStyleSheet("""
#             QMainWindow {
#                 background-color: #1a0000;
#             }
#         """)
        
#         central = QWidget()
#         self.setCentralWidget(central)
#         main_layout = QVBoxLayout(central)
#         main_layout.setSpacing(0)
#         main_layout.setContentsMargins(0, 0, 0, 0)
        
#         # Header with gradient
#         header = QFrame()
#         header.setObjectName("header")
#         header.setStyleSheet("""
#             QFrame#header {
#                 background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
#                     stop:0 #930000, stop:0.5 #b30000, stop:1 #930000);
#                 border-bottom: 3px solid #ff0000;
#                 min-height: 100px;
#                 max-height: 100px;
#             }
#         """)
#         header_layout = QHBoxLayout(header)
#         header_layout.setContentsMargins(30, 20, 30, 20)
        
#         # Logo
#         logo_path = self.get_resource_path("Logo.png")
#         if os.path.exists(logo_path):
#             logo_label = QLabel()
#             pixmap = QPixmap(logo_path)
#             logo_label.setPixmap(pixmap.scaled(70, 70, Qt.KeepAspectRatio, Qt.SmoothTransformation))
#             header_layout.addWidget(logo_label)
        
#         # Title section
#         title_container = QWidget()
#         title_layout = QVBoxLayout(title_container)
#         title_layout.setSpacing(5)
#         title_layout.setContentsMargins(15, 0, 0, 0)
        
#         title = QLabel("ANON SCAN")
#         title_font = QFont("Consolas", 32, QFont.Bold)
#         title.setFont(title_font)
#         title.setStyleSheet("color: #ffffff; letter-spacing: 3px;")
#         title_layout.addWidget(title)
        
#         subtitle = QLabel("Advanced Reconnaissance & Intelligence Platform")
#         subtitle_font = QFont("Segoe UI", 11)
#         subtitle.setFont(subtitle_font)
#         subtitle.setStyleSheet("color: #ffcccc; font-style: italic;")
#         title_layout.addWidget(subtitle)
        
#         header_layout.addWidget(title_container)
#         header_layout.addStretch()
        
#         main_layout.addWidget(header)
        
#         # Content area with scroll
#         scroll = QScrollArea()
#         scroll.setWidgetResizable(True)
#         scroll.setStyleSheet("""
#             QScrollArea {
#                 border: none;
#                 background-color: #1a0000;
#             }
#         """)
        
#         content = QWidget()
#         layout = QVBoxLayout(content)
#         layout.setSpacing(20)
#         layout.setContentsMargins(30, 30, 30, 30)
        
#         # Input section - modern card style
#         input_card = QFrame()
#         input_card.setObjectName("card")
#         input_card_layout = QVBoxLayout(input_card)
#         input_card_layout.setSpacing(15)
#         input_card_layout.setContentsMargins(25, 25, 25, 25)
        
#         input_title = QLabel("TARGET CONFIGURATION")
#         input_title.setFont(QFont("Consolas", 13, QFont.Bold))
#         input_title.setStyleSheet("color: #ff3333; letter-spacing: 2px;")
#         input_card_layout.addWidget(input_title)
        
#         # Target input
#         target_container = QWidget()
#         target_layout = QVBoxLayout(target_container)
#         target_layout.setSpacing(8)
#         target_layout.setContentsMargins(0, 0, 0, 0)
        
#         target_label = QLabel("Target URL/Domain")
#         target_label.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 12px;")
#         target_layout.addWidget(target_label)
        
#         self.target_input = QLineEdit()
#         self.target_input.setPlaceholderText("example.com or https://example.com")
#         self.target_input.setMinimumHeight(45)
#         target_layout.addWidget(self.target_input)
        
#         input_card_layout.addWidget(target_container)
        
#         # API Keys in grid
#         api_grid = QGridLayout()
#         api_grid.setSpacing(15)
        
#         # Shodan
#         shodan_label = QLabel("Shodan API Key")
#         shodan_label.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11px;")
#         api_grid.addWidget(shodan_label, 0, 0)
        
#         self.shodan_input = QLineEdit()
#         self.shodan_input.setPlaceholderText("Optional - Enhanced port/vuln scanning")
#         self.shodan_input.setMinimumHeight(40)
#         api_grid.addWidget(self.shodan_input, 1, 0)
        
#         # Censys ID
#         censys_id_label = QLabel("Censys API ID")
#         censys_id_label.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11px;")
#         api_grid.addWidget(censys_id_label, 0, 1)
        
#         self.censys_id_input = QLineEdit()
#         self.censys_id_input.setPlaceholderText("Optional")
#         self.censys_id_input.setMinimumHeight(40)
#         api_grid.addWidget(self.censys_id_input, 1, 1)
        
#         # Censys Secret
#         censys_secret_label = QLabel("Censys API Secret")
#         censys_secret_label.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 11px;")
#         api_grid.addWidget(censys_secret_label, 2, 0, 1, 2)
        
#         self.censys_secret_input = QLineEdit()
#         self.censys_secret_input.setPlaceholderText("Optional - Service enumeration")
#         self.censys_secret_input.setEchoMode(QLineEdit.Password)
#         self.censys_secret_input.setMinimumHeight(40)
#         api_grid.addWidget(self.censys_secret_input, 3, 0, 1, 2)
        
#         input_card_layout.addLayout(api_grid)
#         layout.addWidget(input_card)
        
#         # Module selection - modern card
#         module_card = QFrame()
#         module_card.setObjectName("card")
#         module_card_layout = QVBoxLayout(module_card)
#         module_card_layout.setSpacing(15)
#         module_card_layout.setContentsMargins(25, 25, 25, 25)
        
#         module_title = QLabel("RECONNAISSANCE MODULES")
#         module_title.setFont(QFont("Consolas", 13, QFont.Bold))
#         module_title.setStyleSheet("color: #ff3333; letter-spacing: 2px;")
#         module_card_layout.addWidget(module_title)
        
#         module_grid = QGridLayout()
#         module_grid.setSpacing(12)
        
#         self.module_checks = {}
#         modules = [
#             ("subdomains", "Subdomain Enumeration", "Discover subdomains via multiple sources"),
#             ("dns", "DNS Records", "Query A, AAAA, MX, NS, TXT, CNAME"),
#             ("shodan_censys", "Shodan/Censys", "API-based intelligence gathering"),
#             ("web_tech", "Web Technologies", "Fingerprint frameworks & servers"),
#             ("http_probe", "HTTP Probing", "Test HTTP/HTTPS endpoints"),
#             ("wayback", "Wayback Machine", "Historical URL discovery"),
#             ("crawler", "Web Crawler", "Extract links and resources"),
#             ("port_scan", "Port Scanner", "TCP port enumeration"),
#             ("ssl_info", "SSL/TLS Analysis", "Certificate inspection"),
#             ("email_osint", "Email Harvesting", "OSINT email extraction")
#         ]
        
#         for i, (key, name, desc) in enumerate(modules):
#             module_item = QFrame()
#             module_item.setObjectName("moduleItem")
#             module_item_layout = QHBoxLayout(module_item)
#             module_item_layout.setContentsMargins(10, 8, 10, 8)
            
#             cb = QCheckBox()
#             cb.setChecked(True)
#             cb.setStyleSheet("""
#                 QCheckBox::indicator {
#                     width: 20px;
#                     height: 20px;
#                     border: 2px solid #ff3333;
#                     border-radius: 4px;
#                     background-color: #2a0000;
#                 }
#                 QCheckBox::indicator:checked {
#                     background-color: #ff0000;
#                     border-color: #ff0000;
#                 }
#                 QCheckBox::indicator:hover {
#                     border-color: #ff6666;
#                 }
#             """)
#             self.module_checks[key] = cb
#             module_item_layout.addWidget(cb)
            
#             text_container = QWidget()
#             text_layout = QVBoxLayout(text_container)
#             text_layout.setSpacing(2)
#             text_layout.setContentsMargins(0, 0, 0, 0)
            
#             name_label = QLabel(name)
#             name_label.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 12px;")
#             text_layout.addWidget(name_label)
            
#             desc_label = QLabel(desc)
#             desc_label.setStyleSheet("color: #cc9999; font-size: 10px;")
#             text_layout.addWidget(desc_label)
            
#             module_item_layout.addWidget(text_container, 1)
            
#             module_grid.addWidget(module_item, i // 2, i % 2)
        
#         module_card_layout.addLayout(module_grid)
#         layout.addWidget(module_card)
        
#         # Scan button - prominent
#         self.scan_btn = QPushButton("▶ INITIATE SCAN")
#         self.scan_btn.setMinimumHeight(55)
#         self.scan_btn.setFont(QFont("Consolas", 14, QFont.Bold))
#         self.scan_btn.setCursor(Qt.PointingHandCursor)
#         self.scan_btn.clicked.connect(self.start_scan)
#         layout.addWidget(self.scan_btn)
        
#         # Results section
#         results_card = QFrame()
#         results_card.setObjectName("card")
#         results_layout = QVBoxLayout(results_card)
#         results_layout.setSpacing(15)
#         results_layout.setContentsMargins(25, 25, 25, 25)
        
#         results_title = QLabel("SCAN RESULTS")
#         results_title.setFont(QFont("Consolas", 13, QFont.Bold))
#         results_title.setStyleSheet("color: #ff3333; letter-spacing: 2px;")
#         results_layout.addWidget(results_title)
        
#         # Tabs
#         self.tabs = QTabWidget()
#         self.tabs.setStyleSheet("""
#             QTabWidget::pane {
#                 border: 2px solid #4a0000;
#                 border-radius: 5px;
#                 background-color: #0d0000;
#             }
#             QTabBar::tab {
#                 background-color: #2a0000;
#                 color: #cc9999;
#                 padding: 12px 24px;
#                 margin-right: 3px;
#                 border-top-left-radius: 5px;
#                 border-top-right-radius: 5px;
#                 font-weight: bold;
#                 font-size: 11px;
#             }
#             QTabBar::tab:selected {
#                 background-color: #930000;
#                 color: #ffffff;
#             }
#             QTabBar::tab:hover {
#                 background-color: #4a0000;
#             }
#         """)
        
#         self.summary_text = QTextEdit()
#         self.summary_text.setReadOnly(True)
#         self.summary_text.setMinimumHeight(300)
#         self.tabs.addTab(self.summary_text, "📊 Summary")
        
#         self.logs_text = QTextEdit()
#         self.logs_text.setReadOnly(True)
#         self.logs_text.setMinimumHeight(300)
#         self.tabs.addTab(self.logs_text, "📝 Logs")
        
#         self.report_browser = QTextBrowser()
#         self.report_browser.setOpenExternalLinks(True)
#         self.report_browser.setMinimumHeight(300)
#         self.tabs.addTab(self.report_browser, "📄 Report")
        
#         results_layout.addWidget(self.tabs)
        
#         # Progress bar
#         self.progress = QProgressBar()
#         self.progress.setValue(0)
#         self.progress.setMinimumHeight(25)
#         self.progress.setTextVisible(True)
#         results_layout.addWidget(self.progress)
        
#         # Status
#         status_container = QHBoxLayout()
#         status_label_text = QLabel("Status:")
#         status_label_text.setStyleSheet("color: #cc9999; font-weight: bold;")
#         status_container.addWidget(status_label_text)
        
#         self.status_label = QLabel("Idle")
#         self.status_label.setStyleSheet("color: #ffcccc; font-style: italic;")
#         status_container.addWidget(self.status_label)
#         status_container.addStretch()
        
#         results_layout.addLayout(status_container)
        
#         # Save button
#         self.save_btn = QPushButton("💾 SAVE REPORT")
#         self.save_btn.setEnabled(False)
#         self.save_btn.setMinimumHeight(45)
#         self.save_btn.setFont(QFont("Consolas", 12, QFont.Bold))
#         self.save_btn.setCursor(Qt.PointingHandCursor)
#         self.save_btn.clicked.connect(self.save_report)
#         results_layout.addWidget(self.save_btn)
        
#         layout.addWidget(results_card)
        
#         scroll.setWidget(content)
#         main_layout.addWidget(scroll)
        
#         self.apply_styles()
        
#     def apply_styles(self):
#         self.setStyleSheet(self.styleSheet() + """
#             QFrame#card {
#                 background-color: #2a0000;
#                 border: 2px solid #4a0000;
#                 border-radius: 10px;
#             }
            
#             QFrame#moduleItem {
#                 background-color: #1a0000;
#                 border: 1px solid #3a0000;
#                 border-radius: 5px;
#             }
            
#             QFrame#moduleItem:hover {
#                 background-color: #3a0000;
#                 border-color: #930000;
#             }
            
#             QPushButton {
#                 background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
#                     stop:0 #b30000, stop:1 #930000);
#                 color: white;
#                 border: 2px solid #ff0000;
#                 border-radius: 8px;
#                 padding: 10px;
#                 font-weight: bold;
#                 letter-spacing: 1px;
#             }
            
#             QPushButton:hover {
#                 background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
#                     stop:0 #d30000, stop:1 #b30000);
#                 border-color: #ff3333;
#             }
            
#             QPushButton:pressed {
#                 background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
#                     stop:0 #930000, stop:1 #700000);
#             }
            
#             QPushButton:disabled {
#                 background-color: #4a0000;
#                 color: #666666;
#                 border-color: #3a0000;
#             }
            
#             QLineEdit {
#                 padding: 12px;
#                 border: 2px solid #4a0000;
#                 border-radius: 6px;
#                 background-color: #0d0000;
#                 color: #ffffff;
#                 font-size: 13px;
#                 selection-background-color: #930000;
#             }
            
#             QLineEdit:focus {
#                 border: 2px solid #ff0000;
#                 background-color: #1a0000;
#             }
            
#             QLineEdit::placeholder {
#                 color: #666666;
#             }
            
#             QTextEdit, QTextBrowser {
#                 background-color: #0d0000;
#                 color: #ffffff;
#                 border: 2px solid #4a0000;
#                 border-radius: 5px;
#                 padding: 10px;
#                 font-family: "Consolas", monospace;
#                 font-size: 12px;
#                 selection-background-color: #930000;
#             }
            
#             QProgressBar {
#                 border: 2px solid #4a0000;
#                 border-radius: 6px;
#                 text-align: center;
#                 background-color: #0d0000;
#                 color: #ffffff;
#                 font-weight: bold;
#             }
            
#             QProgressBar::chunk {
#                 background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
#                     stop:0 #930000, stop:0.5 #ff0000, stop:1 #930000);
#                 border-radius: 4px;
#             }
            
#             QScrollBar:vertical {
#                 background-color: #1a0000;
#                 width: 12px;
#                 border-radius: 6px;
#             }
            
#             QScrollBar::handle:vertical {
#                 background-color: #930000;
#                 border-radius: 6px;
#                 min-height: 20px;
#             }
            
#             QScrollBar::handle:vertical:hover {
#                 background-color: #b30000;
#             }
            
#             QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
#                 height: 0px;
#             }
            
#             QScrollBar:horizontal {
#                 background-color: #1a0000;
#                 height: 12px;
#                 border-radius: 6px;
#             }
            
#             QScrollBar::handle:horizontal {
#                 background-color: #930000;
#                 border-radius: 6px;
#                 min-width: 20px;
#             }
            
#             QScrollBar::handle:horizontal:hover {
#                 background-color: #b30000;
#             }
            
#             QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
#                 width: 0px;
#             }
#         """)
    
#     def get_resource_path(self, relative_path):
#         try:
#             base_path = sys._MEIPASS
#         except:
#             base_path = os.path.abspath(".")
#         return os.path.join(base_path, relative_path)
    
#     def start_scan(self):
#         target = self.target_input.text().strip()
#         if not target:
#             self.append_log("[ERROR] Please enter a target URL or domain")
#             return
        
#         self.scan_btn.setEnabled(False)
#         self.save_btn.setEnabled(False)
#         self.progress.setValue(0)
#         self.summary_text.clear()
#         self.logs_text.clear()
#         self.report_browser.clear()
        
#         enabled_modules = {k: v.isChecked() for k, v in self.module_checks.items()}
        
#         self.scan_thread = QThread()
#         self.worker = ScanWorker(
#             target=target,
#             shodan_key=self.shodan_input.text().strip(),
#             censys_id=self.censys_id_input.text().strip(),
#             censys_secret=self.censys_secret_input.text().strip(),
#             modules=enabled_modules
#         )
        
#         self.worker.moveToThread(self.scan_thread)
#         self.scan_thread.started.connect(self.worker.run)
#         self.worker.log_signal.connect(self.append_log)
#         self.worker.progress_signal.connect(self.update_progress)
#         self.worker.status_signal.connect(self.update_status)
#         self.worker.summary_signal.connect(self.update_summary)
#         self.worker.report_signal.connect(self.update_report)
#         self.worker.finished_signal.connect(self.scan_finished)
#         self.worker.finished_signal.connect(self.scan_thread.quit)
#         self.worker.finished_signal.connect(self.worker.deleteLater)
#         self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        
#         self.scan_thread.start()
    
#     def append_log(self, message):
#         self.logs_text.append(message)
    
#     def update_progress(self, value):
#         self.progress.setValue(value)
    
#     def update_status(self, status):
#         self.status_label.setText(status)
    
#     def update_summary(self, summary):
#         self.summary_text.setPlainText(summary)
    
#     def update_report(self, html):
#         self.report_html = html
#         self.report_browser.setHtml(html)
    
#     def scan_finished(self):
#         self.scan_btn.setEnabled(True)
#         if self.report_html:
#             self.save_btn.setEnabled(True)
#         self.update_status("Scan complete")
#         self.progress.setValue(100)
    
#     def save_report(self):
#         if not self.report_html:
#             return
        
#         target = self.target_input.text().strip().replace("http://", "").replace("https://", "").replace("/", "_")
#         timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#         default_name = f"report_{target}_{timestamp}.html"
        
#         file_path, _ = QFileDialog.getSaveFileName(
#             self,
#             "Save Report",
#             default_name,
#             "HTML Files (*.html)"
#         )
        
#         if file_path:
#             try:
#                 with open(file_path, 'w', encoding='utf-8') as f:
#                     f.write(self.report_html)
#                 self.append_log(f"[SUCCESS] Report saved to {file_path}")
#             except Exception as e:
#                 self.append_log(f"[ERROR] Failed to save report: {str(e)}")

















# ui_main.py
import os
import sys
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QLabel, QLineEdit, QPushButton, QTabWidget, 
                               QTextEdit, QTextBrowser, QProgressBar, QFileDialog,
                               QGroupBox, QCheckBox, QGridLayout, QScrollArea, QFrame)
from PySide6.QtCore import Qt, QThread, Signal, QObject, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QPixmap, QFont, QPalette, QColor
from scanner import AnonScanner
from datetime import datetime

class ScanWorker(QObject):
    log_signal = Signal(str)
    progress_signal = Signal(int)
    status_signal = Signal(str)
    summary_signal = Signal(str)
    report_signal = Signal(str)
    finished_signal = Signal()
    
    def __init__(self, target, shodan_key, censys_id, censys_secret, modules):
        super().__init__()
        self.target = target
        self.shodan_key = shodan_key
        self.censys_id = censys_id
        self.censys_secret = censys_secret
        self.modules = modules
        
    def run(self):
        try:
            scanner = AnonScanner(
                target=self.target,
                shodan_key=self.shodan_key,
                censys_id=self.censys_id,
                censys_secret=self.censys_secret,
                log_callback=self.log_signal.emit,
                progress_callback=self.progress_signal.emit,
                status_callback=self.status_signal.emit,
                enabled_modules=self.modules
            )
            
            results = scanner.run_scan()
            
            summary = scanner.generate_summary(results)
            self.summary_signal.emit(summary)
            
            report_html = scanner.generate_html_report(results)
            self.report_signal.emit(report_html)
            
        except Exception as e:
            self.log_signal.emit(f"[ERROR] Critical failure: {str(e)}")
            self.status_signal.emit("Scan failed")
        finally:
            self.finished_signal.emit()

class AnonScanWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.report_html = ""
        self.scan_thread = None
        self.worker = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Anon Scan")
        self.setMinimumSize(1200, 800)
        
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(90)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(30, 0, 30, 0)
        
        # Logo
        logo_path = self.get_resource_path("Logo.png")
        if os.path.exists(logo_path):
            logo_label = QLabel()
            pixmap = QPixmap(logo_path)
            logo_label.setPixmap(pixmap.scaled(55, 55, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            header_layout.addWidget(logo_label)
        
        # Title
        title = QLabel("ANON SCAN")
        title.setObjectName("title")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        main_layout.addWidget(header)
        
        # Content area with scroll
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Input section
        input_card = QFrame()
        input_card.setObjectName("card")
        input_card_layout = QVBoxLayout(input_card)
        input_card_layout.setSpacing(20)
        input_card_layout.setContentsMargins(25, 25, 25, 25)
        
        input_title = QLabel("TARGET")
        input_title.setObjectName("sectionLabel")
        input_card_layout.addWidget(input_title)
        
        # Target input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com or https://example.com")
        self.target_input.setFixedHeight(45)
        input_card_layout.addWidget(self.target_input)
        
        # API Keys
        api_label = QLabel("API KEYS")
        api_label.setObjectName("sectionLabel")
        input_card_layout.addWidget(api_label)
        
        api_grid = QGridLayout()
        api_grid.setSpacing(15)
        api_grid.setContentsMargins(0, 0, 0, 0)
        
        self.shodan_input = QLineEdit()
        self.shodan_input.setPlaceholderText("Shodan API Key (optional)")
        self.shodan_input.setFixedHeight(40)
        api_grid.addWidget(self.shodan_input, 0, 0)
        
        self.censys_id_input = QLineEdit()
        self.censys_id_input.setPlaceholderText("Censys API ID (optional)")
        self.censys_id_input.setFixedHeight(40)
        api_grid.addWidget(self.censys_id_input, 0, 1)
        
        self.censys_secret_input = QLineEdit()
        self.censys_secret_input.setPlaceholderText("Censys API Secret (optional)")
        self.censys_secret_input.setEchoMode(QLineEdit.Password)
        self.censys_secret_input.setFixedHeight(40)
        api_grid.addWidget(self.censys_secret_input, 1, 0, 1, 2)
        
        input_card_layout.addLayout(api_grid)
        layout.addWidget(input_card)
        
        # Module selection
        module_card = QFrame()
        module_card.setObjectName("card")
        module_card_layout = QVBoxLayout(module_card)
        module_card_layout.setSpacing(20)
        module_card_layout.setContentsMargins(25, 25, 25, 25)
        
        module_title = QLabel("MODULES")
        module_title.setObjectName("sectionLabel")
        module_card_layout.addWidget(module_title)
        
        module_grid = QGridLayout()
        module_grid.setSpacing(10)
        
        self.module_checks = {}
        modules = [
            ("subdomains", "Subdomain Enumeration"),
            ("dns", "DNS Records"),
            ("shodan_censys", "Shodan/Censys"),
            ("web_tech", "Web Technologies"),
            ("http_probe", "HTTP Probing"),
            ("wayback", "Wayback Machine"),
            ("crawler", "Web Crawler"),
            ("port_scan", "Port Scanner"),
            ("ssl_info", "SSL/TLS Analysis"),
            ("email_osint", "Email Harvesting")
        ]
        
        for i, (key, name) in enumerate(modules):
            cb = QCheckBox(name)
            cb.setChecked(True)
            cb.setObjectName("moduleCheck")
            self.module_checks[key] = cb
            module_grid.addWidget(cb, i // 3, i % 3)
        
        module_card_layout.addLayout(module_grid)
        layout.addWidget(module_card)
        
        # Scan button
        self.scan_btn = QPushButton("SCAN")
        self.scan_btn.setObjectName("scanButton")
        self.scan_btn.setFixedHeight(50)
        self.scan_btn.setCursor(Qt.PointingHandCursor)
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn)
        
        # Results section
        results_card = QFrame()
        results_card.setObjectName("card")
        results_layout = QVBoxLayout(results_card)
        results_layout.setSpacing(15)
        results_layout.setContentsMargins(25, 25, 25, 25)
        
        results_title = QLabel("RESULTS")
        results_title.setObjectName("sectionLabel")
        results_layout.addWidget(results_title)
        
        # Status
        status_container = QHBoxLayout()
        status_container.setSpacing(10)
        
        status_label_text = QLabel("Status:")
        status_label_text.setObjectName("statusText")
        status_container.addWidget(status_label_text)
        
        self.status_label = QLabel("Idle")
        self.status_label.setObjectName("statusValue")
        status_container.addWidget(self.status_label)
        status_container.addStretch()
        
        results_layout.addLayout(status_container)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        results_layout.addWidget(self.progress)
        
        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setObjectName("tabs")
        
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setObjectName("outputText")
        self.summary_text.setMinimumHeight(300)
        self.tabs.addTab(self.summary_text, "Summary")
        
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setObjectName("outputText")
        self.logs_text.setMinimumHeight(300)
        self.tabs.addTab(self.logs_text, "Logs")
        
        self.report_browser = QTextBrowser()
        self.report_browser.setOpenExternalLinks(True)
        self.report_browser.setObjectName("outputText")
        self.report_browser.setMinimumHeight(300)
        self.tabs.addTab(self.report_browser, "Report")
        
        results_layout.addWidget(self.tabs)
        
        # Save button
        self.save_btn = QPushButton("SAVE REPORT")
        self.save_btn.setEnabled(False)
        self.save_btn.setObjectName("saveButton")
        self.save_btn.setFixedHeight(45)
        self.save_btn.setCursor(Qt.PointingHandCursor)
        self.save_btn.clicked.connect(self.save_report)
        results_layout.addWidget(self.save_btn)
        
        layout.addWidget(results_card)
        
        scroll.setWidget(content)
        main_layout.addWidget(scroll)
        
        self.apply_styles()
        
    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            
            #header {
                background-color: #0a0a0a;
                border-bottom: 1px solid #930000;
            }
            
            #title {
                color: #930000;
                font-size: 26px;
                font-weight: 600;
                letter-spacing: 4px;
                margin-left: 20px;
            }
            
            #card {
                background-color: #0a0a0a;
                border: 1px solid #1a1a1a;
                border-radius: 0px;
            }
            
            #sectionLabel {
                color: #ffffff;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 2px;
            }
            
            QLineEdit {
                background-color: #000000;
                border: 1px solid #2a2a2a;
                border-radius: 0px;
                color: #ffffff;
                padding: 0 15px;
                font-size: 13px;
            }
            
            QLineEdit:focus {
                border: 1px solid #930000;
            }
            
            QLineEdit::placeholder {
                color: #444444;
            }
            
            #scanButton {
                background-color: #930000;
                border: none;
                border-radius: 0px;
                color: #ffffff;
                font-size: 13px;
                font-weight: 600;
                letter-spacing: 3px;
            }
            
            #scanButton:hover {
                background-color: #b30000;
            }
            
            #scanButton:pressed {
                background-color: #700000;
            }
            
            #scanButton:disabled {
                background-color: #2a2a2a;
                color: #666666;
            }
            
            #saveButton {
                background-color: #1a1a1a;
                border: 1px solid #2a2a2a;
                border-radius: 0px;
                color: #cccccc;
                font-size: 12px;
                font-weight: 600;
                letter-spacing: 2px;
            }
            
            #saveButton:hover {
                background-color: #2a2a2a;
                border-color: #930000;
                color: #ffffff;
            }
            
            #saveButton:pressed {
                background-color: #0a0a0a;
            }
            
            #saveButton:disabled {
                background-color: #0a0a0a;
                border-color: #1a1a1a;
                color: #444444;
            }
            
            #moduleCheck {
                color: #cccccc;
                font-size: 12px;
                spacing: 10px;
            }
            
            #moduleCheck::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #2a2a2a;
                background-color: #000000;
            }
            
            #moduleCheck::indicator:checked {
                background-color: #930000;
                border: 1px solid #930000;
            }
            
            #moduleCheck::indicator:hover {
                border: 1px solid #930000;
            }
            
            #statusText {
                color: #666666;
                font-size: 12px;
                font-weight: 600;
            }
            
            #statusValue {
                color: #cccccc;
                font-size: 12px;
            }
            
            QProgressBar {
                background-color: #1a1a1a;
                border: none;
                border-radius: 2px;
            }
            
            QProgressBar::chunk {
                background-color: #930000;
                border-radius: 2px;
            }
            
            QTabWidget::pane {
                border: 1px solid #1a1a1a;
                background-color: #0a0a0a;
                border-radius: 0px;
            }
            
            QTabBar::tab {
                background-color: #000000;
                color: #666666;
                padding: 12px 24px;
                border: none;
                border-bottom: 2px solid transparent;
                font-size: 12px;
                font-weight: 500;
            }
            
            QTabBar::tab:selected {
                color: #930000;
                border-bottom: 2px solid #930000;
            }
            
            QTabBar::tab:hover:!selected {
                color: #999999;
            }
            
            #outputText {
                background-color: #000000;
                border: none;
                color: #cccccc;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 15px;
            }
            
            QScrollBar:vertical {
                background-color: #0a0a0a;
                width: 10px;
                border: none;
            }
            
            QScrollBar::handle:vertical {
                background-color: #2a2a2a;
                border-radius: 0px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #930000;
            }
            
            QScrollBar:horizontal {
                background-color: #0a0a0a;
                height: 10px;
                border: none;
            }
            
            QScrollBar::handle:horizontal {
                background-color: #2a2a2a;
                border-radius: 0px;
            }
            
            QScrollBar::handle:horizontal:hover {
                background-color: #930000;
            }
            
            QScrollBar::add-line, QScrollBar::sub-line {
                border: none;
                background: none;
            }
            
            QScrollArea {
                border: none;
                background-color: #000000;
            }
        """)
    
    def get_resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS
        except:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    
    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.append_log("[ERROR] Please enter a target URL or domain")
            return
        
        self.scan_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.progress.setValue(0)
        self.summary_text.clear()
        self.logs_text.clear()
        self.report_browser.clear()
        
        enabled_modules = {k: v.isChecked() for k, v in self.module_checks.items()}
        
        self.scan_thread = QThread()
        self.worker = ScanWorker(
            target=target,
            shodan_key=self.shodan_input.text().strip(),
            censys_id=self.censys_id_input.text().strip(),
            censys_secret=self.censys_secret_input.text().strip(),
            modules=enabled_modules
        )
        
        self.worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.worker.run)
        self.worker.log_signal.connect(self.append_log)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.status_signal.connect(self.update_status)
        self.worker.summary_signal.connect(self.update_summary)
        self.worker.report_signal.connect(self.update_report)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.finished_signal.connect(self.scan_thread.quit)
        self.worker.finished_signal.connect(self.worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        
        self.scan_thread.start()
    
    def append_log(self, message):
        self.logs_text.append(message)
    
    def update_progress(self, value):
        self.progress.setValue(value)
    
    def update_status(self, status):
        self.status_label.setText(status)
    
    def update_summary(self, summary):
        self.summary_text.setPlainText(summary)
    
    def update_report(self, html):
        self.report_html = html
        self.report_browser.setHtml(html)
    
    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        if self.report_html:
            self.save_btn.setEnabled(True)
        self.update_status("Scan complete")
        self.progress.setValue(100)
    
    def save_report(self):
        if not self.report_html:
            return
        
        target = self.target_input.text().strip().replace("http://", "").replace("https://", "").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"report_{target}_{timestamp}.html"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            default_name,
            "HTML Files (*.html)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.report_html)
                self.append_log(f"[SUCCESS] Report saved to {file_path}")
            except Exception as e:
                self.append_log(f"[ERROR] Failed to save report: {str(e)}")
