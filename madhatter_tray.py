#!/usr/bin/env python3

import sys
import os
import signal
import subprocess
from PyQt6.QtWidgets import (QApplication, QSystemTrayIcon, QMenu, QMessageBox, 
                             QWidget, QVBoxLayout, QListWidget, QLabel, QPushButton, QDialog)
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import QTimer, QCoreApplication

# Constants
APP_NAME = "Madhatter Drop"
ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
STATUS_FILE = os.path.expanduser("~/.cache/madhatter/status")
LOG_FILE = os.path.expanduser("~/.cache/madhatter/sync.log")
VERSION_DIR = os.path.expanduser("~/madhatterDrop/.versions")
SERVICE_NAME = "madhatter-sync.service"
IGNORE_FILE = os.path.expanduser("~/madhatterDrop/.syncignore")

class VersionBrowser(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Madhatter Version Browser")
        self.resize(600, 400)
        
        layout = QVBoxLayout()
        self.label = QLabel("Archived Versions (.versions):")
        layout.addWidget(self.label)
        
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)
        
        self.restore_btn = QPushButton("Restore Selected")
        self.restore_btn.clicked.connect(self.restore_file)
        layout.addWidget(self.restore_btn)
        
        self.setLayout(layout)
        self.load_versions()

    def load_versions(self):
        self.list_widget.clear()
        if os.path.exists(VERSION_DIR):
            for root, dirs, files in os.walk(VERSION_DIR):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, VERSION_DIR)
                    self.list_widget.addItem(rel_path)

    def restore_file(self):
        item = self.list_widget.currentItem()
        if not item:
            return
            
        rel_path = item.text()
        src_path = os.path.join(VERSION_DIR, rel_path)
        # Assuming original structure is mirrored or flat backup
        # Here we just restore to root of sync dir for simplicity or try to infer real path
        # The script does --backup-dir=.versions so structure is preserved relative to sync root?
        # rsync behavior with --backup-dir preserves hierarchy if relative paths used.
        # Let's assume we restore to ~/madhatterDrop/restored_... for safety
        
        restore_target = os.path.expanduser(f"~/madhatterDrop/{os.path.basename(rel_path)}.restored")
        
        try:
            import shutil
            shutil.copy2(src_path, restore_target)
            QMessageBox.information(self, "Restored", f"File restored to:\n{restore_target}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restore:\n{str(e)}")

class LogViewer(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Madhatter Sync Logs")
        self.resize(800, 500)
        
        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_logs)
        layout.addWidget(self.refresh_btn)
        
        self.setLayout(layout)
        self.load_logs()

    def load_logs(self):
        self.list_widget.clear()
        if os.path.exists(LOG_FILE):
            try:
                # Read last 50 lines
                output = subprocess.check_output(['tail', '-n', '50', LOG_FILE]).decode('utf-8')
                for line in output.splitlines():
                    self.list_widget.addItem(line)
            except Exception as e:
                self.list_widget.addItem(f"Error reading log: {e}")

class MadhatterTray(QSystemTrayIcon):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setIcon(QIcon(os.path.join(ICON_DIR, "idle.png")))
        self.setVisible(True)
        
        # Menu
        self.menu = QMenu()
        
        self.status_action = QAction("Status: Checking...", self)
        self.status_action.setEnabled(False)
        self.menu.addAction(self.status_action)
        self.menu.addSeparator()
        
        self.open_action = QAction("Open Folder", self)
        self.open_action.triggered.connect(self.open_folder)
        self.menu.addAction(self.open_action)
        
        self.sync_action = QAction("Manual Sync", self)
        self.sync_action.triggered.connect(self.manual_sync)
        self.menu.addAction(self.sync_action)
        
        self.logs_action = QAction("View Logs", self)
        self.logs_action.triggered.connect(self.view_logs)
        self.menu.addAction(self.logs_action)
        
        self.versions_action = QAction("Version Browser", self)
        self.versions_action.triggered.connect(self.view_versions)
        self.menu.addAction(self.versions_action)

        self.edit_ignore_action = QAction("Edit .syncignore", self)
        self.edit_ignore_action.triggered.connect(self.edit_ignore)
        self.menu.addAction(self.edit_ignore_action)
        
        self.menu.addSeparator()
        self.quit_action = QAction("Quit Tray", self)
        self.quit_action.triggered.connect(self.quit_app)
        self.menu.addAction(self.quit_action)
        
        self.setContextMenu(self.menu)
        
        # Timer for status check
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_status)
        self.timer.start(1000)
        
        self.current_status = "UNKNOWN"
        self.check_status()

    def check_status(self):
        status = "UNKNOWN"
        if os.path.exists(STATUS_FILE):
            try:
                with open(STATUS_FILE, 'r') as f:
                    status = f.read().strip()
            except:
                pass
        
        if status != self.current_status:
            self.current_status = status
            self.update_icon(status)

    def update_icon(self, status):
        self.status_action.setText(f"Status: {status}")
        if status == "SYNCING":
            self.setIcon(QIcon(os.path.join(ICON_DIR, "syncing.png")))
            self.setToolTip("Madhatter: Syncing...")
        elif status == "ERROR":
            self.setIcon(QIcon(os.path.join(ICON_DIR, "error.png")))
            self.setToolTip("Madhatter: Error")
        else:
            self.setIcon(QIcon(os.path.join(ICON_DIR, "idle.png")))
            self.setToolTip("Madhatter: Idle")

    def open_folder(self):
        folder = os.path.expanduser("~/madhatterDrop")
        subprocess.Popen(['xdg-open', folder])

    def manual_sync(self):
        # Trigger sync by touching a file inside the directory? 
        # Or using systemctl to restart service?
        # Or signals?
        # The script uses inotify, so touching a file works.
        folder = os.path.expanduser("~/madhatterDrop")
        trigger_file = os.path.join(folder, ".sync_trigger")
        subprocess.run(['touch', trigger_file])
        self.showMessage("Sync Triggered", "Manual sync requested.", QSystemTrayIcon.MessageIcon.Information)

    def view_logs(self):
        self.log_viewer = LogViewer()
        self.log_viewer.show()

    def view_versions(self):
        self.version_browser = VersionBrowser()
        self.version_browser.show()

    def edit_ignore(self):
        editor = os.environ.get("EDITOR", "nano")
        # Need to open in a terminal if it's a terminal editor
        # Sway specific: try with 'foot' or 'alacritty' or 'kitty' if detected, 
        # or just xdg-open which might open a GUI editor.
        if os.path.exists(IGNORE_FILE):
             subprocess.Popen(['xdg-open', IGNORE_FILE])
        else:
             subprocess.Popen(['touch', IGNORE_FILE])
             subprocess.Popen(['xdg-open', IGNORE_FILE])

    def showMessage(self, title, msg, icon):
        # Use notify-send for better Wayland compatibility if needed, 
        # but QSystemTrayIcon.showMessage might work with XWayland or native.
        # However, user requested "gdbus or notify-send" for notifications.
        subprocess.Popen(['notify-send', title, msg])

    def quit_app(self):
        QCoreApplication.quit()

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    
    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(None, "Error", "System tray not available on this system!")
        sys.exit(1)
        
    tray = MadhatterTray(app)
    
    # Handle Ctrl+C
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
