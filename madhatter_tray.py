#!/usr/bin/env python3

import sys
import os
import re
import shutil
import signal
import hashlib
import subprocess
from PyQt6.QtWidgets import (QApplication, QSystemTrayIcon, QMenu, QMessageBox,
                             QWidget, QVBoxLayout, QHBoxLayout, QListWidget,
                             QLabel, QPushButton, QDialog)
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import QTimer, QCoreApplication

# Constants
APP_NAME = "Madhatter Drop"
ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
STATUS_FILE = os.path.expanduser("~/.cache/madhatter/status")
LOG_FILE = os.path.expanduser("~/.cache/madhatter/sync.log")
VERSION_DIR = os.path.expanduser("~/madhatterDrop/.versions")
CONFLICT_DIR = os.path.expanduser("~/madhatterDrop/.conflicts")
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

        self.prune_btn = QPushButton("Prune Old Versions (>7 days)")
        self.prune_btn.clicked.connect(self.prune_versions)
        layout.addWidget(self.prune_btn)

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

    @staticmethod
    def _sha256(path):
        """[S3] Compute SHA-256 checksum of a file."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    def restore_file(self):
        item = self.list_widget.currentItem()
        if not item:
            return

        rel_path = item.text()
        src_path = os.path.join(VERSION_DIR, rel_path)

        # rsync --backup with --suffix appends a timestamp like _20260203_190748
        # Strip that suffix to recover the original relative path within the sync dir.
        original_rel = re.sub(r'_\d{8}_\d{6}$', '', rel_path)
        sync_dir = os.path.expanduser("~/madhatterDrop")
        restore_target = os.path.join(sync_dir, original_rel)

        # [S3] Compute source checksum before restore
        try:
            src_hash = self._sha256(src_path)
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Cannot read source file:\n{str(e)}")
            return

        reply = QMessageBox.question(
            self, "Confirm Restore",
            f"Restore this version?\n\nFrom: {rel_path}\nTo: {restore_target}\n\nSHA-256: {src_hash[:16]}…",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            os.makedirs(os.path.dirname(restore_target), exist_ok=True)
            shutil.copy2(src_path, restore_target)

            # [S3] Verify integrity after copy
            dst_hash = self._sha256(restore_target)
            if src_hash != dst_hash:
                os.remove(restore_target)
                QMessageBox.critical(
                    self, "Integrity Error",
                    f"Checksum mismatch after restore!\n\n"
                    f"Source:  {src_hash[:16]}…\nWritten: {dst_hash[:16]}…\n\n"
                    "The corrupted file has been removed."
                )
                return

            QMessageBox.information(self, "Restored", f"File restored to:\n{restore_target}\n\n✓ Integrity verified")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to restore:\n{str(e)}")

    def prune_versions(self):
        """Delete version files older than 7 days and refresh the list."""
        if not os.path.exists(VERSION_DIR):
            QMessageBox.information(self, "Prune", "No versions directory found.")
            return

        max_age_days = 7
        import time
        cutoff = time.time() - (max_age_days * 86400)
        pruned = 0

        for root, dirs, files in os.walk(VERSION_DIR):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getmtime(fpath) < cutoff:
                        os.remove(fpath)
                        pruned += 1
                except OSError:
                    pass

        # Clean up empty directories
        for root, dirs, files in os.walk(VERSION_DIR, topdown=False):
            for d in dirs:
                dpath = os.path.join(root, d)
                try:
                    os.rmdir(dpath)
                except OSError:
                    pass

        self.load_versions()
        QMessageBox.information(
            self, "Prune Complete",
            f"Deleted {pruned} version file(s) older than {max_age_days} days."
        )

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

class ConflictBrowser(QDialog):
    """Browse and resolve file conflicts saved by the sync daemon."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Madhatter Conflict Browser")
        self.resize(700, 500)

        layout = QVBoxLayout()
        self.label = QLabel("Conflicts detected in .conflicts/ — select one to resolve:")
        layout.addWidget(self.label)

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        # Button row
        btn_layout = QHBoxLayout()

        self.keep_local_btn = QPushButton("Keep Local")
        self.keep_local_btn.clicked.connect(self.keep_local)
        btn_layout.addWidget(self.keep_local_btn)

        self.keep_remote_btn = QPushButton("Keep Remote")
        self.keep_remote_btn.clicked.connect(self.keep_remote)
        btn_layout.addWidget(self.keep_remote_btn)

        self.keep_both_btn = QPushButton("Keep Both")
        self.keep_both_btn.clicked.connect(self.keep_both)
        btn_layout.addWidget(self.keep_both_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_conflicts)
        btn_layout.addWidget(self.refresh_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.load_conflicts()

    def load_conflicts(self):
        """Walk CONFLICT_DIR and populate the list widget."""
        self.list_widget.clear()
        if not os.path.exists(CONFLICT_DIR):
            self.label.setText("No conflicts directory found.")
            return

        count = 0
        for root, _dirs, files in os.walk(CONFLICT_DIR):
            for fname in files:
                full_path = os.path.join(root, fname)
                # Relative path inside .conflicts/ e.g. "peer_label/some/file.txt"
                rel = os.path.relpath(full_path, CONFLICT_DIR)
                parts = rel.split(os.sep, 1)
                if len(parts) == 2:
                    peer_label, file_rel = parts
                    display = f"[{peer_label}] {file_rel}"
                else:
                    display = rel
                item = self.list_widget.addItem(display)
                # Store full path as data on the item
                self.list_widget.item(self.list_widget.count() - 1).setData(
                    256, full_path  # Qt.ItemDataRole.UserRole == 256
                )
                count += 1

        self.label.setText(
            f"{count} conflict(s) found:" if count else "No conflicts — all clear!"
        )

    def _selected_conflict(self):
        """Return (full_conflict_path, sync_target_path, rel_in_conflicts) or None."""
        item = self.list_widget.currentItem()
        if not item:
            QMessageBox.information(self, "No Selection", "Select a conflict first.")
            return None
        conflict_path = item.data(256)
        rel = os.path.relpath(conflict_path, CONFLICT_DIR)
        # Strip peer_label prefix to get the path relative to sync dir
        parts = rel.split(os.sep, 1)
        if len(parts) == 2:
            file_rel = parts[1]
        else:
            file_rel = rel
        sync_dir = os.path.expanduser("~/madhatterDrop")
        target = os.path.join(sync_dir, file_rel)
        return conflict_path, target, rel

    def keep_local(self):
        """Discard the remote version — just delete the conflict file."""
        sel = self._selected_conflict()
        if not sel:
            return
        conflict_path, _target, rel = sel

        reply = QMessageBox.question(
            self, "Keep Local",
            f"Discard remote version?\n\n{rel}\n\nThe conflict file will be deleted.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            os.remove(conflict_path)
            self._cleanup_empty_dirs(conflict_path)
            self.load_conflicts()
            QMessageBox.information(self, "Resolved", f"Kept local copy.\nRemoved: {rel}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove conflict:\n{e}")

    def keep_remote(self):
        """Replace local file with the remote (conflict) version."""
        sel = self._selected_conflict()
        if not sel:
            return
        conflict_path, target, rel = sel

        try:
            src_hash = VersionBrowser._sha256(conflict_path)
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Cannot read conflict file:\n{e}")
            return

        reply = QMessageBox.question(
            self, "Keep Remote",
            f"Overwrite local file with remote version?\n\n"
            f"Conflict: {rel}\nTarget: {target}\n\nSHA-256: {src_hash[:16]}…",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(conflict_path, target)

            # Verify integrity
            dst_hash = VersionBrowser._sha256(target)
            if src_hash != dst_hash:
                os.remove(target)
                QMessageBox.critical(
                    self, "Integrity Error",
                    f"Checksum mismatch!\nSource: {src_hash[:16]}…\n"
                    f"Written: {dst_hash[:16]}…\n\nCorrupted file removed.",
                )
                return

            os.remove(conflict_path)
            self._cleanup_empty_dirs(conflict_path)
            self.load_conflicts()
            QMessageBox.information(
                self, "Resolved",
                f"Replaced local with remote version.\n\n✓ Integrity verified",
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to resolve conflict:\n{e}")

    def keep_both(self):
        """Copy remote version alongside local with a .remote suffix."""
        sel = self._selected_conflict()
        if not sel:
            return
        conflict_path, target, rel = sel

        # Add .remote before extension (or at end if no extension)
        base, ext = os.path.splitext(target)
        both_target = f"{base}.remote{ext}"

        reply = QMessageBox.question(
            self, "Keep Both",
            f"Save remote version alongside local?\n\n"
            f"Remote copy → {os.path.basename(both_target)}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            os.makedirs(os.path.dirname(both_target), exist_ok=True)
            shutil.copy2(conflict_path, both_target)
            os.remove(conflict_path)
            self._cleanup_empty_dirs(conflict_path)
            self.load_conflicts()
            QMessageBox.information(
                self, "Resolved",
                f"Both versions kept.\nRemote saved as:\n{both_target}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to resolve conflict:\n{e}")

    @staticmethod
    def _cleanup_empty_dirs(removed_file):
        """Remove empty parent directories up to CONFLICT_DIR."""
        parent = os.path.dirname(removed_file)
        while parent != CONFLICT_DIR and parent.startswith(CONFLICT_DIR):
            try:
                os.rmdir(parent)  # only succeeds if empty
                parent = os.path.dirname(parent)
            except OSError:
                break


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

        self.conflicts_action = QAction("Resolve Conflicts", self)
        self.conflicts_action.triggered.connect(self.view_conflicts)
        self.menu.addAction(self.conflicts_action)

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
            except (OSError, IOError):
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
        elif status == "STOPPED":
            self.setIcon(QIcon(os.path.join(ICON_DIR, "error.png")))
            self.setToolTip("Madhatter: Service Stopped")
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
        self._notify("Sync Triggered", "Manual sync requested.")

    def view_logs(self):
        self.log_viewer = LogViewer()
        self.log_viewer.show()

    def view_versions(self):
        self.version_browser = VersionBrowser()
        self.version_browser.show()

    def view_conflicts(self):
        self.conflict_browser = ConflictBrowser()
        self.conflict_browser.show()

    def edit_ignore(self):
        # Ensure the file exists before opening it
        if not os.path.exists(IGNORE_FILE):
            open(IGNORE_FILE, 'a').close()
        subprocess.Popen(['xdg-open', IGNORE_FILE])

    def _notify(self, title, msg):
        """Send a desktop notification via notify-send (Wayland-compatible)."""
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
