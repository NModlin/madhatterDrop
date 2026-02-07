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
                             QLabel, QPushButton, QDialog, QListWidgetItem)
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import QTimer, QCoreApplication

# ---------------------------------------------------------------------------
# Configuration — defaults, then override from ~/.config/madhatter/config
# ---------------------------------------------------------------------------
APP_NAME = "Madhatter Drop"
ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
SERVICE_NAME = "madhatter-sync.service"

# Defaults (same as sync_madhatter.sh)
SYNC_DIR = os.path.expanduser("~/madhatterDrop")
PEERS_FILE = os.path.expanduser("~/.config/madhatter/peers")
STATUS_FILE = os.path.expanduser("~/.cache/madhatter/status")
LOG_FILE = os.path.expanduser("~/.cache/madhatter/sync.log")

ENCRYPT_AT_REST = ""  # empty = disabled; "gpg" or "age"
MAX_VERSION_AGE_DAYS = 7

_CONFIG_FILE = os.path.expanduser("~/.config/madhatter/config")
if os.path.isfile(_CONFIG_FILE):
    with open(_CONFIG_FILE, 'r') as _cf:
        for _line in _cf:
            _line = _line.strip()
            if not _line or _line.startswith('#') or '=' not in _line:
                continue
            _key, _, _val = _line.partition('=')
            _key = _key.strip()
            _val = _val.strip().strip('"').strip("'")
            if _key == 'SYNC_DIR':
                SYNC_DIR = os.path.expanduser(_val)
            elif _key == 'PEERS_FILE':
                PEERS_FILE = os.path.expanduser(_val)
            elif _key == 'STATUS_FILE':
                STATUS_FILE = os.path.expanduser(_val)
            elif _key == 'LOG_FILE':
                LOG_FILE = os.path.expanduser(_val)
            elif _key == 'ENCRYPT_AT_REST':
                ENCRYPT_AT_REST = _val
            elif _key == 'MAX_VERSION_AGE_DAYS':
                try:
                    MAX_VERSION_AGE_DAYS = int(_val)
                except ValueError:
                    pass

# Derived paths
VERSION_DIR = os.path.join(SYNC_DIR, ".versions")
CONFLICT_DIR = os.path.join(SYNC_DIR, ".conflicts")
IGNORE_FILE = os.path.join(SYNC_DIR, ".syncignore")
ENCRYPT_KEY = os.path.expanduser("~/.config/madhatter/encrypt.key")


def decrypt_file(encrypted_path):
    """Decrypt a .gpg or .age file to a temp plaintext path. Returns plaintext path or None."""
    if not ENCRYPT_AT_REST:
        return encrypted_path  # not encrypted
    if not encrypted_path.endswith(('.gpg', '.age')):
        return encrypted_path  # not an encrypted file

    import tempfile
    fd, plaintext = tempfile.mkstemp(suffix=os.path.basename(encrypted_path).rsplit('.', 1)[0])
    os.close(fd)

    try:
        if encrypted_path.endswith('.gpg'):
            subprocess.check_call([
                'gpg', '--batch', '--yes', '--decrypt',
                '--passphrase-file', ENCRYPT_KEY,
                '--output', plaintext, encrypted_path
            ], stderr=subprocess.DEVNULL)
        elif encrypted_path.endswith('.age'):
            subprocess.check_call([
                'age', '-d', '-i', ENCRYPT_KEY,
                '-o', plaintext, encrypted_path
            ], stderr=subprocess.DEVNULL)
        return plaintext
    except (subprocess.CalledProcessError, FileNotFoundError):
        if os.path.exists(plaintext):
            os.remove(plaintext)
        return None

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

        self.prune_btn = QPushButton(f"Prune Old Versions (>{MAX_VERSION_AGE_DAYS} days)")
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
        # Strip encryption extension from restore target
        for ext in ('.gpg', '.age'):
            if original_rel.endswith(ext):
                original_rel = original_rel[:-len(ext)]
                break
        restore_target = os.path.join(SYNC_DIR, original_rel)

        # Decrypt if encrypted
        source_path = decrypt_file(src_path)
        if source_path is None:
            QMessageBox.critical(self, "Error", "Failed to decrypt version file.")
            return
        _decrypted_tmp = source_path if source_path != src_path else None

        # [S3] Compute source checksum before restore
        try:
            src_hash = self._sha256(source_path)
        except OSError as e:
            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            QMessageBox.critical(self, "Error", f"Cannot read source file:\n{str(e)}")
            return

        reply = QMessageBox.question(
            self, "Confirm Restore",
            f"Restore this version?\n\nFrom: {rel_path}\nTo: {restore_target}\n\nSHA-256: {src_hash[:16]}…",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            return

        try:
            os.makedirs(os.path.dirname(restore_target), exist_ok=True)
            shutil.copy2(source_path, restore_target)

            # [S3] Verify integrity after copy
            dst_hash = self._sha256(restore_target)
            if src_hash != dst_hash:
                os.remove(restore_target)
                if _decrypted_tmp:
                    os.remove(_decrypted_tmp)
                QMessageBox.critical(
                    self, "Integrity Error",
                    f"Checksum mismatch after restore!\n\n"
                    f"Source:  {src_hash[:16]}…\nWritten: {dst_hash[:16]}…\n\n"
                    "The corrupted file has been removed."
                )
                return

            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            QMessageBox.information(self, "Restored", f"File restored to:\n{restore_target}\n\n✓ Integrity verified")
        except Exception as e:
            if _decrypted_tmp and os.path.exists(_decrypted_tmp):
                os.remove(_decrypted_tmp)
            QMessageBox.critical(self, "Error", f"Failed to restore:\n{str(e)}")

    def prune_versions(self):
        """Delete version files older than MAX_VERSION_AGE_DAYS and refresh the list."""
        if not os.path.exists(VERSION_DIR):
            QMessageBox.information(self, "Prune", "No versions directory found.")
            return

        max_age_days = MAX_VERSION_AGE_DAYS
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
        # Strip encryption extension from target path
        for ext in ('.gpg', '.age'):
            if file_rel.endswith(ext):
                file_rel = file_rel[:-len(ext)]
                break
        target = os.path.join(SYNC_DIR, file_rel)
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

        # Decrypt if encrypted
        source_path = decrypt_file(conflict_path)
        if source_path is None:
            QMessageBox.critical(self, "Error", "Failed to decrypt conflict file.")
            return
        _decrypted_tmp = source_path if source_path != conflict_path else None

        try:
            src_hash = VersionBrowser._sha256(source_path)
        except OSError as e:
            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            QMessageBox.critical(self, "Error", f"Cannot read conflict file:\n{e}")
            return

        reply = QMessageBox.question(
            self, "Keep Remote",
            f"Overwrite local file with remote version?\n\n"
            f"Conflict: {rel}\nTarget: {target}\n\nSHA-256: {src_hash[:16]}…",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            return

        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(source_path, target)

            # Verify integrity
            dst_hash = VersionBrowser._sha256(target)
            if src_hash != dst_hash:
                os.remove(target)
                if _decrypted_tmp:
                    os.remove(_decrypted_tmp)
                QMessageBox.critical(
                    self, "Integrity Error",
                    f"Checksum mismatch!\nSource: {src_hash[:16]}…\n"
                    f"Written: {dst_hash[:16]}…\n\nCorrupted file removed.",
                )
                return

            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            os.remove(conflict_path)
            self._cleanup_empty_dirs(conflict_path)
            self.load_conflicts()
            QMessageBox.information(
                self, "Resolved",
                f"Replaced local with remote version.\n\n✓ Integrity verified",
            )
        except Exception as e:
            if _decrypted_tmp and os.path.exists(_decrypted_tmp):
                os.remove(_decrypted_tmp)
            QMessageBox.critical(self, "Error", f"Failed to resolve conflict:\n{e}")

    def keep_both(self):
        """Copy remote version alongside local with a .remote suffix."""
        sel = self._selected_conflict()
        if not sel:
            return
        conflict_path, target, rel = sel

        # Decrypt if encrypted
        source_path = decrypt_file(conflict_path)
        if source_path is None:
            QMessageBox.critical(self, "Error", "Failed to decrypt conflict file.")
            return
        _decrypted_tmp = source_path if source_path != conflict_path else None

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
            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            return

        try:
            os.makedirs(os.path.dirname(both_target), exist_ok=True)
            shutil.copy2(source_path, both_target)
            if _decrypted_tmp:
                os.remove(_decrypted_tmp)
            os.remove(conflict_path)
            self._cleanup_empty_dirs(conflict_path)
            self.load_conflicts()
            QMessageBox.information(
                self, "Resolved",
                f"Both versions kept.\nRemote saved as:\n{both_target}",
            )
        except Exception as e:
            if _decrypted_tmp and os.path.exists(_decrypted_tmp):
                os.remove(_decrypted_tmp)
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



try:
    from madhatter_discovery import DiscoveryManager
except ImportError:
    DiscoveryManager = None

class PeerManager(QDialog):
    """Dialog to add, remove, and test peers from the tray app."""

    # Same regex as sync_madhatter.sh PEER_REGEX
    PEER_REGEX = re.compile(r'^[a-zA-Z0-9._-]+(@[a-zA-Z0-9._-]+)?:[a-zA-Z0-9/._ -]+$')

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Madhatter Peer Manager")
        self.resize(600, 450)

        self.discovery = DiscoveryManager() if DiscoveryManager else None

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Configured Peers:"))

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        # Discovery Area
        if self.discovery and self.discovery.is_available():
            disc_group = QVBoxLayout()
            self.scan_btn = QPushButton("Scan for Local Peers (Avahi/mDNS)")
            self.scan_btn.clicked.connect(self.scan_network)
            disc_group.addWidget(self.scan_btn)
            
            self.disc_list = QListWidget()
            self.disc_list.setMaximumHeight(100)
            self.disc_list.itemDoubleClicked.connect(self.add_discovered_peer)
            disc_group.addWidget(self.disc_list)
            
            layout.addLayout(disc_group)
        else:
            layout.addWidget(QLabel("<i>Avahi automated discovery not available. Install 'avahi-utils' to enable.</i>"))

        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("Add Manually")
        self.add_btn.clicked.connect(self.add_peer)
        btn_row.addWidget(self.add_btn)

        self.remove_btn = QPushButton("Remove Peer")
        self.remove_btn.clicked.connect(self.remove_peer)
        btn_row.addWidget(self.remove_btn)

        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self.test_peer)
        btn_row.addWidget(self.test_btn)

        layout.addLayout(btn_row)
        self.setLayout(layout)
        self.load_peers()

    def load_peers(self):
        """Load peers from the peers file."""
        self.list_widget.clear()
        if not os.path.isfile(PEERS_FILE):
            return
        try:
            with open(PEERS_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    self.list_widget.addItem(line)
        except OSError:
            pass

    def _save_peers(self):
        """Write the current list back to the peers file atomically."""
        import tempfile
        peers = []
        for i in range(self.list_widget.count()):
            peers.append(self.list_widget.item(i).text())
        try:
            os.makedirs(os.path.dirname(PEERS_FILE), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(PEERS_FILE))
            with os.fdopen(fd, 'w') as f:
                for p in peers:
                    f.write(p + '\n')
            os.replace(tmp, PEERS_FILE)
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Failed to save peers:\n{e}")

    def scan_network(self):
        """Scan for peers using Avahi."""
        if not self.discovery:
            return
            
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        self.disc_list.clear()
        QApplication.processEvents() # Force UI update
        
        peers = self.discovery.browse_peers()
        
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan for Local Peers (Avahi/mDNS)")
        
        if not peers:
            self.disc_list.addItem("No peers found.")
            return

        for p in peers:
            # Display: "Hostname (IP) - User: X"
            label = f"{p['hostname']} ({p['ip']}) - User: {p.get('user', '?')}"
            item = QListWidget.item(self.disc_list)
            # Store raw data for retrieval
            # QListWidgetItem doesn't hold arbitrary data easily without subclassing or setData(UserRole)
            # We'll construct the connection string and store it in UserRole (256)
            
            # Construct suggested peer string: user@ip:/home/user/madhatterDrop
            # We guess the path based on standard layout, user can edit.
            user = p.get('user', 'user')
            ip = p['ip']
            # Default path assumption
            path = f"/home/{user}/madhatterDrop"
            peer_str = f"{user}@{ip}:{path}"
            
            list_item = QListWidgetItem(label)
            list_item.setData(256, peer_str)
            self.disc_list.addItem(list_item)
            
        QMessageBox.information(self, "Scan Complete", f"Found {len(peers)} peer(s). Double-click to add.")

    def add_discovered_peer(self, item):
        """Handle double-click on discovered peer."""
        peer_str = item.data(256)
        if not peer_str:
            return
            
        # Prompt user to confirm/edit
        from PyQt6.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(
            self, "Add Peer",
            "Confirm peer details (user@host:/path):",
            text=peer_str
        )
        
        if ok and text.strip():
            self._add_peer_str(text.strip())
            
            # Offer to pair (ssh-copy-id)
            reply = QMessageBox.question(
                self, "Pair Device?",
                f"Do you want to copy your SSH key to {text.strip()} now?\n(Requires password)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._run_ssh_copy_id(text.strip())

    def _add_peer_str(self, peer):
        if not self.PEER_REGEX.match(peer):
            QMessageBox.warning(self, "Invalid Peer", "Invalid format.")
            return
        # Check duplicates
        for i in range(self.list_widget.count()):
            if self.list_widget.item(i).text() == peer:
                return
        self.list_widget.addItem(peer)
        self._save_peers()

    def add_peer(self):
        """Prompt for a new peer and validate format."""
        from PyQt6.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(
            self, "Add Peer",
            "Enter peer (user@host:/path or host:/path):"
        )
        if not ok or not text.strip():
            return
        self._add_peer_str(text.strip())

    def remove_peer(self):
        """Remove the selected peer."""
        item = self.list_widget.currentItem()
        if not item:
            QMessageBox.information(self, "No Selection", "Select a peer first.")
            return
        reply = QMessageBox.question(
            self, "Remove Peer",
            f"Remove peer?\n\n{item.text()}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.list_widget.takeItem(self.list_widget.row(item))
            self._save_peers()

    def test_peer(self):
        """Test SSH reachability of the selected peer."""
        item = self.list_widget.currentItem()
        if not item:
            QMessageBox.information(self, "No Selection", "Select a peer first.")
            return
        peer = item.text()
        host = peer.split(':')[0]
        try:
            # -o BatchMode=yes prevents password prompt hanging
            result = subprocess.run(
                ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', host, 'exit'],
                capture_output=True, timeout=10
            )
            if result.returncode == 0:
                QMessageBox.information(self, "Peer Reachable", f"✓ {host} is reachable via SSH.")
            else:
                stderr = result.stderr.decode(errors='replace').strip()
                QMessageBox.warning(
                    self, "Peer Unreachable",
                    f"✗ {host} is not reachable.\n\n{stderr}\n\nHint: Did you copy your SSH key?"
                )
        except subprocess.TimeoutExpired:
            QMessageBox.warning(self, "Timeout", f"SSH connection to {host} timed out (5s).")
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", "ssh command not found.")

    def _run_ssh_copy_id(self, peer):
        """Run ssh-copy-id in a terminal."""
        host = peer.split(':')[0]
        # We need to run this in a terminal so user can type password.
        # Try common terminals: gnome-terminal, konsole, xterm
        cmd = f"ssh-copy-id {host}; echo 'Press Enter to close...'; read"
        
        terminals = [
            ['gnome-terminal', '--', 'bash', '-c', cmd],
            ['konsole', '-e', 'bash', '-c', cmd],
            ['xterm', '-e', 'bash', '-c', cmd],
            ['uxterm', '-e', 'bash', '-c', cmd]
        ]
        
        launched = False
        for t in terminals:
            if shutil.which(t[0]):
                subprocess.Popen(t)
                launched = True
                break
        
        if not launched:
            QMessageBox.warning(self, "Terminal Not Found", 
                f"Could not launch a terminal to run ssh-copy-id.\nPlease run this manually:\n\nssh-copy-id {host}")


class MadhatterTray(QSystemTrayIcon):
    def __init__(self, app, icon_path=None):
        super().__init__()
        self.app = app
        self.default_icon_path = icon_path or os.path.join(ICON_DIR, "idle.png")
        
        self.setIcon(QIcon(self.default_icon_path))
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

        self.peers_action = QAction("Manage Peers", self)
        self.peers_action.triggered.connect(self.manage_peers)
        self.menu.addAction(self.peers_action)

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
            self.setIcon(QIcon(self.default_icon_path))
            self.setToolTip("Madhatter: Idle")

    def open_folder(self):
        subprocess.Popen(['xdg-open', SYNC_DIR])

    def manual_sync(self):
        # Trigger sync by touching a file inside the directory?
        # Or using systemctl to restart service?
        # Or signals?
        # The script uses inotify, so touching a file works.
        trigger_file = os.path.join(SYNC_DIR, ".sync_trigger")
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

    def manage_peers(self):
        self.peer_manager = PeerManager()
        self.peer_manager.show()

    def edit_ignore(self):
        # Ensure the file exists before opening it
        if not os.path.exists(IGNORE_FILE):
            open(IGNORE_FILE, 'a').close()
        subprocess.Popen(['xdg-open', IGNORE_FILE])

    def _notify(self, title, msg):
        """Send a desktop notification via notify-send (Wayland-compatible)."""
        cmd = ['notify-send', title, msg]
        if self.default_icon_path:
            cmd.extend(['-i', self.default_icon_path])
        subprocess.Popen(cmd)

    def quit_app(self):
        QCoreApplication.quit()

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(None, "Error", "System tray not available on this system!")
        sys.exit(1)

    # Set Application Icon
    # Check common locations
    app_icon_path = None
    possible_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon", "icon.png"), # Local run (png)
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon", "icon.jpg"), # Local run (jpg)
        "/usr/share/pixmaps/madhatter-drop.png", # Installed (png)
        "/usr/share/pixmaps/madhatter-drop.jpg", # Installed (jpg)
    ]
    for p in possible_paths:
        if os.path.exists(p):
            app_icon_path = p
            break
            
    if app_icon_path:
        app.setWindowIcon(QIcon(app_icon_path))

    # Initialize discovery and start advertising
    discovery = None
    if DiscoveryManager:
        try:
            discovery = DiscoveryManager()
            if discovery.is_available():
                discovery.start_advertising()
        except Exception as e:
            print(f"Discovery init failed: {e}")

    tray = MadhatterTray(app, icon_path=app_icon_path)
    
    # Ensure advertisement stops on exit
    def cleanup_discovery():
        if discovery:
            discovery.stop_advertising()
            
    app.aboutToQuit.connect(cleanup_discovery)
    
    # Handle Ctrl+C
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
