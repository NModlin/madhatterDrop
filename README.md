# Madhatter Drop

**P2P Delta Sync Tool with Wayland Tray Support**

A lightweight, rsync-based file synchronization daemon for Linux desktops. Watches a local directory for changes, syncs bidirectionally with configured peers over SSH, and provides a PyQt6 system tray app for status monitoring and conflict resolution.

## Features

- **Two-way sync** — pull remote changes then push local changes, with configurable `--push-only` / `--pull-only` modes
- **Conflict detection & resolution UI** — automatically detects conflicting files on both push and pull; resolve via system tray dialog (keep local, keep remote, or keep both)
- **Version backup** — every overwritten file is saved to `.versions/` with a timestamp suffix; old versions pruned after 7 days
- **Parallel peer sync** — syncs to/from all peers concurrently
- **Systemd integration** — `Type=notify` with `WatchdogSec=120` heartbeat; auto-restart on failure
- **Security hardening** — peer validation regex blocks shell injection, `umask 077` for all created files, SHA-256 integrity checks on conflict resolution
- **Encryption at rest** — optional GPG (AES-256) or age encryption for `.versions/` and `.conflicts/` files
- **Externalized configuration** — all paths and thresholds configurable via `~/.config/madhatter/config`
- **Peer management UI** — add, remove, and test peers from the system tray (SSH reachability check)
- **Log rotation** — sync log rotated at 10 MB, keeps 3 rotated copies
- **`.syncignore`** — rsync exclude file for patterns you don't want synced
- **Atomic status writes** — tray app reads status safely via temp-file + `mv`
- **Graceful shutdown** — `SIGTERM`/`SIGINT` handlers drain in-flight syncs before exit

## Requirements

| Package | Purpose |
|:---|:---|
| `rsync` | File synchronization |
| `inotify-tools` | Filesystem change detection (`inotifywait`) |
| `python-pyqt6` | System tray GUI |
| `libnotify` | Desktop notifications (`notify-send`) |
| `openssh` | SSH transport for rsync |

## Installation

Please refer to [INSTALL.md](INSTALL.md) for detailed installation instructions for Arch Linux, Debian/Ubuntu, Fedora, and manual installation from source.

### Quick Start (Arch Linux)

```bash
makepkg -si
```

## Configuration

### Peers

Add one peer per line to `~/.config/madhatter/peers`:

```
user@hostname:/home/user/madhatterDrop
192.168.1.50:/home/alice/madhatterDrop
```

Lines starting with `#` are comments. Peers must match the format `[user@]host:/path` — shell metacharacters are rejected.

### Config file (optional)

Create `~/.config/madhatter/config` to override defaults:

```
SYNC_DIR=~/madhatterDrop
PEERS_FILE=~/.config/madhatter/peers
MAX_LOG_BYTES=10485760
MAX_LOG_FILES=3
MAX_VERSION_AGE_DAYS=7
ENCRYPT_AT_REST=gpg
```

### Encryption at rest (optional)

Set `ENCRYPT_AT_REST=gpg` (or `age`) in the config file and create a passphrase/key file:

```bash
mkdir -p ~/.config/madhatter
echo "your-passphrase" > ~/.config/madhatter/encrypt.key
chmod 600 ~/.config/madhatter/encrypt.key
```

When enabled, all files saved to `.versions/` and `.conflicts/` are encrypted in-place. The tray app decrypts transparently when restoring or resolving conflicts.

### Sync ignore

Create `~/madhatterDrop/.syncignore` with rsync exclude patterns:

```
*.tmp
*.swp
.DS_Store
node_modules/
```

## Usage

### Start the sync daemon

```bash
systemctl --user enable --now madhatter-sync.service
```

### Start the tray app

```bash
madhatter-tray
```

Or add `madhatter-tray.desktop` to your autostart directory.

### CLI flags

```
madhatter-sync --check-peers   # Test SSH reachability of all peers
madhatter-sync --push-only     # Only push local → peers (no pull)
madhatter-sync --pull-only     # Only pull peers → local (no push)
madhatter-sync --help          # Show help
```

## Directory structure

```
~/madhatterDrop/              # Synced directory (watched by inotifywait)
├── .syncignore               # Rsync exclude patterns
├── .versions/                # Backup of overwritten files (auto-pruned after 7 days)
├── .conflicts/               # Conflict snapshots
│   ├── <peer_label>/         # Remote versions saved before push overwrites them
│   └── <peer_label>_local/   # Local versions saved before pull overwrites them
└── (your files)

~/.config/madhatter/
├── peers                     # Peer list (one per line)
├── config                    # Optional config overrides (KEY=VALUE)
└── encrypt.key               # Encryption passphrase (if ENCRYPT_AT_REST is set)

~/.cache/madhatter/
├── status                    # Daemon status (IDLE / SYNCING / ERROR)
└── sync.log                  # Sync log (rotated at 10 MB)
```

## How sync works

1. **Pull phase** — `rsync -avz` from each peer to local (no `--delete`; safe — won't remove local-only files). Conflicting local files are saved to `.conflicts/<peer>_local/` before overwrite.
2. **Push phase** — `rsync -avz --delete` from local to each peer (local is authoritative). Conflicting remote files are saved to `.conflicts/<peer>/` before overwrite.
3. Both phases run peers in parallel and use `--backup --backup-dir=.versions/` to preserve every overwritten file.

## Development

### Running tests

```bash
cd tests
bash test_peer_validation.sh
```

The test suite includes 170+ tests: static analysis (grep-based validation of script structure), two-way sync tests, integration tests (actual rsync between temp directories), conflict resolution UI tests, encryption at rest tests, peer management UI tests, and AUR publishing validation.

### Project structure

| File | Lines | Purpose |
|:---|:---|:---|
| `sync_madhatter.sh` | ~655 | Sync daemon (bash) |
| `madhatter_tray.py` | ~770 | System tray app (PyQt6) |
| `tests/test_peer_validation.sh` | ~1690 | Test suite |
| `madhatter-sync.service` | 19 | Systemd user service |
| `madhatter-tray.desktop` | 11 | Desktop autostart entry |
| `PKGBUILD` | 44 | Arch Linux package build |
| `.SRCINFO` | — | AUR source info (auto-generated) |
| `LICENSE` | 21 | MIT license |

## License

MIT

