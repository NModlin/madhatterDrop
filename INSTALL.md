# Installation Instructions

## Prerequisites

Madhatter Drop requires the following dependencies:
- **rsync**: File synchronization tool.
- **inotify-tools**: Filesystem monitoring (`inotifywait`).
- **Python 3 with PyQt6**: For the system tray application.
- **libnotify**: For desktop notifications (`notify-send`).
- **OpenSSH**: For secure file transfer.

## Distribution-Specific Installation

### Arch Linux / Manjaro

Install dependencies:
```bash
sudo pacman -S rsync inotify-tools python-pyqt6 libnotify openssh git
```

You can install `madhatter-drop` directly from the AUR if it's available, walk through the manual steps below, or use the provided `PKGBUILD`:

```bash
git clone https://github.com/NModlin/madhatterDrop.git
cd madhatterDrop
makepkg -si
```

### Debian / Ubuntu / Mint

Install dependencies:
```bash
sudo apt update
sudo apt install rsync inotify-tools python3-pyqt6 libnotify-bin openssh-client git
```

Proceed with the **Manual Installation** steps below.

### Fedora

Install dependencies:
```bash
sudo dnf install rsync inotify-tools python3-pyqt6 libnotify openssh-clients git
```

Proceed with the **Manual Installation** steps below.

## Manual Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/NModlin/madhatterDrop.git
    cd madhatterDrop
    ```

2.  **Install the sync daemon:**
    ```bash
    sudo install -m 755 sync_madhatter.sh /usr/bin/madhatter-sync
    ```

3.  **Install the tray application:**
    ```bash
    # Create directory and install resources
    sudo mkdir -p /usr/share/madhatter/icons
    sudo install -m 644 madhatter_tray.py /usr/share/madhatter/
    sudo install -m 644 icons/*.png /usr/share/madhatter/icons/

    # Create executable wrapper
    printf '#!/bin/sh\nexec python3 /usr/share/madhatter/madhatter_tray.py "$@"\n' | sudo tee /usr/bin/madhatter-tray > /dev/null
    sudo chmod 755 /usr/bin/madhatter-tray
    ```

4.  **Install system integration files:**
    ```bash
    # Systemd user service
    sudo install -m 644 madhatter-sync.service /usr/lib/systemd/user/

    # Desktop entry (for application menu and autostart)
    sudo install -m 644 madhatter-tray.desktop /usr/share/applications/
    ```

## Post-Installation Setup

1.  **Enable and start the sync service:**
    ```bash
    systemctl --user enable --now madhatter-sync.service
    ```

2.  **Start the tray application:**
    You can launch **Madhatter Drop** from your application menu or run:
    ```bash
    madhatter-tray &
    ```
    To have it start automatically on login, ensure `madhatter-tray.desktop` is in your autostart configuration (most desktop environments handle this automatically via `/usr/share/applications/`).

3.  **Configure Peers:**
    See [Configuration](README.md#configuration) in the main README for setting up your peers.
