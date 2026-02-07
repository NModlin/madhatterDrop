#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Madhatter Drop - Smart Installer
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1"; }

# Default mode
MODE="auto"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --headless) MODE="headless" ;;
        --desktop)  MODE="desktop" ;;
        --help|-h)
            echo "Usage: sudo ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --headless   Force headless (server) installation"
            echo "  --desktop    Force desktop (tray app) installation"
            echo "  --help       Show this help"
            exit 0
            ;;
        *) 
            log_err "Unknown option: $1"
            exit 1 
            ;;
    esac
    shift
done

# Check for root
if [ "$EUID" -ne 0 ]; then
   log_err "Please run as root (sudo ./install.sh)"
   exit 1
fi

# Detect environment if auto
if [ "$MODE" = "auto" ]; then
    if command -v swaymsg &>/dev/null || [ -n "${SWAYSOCK:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
        MODE="desktop"
        log_info "Detected Desktop Environment (Wayland/Sway)."
    else
        MODE="headless"
        log_info "Detected Headless Environment (no Wayland/Sway found)."
    fi
fi

# Get the real user (who called sudo)
REAL_USER="${SUDO_USER:-$(whoami)}"

log_info "Installing for user: $REAL_USER ($MODE mode)"

# ---------------------------------------------------------------------------
# Install Dependencies (Basic Check)
# ---------------------------------------------------------------------------
log_info "Checking dependencies..."
MISSING=()

# Core deps
for cmd in rsync inotifywait ssh git; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING+=("$cmd")
    fi
done

# Desktop deps
if [ "$MODE" = "desktop" ]; then
    if ! command -v notify-send &>/dev/null; then
        MISSING+=("libnotify")
    fi
    if ! python3 -c "import PyQt6" &>/dev/null; then
        MISSING+=("python-pyqt6")
    fi
    if ! command -v avahi-browse &>/dev/null; then
        log_warn "avahi-utils not found. Automated discovery will be disabled."
        # We don't fail, just warn, as it's optional
    fi
fi

if [ ${#MISSING[@]} -gt 0 ]; then
    log_warn "Missing dependencies: ${MISSING[*]}"
    log_info "Attempting to install via pacman/apt/dnf..."
    
    if command -v pacman &>/dev/null; then
        # Arch
        PKGS=("rsync" "inotify-tools" "openssh" "git")
        [ "$MODE" = "desktop" ] && PKGS+=("python-pyqt6" "libnotify")
        pacman -S --needed "${PKGS[@]}"
    elif command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        PKGS=("rsync" "inotify-tools" "openssh-client" "git")
        [ "$MODE" = "desktop" ] && PKGS+=("python3-pyqt6" "libnotify-bin")
        apt-get update && apt-get install -y "${PKGS[@]}"
    elif command -v dnf &>/dev/null; then
        # Fedora
        PKGS=("rsync" "inotify-tools" "openssh-clients" "git")
        [ "$MODE" = "desktop" ] && PKGS+=("python3-pyqt6" "libnotify")
        dnf install -y "${PKGS[@]}"
    else
        log_err "Could not detect package manager. Please install missing dependencies manually."
        exit 1
    fi
else
    log_info "Dependencies look good."
fi

# ---------------------------------------------------------------------------
# Install Core Components (Headless & Desktop)
# ---------------------------------------------------------------------------
log_info "Installing sync daemon..."
install -m 755 sync_madhatter.sh /usr/bin/madhatter-sync

log_info "Installing systemd service..."
# Install globally so it's available for all users as a user service
install -m 644 madhatter-sync.service /usr/lib/systemd/user/

# ---------------------------------------------------------------------------
# Install Desktop Components
# ---------------------------------------------------------------------------
if [ "$MODE" = "desktop" ]; then
    log_info "Installing desktop tray app..."
    install -d /usr/share/madhatter/icons
    install -m 644 madhatter_tray.py /usr/share/madhatter/
    install -m 755 madhatter_discovery.py /usr/share/madhatter/
    install -m 644 icons/*.png /usr/share/madhatter/icons/

    # Install main app icon
    # Install main app icon
    if [ -f "icon/icon.png" ]; then
        log_info "Installing app icon (PNG)..."
        install -m 644 icon/icon.png /usr/share/pixmaps/madhatter-drop.png
    elif [ -f "icon/icon.jpg" ]; then
        log_info "Installing app icon (JPG)..."
        install -m 644 icon/icon.jpg /usr/share/pixmaps/madhatter-drop.jpg
    fi

    # Tray wrapper
    cat <<EOF > /usr/bin/madhatter-tray
#!/bin/sh
exec python3 /usr/share/madhatter/madhatter_tray.py "\$@"
EOF
    chmod 755 /usr/bin/madhatter-tray

    # Desktop entry
    install -m 644 madhatter-tray.desktop /usr/share/applications/
fi

# ---------------------------------------------------------------------------
# Configuration & Post-Install
# ---------------------------------------------------------------------------

# Use runuser to reload the USER'S systemd instance, not root's
if command -v systemctl &>/dev/null; then
    runuser -u "$REAL_USER" -- systemctl --user daemon-reload 2>/dev/null || true
fi

if [ "$MODE" = "headless" ]; then
    log_info "Enabling linger for user $REAL_USER (required for headless operation)..."
    loginctl enable-linger "$REAL_USER" || log_warn "Failed to enable linger. Please run: sudo loginctl enable-linger $REAL_USER"
fi

echo ""
log_info "Installation Complete!"
echo ""
echo "Next Steps:"
echo "1. Run peer check:   madhatter-sync --check-peers"
echo "2. Start service:    systemctl --user enable --now madhatter-sync.service"

if [ "$MODE" = "desktop" ]; then
    echo "3. Start tray app:   madhatter-tray (or check your app menu)"
fi
echo ""
