#!/bin/bash
set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SYNC_DIR="$HOME/madhatterDrop"
PEERS_FILE="$HOME/.config/madhatter/peers"
STATUS_FILE="$HOME/.cache/madhatter/status"
LOG_FILE="$HOME/.cache/madhatter/sync.log"
VERSION_DIR="$SYNC_DIR/.versions"
IGNORE_FILE="$SYNC_DIR/.syncignore"

# Peer format: [user@]hostname:/remote/path  OR  [user@]IP:/remote/path
# Rejects any entry containing shell metacharacters: ; $ ` | & ( ) { } < > \ ' "
PEER_REGEX='^[a-zA-Z0-9._-]+(@[a-zA-Z0-9._-]+)?:[a-zA-Z0-9/._ -]+$'
SHELL_META_CHARS='[;$`|&(){}<>\\\"'"'"']'

# ---------------------------------------------------------------------------
# Ensure directories exist
# ---------------------------------------------------------------------------
mkdir -p "$SYNC_DIR"
mkdir -p "$(dirname "$STATUS_FILE")"
mkdir -p "$(dirname "$PEERS_FILE")"
mkdir -p "$VERSION_DIR"
touch "$LOG_FILE"
touch "$IGNORE_FILE"

# Seed the peers file with a format comment if it doesn't exist
if [ ! -f "$PEERS_FILE" ]; then
    cat > "$PEERS_FILE" <<'EOF'
# Madhatter Drop — Peer List
# Format: [user@]hostname:/remote/path   (one per line)
# Examples:
#   alice@server.local:/home/alice/madhatterDrop
#   192.168.1.50:/home/bob/madhatterDrop
EOF
    chmod 600 "$PEERS_FILE"
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

update_status() {
    echo "$1" > "$STATUS_FILE"
}

# ---------------------------------------------------------------------------
# [S1] Peer validation
# ---------------------------------------------------------------------------
validate_peer() {
    local peer="$1"

    # Reject shell metacharacters outright
    if [[ "$peer" =~ $SHELL_META_CHARS ]]; then
        log "[WARN] Rejected peer (shell metacharacters): $peer"
        return 1
    fi

    # Enforce [user@]host:/path format
    if [[ ! "$peer" =~ $PEER_REGEX ]]; then
        log "[WARN] Rejected peer (invalid format): $peer"
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
for cmd in rsync inotifywait; do
    if ! command -v $cmd &> /dev/null; then
        log "Error: $cmd could not be found."
        update_status "ERROR"
        notify-send -u critical "Madhatter Sync Error" "Missing dependency: $cmd"
        exit 1
    fi
done

log "Madhatter Sync Engine Started."
update_status "IDLE"

# ---------------------------------------------------------------------------
# Sync function
# ---------------------------------------------------------------------------
sync_to_peers() {
    update_status "SYNCING"

    # Read peers from config file (one per line)
    if [ ! -f "$PEERS_FILE" ] || [ ! -s "$PEERS_FILE" ]; then
        log "No peers defined in $PEERS_FILE."
        update_status "IDLE"
        return
    fi

    while IFS= read -r peer; do
        # Skip empty lines and comments
        [[ -z "$peer" || "$peer" =~ ^[[:space:]]*# ]] && continue

        # [S1] Validate before use
        if ! validate_peer "$peer"; then
            continue
        fi

        log "Syncing to $peer..."

        rsync -avz --delete --delay-updates --exclude-from="$IGNORE_FILE" \
            --exclude=".versions" --exclude=".sync_trigger" --exclude=".syncignore" \
            --backup --backup-dir="$VERSION_DIR" --suffix="_$(date +%Y%m%d_%H%M%S)" \
            "$SYNC_DIR/" "$peer" >> "$LOG_FILE" 2>&1

        if [ $? -eq 0 ]; then
            log "Sync to $peer successful."
        else
            log "Error syncing to $peer (exit code $?)."
            update_status "ERROR"
            notify-send -u critical "Madhatter Sync Failed" \
                "Could not sync with $peer. Check logs."
            return 1
        fi
    done < "$PEERS_FILE"

    update_status "IDLE"
}

# ---------------------------------------------------------------------------
# Watch loop
# Triggers on: close_write, moved_to, create, delete, move
# ---------------------------------------------------------------------------
while true; do
    log "Watching $SYNC_DIR for changes..."

    # Block until a change happens
    inotifywait -r -e close_write,moved_to,create,delete,move \
        --exclude "$VERSION_DIR" --exclude "\.sync_trigger" --exclude "\.syncignore" \
        --exclude ".*\.swp" --exclude ".*\.tmp" \
        "$SYNC_DIR" >> "$LOG_FILE" 2>&1 || true

    # Wait a moment for settling (debounce)
    sleep 2

    sync_to_peers

    # Wait before loop restarts to avoid rapid-fire loops on mass changes
    sleep 1
done
