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
CONFLICT_DIR="$SYNC_DIR/.conflicts"
IGNORE_FILE="$SYNC_DIR/.syncignore"

# [M2] Log rotation config
MAX_LOG_BYTES=$((10 * 1024 * 1024))   # 10 MB
MAX_LOG_FILES=3

# [M5] Version pruning config
MAX_VERSION_AGE_DAYS=7

# Peer format: [user@]hostname:/remote/path  OR  [user@]IP:/remote/path
# Rejects any entry containing shell metacharacters: ; $ ` | & ( ) { } < > \ ' "
PEER_REGEX='^[a-zA-Z0-9._-]+(@[a-zA-Z0-9._-]+)?:[a-zA-Z0-9/._ -]+$'
SHELL_META_CHARS='[;$`|&(){}<>\\\"'"'"']'

# [M4] Shutdown machinery
SHUTTING_DOWN=0
RSYNC_PID=""

# ---------------------------------------------------------------------------
# Ensure directories exist
# ---------------------------------------------------------------------------
mkdir -p "$SYNC_DIR"
mkdir -p "$(dirname "$STATUS_FILE")"
mkdir -p "$(dirname "$PEERS_FILE")"
mkdir -p "$VERSION_DIR"
mkdir -p "$CONFLICT_DIR"
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

# [M3] Atomic status write — write to temp then mv to avoid TOCTOU races
update_status() {
    local tmp="${STATUS_FILE}.tmp.$$"
    echo "$1" > "$tmp"
    mv -f "$tmp" "$STATUS_FILE"
}

# [O1] Systemd watchdog — notify systemd we're alive
sd_notify() {
    # Only works when launched by systemd with Type=notify (NOTIFY_SOCKET set)
    if command -v systemd-notify &>/dev/null && [ -n "${NOTIFY_SOCKET:-}" ]; then
        systemd-notify "$@" 2>/dev/null || true
    fi
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
# [M2] Log rotation — rotate when log exceeds MAX_LOG_BYTES
# ---------------------------------------------------------------------------
rotate_log() {
    if [ ! -f "$LOG_FILE" ]; then
        return
    fi
    local size
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$size" -lt "$MAX_LOG_BYTES" ]; then
        return
    fi
    # Shift rotated files: .3 deleted, .2→.3, .1→.2, current→.1
    local i=$MAX_LOG_FILES
    while [ "$i" -gt 1 ]; do
        local prev=$((i - 1))
        if [ -f "$LOG_FILE.$prev" ]; then
            mv "$LOG_FILE.$prev" "$LOG_FILE.$i"
        fi
        i=$prev
    done
    mv "$LOG_FILE" "$LOG_FILE.1"
    touch "$LOG_FILE"
    log "[ROTATE] Log rotated (was ${size} bytes)"
}

# ---------------------------------------------------------------------------
# [M5] Version pruning — delete versions older than MAX_VERSION_AGE_DAYS
# ---------------------------------------------------------------------------
prune_versions() {
    if [ ! -d "$VERSION_DIR" ]; then
        return
    fi
    local count
    count=$(find "$VERSION_DIR" -type f -mtime +"$MAX_VERSION_AGE_DAYS" -delete -print 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        log "[PRUNE] Deleted $count version file(s) older than $MAX_VERSION_AGE_DAYS days"
        # Clean up empty directories left behind
        find "$VERSION_DIR" -type d -empty -delete 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# [O4] Conflict detection — save remote versions that would be overwritten
# ---------------------------------------------------------------------------
detect_conflicts() {
    local peer="$1"
    local host="${peer%%:*}"
    local peer_label="${host//[^a-zA-Z0-9._-]/_}"

    # Dry-run rsync to find files that would be updated on the remote
    local dry_output
    dry_output=$(rsync -avzn --itemize-changes --exclude-from="$IGNORE_FILE" \
        --exclude=".versions" --exclude=".sync_trigger" --exclude=".syncignore" \
        --exclude=".conflicts" \
        "$SYNC_DIR/" "$peer" 2>/dev/null) || return 0

    # Parse itemize output for files being sent that already exist remotely
    # Format: >f..t...... path/to/file  (> = sent to remote, f = file, t = timestamp differs)
    # We only care about updates (>f), not new files (>f+)
    local conflict_count=0
    while IFS= read -r line; do
        # Match lines like ">f..t...... some/file" (update, not create >f+++)
        if [[ "$line" =~ ^\>f[^+] ]]; then
            # Extract the filename (everything after the itemize flags + space)
            local rel_file="${line#* }"
            # Trim leading/trailing whitespace
            rel_file="${rel_file#"${rel_file%%[![:space:]]*}"}"
            rel_file="${rel_file%"${rel_file##*[![:space:]]}"}"

            if [ -z "$rel_file" ]; then
                continue
            fi

            # Fetch the remote version to .conflicts/ before we overwrite it
            local conflict_dest="$CONFLICT_DIR/$peer_label/$rel_file"
            mkdir -p "$(dirname "$conflict_dest")"

            if rsync -az "$peer/$rel_file" "$conflict_dest" 2>/dev/null; then
                ((conflict_count++))
            fi
        fi
    done <<< "$dry_output"

    if [ "$conflict_count" -gt 0 ]; then
        log "[CONFLICT] Saved $conflict_count remote file(s) from $peer to $CONFLICT_DIR/$peer_label/"
        notify-send -u normal "Madhatter Sync — Conflicts" \
            "$conflict_count file(s) had remote changes. Saved to .conflicts/$peer_label/"
    fi
}

# ---------------------------------------------------------------------------
# [M4] Graceful shutdown
# ---------------------------------------------------------------------------
cleanup() {
    SHUTTING_DOWN=1
    log "[SHUTDOWN] Signal received — shutting down gracefully."

    # Wait for active sync process to finish (up to TimeoutStopSec)
    if [[ -n "$RSYNC_PID" ]] && kill -0 "$RSYNC_PID" 2>/dev/null; then
        log "[SHUTDOWN] Waiting for sync process (PID $RSYNC_PID) to finish..."
        wait "$RSYNC_PID" 2>/dev/null || true
    fi

    update_status "STOPPED"
    log "[SHUTDOWN] Madhatter Sync Engine stopped."
    exit 0
}

trap cleanup SIGTERM SIGINT EXIT

# ---------------------------------------------------------------------------
# [M1] --check-peers: test SSH reachability and exit
# ---------------------------------------------------------------------------
check_peers() {
    if [ ! -f "$PEERS_FILE" ] || [ ! -s "$PEERS_FILE" ]; then
        echo "No peers defined in $PEERS_FILE."
        exit 1
    fi

    local total=0 reachable=0 unreachable=0 invalid=0

    while IFS= read -r peer; do
        [[ -z "$peer" || "$peer" =~ ^[[:space:]]*# ]] && continue

        if ! validate_peer "$peer"; then
            echo "  INVALID  $peer"
            ((invalid++))
            ((total++))
            continue
        fi

        # Extract host portion (everything before the colon)
        local host="${peer%%:*}"

        echo -n "  Testing  $peer ... "
        if ssh -n -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
               "$host" true 2>/dev/null; then
            echo "OK"
            ((reachable++))
        else
            echo "UNREACHABLE"
            ((unreachable++))
        fi
        ((total++))
    done < "$PEERS_FILE"

    echo ""
    echo "Results: $total peers — $reachable reachable, $unreachable unreachable, $invalid invalid"

    if [ "$unreachable" -gt 0 ] || [ "$invalid" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

# Handle CLI flags
case "${1:-}" in
    --check-peers)
        check_peers
        ;;
    --help|-h)
        echo "Usage: $(basename "$0") [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --check-peers   Test SSH reachability of all configured peers and exit"
        echo "  --help, -h      Show this help message"
        echo ""
        echo "Without options, starts the sync daemon (watch + sync loop)."
        exit 0
        ;;
    "")
        # No flag — continue to daemon mode below
        ;;
    *)
        echo "Unknown option: $1"
        echo "Run '$(basename "$0") --help' for usage."
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
for cmd in rsync inotifywait; do
    if ! command -v "$cmd" &> /dev/null; then
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
    # [M4] Abort early if shutting down
    [[ "$SHUTTING_DOWN" -eq 1 ]] && return 0

    # [M2] Rotate log before sync if it's grown too large
    rotate_log

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

        # [M4] Check shutdown flag before each peer
        [[ "$SHUTTING_DOWN" -eq 1 ]] && break

        log "Syncing to $peer..."

        # [O4] Detect conflicts before pushing
        detect_conflicts "$peer"

        rsync -avz --delete --delay-updates --exclude-from="$IGNORE_FILE" \
            --exclude=".versions" --exclude=".sync_trigger" --exclude=".syncignore" \
            --exclude=".conflicts" \
            --backup --backup-dir="$VERSION_DIR" --suffix="_$(date +%Y%m%d_%H%M%S)" \
            "$SYNC_DIR/" "$peer" >> "$LOG_FILE" 2>&1 &
        RSYNC_PID=$!

        wait "$RSYNC_PID" 2>/dev/null
        local rc=$?
        RSYNC_PID=""

        [[ "$SHUTTING_DOWN" -eq 1 ]] && return 0

        if [ $rc -eq 0 ]; then
            log "Sync to $peer successful."
        else
            log "Error syncing to $peer (exit code $rc)."
            update_status "ERROR"
            notify-send -u critical "Madhatter Sync Failed" \
                "Could not sync with $peer. Check logs."
            return 1
        fi
    done < "$PEERS_FILE"

    [[ "$SHUTTING_DOWN" -eq 1 ]] && return 0

    # [M5] Prune old versions after successful sync
    prune_versions

    if [[ "$SHUTTING_DOWN" -eq 0 ]]; then
        update_status "IDLE"
    fi
}

# ---------------------------------------------------------------------------
# [O2] Initial sync on startup — run once before entering the watch loop
# ---------------------------------------------------------------------------
log "[STARTUP] Running initial sync..."
sync_to_peers || log "[STARTUP] Initial sync completed with errors, continuing to watch mode"

# [O1] Tell systemd we're ready (after initial sync completes)
sd_notify --ready

# ---------------------------------------------------------------------------
# Watch loop
# Triggers on: close_write, moved_to, create, delete, move
# ---------------------------------------------------------------------------
while [[ "$SHUTTING_DOWN" -eq 0 ]]; do
    # [O1] Heartbeat — tell systemd we're still alive
    sd_notify WATCHDOG=1

    log "Watching $SYNC_DIR for changes..."

    # Block until a change happens
    inotifywait -r -e close_write,moved_to,create,delete,move \
        --exclude "$VERSION_DIR" --exclude "\.sync_trigger" --exclude "\.syncignore" \
        --exclude "$CONFLICT_DIR" \
        --exclude ".*\.swp" --exclude ".*\.tmp" \
        "$SYNC_DIR" >> "$LOG_FILE" 2>&1 || true

    # [M4] If we were signalled while blocking, exit the loop
    [[ "$SHUTTING_DOWN" -eq 1 ]] && break

    # Wait a moment for settling (debounce)
    sleep 2

    sync_to_peers || true

    # Wait before loop restarts to avoid rapid-fire loops on mass changes
    sleep 1
done
