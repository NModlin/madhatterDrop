#!/bin/bash
set -uo pipefail

# [S2] Restrictive umask — files 600, dirs 700 (owner-only)
umask 077

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

# ---------------------------------------------------------------------------
# Optional config file — overrides defaults above
# Format: KEY=VALUE (one per line, # comments, blank lines ignored)
# ---------------------------------------------------------------------------
CONFIG_FILE="$HOME/.config/madhatter/config"
ENCRYPT_AT_REST=""   # empty = disabled; "gpg" or "age" to enable

if [ -f "$CONFIG_FILE" ]; then
    while IFS='=' read -r key value; do
        # Skip comments and blank lines
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        # Trim whitespace
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        # Remove surrounding quotes from value
        value="${value#\"}"
        value="${value%\"}"
        value="${value#\'}"
        value="${value%\'}"

        case "$key" in
            SYNC_DIR)            SYNC_DIR="$value" ;;
            PEERS_FILE)          PEERS_FILE="$value" ;;
            STATUS_FILE)         STATUS_FILE="$value" ;;
            LOG_FILE)            LOG_FILE="$value" ;;
            MAX_LOG_BYTES)       MAX_LOG_BYTES="$value" ;;
            MAX_LOG_FILES)       MAX_LOG_FILES="$value" ;;
            MAX_VERSION_AGE_DAYS) MAX_VERSION_AGE_DAYS="$value" ;;
            ENCRYPT_AT_REST)     ENCRYPT_AT_REST="$value" ;;
            *)  ;; # ignore unknown keys
        esac
    done < "$CONFIG_FILE"

    # Recompute derived paths after SYNC_DIR may have changed
    VERSION_DIR="$SYNC_DIR/.versions"
    CONFLICT_DIR="$SYNC_DIR/.conflicts"
    IGNORE_FILE="$SYNC_DIR/.syncignore"
fi

# [M4] Shutdown machinery
SHUTTING_DOWN=0
SYNC_PIDS=()   # [O3] Track all background sync PIDs for parallel sync

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

# ---------------------------------------------------------------------------
# [O1] Systemd watchdog — notify systemd we're alive
# ---------------------------------------------------------------------------
sd_notify() {
    # Only works when launched by systemd with Type=notify (NOTIFY_SOCKET set)
    if command -v systemd-notify &>/dev/null && [ -n "${NOTIFY_SOCKET:-}" ]; then
        systemd-notify "$@" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# [H1] Headless support: notification wrapper
# ---------------------------------------------------------------------------
send_notification() {
    local title="$1"
    local message="$2"
    local urgency="${3:-normal}"

    # Only try to notify if we have a display and notify-send is available
    if [ -n "${DISPLAY:-}" ] && command -v notify-send &>/dev/null; then
        notify-send -u "$urgency" "$title" "$message" 2>/dev/null || true
    fi
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
# Encryption at rest — encrypt a file in-place if ENCRYPT_AT_REST is set
# ---------------------------------------------------------------------------
encrypt_file() {
    local file="$1"
    [ -z "$ENCRYPT_AT_REST" ] && return 0
    [ ! -f "$file" ] && return 0

    case "$ENCRYPT_AT_REST" in
        gpg)
            if command -v gpg &>/dev/null; then
                gpg --batch --yes --symmetric --cipher-algo AES256 \
                    --passphrase-file "$HOME/.config/madhatter/encrypt.key" \
                    --output "${file}.gpg" "$file" 2>/dev/null && rm -f "$file"
            else
                log "[ENCRYPT] gpg not found — skipping encryption for $file"
            fi
            ;;
        age)
            if command -v age &>/dev/null; then
                local keyfile="$HOME/.config/madhatter/encrypt.key"
                age -e -i "$keyfile" -o "${file}.age" "$file" 2>/dev/null && rm -f "$file"
            else
                log "[ENCRYPT] age not found — skipping encryption for $file"
            fi
            ;;
        *)
            log "[ENCRYPT] Unknown encryption method: $ENCRYPT_AT_REST"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Encrypt all new files in .versions/ after rsync --backup
# ---------------------------------------------------------------------------
encrypt_versions() {
    [ -z "$ENCRYPT_AT_REST" ] && return 0
    # Find unencrypted files (not .gpg or .age) and encrypt them
    find "$VERSION_DIR" -type f ! -name '*.gpg' ! -name '*.age' -print0 2>/dev/null | \
        while IFS= read -r -d '' vfile; do
            encrypt_file "$vfile"
        done
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

    # Parse itemize output for files being sent that already exist remotely.
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
                encrypt_file "$conflict_dest"
                ((conflict_count++))
            fi
        fi
    done <<< "$dry_output"

    if [ "$conflict_count" -gt 0 ]; then
        log "[CONFLICT] Saved $conflict_count remote file(s) from $peer to $CONFLICT_DIR/$peer_label/"
        send_notification "Madhatter Sync — Conflicts" \
            "$conflict_count file(s) had remote changes. Saved to .conflicts/$peer_label/"
    fi
}

# ---------------------------------------------------------------------------
# [O4] Pull conflict detection — save local versions before pull overwrites
# ---------------------------------------------------------------------------
detect_pull_conflicts() {
    local peer="$1"
    local host="${peer%%:*}"
    local peer_label="${host//[^a-zA-Z0-9._-]/_}"

    # Dry-run rsync from remote to local to find files that would be updated
    local dry_output
    dry_output=$(rsync -avzn --itemize-changes --exclude-from="$IGNORE_FILE" \
        --exclude=".versions" --exclude=".sync_trigger" --exclude=".syncignore" \
        --exclude=".conflicts" \
        "$peer/" "$SYNC_DIR" 2>/dev/null) || return 0

    # Parse for incoming file updates (>f = received file, not >f+++ which is new)
    local conflict_count=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^\>f[^+] ]]; then
            local rel_file="${line#* }"
            rel_file="${rel_file#"${rel_file%%[![:space:]]*}"}"
            rel_file="${rel_file%"${rel_file##*[![:space:]]}"}"

            if [ -z "$rel_file" ]; then
                continue
            fi

            # Save the LOCAL version before pull overwrites it
            local local_file="$SYNC_DIR/$rel_file"
            local conflict_dest="$CONFLICT_DIR/${peer_label}_local/$rel_file"
            if [ -f "$local_file" ]; then
                mkdir -p "$(dirname "$conflict_dest")"
                if cp -a "$local_file" "$conflict_dest" 2>/dev/null; then
                    encrypt_file "$conflict_dest"
                    ((conflict_count++))
                fi
            fi
        fi
    done <<< "$dry_output"

    if [ "$conflict_count" -gt 0 ]; then
        log "[CONFLICT] Saved $conflict_count local file(s) before pull from $peer to $CONFLICT_DIR/${peer_label}_local/"
        send_notification "Madhatter Sync — Pull Conflicts" \
            "$conflict_count local file(s) will be overwritten by pull from $peer_label. Saved to .conflicts/${peer_label}_local/"
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
# [M4] Graceful shutdown
# ---------------------------------------------------------------------------
cleanup() {
    SHUTTING_DOWN=1
    log "[SHUTDOWN] Signal received — shutting down gracefully."

    # [O3] Wait for all active sync processes to finish (up to TimeoutStopSec)
    for pid in "${SYNC_PIDS[@]}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "[SHUTDOWN] Waiting for sync process (PID $pid) to finish..."
            wait "$pid" 2>/dev/null || true
        fi
    done
    SYNC_PIDS=()

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
SYNC_MODE="full"   # full | push | pull
case "${1:-}" in
    --check-peers)
        check_peers
        ;;
    --push-only)
        SYNC_MODE="push"
        ;;
    --pull-only)
        SYNC_MODE="pull"
        ;;
    --help|-h)
        echo "Usage: $(basename "$0") [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --check-peers   Test SSH reachability of all configured peers and exit"
        echo "  --push-only     Only push local changes to peers (no pull)"
        echo "  --pull-only     Only pull remote changes from peers (no push)"
        echo "  --help, -h      Show this help message"
        echo ""
        echo "Without options, starts the sync daemon (pull + push, watch loop)."
        echo ""
        echo "Config: ~/.config/madhatter/config (KEY=VALUE, one per line)"
        echo "  SYNC_DIR, PEERS_FILE, STATUS_FILE, LOG_FILE,"
        echo "  MAX_LOG_BYTES, MAX_LOG_FILES, MAX_VERSION_AGE_DAYS, ENCRYPT_AT_REST"
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
        # Since this is a critical failure, we try to notify, but don't fail if we can't
        send_notification "Madhatter Sync Error" "Missing dependency: $cmd" "critical"
        exit 1
    fi
done

log "Madhatter Sync Engine Started."
update_status "IDLE"

# ---------------------------------------------------------------------------
# Sync function
# ---------------------------------------------------------------------------
sync_to_peers() {
    # Abort early if shutting down
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

    # [O3] Collect valid peers into an array, then sync in parallel
    local peers=()
    while IFS= read -r peer; do
        [[ -z "$peer" || "$peer" =~ ^[[:space:]]*# ]] && continue
        validate_peer "$peer" && peers+=("$peer")
    done < "$PEERS_FILE"

    if [ ${#peers[@]} -eq 0 ]; then
        log "No valid peers to sync."
        update_status "IDLE"
        return
    fi

    # [O3] Launch all peer syncs in parallel
    SYNC_PIDS=()
    for peer in "${peers[@]}"; do
        [[ "$SHUTTING_DOWN" -eq 1 ]] && break

        log "Syncing to $peer..."

        # Each peer sync runs in a subshell: conflict detection then rsync
        (
            detect_conflicts "$peer"
            rsync -avz --delete --delay-updates --exclude-from="$IGNORE_FILE" \
                --exclude=".versions" --exclude=".sync_trigger" --exclude=".syncignore" \
                --exclude=".conflicts" \
                --backup --backup-dir="$VERSION_DIR" --suffix="_$(date +%Y%m%d_%H%M%S)" \
                "$SYNC_DIR/" "$peer" >> "$LOG_FILE" 2>&1
        ) &
        SYNC_PIDS+=($!)
    done

    # [O3] Wait for all parallel syncs and collect results
    local any_failed=0
    for i in "${!SYNC_PIDS[@]}"; do
        wait "${SYNC_PIDS[$i]}" 2>/dev/null
        local rc=$?

        [[ "$SHUTTING_DOWN" -eq 1 ]] && break

        if [ $rc -eq 0 ]; then
            log "Sync to ${peers[$i]} successful."
        else
            log "Error syncing to ${peers[$i]} (exit code $rc)."
            any_failed=1
        fi
    done
    SYNC_PIDS=()

    [[ "$SHUTTING_DOWN" -eq 1 ]] && return 0

    if [ "$any_failed" -eq 1 ]; then
        update_status "ERROR"
        send_notification "Madhatter Sync Failed" \
            "One or more peers failed. Check logs." "critical"
        return 1
    fi

    # Encrypt any new version backups
    encrypt_versions

    # [M5] Prune old versions after successful sync
    prune_versions

    if [[ "$SHUTTING_DOWN" -eq 0 ]]; then
        update_status "IDLE"
    fi
}

# ---------------------------------------------------------------------------
# Pull from peers — fetch remote changes to local
# ---------------------------------------------------------------------------
pull_from_peers() {
    # Abort early if shutting down
    [[ "$SHUTTING_DOWN" -eq 1 ]] && return 0

    # Read peers from config file (one per line)
    if [ ! -f "$PEERS_FILE" ] || [ ! -s "$PEERS_FILE" ]; then
        return 0
    fi

    local peers=()
    while IFS= read -r peer; do
        [[ -z "$peer" || "$peer" =~ ^[[:space:]]*# ]] && continue
        validate_peer "$peer" && peers+=("$peer")
    done < "$PEERS_FILE"

    if [ ${#peers[@]} -eq 0 ]; then
        return 0
    fi

    log "[PULL] Pulling changes from ${#peers[@]} peer(s)..."

    # Launch all peer pulls in parallel
    local pull_pids=()
    for peer in "${peers[@]}"; do
        [[ "$SHUTTING_DOWN" -eq 1 ]] && break

        log "[PULL] Pulling from $peer..."

        (
            detect_pull_conflicts "$peer"
            rsync -avz --exclude-from="$IGNORE_FILE" \
                --exclude=".versions" --exclude=".sync_trigger" --exclude=".syncignore" \
                --exclude=".conflicts" \
                --backup --backup-dir="$VERSION_DIR" --suffix="_$(date +%Y%m%d_%H%M%S)" \
                "$peer/" "$SYNC_DIR" >> "$LOG_FILE" 2>&1
        ) &
        pull_pids+=($!)
    done

    # Wait for all pulls and collect results
    local any_failed=0
    for i in "${!pull_pids[@]}"; do
        wait "${pull_pids[$i]}" 2>/dev/null
        local rc=$?

        [[ "$SHUTTING_DOWN" -eq 1 ]] && break

        if [ $rc -eq 0 ]; then
            log "[PULL] Pull from ${peers[$i]} successful."
        else
            log "[PULL] Error pulling from ${peers[$i]} (exit code $rc)."
            any_failed=1
        fi
    done

    if [ "$any_failed" -eq 1 ]; then
        log "[PULL] One or more pulls failed."
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Full sync — pull first (get remote changes), then push (send local changes)
# ---------------------------------------------------------------------------
full_sync() {
    case "$SYNC_MODE" in
        pull)
            pull_from_peers
            ;;
        push)
            sync_to_peers
            ;;
        *)
            pull_from_peers || log "[SYNC] Pull phase completed with errors, continuing to push"
            sync_to_peers
            ;;
    esac
}

# ---------------------------------------------------------------------------
# [O2] Initial sync on startup — run once before entering the watch loop
# ---------------------------------------------------------------------------
log "[STARTUP] Running initial sync..."
full_sync || log "[STARTUP] Initial sync completed with errors, continuing to watch mode"

# [O1] Tell systemd we're ready (Type=notify)
sd_notify --ready

# ---------------------------------------------------------------------------
# Watch loop
# Triggers on: close_write, moved_to, create, delete, move
# ---------------------------------------------------------------------------
while [[ "$SHUTTING_DOWN" -eq 0 ]]; do
    # [O1] Pet the watchdog each iteration
    sd_notify WATCHDOG=1

    log "Watching $SYNC_DIR for changes..."

    # Block until a change happens
    inotifywait -r -e close_write,moved_to,create,delete,move \
        --exclude "$VERSION_DIR" --exclude "$CONFLICT_DIR" \
        --exclude "\.sync_trigger" --exclude "\.syncignore" \
        --exclude ".*\.swp" --exclude ".*\.tmp" \
        "$SYNC_DIR" >> "$LOG_FILE" 2>&1 || true

    # If we were signalled while blocking, exit the loop
    [[ "$SHUTTING_DOWN" -eq 1 ]] && break

    # Wait a moment for settling (debounce)
    sleep 2

    full_sync || true

    # Wait before loop restarts to avoid rapid-fire loops on mass changes
    sleep 1
done
