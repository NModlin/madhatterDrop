#!/bin/bash

# Configuration
SYNC_DIR="$HOME/madhatterDrop"
PEERS_FILE="$HOME/.config/madhatter/peers"
STATUS_FILE="$HOME/.cache/madhatter/status"
LOG_FILE="$HOME/.cache/madhatter/sync.log"
VERSION_DIR="$SYNC_DIR/.versions"
IGNORE_FILE="$SYNC_DIR/.syncignore"

# Ensure directories exist
mkdir -p "$SYNC_DIR"
mkdir -p "$(dirname "$STATUS_FILE")"
mkdir -p "$(dirname "$PEERS_FILE")"
mkdir -p "$VERSION_DIR"
touch "$LOG_FILE"
touch "$IGNORE_FILE"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

update_status() {
    echo "$1" > "$STATUS_FILE"
}

# Check if required tools are installed
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

# Initial Sync Function
sync_to_peers() {
    update_status "SYNCING"
    
    # Read peers from config file (one per line)
    if [ ! -f "$PEERS_FILE" ] || [ ! -s "$PEERS_FILE" ]; then
        log "No peers defined in $PEERS_FILE."
        update_status "IDLE"
        return
    fi
    
    while IFS= read -r peer; do
        # Skip empty lines or comments
        [[ "$peer" =~ ^#.*$ ]] || [ -z "$peer" ] && continue
        
        log "Syncing to $peer..."
        
        # Rsync options:
        # -a: archive mode
        # -v: verbose
        # -z: compress
        # --delete: access delete on receiver
        # --delay-updates: atomic update
        # --exclude-from: ignore file
        
        rsync -avz --delete --delay-updates --exclude-from="$IGNORE_FILE" \
            --backup --backup-dir="$VERSION_DIR" --suffix="_$(date +%Y%m%d_%H%M%S)" \
            "$SYNC_DIR/" "$peer:$SYNC_DIR/" >> "$LOG_FILE" 2>&1
            
        if [ $? -eq 0 ]; then
            log "Sync to $peer successful."
        else
            log "Error syncing to $peer."
            update_status "ERROR"
            notify-send -u critical "Madhatter Sync Failed" "Could not sync with $peer. Check logs."
            return 1
        fi
    done < "$PEERS_FILE"
    
    update_status "IDLE"
}

# Watch loop
# Triggers on: close_write, moved_to, create, delete, move
while true; do
    log "Watching $SYNC_DIR for changes..."
    
    # Block until a change happens
    inotifywait -r -e close_write,moved_to,create,delete,move \
        --exclude "$VERSION_DIR" --exclude ".*\.swp" --exclude ".*\.tmp" \
        "$SYNC_DIR" >> "$LOG_FILE" 2>&1
        
    # Wait a moment for settling (debounce)
    sleep 2
    
    sync_to_peers
    
    # Wait before loop restarts to avoid rapid-fire loops on mass changes
    sleep 1
done
