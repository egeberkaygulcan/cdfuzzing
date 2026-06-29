#!/bin/bash
##
# fix-ssh-workers.sh — Restore inter-node SSH after Emulab keymgmt wipe.
#
# Run on the HEAD NODE. Adds the cluster pubkey back to ~/.ssh/authorized_keys
# then immediately SSHes to every worker (in parallel, before keymgmt can wipe
# the key again) to install the sshd drop-in that survives keymgmt resets.
#
# Usage (on Utah head):
#   bash /local/repository/cloudlab/fix-ssh-workers.sh [--shared /proj/cdfuzzing-PG0]
#
# The script:
#   1. Reads worker IPs from the cluster manifest (or scans 192.168.1.10–192.168.1.60)
#   2. Adds cluster pubkey to ~/.ssh/authorized_keys
#   3. Parallel-SSHes to each worker to write /etc/ssh/cdfuzz_authorized_keys
#      and the sshd drop-in via sudo (no-password sudo is standard on CloudLab).
#   4. Verifies connectivity to each worker after the drop-in is installed.
##
set -uo pipefail

SHARED="${1:-}"
if [ -z "$SHARED" ]; then
    # auto-detect from /local/cdfuzz-role
    [ -f /local/cdfuzz-role ] && . /local/cdfuzz-role 2>/dev/null
    SHARED="${SHARED:-/proj/cdfuzzing-PG0}"
fi
# Handle --shared flag
while [ $# -gt 0 ]; do
    case "$1" in
        --shared) SHARED="$2"; shift 2;;
        *) shift;;
    esac
done

CLUSTER_SSH="$SHARED/cluster/ssh"
PUBKEY_FILE="$CLUSTER_SSH/id_rsa.pub"

log() { echo "[$(date '+%F %T')] fix-ssh: $*"; }

if [ ! -f "$PUBKEY_FILE" ]; then
    echo "ERROR: cluster pubkey not found at $PUBKEY_FILE" >&2
    exit 1
fi
PUBKEY="$(cat "$PUBKEY_FILE")"

# --- Step 1: Restore cluster key to ~/.ssh/authorized_keys -------------------
log "Re-adding cluster key to ~/.ssh/authorized_keys"
touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
grep -qxF "$PUBKEY" ~/.ssh/authorized_keys || echo "$PUBKEY" >> ~/.ssh/authorized_keys
log "authorized_keys updated ($(wc -l < ~/.ssh/authorized_keys) total keys)"

# --- Step 2: Build worker IP list from manifest or ARP -----------------------
MANIFEST="$SHARED/cluster/manifest.txt"
if [ -f "$MANIFEST" ]; then
    mapfile -t WORKER_IPS < <(grep -v '^#' "$MANIFEST" | grep -v '^\s*head' | awk '{print $2}')
    log "Using manifest: ${#WORKER_IPS[@]} workers"
else
    log "No manifest found, scanning ARP table for 192.168.1.10–192.168.1.60"
    mapfile -t WORKER_IPS < <(arp -n 2>/dev/null | awk '{print $1}' | grep '^192\.168\.1\.[1-9][0-9]$')
    log "ARP scan found: ${#WORKER_IPS[@]} potential workers"
fi

if [ ${#WORKER_IPS[@]} -eq 0 ]; then
    echo "ERROR: no worker IPs found" >&2
    exit 1
fi

# --- Step 3: Install sshd drop-in on all workers (in parallel) ---------------
DROPIN_CMD="sudo bash -c '"'
    echo '"'"'$(cat "$PUBKEY_FILE")'"'"' > /etc/ssh/cdfuzz_authorized_keys
    chmod 644 /etc/ssh/cdfuzz_authorized_keys
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/90-cdfuzz.conf <<SSHDEOF
AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/cdfuzz_authorized_keys
SSHDEOF
    chmod 644 /etc/ssh/sshd_config.d/90-cdfuzz.conf
    systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null || true
    echo ok
'"'"

log "Installing sshd drop-in on ${#WORKER_IPS[@]} workers in parallel..."
PUBKEY_ESCAPED="${PUBKEY//\//\\/}"
declare -A PIDS
for ip in "${WORKER_IPS[@]}"; do
    ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no "$ip" \
        "sudo bash -c 'echo \"$PUBKEY\" > /etc/ssh/cdfuzz_authorized_keys; chmod 644 /etc/ssh/cdfuzz_authorized_keys; mkdir -p /etc/ssh/sshd_config.d; printf \"AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/cdfuzz_authorized_keys\n\" > /etc/ssh/sshd_config.d/90-cdfuzz.conf; chmod 644 /etc/ssh/sshd_config.d/90-cdfuzz.conf; systemctl reload sshd 2>/dev/null || true; echo ok'" \
        &
    PIDS[$ip]=$!
done

# Collect results
FAILED=()
OK=()
for ip in "${!PIDS[@]}"; do
    if wait "${PIDS[$ip]}"; then
        OK+=("$ip")
    else
        FAILED+=("$ip")
    fi
done
log "Drop-in installed on ${#OK[@]}/${#WORKER_IPS[@]} workers"
if [ ${#FAILED[@]} -gt 0 ]; then
    log "FAILED (${#FAILED[@]}): ${FAILED[*]}"
fi

# --- Step 4: Verify SSH works now (without relying on authorized_keys) --------
log "Verifying SSH connectivity..."
VERIFIED=0
STILL_FAILED=()
for ip in "${WORKER_IPS[@]}"; do
    result=$(ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no "$ip" 'hostname' 2>/dev/null) && {
        VERIFIED=$((VERIFIED + 1))
    } || STILL_FAILED+=("$ip")
done
log "Verified: $VERIFIED/${#WORKER_IPS[@]} workers reachable"
if [ ${#STILL_FAILED[@]} -gt 0 ]; then
    log "Still unreachable: ${STILL_FAILED[*]}"
    log "These workers may need to be reprovisioned or accessed via CloudLab portal"
fi
