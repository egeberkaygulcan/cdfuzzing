#!/bin/bash
##
# Boot-time setup, run once per node by the CloudLab Execute service (as root).
#
# Responsibilities (idempotent):
#   * make the /mydata blockstore writable by the experiment user
#   * move Docker's data-root onto /mydata so the small root partition cannot
#     fill up (this was the cause of the seed_4 honggfuzz build failures)
#   * set up passwordless inter-node SSH over the shared home .ssh directory
#   * record this node's role so orchestrate.sh / worker-run.sh know what to do
#   * (head only) write the cluster manifest to the shared NFS
#
# Usage:
#   setup-node.sh head   --fuzzers a,b,c --nodes-per-fuzzer K --repo PATH --shared PATH
#   setup-node.sh worker --fuzzer F --rep N --repo PATH --shared PATH
##
set -uo pipefail

ROLE="${1:-}"; shift || true

FUZZER=""
REP="0"
FUZZERS=""
NPF="1"
REPO="/users/eldarfin/cdfuzzing"
SHARED="/proj/cdfuzzing-PG0"
START_IP=10   # first worker is 192.168.1.10 (must match profile.py)

while [ $# -gt 0 ]; do
    case "$1" in
        --fuzzer)           FUZZER="$2"; shift 2;;
        --rep)              REP="$2"; shift 2;;
        --fuzzers)          FUZZERS="$2"; shift 2;;
        --nodes-per-fuzzer) NPF="$2"; shift 2;;
        --repo)             REPO="$2"; shift 2;;
        --shared)           SHARED="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; shift;;
    esac
done

log() { echo "[$(date '+%F %T')] setup-node($ROLE): $*"; }

# The experiment user (the account that owns the shared home / runs sudo).
USER_NAME="${SUDO_USER:-$(basename "$(dirname "$REPO")")}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
[ -n "$USER_HOME" ] || USER_HOME="/users/$USER_NAME"

log "user=$USER_NAME home=$USER_HOME repo=$REPO shared=$SHARED"

# --- 1. Wait for and claim the /mydata blockstore --------------------------
for _ in $(seq 1 60); do
    mountpoint -q /mydata && break
    sleep 5
done
if mountpoint -q /mydata; then
    mkdir -p /mydata
    chown "$USER_NAME":"$(id -gn "$USER_NAME")" /mydata || true
    chmod 0775 /mydata || true
    log "/mydata is mounted"
else
    log "WARNING: /mydata not mounted; falling back to root disk"
    mkdir -p /mydata
    chown "$USER_NAME":"$(id -gn "$USER_NAME")" /mydata || true
fi

# --- 1b. Ensure Docker (and rsync) are installed ---------------------------
# Stock CloudLab Ubuntu images do not ship Docker. Install it idempotently so
# the profile does not depend on a prebuilt custom image.
if ! command -v rsync >/dev/null 2>&1 || ! command -v docker >/dev/null 2>&1; then
    log "Installing prerequisites (docker.io, rsync)"
    export DEBIAN_FRONTEND=noninteractive
    for _ in $(seq 1 5); do apt-get update -y && break || sleep 10; done
    apt-get install -y docker.io rsync || log "WARNING: apt install failed (will retry data-root move only if docker exists)"
    systemctl enable docker 2>/dev/null || true
    systemctl start docker 2>/dev/null || true
fi

# --- 2. Move Docker data-root onto /mydata ---------------------------------
if command -v docker >/dev/null 2>&1; then
    if [ ! -f /mydata/.docker-moved ]; then
        log "Relocating Docker data-root to /mydata/docker"
        systemctl stop docker 2>/dev/null || true
        systemctl stop docker.socket 2>/dev/null || true
        mkdir -p /mydata/docker
        if [ -d /var/lib/docker ] && [ -n "$(ls -A /var/lib/docker 2>/dev/null)" ]; then
            rsync -aXS /var/lib/docker/ /mydata/docker/ 2>/dev/null \
                || cp -a /var/lib/docker/. /mydata/docker/ 2>/dev/null || true
        fi
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json <<'JSON'
{
  "data-root": "/mydata/docker"
}
JSON
        systemctl reset-failed docker.socket docker.service 2>/dev/null || true
        systemctl start docker 2>/dev/null || true
        touch /mydata/.docker-moved
        log "Docker data-root now /mydata/docker"
    fi
    # make the socket usable without re-login (best effort)
    chmod 666 /var/run/docker.sock 2>/dev/null || true
    usermod -aG docker "$USER_NAME" 2>/dev/null || true
fi

# --- 3. Passwordless inter-node SSH via the shared home .ssh ---------------
# The home directory is one NFS share across every node, so this only has to
# succeed once; a flock prevents the 25 nodes from racing on the same files.
sudo -u "$USER_NAME" HOME="$USER_HOME" bash <<'SSHEOF'
set -e
mkdir -p ~/.ssh && chmod 700 ~/.ssh
exec 9>~/.ssh/.cdfuzz-cluster.lock
flock 9
if [ ! -f ~/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -b 2048 -N "" -f ~/.ssh/id_rsa -q
fi
touch ~/.ssh/authorized_keys
grep -qxF "$(cat ~/.ssh/id_rsa.pub)" ~/.ssh/authorized_keys \
    || cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
if ! grep -q "cdfuzz-cluster" ~/.ssh/config 2>/dev/null; then
    cat >> ~/.ssh/config <<'CFG'

# cdfuzz-cluster: relax host checking for the private experiment LAN
Host 192.168.1.* head *-0 *-1 *-2 *-3
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
CFG
    chmod 600 ~/.ssh/config
fi
SSHEOF
log "SSH cluster keys ready"

# --- 4. Record this node's role -------------------------------------------
mkdir -p /local
{
    echo "ROLE=$ROLE"
    echo "FUZZER=$FUZZER"
    echo "REP=$REP"
    echo "REPO=$REPO"
    echo "SHARED=$SHARED"
    echo "USER_NAME=$USER_NAME"
    echo "USER_HOME=$USER_HOME"
} > /local/cdfuzz-role
chmod 0644 /local/cdfuzz-role

# --- 5. Head writes the cluster manifest to the shared NFS -----------------
if [ "$ROLE" = "head" ]; then
    CLUSTER_DIR="$SHARED/cluster"
    sudo -u "$USER_NAME" mkdir -p "$CLUSTER_DIR" 2>/dev/null || mkdir -p "$CLUSTER_DIR"
    MANIFEST="$CLUSTER_DIR/manifest.txt"
    {
        echo "# name ip fuzzer rep   (generated $(date '+%F %T'))"
        echo "head 192.168.1.1 - -"
        ip=$START_IP
        IFS=',' read -r -a FARR <<< "$FUZZERS"
        for f in "${FARR[@]}"; do
            r=0
            while [ "$r" -lt "$NPF" ]; do
                echo "${f}-${r} 192.168.1.${ip} ${f} ${r}"
                ip=$((ip + 1))
                r=$((r + 1))
            done
        done
    } > "$MANIFEST"
    chown "$USER_NAME":"$(id -gn "$USER_NAME")" "$MANIFEST" 2>/dev/null || true
    log "Wrote manifest -> $MANIFEST"
fi

log "done"
