#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Ride Status Installer
# Version: v2.0.6
# =============================================================================
INSTALLER_VERSION="v2.0.6"

# -----------------------------------------------------------------------------
# Early logging buffer (before sudo is available)
# -----------------------------------------------------------------------------
TMP_LOG_DIR="/tmp/ridestatus-installer"
TMP_LOG_FILE="${TMP_LOG_DIR}/install.log"
mkdir -p "$TMP_LOG_DIR"
exec > >(tee "$TMP_LOG_FILE") 2>&1

echo "RideStatus Installer ${INSTALLER_VERSION}"
echo "======================================"

# -----------------------------------------------------------------------------
# Flags
# -----------------------------------------------------------------------------
AUTO_EXPAND_ROOT=0
for arg in "$@"; do
  case "$arg" in
    --auto-expand-root|-y|--yes) AUTO_EXPAND_ROOT=1 ;;
  esac
done

# -----------------------------------------------------------------------------
# Safety checks
# -----------------------------------------------------------------------------
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  echo "ERROR: Do not run as root. Log in as 'sftp' and run the installer."
  exit 1
fi

if [[ "$(whoami)" != "sftp" ]]; then
  echo "ERROR: Installer must be run as user 'sftp'."
  exit 1
fi

source /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
  echo "ERROR: Ubuntu Server 24.04 LTS is required."
  exit 1
fi
echo "OS check passed."

# -----------------------------------------------------------------------------
# Sudo check (NOPASSWD required)
# -----------------------------------------------------------------------------
echo "Checking sudo access (non-interactive; must be NOPASSWD)..."
if ! sudo -n true 2>/dev/null; then
  echo "ERROR: sudo is not passwordless for user 'sftp'."
  echo "Expected sudoers line:"
  echo "  sftp ALL=(ALL) NOPASSWD:ALL"
  exit 1
fi
echo "Sudo check passed (NOPASSWD)."

# -----------------------------------------------------------------------------
# Disk check / optional auto-expand (LVM)
# -----------------------------------------------------------------------------
RECOMMENDED_ROOT_GB=55
ROOT_GB="$(df -BG --output=size / | tail -1 | tr -d ' G')"

if (( ROOT_GB < RECOMMENDED_ROOT_GB )); then
  echo "WARNING: Root filesystem is ${ROOT_GB}G (recommended >= ${RECOMMENDED_ROOT_GB}G)."
  ROOT_SRC="$(findmnt -n -o SOURCE / || true)"
  if [[ "$ROOT_SRC" == /dev/mapper/* && "$AUTO_EXPAND_ROOT" == "1" ]]; then
    echo "Attempting LVM auto-expand..."
    sudo lvextend -l +100%FREE "$ROOT_SRC"
    sudo resize2fs "$ROOT_SRC"
    df -h /
  else
    echo "Re-run with --auto-expand-root to expand automatically."
  fi
fi

# -----------------------------------------------------------------------------
# Base packages
# -----------------------------------------------------------------------------
echo "Installing base packages..."
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  git \
  jq \
  openssl

# -----------------------------------------------------------------------------
# /opt/ridestatus layout + final log location
# -----------------------------------------------------------------------------
RIDESTATUS_ROOT="/opt/ridestatus"
CONFIG_DIR="${RIDESTATUS_ROOT}/config"
BACKUPS_DIR="${RIDESTATUS_ROOT}/backups"
LOG_DIR="${RIDESTATUS_ROOT}/logs"
BIN_DIR="${RIDESTATUS_ROOT}/bin"
SRC_DIR="${RIDESTATUS_ROOT}/src"

LOG_FILE="${LOG_DIR}/install.log"

sudo mkdir -p "$CONFIG_DIR" "$BACKUPS_DIR" "$LOG_DIR" "$BIN_DIR" "$SRC_DIR"
sudo chown -R sftp:sftp "$RIDESTATUS_ROOT"
sudo chmod 0755 "$RIDESTATUS_ROOT" "$CONFIG_DIR" "$BACKUPS_DIR" "$LOG_DIR" "$BIN_DIR" "$SRC_DIR"

cat "$TMP_LOG_FILE" | tee -a "$LOG_FILE" >/dev/null
exec > >(tee -a "$LOG_FILE") 2>&1
rm -rf "$TMP_LOG_DIR"

echo "Logging to $LOG_FILE"
echo "Installer version: ${INSTALLER_VERSION}"

# -----------------------------------------------------------------------------
# Enforce NOPASSWD sudo
# -----------------------------------------------------------------------------
SUDOERS_FILE="/etc/sudoers.d/ridestatus-sftp"
SUDOERS_LINE="sftp ALL=(ALL) NOPASSWD:ALL"

if ! sudo test -f "$SUDOERS_FILE"; then
  sudo tee "$SUDOERS_FILE" >/dev/null <<EOF
# Managed by RideStatus installer (${INSTALLER_VERSION})
${SUDOERS_LINE}
EOF
  sudo chmod 0440 "$SUDOERS_FILE"
fi

sudo visudo -cf /etc/sudoers >/dev/null
echo "Sudoers validation passed."

# -----------------------------------------------------------------------------
# SSH key (GitHub USER key model)
# -----------------------------------------------------------------------------
SSH_DIR="$HOME/.ssh"
KEY_FILE="$SSH_DIR/id_ed25519"
PUB_FILE="${KEY_FILE}.pub"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

if [[ ! -f "$KEY_FILE" || ! -f "$PUB_FILE" ]]; then
  ssh-keygen -t ed25519 -f "$KEY_FILE" -N ""
fi

chmod 600 "$KEY_FILE"
chmod 644 "$PUB_FILE"

ssh-keyscan -H github.com 2>/dev/null | sort -u > "$SSH_DIR/known_hosts"
chmod 600 "$SSH_DIR/known_hosts"

PUB_FPR="$(ssh-keygen -lf "$PUB_FILE" -E sha256 | awk '{print $2}')"

echo
echo "=============================="
echo "GITHUB SSH KEY (ADD TO USER)"
echo "=============================="
cat "$PUB_FILE"
echo
echo "Public key fingerprint (SHA256): $PUB_FPR"
echo
echo "Add the above public key to your GitHub USER account:"
echo "  GitHub -> Settings -> SSH and GPG keys -> New SSH key"
echo
echo "Tip: When sharing logs, redact the key but keep the fingerprint."

# -----------------------------------------------------------------------------
# GitHub SSH connectivity test (NON-FATAL, TIME-BOUNDED)
# -----------------------------------------------------------------------------
echo
echo "Testing GitHub SSH connectivity (optional; non-fatal)..."
set +e
timeout 8s ssh \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ConnectTimeout=5 \
  -T git@github.com 2>&1
ssh_rc=$?
set -e
echo "[ssh] exit code: ${ssh_rc} (ignored; GitHub commonly returns 1)"

# -----------------------------------------------------------------------------
# GitHub org config
# -----------------------------------------------------------------------------
GITHUB_ENV_FILE="${CONFIG_DIR}/github.env"
DEFAULT_ORG="SFTPRS"

if [[ -n "${RIDESTATUS_GITHUB_ORG:-}" ]]; then
  GITHUB_ORG="$RIDESTATUS_GITHUB_ORG"
else
  if [[ -f "$GITHUB_ENV_FILE" ]]; then
    source "$GITHUB_ENV_FILE"
    GITHUB_ORG="${GITHUB_ORG:-$DEFAULT_ORG}"
  else
    GITHUB_ORG="$DEFAULT_ORG"
    echo "GITHUB_ORG=\"$GITHUB_ORG\"" > "$GITHUB_ENV_FILE"
  fi
fi

echo "Using GitHub org: $GITHUB_ORG"

# -----------------------------------------------------------------------------
# Core services
# -----------------------------------------------------------------------------
echo "Installing Node-RED, Mosquitto, Ansible, MariaDB..."
sudo apt-get install -y \
  nodejs \
  npm \
  build-essential \
  python3 \
  mosquitto \
  mosquitto-clients \
  ansible \
  sshpass \
  mariadb-server \
  mariadb-client

# -----------------------------------------------------------------------------
# Mosquitto
# -----------------------------------------------------------------------------
sudo tee /etc/mosquitto/conf.d/ridestatus.conf >/dev/null <<'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF
sudo systemctl enable mosquitto
sudo systemctl restart mosquitto

# -----------------------------------------------------------------------------
# MariaDB
# -----------------------------------------------------------------------------
sudo systemctl enable mariadb
sudo systemctl restart mariadb

# -----------------------------------------------------------------------------
# Database setup
# -----------------------------------------------------------------------------
DB_ENV_FILE="${CONFIG_DIR}/db.env"

if [[ ! -f "$DB_ENV_FILE" ]]; then
  cat > "$DB_ENV_FILE" <<EOF
DB_NAME=ridestatus
DB_HOST=127.0.0.1
DB_PORT=3306
DB_APP_USER=ridestatus_app
DB_APP_PASS=$(openssl rand -base64 32)
DB_MIGRATE_USER=ridestatus_migrate
DB_MIGRATE_PASS=$(openssl rand -base64 32)
EOF
  chmod 600 "$DB_ENV_FILE"
fi

source "$DB_ENV_FILE"

sudo mysql <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_APP_USER}'@'localhost' IDENTIFIED BY '${DB_APP_PASS}';
CREATE USER IF NOT EXISTS '${DB_MIGRATE_USER}'@'localhost' IDENTIFIED BY '${DB_MIGRATE_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_MIGRATE_USER}'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON ${DB_NAME}.* TO '${DB_APP_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# -----------------------------------------------------------------------------
# Clone repos (THIS NOW ALWAYS RUNS)
# -----------------------------------------------------------------------------
echo
echo "Cloning/updating repos into ${SRC_DIR}..."

REPOS=(
  "ridestatus-server"
  "ridestatus-ride"
  "ridestatus-deploy"
)

for repo in "${REPOS[@]}"; do
  dest="${SRC_DIR}/${repo}"
  url="git@github.com:${GITHUB_ORG}/${repo}.git"

  if [[ -d "$dest/.git" ]]; then
    echo "Updating $repo..."
    (cd "$dest" && git pull --ff-only) || echo "WARNING: update failed for $repo"
  else
    echo "Cloning $repo..."
    (cd "$SRC_DIR" && git clone "$url") || echo "WARNING: clone failed for $repo"
  fi
done

# -----------------------------------------------------------------------------
# Node-RED systemd service
# -----------------------------------------------------------------------------
sudo tee /etc/systemd/system/ridestatus-nodered.service >/dev/null <<'EOF'
[Unit]
Description=RideStatus Node-RED
After=network.target mosquitto.service mariadb.service

[Service]
User=sftp
ExecStart=/usr/bin/env node-red -u /home/sftp/.node-red
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ridestatus-nodered
sudo systemctl restart ridestatus-nodered

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
IP="$(hostname -I | awk '{print $1}')"

echo
echo "======================================"
echo "INSTALLER COMPLETE – ${INSTALLER_VERSION}"
echo "======================================"
echo "Node-RED URL: http://${IP}:1880"
echo "MQTT Broker:  mqtt://${IP}:1883"
echo "Install log:  ${LOG_FILE}"
echo "Repos:        ${SRC_DIR}"
echo "SSH key fpr:  ${PUB_FPR}"
