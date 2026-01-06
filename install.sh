#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Ride Status Installer
# Full drop-in replacement with improvements:
# - Ensures Node-RED palette dependency: node-red-node-mysql
# - Ensures Node-RED service loads /opt/ridestatus/config/db.env via EnvironmentFile=
# - Normalizes db.env to SYSTEMD-SAFE format (no quotes, no export, no spaces)
#   while preserving existing credentials for continuity across installs
# - Ensures /home/sftp/.node-red exists + has package.json before npm installs
# - Adds non-secret verification that Node-RED service sees DB_NAME in env
# =============================================================================
INSTALLER_VERSION="v2.0.9"

# -----------------------------------------------------------------------------
# Early logging buffer (before /opt/ridestatus exists)
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

# Append buffered log and switch to final log file
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

if sudo test -f "$SUDOERS_FILE" && sudo grep -Fxq "$SUDOERS_LINE" "$SUDOERS_FILE"; then
  echo "NOPASSWD already configured in $SUDOERS_FILE"
else
  echo "Writing $SUDOERS_FILE"
  sudo tee "$SUDOERS_FILE" >/dev/null <<EOF
# Managed by RideStatus installer (${INSTALLER_VERSION})
${SUDOERS_LINE}
EOF
  sudo chmod 0440 "$SUDOERS_FILE"
fi

echo "Validating sudoers configuration..."
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
  echo "Generating SSH key..."
  rm -f "$KEY_FILE" "$PUB_FILE"
  ssh-keygen -t ed25519 -f "$KEY_FILE" -N ""
fi

chmod 600 "$KEY_FILE"
chmod 644 "$PUB_FILE"

ssh-keyscan -H github.com 2>/dev/null | sort -u > "$SSH_DIR/known_hosts"
chmod 600 "$SSH_DIR/known_hosts"

PUB_FPR="$(ssh-keygen -lf "$PUB_FILE" -E sha256 | awk '{print $2}' || true)"

echo
echo "=============================="
echo "GITHUB SSH KEY (ADD TO USER)"
echo "=============================="
cat "$PUB_FILE"
echo
echo "Public key fingerprint (SHA256): ${PUB_FPR:-unknown}"
echo
echo "Add the above public key to your GitHub USER account:"
echo "  GitHub -> Settings -> SSH and GPG keys -> New SSH key"
echo
echo "Tip: When sharing logs, redact the key but keep the fingerprint."

# -----------------------------------------------------------------------------
# GitHub SSH connectivity test (NON-FATAL, TIME-BOUNDED, DOES NOT CONSUME STDIN)
# -----------------------------------------------------------------------------
echo
echo "Testing GitHub SSH connectivity (optional; non-fatal)..."
set +e
timeout 8s ssh -n \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o ConnectTimeout=5 \
  -T git@github.com </dev/null 2>&1
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
    # shellcheck disable=SC1090
    source "$GITHUB_ENV_FILE"
    GITHUB_ORG="${GITHUB_ORG:-$DEFAULT_ORG}"
  else
    GITHUB_ORG="$DEFAULT_ORG"
    echo "GITHUB_ORG=\"${GITHUB_ORG}\"" > "$GITHUB_ENV_FILE"
    chmod 0644 "$GITHUB_ENV_FILE"
  fi
fi

echo "Using GitHub org: $GITHUB_ORG"

# -----------------------------------------------------------------------------
# Core services
# -----------------------------------------------------------------------------
echo "Installing Node-RED prerequisites, Mosquitto, Ansible, MariaDB..."
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
echo "Configuring Mosquitto (listen on all interfaces)..."
sudo tee /etc/mosquitto/conf.d/ridestatus.conf >/dev/null <<'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF
sudo systemctl enable mosquitto
sudo systemctl restart mosquitto

# -----------------------------------------------------------------------------
# MariaDB
# -----------------------------------------------------------------------------
echo "Ensuring MariaDB is enabled and running..."
sudo systemctl enable mariadb
sudo systemctl restart mariadb

# -----------------------------------------------------------------------------
# Database env file (idempotent + NORMALIZED for systemd)
# -----------------------------------------------------------------------------
DB_ENV_FILE="${CONFIG_DIR}/db.env"

ensure_db_env_normalized() {
  # Load existing values if present (quoted or unquoted), then rewrite unquoted.
  if [[ -f "$DB_ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$DB_ENV_FILE"
    set +a
  fi

  : "${DB_NAME:=ridestatus}"
  : "${DB_HOST:=127.0.0.1}"
  : "${DB_PORT:=3306}"
  : "${DB_APP_USER:=ridestatus_app}"
  : "${DB_MIGRATE_USER:=ridestatus_migrate}"

  if [[ -z "${DB_APP_PASS:-}" ]]; then
    DB_APP_PASS="$(openssl rand -base64 48 | tr -d '\n')"
  fi
  if [[ -z "${DB_MIGRATE_PASS:-}" ]]; then
    DB_MIGRATE_PASS="$(openssl rand -base64 48 | tr -d '\n')"
  fi

  # Write in systemd-safe format (NO quotes)
  sudo tee "$DB_ENV_FILE" >/dev/null <<EOF
# Managed by RideStatus installer (${INSTALLER_VERSION})
DB_NAME=${DB_NAME}
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_APP_USER=${DB_APP_USER}
DB_APP_PASS=${DB_APP_PASS}
DB_MIGRATE_USER=${DB_MIGRATE_USER}
DB_MIGRATE_PASS=${DB_MIGRATE_PASS}
EOF

  # Readable by root + sftp group (service runs as sftp); not world readable
  sudo chown root:sftp "$DB_ENV_FILE"
  sudo chmod 640 "$DB_ENV_FILE"
}

echo "Ensuring DB env file exists and is normalized for systemd..."
ensure_db_env_normalized

# Load normalized values for the remainder of the installer
# shellcheck disable=SC1090
set -a
source "$DB_ENV_FILE"
set +a

echo "DB env file: ${DB_ENV_FILE}"

# -----------------------------------------------------------------------------
# Database setup (idempotent)
# -----------------------------------------------------------------------------
echo "Creating database and users (idempotent)..."
sudo mysql --protocol=socket <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS '${DB_APP_USER}'@'localhost' IDENTIFIED BY '${DB_APP_PASS}';
CREATE USER IF NOT EXISTS '${DB_MIGRATE_USER}'@'localhost' IDENTIFIED BY '${DB_MIGRATE_PASS}';

GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE, CREATE TEMPORARY TABLES, LOCK TABLES
  ON \`${DB_NAME}\`.*
  TO '${DB_APP_USER}'@'localhost';

GRANT ALL PRIVILEGES
  ON \`${DB_NAME}\`.*
  TO '${DB_MIGRATE_USER}'@'localhost';

FLUSH PRIVILEGES;
SQL

echo "DB setup complete: ${DB_NAME}"

# -----------------------------------------------------------------------------
# Clone repos
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
    (cd "$dest" && git fetch --all --prune) || { echo "WARNING: fetch failed for $repo"; continue; }
    (cd "$dest" && git checkout -q main) || true
    (cd "$dest" && git pull -q --ff-only) || true
  else
    echo "Cloning $repo..."
    if ! (cd "$SRC_DIR" && git clone "$url" "$dest"); then
      echo "WARNING: clone failed for $repo"
    fi
  fi
done

# -----------------------------------------------------------------------------
# Node-RED install (ensure command exists)
# -----------------------------------------------------------------------------
if ! command -v node-red >/dev/null 2>&1; then
  echo "Installing Node-RED via npm (global)..."
  sudo npm install -g --unsafe-perm node-red
fi

# -----------------------------------------------------------------------------
# Ensure Node-RED userDir exists and is npm-initialized
# -----------------------------------------------------------------------------
NR_USERDIR="/home/sftp/.node-red"
echo "Ensuring Node-RED userDir exists: ${NR_USERDIR}"
mkdir -p "$NR_USERDIR"
chown -R sftp:sftp "$NR_USERDIR"

if [[ ! -f "${NR_USERDIR}/package.json" ]]; then
  echo "Initializing ${NR_USERDIR}/package.json (npm init -y)..."
  (cd "$NR_USERDIR" && npm init -y >/dev/null)
fi

# -----------------------------------------------------------------------------
# Install required Node-RED palette nodes (runtime dependencies)
# -----------------------------------------------------------------------------
echo "Installing required Node-RED nodes (palette deps)..."
(cd "$NR_USERDIR" && npm install node-red-node-mysql)
echo "Node-RED nodes installed."

# -----------------------------------------------------------------------------
# Node-RED systemd service (RideStatus)
# -----------------------------------------------------------------------------
echo "Configuring systemd service: ridestatus-nodered.service"
sudo tee /etc/systemd/system/ridestatus-nodered.service >/dev/null <<EOF
[Unit]
Description=RideStatus Node-RED
After=network.target mosquitto.service mariadb.service
Wants=mosquitto.service mariadb.service

[Service]
Type=simple
User=sftp
Group=sftp
WorkingDirectory=/home/sftp
ExecStart=/usr/bin/env node-red -u /home/sftp/.node-red
Restart=on-failure
RestartSec=5
Environment=NODE_OPTIONS=--max-old-space-size=256
# Load RideStatus DB config so nodes (e.g., MySQL) can use \${DB_*} variables
EnvironmentFile=/opt/ridestatus/config/db.env

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ridestatus-nodered
sudo systemctl restart ridestatus-nodered

# -----------------------------------------------------------------------------
# Non-secret verification that Node-RED service sees DB env vars
# -----------------------------------------------------------------------------
echo "Verifying Node-RED service environment contains DB_NAME (non-secret check)..."
if sudo systemctl show ridestatus-nodered -p Environment | tr ' ' '\n' | grep -q '^DB_NAME='; then
  echo "OK: DB_NAME present in ridestatus-nodered environment."
else
  echo "WARNING: DB_NAME NOT present in ridestatus-nodered environment."
  echo "         This usually means db.env formatting isn't systemd-friendly."
  echo "         Expected: KEY=VALUE (no quotes). Actual file:"
  sudo sed -n '1,120p' /opt/ridestatus/config/db.env | sed 's/DB_.*PASS=.*/DB_***PASS=[redacted]/g'
fi

IP="$(hostname -I | awk '{print $1}' || true)"
[[ -n "${IP:-}" ]] || IP="127.0.0.1"

echo
echo "======================================"
echo "INSTALLER COMPLETE – ${INSTALLER_VERSION}"
echo "======================================"
echo "Node-RED URL: http://${IP}:1880"
echo "MQTT Broker:  mqtt://${IP}:1883"
echo "Install log:  ${LOG_FILE}"
echo "Repos:        ${SRC_DIR}"
echo "SSH key fpr:  ${PUB_FPR:-unknown}"
echo
echo "DB env file (used by services + Node-RED):"
echo "  /opt/ridestatus/config/db.env"
echo
echo "In Node-RED, configure the MySQL node with env vars:"
echo "  Host: \${DB_HOST}  Port: \${DB_PORT}  DB: \${DB_NAME}"
echo "  User: \${DB_APP_USER}  Pass: \${DB_APP_PASS}"
