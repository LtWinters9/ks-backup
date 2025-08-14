#!/bin/bash

# Optional flag to clear terminal at the end
CLEAR_TERMINAL=false

print_msg() {
  local type="$1"
  local msg="$2"
  local color=""
  local emoji=""

  case "$type" in
    info)
      color="\033[1;34m"
      emoji="ℹ️"
      ;;
    warn)
      color="\033[1;33m"
      emoji="⚠️"
      ;;
    error)
      color="\033[1;31m"
      emoji="❌"
      ;;
    success)
      color="\033[1;32m"
      emoji="✅"
      ;;
    *)
      color="\033[0m"
      emoji=""
      ;;
  esac

  echo -e "${color}${emoji} ${msg}\033[0m"
}

umask 077  # Set restrictive permissions for all created files

# Variables
SOURCE_DIRS=("/var/www" "/etc/caddy" "/var/log/caddy" "/var/log/" "/opt/ks-guvnor")
DEST_DIRS=("/mnt/hetzner-sb/hel1-bx98/" "/mnt/hetzner-sb/fsn1-bx196/")
BACKUP_NAME="backup_$(date +%d-%m-%Y-%I%p).tar.gz"
TEMP_DIR=$(mktemp -d /tmp/backup_tmp.XXXXXX)
RETENTION_DAYS=180

ENCRYPTION_KEY_FILE="/etc/backups/encryption_key.txt"
LOG_FILE="/var/log/backup.log"  # Log file variable

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Spinner function with emojis
spinner() {
  local pid=$1
  local delay=0.1
  local spinstr=('⏳' '🔄' '🔁' '🔃')
  while kill -0 "$pid" 2>/dev/null; do
    for i in "${spinstr[@]}"; do
      printf " [%s]  " "$i"
      sleep $delay
      printf "\b\b\b\b\b\b"
    done
  done
  printf "      \b\b\b\b\b\b"
}

# Helper function for fatal errors
fatal_error() {
print_msg info "$(date +%Y-%m-%d %H:%M:%S) [ERROR] $1 >&2"
  log_error "$1"
  exit $2
}

# Enhanced logging function
log_info() {
print_msg info "$(date +%Y-%m-%d %H:%M:%S) [INFO] $1"
}

log_warn() {
print_msg info "$(date +%Y-%m-%d %H:%M:%S) [WARN] $1 >&2"
}

log_error() {
print_msg info "$(date +%Y-%m-%d %H:%M:%S) [ERROR] $1 >&2"
}

# Centralized error logging function
log_error() {
  echo "[$(date)] Error: $1" >> "$LOG_FILE"
}

# Log rotation function (keeps last 5 logs, rotates daily)
rotate_logs() {
  local max_logs=5
  local log_dir
  log_dir=$(dirname "$LOG_FILE")
  local log_base
  log_base=$(basename "$LOG_FILE")
  local today_log="$LOG_FILE.$(date +%Y-%m-%d)"

  # Move current log to dated log if not already done today
  if [ -f "$LOG_FILE" ]; then
    if [ ! -f "$today_log" ]; then
      mv "$LOG_FILE" "$today_log"
    fi
  fi

  # Remove oldest logs if more than $max_logs exist
  ls -1t "$LOG_FILE".* 2>/dev/null | tail -n +$((max_logs + 1)) | xargs -r rm --
}

# Retry mount check function
retry_mount_check() {
  local dir=$1
  for i in {1..3}; do
    if mountpoint -q "$dir" && [ -w "$dir" ]; then return 0; fi
    sleep 10
  done
  return 1
}

# Exit codes
EXIT_KEY_NOT_READABLE=10
EXIT_KEY_PERM_FAIL=11
EXIT_MOUNT_FAIL=12
EXIT_DIR_SETUP_FAIL=20
EXIT_COMPRESSION_FAIL=30
EXIT_ENCRYPTION_FAIL=31
EXIT_DISK_SPACE_FAIL=40
EXIT_COPY_FAIL=50
EXIT_CLEANUP_FAIL=60
EXIT_RETENTION_FAIL=70
EXIT_TEMP_SPACE_FAIL=80

# Rotate logs at the start of the script
rotate_logs

# Check encryption key file permissions and readability
if [ ! -r "$ENCRYPTION_KEY_FILE" ]; then
print_msg info "${RED}Error: Encryption key file is not readable.${NC} >&2"
  log_error "Encryption key file is not readable."
  exit $EXIT_KEY_NOT_READABLE
fi

KEY_PERMS=$(stat -c "%a" "$ENCRYPTION_KEY_FILE")
if [ "$KEY_PERMS" -ne 400 ]; then
print_msg info "${YELLOW}Warning: Encryption key file permissions are not 400. Updating...${NC}"
  chmod 400 "$ENCRYPTION_KEY_FILE"
  KEY_PERMS=$(stat -c "%a" "$ENCRYPTION_KEY_FILE")
  if [ "$KEY_PERMS" -ne 400 ]; then
print_msg info "${RED}Error: Failed to set encryption key file permissions to 400.${NC} >&2"
    log_error "Failed to set encryption key file permissions to 400."
    exit $EXIT_KEY_PERM_FAIL
  fi
fi

ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")
ITERATIONS=100000
HASHED_KEY=$(echo -n $ENCRYPTION_KEY | openssl dgst -sha3-256 | awk '{print $2}')

function setup_directories() {
print_msg info "${YELLOW}Preparing backup directories...${NC}"
  mkdir -p "$TEMP_DIR" && chmod 700 "$TEMP_DIR"
  for dir in "${DEST_DIRS[@]}"; do
    mkdir -p "$dir" && chmod 700 "$dir"
  done
  if [ $? -ne 0 ]; then
print_msg info "${RED}Error: Unable to initialize directories.${NC} >&2"
    log_error "Unable to initialize directories."
    exit $EXIT_DIR_SETUP_FAIL
  fi
}

function validate_mounts() {
  VALID_DEST_DIRS=()
  for dir in "${DEST_DIRS[@]}"; do
    if ! retry_mount_check "$dir"; then
      log_warn "$dir is not mounted or not writable. Skipping..."
      continue
    fi
    VALID_DEST_DIRS+=("$dir")
  done
  if [ ${#VALID_DEST_DIRS[@]} -eq 0 ]; then
    fatal_error "All destination directories are either offline or unwritable." $EXIT_MOUNT_FAIL
  fi
  DEST_DIRS=("${VALID_DEST_DIRS[@]}")
}


function check_temp_space() {
print_msg info "${YELLOW}Checking available space for temporary backup files...${NC}"
  SOURCE_SIZE=$(du -sb "${SOURCE_DIRS[@]}" | awk '{sum += $1} END {print sum}')
  REQUIRED_TEMP_SPACE=$((SOURCE_SIZE + SOURCE_SIZE / 3))
  TEMP_MOUNT=$(df -B1 "$TEMP_DIR" | tail -1 | awk '{print $4}')
  if [ "$TEMP_MOUNT" -lt "$REQUIRED_TEMP_SPACE" ]; then
print_msg info "${RED}Error: Not enough space in temp directory ($TEMP_DIR). Needed: $REQUIRED_TEMP_SPACE bytes.${NC} >&2"
    log_error "Not enough space in temp directory ($TEMP_DIR). Needed: $REQUIRED_TEMP_SPACE bytes."
    exit $EXIT_TEMP_SPACE_FAIL
  fi
print_msg info "${GREEN}Sufficient space available in temp directory.${NC}"
}

function create_compressed_file() {
print_msg info "${YELLOW}Compressing source directories...${NC}"
  tar --exclude='/var/log/journal/*' --warning=no-file-changed --transform 's,^/,,' -czf "$TEMP_DIR/$BACKUP_NAME" -C / "${SOURCE_DIRS[@]}" &
  pid=$!
  spinner $pid
  wait $pid
  if [ $? -ne 0 ]; then
print_msg info "${RED}Error: Compression failed.${NC} >&2"
    log_error "Compression failed."
    exit $EXIT_COMPRESSION_FAIL
  fi
print_msg info "${GREEN}Archive created: $TEMP_DIR/$BACKUP_NAME${NC}"
}

function encrypt_backup_file() {
print_msg info "${YELLOW}Encrypting the backup archive...${NC}"
  openssl enc -aes-128-cbc -salt -pbkdf2 -iter $ITERATIONS -in "$TEMP_DIR/$BACKUP_NAME" -out "$TEMP_DIR/${BACKUP_NAME}.enc" -k "$HASHED_KEY" &
  pid=$!
  spinner $pid
  wait $pid
  if [ $? -ne 0 ]; then
print_msg info "${RED}Error: Encryption failed.${NC} >&2"
    log_error "Encryption failed."
    exit $EXIT_ENCRYPTION_FAIL
  fi
print_msg info "${GREEN}Encrypted file created: $TEMP_DIR/${BACKUP_NAME}.enc${NC}"
}

function check_disk_space() {
print_msg info "${YELLOW}Verifying available disk space...${NC}"
  REQUIRED_SPACE=$(du -sb "$TEMP_DIR/${BACKUP_NAME}.enc" | awk '{print $1}')
  for dir in "${DEST_DIRS[@]}"; do
    AVAILABLE_SPACE=$(df -B1 "$dir" | tail -1 | awk '{print $4}')
    if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
print_msg info "${RED}Error: Insufficient space in $dir.${NC} >&2"
      log_error "Insufficient space in $dir."
      exit $EXIT_DISK_SPACE_FAIL
    fi
  done
}

function copy_backup_file() {
print_msg info "${YELLOW}Transferring encrypted backup to destination(s)...${NC}"
  for dir in "${DEST_DIRS[@]}"; do
    cp "$TEMP_DIR/${BACKUP_NAME}.enc" "$dir/"
    if [ $? -eq 0 ]; then
      echo "Backup successfully copied to $dir on $(date)" >> "$LOG_FILE"
    else
      log_error "Copy failed for $dir."
print_msg info "${RED}Error: Copy failed for $dir.${NC} >&2"
      exit $EXIT_COPY_FAIL
    fi
  done
print_msg info "${GREEN}Backup successfully copied to all destinations.${NC}"
}

function clean_temp_files() {
print_msg info "${YELLOW}Removing temporary files and directory...${NC}"
  rm -rf "$TEMP_DIR"
  if [ $? -ne 0 ]; then
print_msg info "${RED}Error: Cleanup failed.${NC} >&2"
    log_error "Cleanup failed."
    exit $EXIT_CLEANUP_FAIL
  fi
print_msg info "${GREEN}Temporary directory cleaned up.${NC}"
}

function apply_retention_policy() {
print_msg info "${YELLOW}Enforcing retention policy...${NC}"
  for dir in "${DEST_DIRS[@]}"; do
    find "$dir" -type f -name "backup_*.tar.gz.enc" -mtime +$RETENTION_DAYS -exec rm {} \;
  done
  if [ $? -ne 0 ]; then
print_msg info "${RED}Error: Retention policy application failed.${NC} >&2"
    log_error "Retention policy application failed."
    exit $EXIT_RETENTION_FAIL
  fi
print_msg info "${GREEN}Old backups removed as per retention policy.${NC}"
}

# Main script
print_msg info "${YELLOW}Initiating backup process...${NC}"
setup_directories
validate_mounts
check_temp_space
create_compressed_file
wait  # Wait for compression to complete
encrypt_backup_file
wait  # Wait for encryption to complete
print_msg info "${GREEN}Backup archive created and encrypted successfully.${NC}"
check_disk_space
copy_backup_file
clean_temp_files
apply_retention_policy
print_msg info "${GREEN}Backup process completed successfully.${NC}"

# Ensure cleanup on exit or failure
trap clean_temp_files EXIT INT ERR

# Clear the terminal
if [ "$CLEAR_TERMINAL" = true ]; then
  clear
fi
