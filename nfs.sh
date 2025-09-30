#!/bin/bash
set -euo pipefail

# Source encryption key from .env file
source /etc/backups/.env  # Load ENCRYPTION_KEY securely

# Optional flag to clear terminal at the end
CLEAR_TERMINAL=true

# Safe fallback for RETENTION_DAYS
: "${RETENTION_DAYS:=180}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Logging functions
log_info() {
  echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1${NC}"
}
log_warn() {
  echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1${NC}" >&2
}
log_error() {
  echo "[$(date)] Error: $1" >> "$LOG_FILE"
}
fatal_error() {
  log_error "$1"
  exit "$2"
}

# Variables
SOURCE_DIRS=("/var/www" "/etc/caddy" "/var/log/caddy" "/var/log/" "/opt/ks-guvnor")
DEST_DIRS=("/mnt/hetzner-sb/hel1-bx98/" "/mnt/hetzner-sb/fsn1-bx196/")
BACKUP_NAME="backup_$(date +%d-%m-%Y-%I%p).tar.gz"
TEMP_DIR=$(mktemp -d /tmp/backup_tmp.XXXXXX)
LOG_FILE="/var/log/backup.log"
ITERATIONS=100000
HASHED_KEY="$ENCRYPTION_KEY"

# Rotate logs
rotate_logs() {
  local max_logs=5
  local log_dir
  log_dir=$(dirname "$LOG_FILE")
  local log_base
  log_base=$(basename "$LOG_FILE")
  local today_log="$LOG_FILE.$(date +%Y-%m-%d)"
  if [ -f "$LOG_FILE" ] && [ ! -f "$today_log" ]; then
    mv "$LOG_FILE" "$today_log"
  fi
  ls -1t "$LOG_FILE".* 2>/dev/null | tail -n +$((max_logs + 1)) | xargs -r rm --
}

# Retry mount check
retry_mount_check() {
  local dir=$1
  for i in {1..3}; do
    if mountpoint -q "$dir" && [ -w "$dir" ]; then return 0; fi
    sleep 10
  done
  return 1
}

# Setup directories
setup_directories() {
  log_info "Preparing backup directories..."
  mkdir -p "$TEMP_DIR" && chmod 700 "$TEMP_DIR"
  for dir in "${DEST_DIRS[@]}"; do
    mkdir -p "$dir" && chmod 700 "$dir"
  done
}

# Validate mounts (parallelised)
validate_mounts() {
  log_info "Validating mount points..."
  for dir in "${DEST_DIRS[@]}"; do
    (retry_mount_check "$dir" && echo "$dir" >> /tmp/valid_mounts.txt) &
  done
  wait
  mapfile -t VALID_DEST_DIRS < /tmp/valid_mounts.txt
  if [ ${#VALID_DEST_DIRS[@]} -eq 0 ]; then
    fatal_error "All destination directories are either offline or unwritable." 12
  fi
  DEST_DIRS=("${VALID_DEST_DIRS[@]}")
}

# Check temp space
check_temp_space() {
  log_info "Checking available space for temporary backup files..."
  SOURCE_SIZE=$(du -sb "${SOURCE_DIRS[@]}" | awk '{sum += $1} END {print sum}')
  REQUIRED_TEMP_SPACE=$((SOURCE_SIZE + SOURCE_SIZE / 3))
  TEMP_MOUNT=$(df -B1 "$TEMP_DIR" | tail -1 | awk '{print $4}')
  if [ "$TEMP_MOUNT" -lt "$REQUIRED_TEMP_SPACE" ]; then
    fatal_error "Not enough space in temp directory ($TEMP_DIR). Needed: $REQUIRED_TEMP_SPACE bytes." 80
  fi
  log_info "Sufficient space available in temp directory."
}

# Stream compression and encryption using AES-256-CBC
stream_compress_encrypt() {
  log_info "Compressing and encrypting source directories..."
  tar --exclude='/var/log/journal/*' -czf - -C / "${SOURCE_DIRS[@]}" 2>>"$LOG_FILE"     | openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$ITERATIONS" -out "$TEMP_DIR/$BACKUP_NAME.enc" -k "$HASHED_KEY"
  log_info "Encrypted archive created: $TEMP_DIR/$BACKUP_NAME.enc"
}

# Check disk space
check_disk_space() {
  log_info "Verifying available disk space..."
  REQUIRED_SPACE=$(du -sb "$TEMP_DIR/$BACKUP_NAME.enc" | awk '{print $1}')
  for dir in "${DEST_DIRS[@]}"; do
    AVAILABLE_SPACE=$(df -B1 "$dir" | tail -1 | awk '{print $4}')
    if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
      fatal_error "Insufficient space in $dir." 40
    fi
  done
}

# Copy backup file
copy_backup_file() {
  log_info "Transferring encrypted backup to destination(s)..."
  for dir in "${DEST_DIRS[@]}"; do
    rsync -aW --inplace --no-compress --stats --info=progress2 "$TEMP_DIR/$BACKUP_NAME.enc" "$dir/" >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
      echo "Backup successfully copied to $dir on $(date)" >> "$LOG_FILE"
    else
      fatal_error "Copy failed for $dir." 50
    fi
  done
  log_info "Backup successfully copied to all destinations."
}

# Cleanup temp files
clean_temp_files() {
  log_info "Removing temporary files and directory..."
  rm -rf "$TEMP_DIR"
}

# Tiered retention policy
apply_retention_policy() {
  log_info "Applying tiered retention policy..."

  for dir in "${DEST_DIRS[@]}"; do
    declare -A daily_kept
    declare -A weekly_kept

    find "$dir" -type f -name "backup_*.tar.gz.enc" | while read -r file; do
      filename=$(basename "$file")
      date_str=$(echo "$filename" | sed -n 's/backup_\([0-9]\{2\}-[0-9]\{2\}-[0-9]\{4\}\)-.*\.tar\.gz\.enc/\1/p')
      [[ -z "$date_str" ]] && { log_warn "Skipping unrecognized file: $filename"; continue; }

      iso_date=$(echo "$date_str" | awk -F- '{print $3"-"$2"-"$1}')
      file_date=$(date -d "$iso_date" +%s 2>/dev/null)
      [[ -z "$file_date" ]] && { log_warn "Invalid date format: $date_str"; continue; }

      age_days=$(( ( $(date +%s) - file_date ) / 86400 ))

      if (( age_days <= 60 )); then
        continue
      elif (( age_days <= 150 )); then
        key=$(date -d "$iso_date" +%Y-%m-%d)
        [[ -z "${daily_kept[$key]}" ]] && daily_kept[$key]="$file" || { rm -f "$file"; log_info "Deleted daily duplicate: $filename"; }
      else
        key=$(date -d "$iso_date" +%Y-%U)
        [[ -z "${weekly_kept[$key]}" ]] && weekly_kept[$key]="$file" || { rm -f "$file"; log_info "Deleted weekly duplicate: $filename"; }
      fi
    done
  done

  log_info "Tiered retention policy applied."
}

# Trap cleanup
trap clean_temp_files EXIT INT ERR

# Main flow
rotate_logs
setup_directories
validate_mounts
check_temp_space
stream_compress_encrypt
check_disk_space
copy_backup_file
apply_retention_policy &
wait
log_info "Backup process completed successfully."

# Clear terminal if requested
if [ "$CLEAR_TERMINAL" = true ]; then
  clear
fi
