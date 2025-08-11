#!/bin/bash

# Variables
SOURCE_DIRS=("/var/www" "/etc/caddy" "/var/log/caddy" "/var/log/" "/opt/scripts")
DEST_DIRS=("/mnt/p/" "/mnt/s")
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

# Check encryption key file permissions and readability
if [ ! -r "$ENCRYPTION_KEY_FILE" ]; then
  echo -e "${RED}Error: Encryption key file is not readable.${NC}" >&2
  echo "[$(date)] Error: Encryption key file is not readable." >> "$LOG_FILE"
  exit 1
fi

KEY_PERMS=$(stat -c "%a" "$ENCRYPTION_KEY_FILE")
if [ "$KEY_PERMS" -ne 400 ]; then
  echo -e "${YELLOW}Warning: Encryption key file permissions are not 400. Updating...${NC}"
  chmod 400 "$ENCRYPTION_KEY_FILE"
  KEY_PERMS=$(stat -c "%a" "$ENCRYPTION_KEY_FILE")
  if [ "$KEY_PERMS" -ne 400 ]; then
    echo -e "${RED}Error: Failed to set encryption key file permissions to 400.${NC}" >&2
    echo "[$(date)] Error: Failed to set encryption key file permissions to 400." >> "$LOG_FILE"
    exit 1
  fi
fi

ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")
ITERATIONS=100000
HASHED_KEY=$(echo -n $ENCRYPTION_KEY | openssl dgst -sha3-256 | awk '{print $2}')

# Functions
function setup_directories() {
  echo -e "${YELLOW}Preparing backup directories...${NC}"
  mkdir -p "$TEMP_DIR" && chmod 700 "$TEMP_DIR"
  for dir in "${DEST_DIRS[@]}"; do
    mkdir -p "$dir" && chmod 700 "$dir"
  done
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Unable to initialize directories.${NC}" >&2
    echo "[$(date)] Error: Unable to initialize directories." >> "$LOG_FILE"
    exit 1
  fi
}

function create_compressed_file() {
  echo -e "${YELLOW}Compressing source directories...${NC}"
  tar --transform 's,^/,,' -czf "$TEMP_DIR/$BACKUP_NAME" -C / "${SOURCE_DIRS[@]}" &
  pid=$!
  spinner $pid
  wait $pid
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Compression failed.${NC}" >&2
    echo "[$(date)] Error: Compression failed." >> "$LOG_FILE"
    exit 1
  fi
  echo -e "${GREEN}Archive created: $TEMP_DIR/$BACKUP_NAME${NC}"
}

function encrypt_backup_file() {
  echo -e "${YELLOW}Encrypting the backup archive...${NC}"
  openssl enc -aes-128-cbc -salt -pbkdf2 -iter $ITERATIONS -in "$TEMP_DIR/$BACKUP_NAME" -out "$TEMP_DIR/${BACKUP_NAME}.enc" -k "$HASHED_KEY" &
  pid=$!
  spinner $pid
  wait $pid
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Encryption failed.${NC}" >&2
    echo "[$(date)] Error: Encryption failed." >> "$LOG_FILE"
    exit 1
  fi
  echo -e "${GREEN}Encrypted file created: $TEMP_DIR/${BACKUP_NAME}.enc${NC}"
}

function check_disk_space() {
  echo -e "${YELLOW}Verifying available disk space...${NC}"
  REQUIRED_SPACE=$(du -sb "$TEMP_DIR/${BACKUP_NAME}.enc" | awk '{print $1}')
  for dir in "${DEST_DIRS[@]}"; do
    AVAILABLE_SPACE=$(df -B1 "$dir" | tail -1 | awk '{print $4}')
    if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
      echo -e "${RED}Error: Insufficient space in $dir.${NC}" >&2
      echo "[$(date)] Error: Insufficient space in $dir." >> "$LOG_FILE"
      exit 1
    fi
  done
}

function copy_backup_file() {
  echo -e "${YELLOW}Transferring encrypted backup to destination(s)...${NC}"
  for dir in "${DEST_DIRS[@]}"; do
    cp "$TEMP_DIR/${BACKUP_NAME}.enc" "$dir/"
    if [ $? -eq 0 ]; then
      echo "Backup successfully copied to $dir on $(date)" >> "$LOG_FILE"
    else
      echo "Backup copy failed for $dir on $(date)" >> "$LOG_FILE"
      echo -e "${RED}Error: Copy failed for $dir.${NC}" >&2
      echo "[$(date)] Error: Copy failed for $dir." >> "$LOG_FILE"
      exit 1
    fi
  done
  echo -e "${GREEN}Backup successfully copied to all destinations.${NC}"
}

function clean_temp_files() {
  echo -e "${YELLOW}Removing temporary files and directory...${NC}"
  rm -rf "$TEMP_DIR"
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Cleanup failed.${NC}" >&2
    echo "[$(date)] Error: Cleanup failed." >> "$LOG_FILE"
    exit 1
  fi
  echo -e "${GREEN}Temporary directory cleaned up.${NC}"
}

function apply_retention_policy() {
  echo -e "${YELLOW}Enforcing retention policy...${NC}"
  for dir in "${DEST_DIRS[@]}"; do
    find "$dir" -type f -name "backup_*.tar.gz.enc" -mtime +$RETENTION_DAYS -exec rm {} \;
  done
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Retention policy application failed.${NC}" >&2
    echo "[$(date)] Error: Retention policy application failed." >> "$LOG_FILE"
    exit 1
  fi
  echo -e "${GREEN}Old backups removed as per retention policy.${NC}"
}

# Main script
echo -e "${YELLOW}Initiating backup process...${NC}"
setup_directories
create_compressed_file &
wait  # Wait for compression to complete
encrypt_backup_file &
wait  # Wait for encryption to complete
echo -e "${GREEN}Backup archive created and encrypted successfully.${NC}"
check_disk_space
copy_backup_file
clean_temp_files
apply_retention_policy
echo -e "${GREEN}Backup process completed successfully.${NC}"

# Ensure cleanup on exit or failure
trap clean_temp_files EXIT INT ERR

# Clear the terminal
clear
