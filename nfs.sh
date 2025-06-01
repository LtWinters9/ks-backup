#!/bin/bash

# Variables
SOURCE_DIRS=("/var/www" "/etc/caddy" "/var/log/caddy" "/var/log/")
DEST_DIRS=("/mnt/nfs/primary" "/mnt/nfs/secondary")
BACKUP_NAME="backup_$(date +%d-%m-%Y).tar.gz"
TEMP_DIR=$(mktemp -d /tmp/backup_tmp.XXXXXX)
RETENTION_DAYS=60
ENCRYPTION_KEY=$(cat /etc/backups/encryption_key.txt)
ITERATIONS=100000
HASHED_KEY=$(echo -n $ENCRYPTION_KEY | openssl dgst -sha3-256 | awk '{print $2}')

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Functions
function setup_directories() {
  echo -e "${YELLOW}Preparing backup directories...${NC}"
  mkdir -p "$TEMP_DIR" && chmod 700 "$TEMP_DIR"
  for dir in "${DEST_DIRS[@]}"; do
    mkdir -p "$dir" && chmod 700 "$dir"
  done
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Unable to initialize directories.${NC}" >&2
    exit 1
  fi
}

function create_compressed_file() {
  echo -e "${YELLOW}Compressing source directories...${NC}"
  tar --transform 's,^/,,' -czf "$TEMP_DIR/$BACKUP_NAME" -C / "${SOURCE_DIRS[@]}"
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Compression failed.${NC}" >&2
    exit 1
  fi
  echo -e "${GREEN}Archive created: $TEMP_DIR/$BACKUP_NAME${NC}"
}

function encrypt_backup_file() {
  echo -e "${YELLOW}Encrypting the backup archive...${NC}"
  openssl enc -aes-128-cbc -salt -pbkdf2 -iter $ITERATIONS -in "$TEMP_DIR/$BACKUP_NAME" -out "$TEMP_DIR/${BACKUP_NAME}.enc" -k "$HASHED_KEY"
  if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Encryption failed.${NC}" >&2
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
      exit 1
    fi
  done
}

function copy_backup_file() {
  echo -e "${YELLOW}Transferring encrypted backup to destination(s)...${NC}"
  for dir in "${DEST_DIRS[@]}"; do
    cp "$TEMP_DIR/${BACKUP_NAME}.enc" "$dir/"
    if [ $? -eq 0 ]; then
      echo "Backup successfully copied to $dir on $(date)" >> /var/log/backup.log
    else
      echo "Backup copy failed for $dir on $(date)" >> /var/log/backup.log
      echo -e "${RED}Error: Copy failed for $dir.${NC}" >&2
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
    exit 1
  fi
  echo -e "${GREEN}Old backups removed as per retention policy.${NC}"
}

# Main script
echo -e "${YELLOW}Initiating backup process...${NC}"
setup_directories
create_compressed_file &
wait
encrypt_backup_file &
wait
check_disk_space
copy_backup_file
clean_temp_files
apply_retention_policy
echo -e "${GREEN}Backup process completed successfully.${NC}"

# Ensure cleanup on exit or failure
trap clean_temp_files EXIT INT ERR

# Clear the terminal
clear
