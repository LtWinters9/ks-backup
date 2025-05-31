#!/bin/bash

# Variables
TEMP_DIR="/tmp/backup_tmp" # Temporary directory for processing
ENCRYPTION_KEY=$(cat /etc/backups/encryption_key.txt) # Encryption key from file
ITERATIONS=100000 # Number of iterations for key derivation
HASHED_KEY=$(echo -n $ENCRYPTION_KEY | openssl dgst -sha3-256 | awk '{print $2}') # Hashed encryption key

# Color codes for output messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
create_dir() {
  local dir=$1
  echo -e "${BLUE}📁 Creating directory: $dir...${NC}"
  mkdir -p "$dir" && chmod 700 "$dir"
  if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Could not create the directory. Please check permissions.${NC}" >&2
    exit 1
  fi
}

select_backup_server() {
  echo -e "${YELLOW}📡 Please choose the backup server to restore from:${NC}"
  PS3="➡️ Type the number corresponding to your chosen server: "
  select SERVER in "Primary" "Secondary"; do
    case $REPLY in
      1) DEST_DIR="/mnt/primary"; break ;;
      2) DEST_DIR="/mnt/secondary"; break ;;
      *) echo -e "${RED}❌ That option isn't valid. Please select a valid number.${NC}" ;;
    esac
  done
}

list_backup_files() {
  echo -e "${YELLOW}📂 Here are the available backup archives:${NC}"
  select BACKUP_FILE in $(ls -t "$DEST_DIR"/*.tar.gz.enc); do
    if [[ -n "$BACKUP_FILE" && "$BACKUP_FILE" =~ \.tar\.gz\.enc$ ]]; then
      echo -e "${GREEN}✅ Backup file selected: $BACKUP_FILE${NC}"
      break
    else
      echo -e "${RED}❌ That doesn't look right. Please choose a valid backup file.${NC}"
    fi
  done
}

prompt_destination_dir() {
  echo -e "${YELLOW}📁 Where should the backup be extracted? Enter the full path:${NC}"
  read -r EXTRACT_DIR
  if [[ -z "$EXTRACT_DIR" || "$EXTRACT_DIR" =~ [^a-zA-Z0-9/_-] || "$EXTRACT_DIR" =~ ^(/etc|/bin|/usr|/sbin|/lib|/root|/dev|/proc|/sys|/boot|/mnt|/media|/run)$ ]]; then
    echo -e "${RED}🚫 That directory is either invalid or protected. Exiting for safety.${NC}" >&2
    exit 1
  fi
  if [ -d "$EXTRACT_DIR" ]; then
    if [ ! -w "$EXTRACT_DIR" ]; then
      echo -e "${RED}🚫 You don't have permission to write to that directory. Exiting.${NC}" >&2
      exit 1
    fi
    echo -e "${YELLOW}⚠️ The directory already exists. Overwrite its contents? (yes/no)${NC}"
    read -r CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
      echo -e "${RED}❎ Operation cancelled. No changes were made.${NC}" >&2
      exit 1
    fi
  else
    create_dir "$EXTRACT_DIR"
  fi
}

decrypt_and_extract() {
  local file=$1
  local temp_file="$TEMP_DIR/$(basename "$file" .enc)"
  echo -e "${BLUE}🔐 Decrypting the selected backup file...${NC}"
  openssl enc -d -aes-128-cbc -salt -pbkdf2 -iter $ITERATIONS -in "$file" -out "$temp_file" -k "$HASHED_KEY"
  if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Decryption failed. Please verify the encryption key.${NC}" >&2
    return 1
  fi
  echo -e "${GREEN}✅ Decryption successful. Temporary file created: $temp_file${NC}"
  echo -e "${BLUE}📦 Extracting contents from the decrypted archive...${NC}"
  tar -xzf "$temp_file" -C "$EXTRACT_DIR"
  if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Extraction failed. Please check the archive integrity.${NC}" >&2
    return 1
  fi
  echo -e "${GREEN}✅ Files successfully extracted to: $EXTRACT_DIR${NC}"
  rm -f "$temp_file"
}

# Main script
echo -e "${BLUE}🔄 Initiating the backup restoration process...${NC}"
select_backup_server
create_dir "$TEMP_DIR"
list_backup_files
prompt_destination_dir

# Decrypt and extract selected backup files in parallel
for file in "$DEST_DIR"/*.tar.gz.enc; do
  decrypt_and_extract "$file" &
done
wait

echo -e "${GREEN}🎉 Backup restoration completed successfully!${NC}"

# Ensure cleanup on exit
trap 'rm -f "$TEMP_DIR"/*' EXIT

# Clear the terminal
clear
