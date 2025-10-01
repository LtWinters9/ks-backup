#!/bin/bash

# Variables
TEMP_DIR=$(mktemp -d) # Unique temporary directory for processing
ENCRYPTION_KEY_FILE="/etc/backups/encryption_key.txt" # Encryption key file
ITERATIONS=100000 # Number of iterations for key derivation

# Color codes for output messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
  while true; do
    echo -e "${YELLOW}📡 Please choose the backup server to restore from:${NC}"
    PS3="➡️ Type the number corresponding to your chosen server: "
    select SERVER in "HEL1-BX98" "FSN1-BX196"; do
      case $REPLY in
        1) DEST_DIR="/mnt/hetzner-sb/hel1-bx98"; break ;;
        2) DEST_DIR="/mnt/hetzner-sb/fsn1-bx196"; break ;;
        *) echo -e "${RED}❌ That option isn't valid. Please select a valid number.${NC}" ;;
      esac
    done
    echo -e "${YELLOW}⚠️ You have selected: $SERVER. Is this correct? (yes/no)${NC}"
    read -r CONFIRM
    if [ "$CONFIRM" == "yes" ]; then
      break
    fi
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
  openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter $ITERATIONS -in "$file" -out "$temp_file" -k "$ENCRYPTION_KEY" &
  pid=$!
  spinner $pid
  wait $pid
  if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Decryption failed. Please verify the encryption key.${NC}" >&2
    return 1
  fi
  echo -e "${GREEN}✅ Decryption successful. Temporary file created: $temp_file${NC}"
  echo -e "${BLUE}📦 Extracting contents from the decrypted archive...${NC}"
  tar -xzf "$temp_file" -C "$EXTRACT_DIR" &
  pid=$!
  spinner $pid
  wait $pid
  if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Extraction failed. Please check the archive integrity.${NC}" >&2
    return 1
  fi
  echo -e "${GREEN}✅ Files successfully extracted to: $EXTRACT_DIR${NC}"
  rm -f "$temp_file"
}

# Main script
echo -e "${BLUE}🔄 Initiating the backup restoration process...${NC}"

if [ ! -s "$ENCRYPTION_KEY_FILE" ]; then
  echo -e "${RED}❌ Encryption key file is missing or empty.${NC}" >&2
  exit 1
fi

ENCRYPTION_KEY=$(cat "$ENCRYPTION_KEY_FILE")

select_backup_server
list_backup_files
prompt_destination_dir
decrypt_and_extract "$BACKUP_FILE"

echo -e "${GREEN}🎉 Backup restoration completed successfully!${NC}"

# Ensure cleanup on exit
cleanup() {
  echo -e "${BLUE}🧹 Cleaning up temporary files...${NC}"
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT INT TERM

# Clear the terminal
clear
