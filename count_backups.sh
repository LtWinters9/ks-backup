#!/bin/bash

# Color codes
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# Prompt for location
echo -e "${YELLOW}Select backup location:${RESET}"
echo "1) hel1-bx98"
echo "2) fsn1-bx196"
read -p "Enter choice [1 or 2]: " choice

# Set location based on choice
case "$choice" in
  1) location="hel1-bx98" ;;
  2) location="fsn1-bx196" ;;
  *) echo -e "${RED}Invalid choice. Exiting.${RESET}"; exit 1 ;;
esac

# Set full path
dir="/mnt/hetzner-sb/$location"

# Check if directory exists
if [ ! -d "$dir" ]; then
  echo -e "${RED}Directory $dir does not exist. Exiting.${RESET}"
  exit 1
fi

# Count matching files
count=$(find "$dir" -maxdepth 1 -type f -name "*.tar.gz.enc" | wc -l)

# Calculate total size of matching files
size=$(find "$dir" -maxdepth 1 -type f -name "*.tar.gz.enc" -exec du -ch {} + | grep total$ | awk '{print $1}')

# Output results
echo -e "${GREEN}Found $count .tar.gz.enc files in $dir${RESET}"
echo -e "${CYAN}Total size of these files: $size${RESET}"

# Clean exit message
#echo -e "${GREEN}Script completed successfully.${RESET}"
exit 0
