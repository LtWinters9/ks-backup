#!/bin/bash

set -e

# -------------------------------------------
# VARS
# -------------------------------------------


## NFS details
NFS_DIR="/mnt/path"

## IDs for backups
ID_1="websites"
ID_2="caddy"
ID_3="logs"

## SOURCE
S1="/var/www"
S2="/etc/caddy"
S3="/var/log/caddy"

## BACKUP
B1="${S1}"
B2="${S2}"
B3="${S3}"

## DESTINATION
D1=${NFS_DIR}/${ID_1}/
D2=${NFS_DIR}/${ID_2}/
D3=${NFS_DIR}/${ID_3}/

# -------------------------------------------
# FUNCTIONS
# -------------------------------------------

function start_backup {
echo Starting backup on: ${HOSTNAME}
echo rsync data to ${NFS_DIR}
rsync -avzHP --progress "${B1}" "${D1}"
rsync -avzHP --progress "${B2}" "${D2}"
rsync -avzHP --progress "${B3}" "${D3}"
echo Job completed
}

function end_backup {
clear
echo All Done!
}

###### Script start
cd #
cd /script/path/

if start_backup && sleep 2 && clear
then
 end_backup && sleep 2 && clear
 exit 0
else
 echo "Script Failed"
 exit 1
fi
