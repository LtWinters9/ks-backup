#!/bin/bash

set -e

# -------------------------------------------
# SMTP
# -------------------------------------------

SMTP_TO=""
SMTP_FROM=""
SMTP_SERVER=""
SMTP_USER=""
SMTP_AUTH=''

# -------------------------------------------
# VARS
# -------------------------------------------

## IDs for backups
ID_1="Custom ID"


## Backup server details
VPS_SSH='username@server.tld'
VPS_DIR="data/dir"

## SOURCE
S1="/var/www"

## BACKUP
B1="${S1}/mywebsite"


## DESTINATION
D1=${VPS_DIR}/${ID_1}/

# -------------------------------------------
# FUNCTIONS
# -------------------------------------------

function start_backup {
echo Starting backup on: ${VPS_SSH}
rsync -avzHP -q "${B1}" "${VPS_SSH}":"${D1}"
}

function end_backup {
sleep 1
clear
echo Finished  backup on: ${VPS_SSH}
sleep 2
}

###### Script start
echo "Let's get started..."

if start_backup
then
 end_backup
 exit 0
else
 echo " Script failed - sending email"
 swaks --to ${SMTP_TO} --from ${SMTP_FROM} --server ${SMTP_SERVER} --auth-user ${SMTP_USER} --auth-password ${SMTP_AUTH} --body "failed to backup on $(date '+%Y-%m-%d')" --header 'Subject: BACKUP FAILED for backup server' ; exit 1
fi
