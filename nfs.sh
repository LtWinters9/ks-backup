#!/usr/bin/env bash


set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
umask 077
export LC_ALL=C

############################################
#               CONFIGURATION              #
############################################

# Default sources and destinations
DEFAULT_SOURCE_DIRS=( "/var/www" "/etc/caddy" "/var/log/" "/opt/" )
DEFAULT_DEST_DIRS=( "/mnt/katapult/kefs1/" "/mnt/katapult/kefs2/" )

# Where to read secrets from (preferred: file; fallback: env var)
# Expected keys in /etc/backups/.env:
#   ENCRYPTION_KEY_FILE=/etc/backups/key   (preferred)
#   or
#   ENCRYPTION_KEY=...                      (fallback)
ENV_FILE="/etc/backups/.env"

# Logging
LOG_FILE="/var/log/backup.log"
SYSLOG=false                 # set true or pass --syslog to also log via `logger`

# Encryption parameters
OPENSSL_CIPHER="aes-256-cbc"
OPENSSL_PBKDF2_ITER=100000   # tune per CPU
BACKUP_TIMESTAMP_FMT="%d-%m-%Y-%I%p"  # aligns with your naming
BACKUP_NAME="backup_$(date +"${BACKUP_TIMESTAMP_FMT}").tar.gz"
BACKUP_ARCHIVE_EXT="enc"     # final file is .tar.gz.enc

# Resource friendliness (auto-detected)
NICE_WRAP=""                 # will be set at runtime if ionice/nice exist

# Retention policy
RECENT_DAYS=60    # keep everything for <= RECENT_DAYS
MID_DAYS=150      # keep newest per day for RECENT_DAYS+1 .. MID_DAYS
# beyond MID_DAYS: keep newest per ISO week

# Safety fallback for a potential hard cutoff if you want it later
: "${RETENTION_DAYS:=180}"

############################################
#                GLOBALS                   #
############################################

# Parseable state toggles
DRY_RUN=false
SKIP_RETENTION=false
RETENTION_ONLY=false
CLEAR_TERMINAL=false

# Will be resolved/filled at runtime
SOURCE_DIRS=("${DEFAULT_SOURCE_DIRS[@]}")
DEST_DIRS=("${DEFAULT_DEST_DIRS[@]}")
TEMP_DIR="$(mktemp -d /tmp/backup_tmp.XXXXXX)"
ARCHIVE_PATH="${TEMP_DIR}/${BACKUP_NAME}.${BACKUP_ARCHIVE_EXT}"
VALID_DEST_DIRS=()
OPENSSL_PASS_ARGS=()

############################################
#               LOGGING                    #
############################################

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
NC=$'\033[0m'

log_plain() {
  # $1 level, $2 message (plain)
  local when level msg
  when="$(date '+%Y-%m-%d %H:%M:%S')"
  level="$1"; shift
  msg="$*"
  printf "[%s] [%s] %s\n" "$when" "$level" "$msg" >> "$LOG_FILE"
  if [[ "$SYSLOG" == true ]]; then
    logger -t backup "[$level] $msg"
  fi
}

log_info() {
  local msg="$*"
  echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] ${msg}${NC}"
  log_plain "INFO" "$msg"
}

log_warn() {
  local msg="$*"
  echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] ${msg}${NC}" >&2
  log_plain "WARN" "$msg"
}

log_error() {
  local msg="$*"
  echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${msg}${NC}" >&2
  log_plain "ERROR" "$msg"
}

############################################
#               ERROR TRAPS                #
############################################

cleanup() {
  # Always try to remove temp files; ignore errors
  if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
    log_info "Removing temporary files and directory..."
    rm -rf -- "$TEMP_DIR" || true
  fi
}

report_err() {
  local exit_code=$?
  local src="${BASH_SOURCE[1]:-?}"
  local line="${BASH_LINENO[0]:-?}"
  log_error "Aborted with exit code ${exit_code} at ${src}:${line}"
  exit "$exit_code"
}

trap cleanup EXIT
trap report_err ERR
trap 'log_warn "Interrupted (SIGINT)"; exit 130' INT

############################################
#              USAGE / ARGS                #
############################################

usage() {
  cat <<'USAGE'
Usage: nfs.sh [options]

Options:
  --dry-run           Do not copy archives or delete files (retention). Log only.
  --no-retention      Skip retention step.
  --retention-only    Only apply retention; do not create a backup.
  --syslog            Also log to syslog via `logger`.
  --clear-terminal    Clear the terminal at the end.
  --log-file PATH     Override log file path.
  --dest "D1 D2"      Override destination directories (space-separated, quoted).
  --sources "S1 S2"   Override source directories (space-separated, quoted).
  --key-file PATH     Override ENCRYPTION_KEY_FILE location.
  -h, --help          Show this help and exit.

Environment (via /etc/backups/.env or exported):
  ENCRYPTION_KEY_FILE=/path/to/key     # preferred (file content used)
  or
  ENCRYPTION_KEY=...                   # fallback (exported in environment)

Naming/format:
  backup_<DD-MM-YYYY>-<HH(12)AM|PM>.tar.gz.enc

Retention policy:
  - <= 60 days: keep all backups
  - 61..150 days: keep the newest backup per day
  - > 150 days: keep the newest backup per ISO week

USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN=true; shift ;;
      --no-retention) SKIP_RETENTION=true; shift ;;
      --retention-only) RETENTION_ONLY=true; shift ;;
      --syslog) SYSLOG=true; shift ;;
      --clear-terminal) CLEAR_TERMINAL=true; shift ;;
      --log-file) LOG_FILE="${2:?}"; shift 2 ;;
      --dest) IFS=' ' read -r -a DEST_DIRS <<< "${2:?}"; shift 2 ;;
      --sources) IFS=' ' read -r -a SOURCE_DIRS <<< "${2:?}"; shift 2 ;;
      --key-file) ENCRYPTION_KEY_FILE="${2:?}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      --) shift; break ;;
      *) log_error "Unknown option: $1"; usage; exit 2 ;;
    esac
  done
}

############################################
#             PREREQUISITES                #
############################################

ensure_root_and_paths() {
  # Create log file safely if needed
  mkdir -p -- "$(dirname -- "$LOG_FILE")"
  if [[ ! -f "$LOG_FILE" ]]; then
    : > "$LOG_FILE"
    chmod 0640 "$LOG_FILE" || true
  fi

  # Auto-detect ionice/nice
  local ion="" nic=""
  if command -v ionice >/dev/null 2>&1; then
    ion="ionice -c2 -n7"
  fi
  if command -v nice >/dev/null 2>&1; then
    nic="nice -n 19"
  fi
  NICE_WRAP="${ion} ${nic}"
}

rotate_logs() {
  local max_logs=5
  local today_log="${LOG_FILE}.$(date +%Y-%m-%d)"
  if [[ -f "$LOG_FILE" && ! -f "$today_log" ]]; then
    mv -- "$LOG_FILE" "$today_log"
    : > "$LOG_FILE"
    chmod 0640 "$LOG_FILE" || true
  fi
  # prune old rotated logs
  ls -1t "${LOG_FILE}".* 2>/dev/null | tail -n +"$((max_logs + 1))" | xargs -r rm -f --
}

source_env_and_resolve_key() {
  # Load .env if present
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/etc/backups/.env
    . "$ENV_FILE"
  fi

  # Prefer a key file over env variable
  if [[ -n "${ENCRYPTION_KEY_FILE:-}" && -r "${ENCRYPTION_KEY_FILE}" ]]; then
    OPENSSL_PASS_ARGS=( -pass "file:${ENCRYPTION_KEY_FILE}" )
  elif [[ -n "${ENCRYPTION_KEY:-}" ]]; then
    export ENCRYPTION_KEY   # required for env pass
    OPENSSL_PASS_ARGS=( -pass "env:ENCRYPTION_KEY" )
  else
    log_error "Missing encryption secret. Set ENCRYPTION_KEY_FILE (preferred) or ENCRYPTION_KEY in ${ENV_FILE}."
    exit 10
  fi
}

############################################
#         MOUNTS / SPACE CHECKS            #
############################################

retry_mount_check() {
  local dir=$1
  for _ in {1..3}; do
    if mountpoint -q -- "$dir" && [[ -w "$dir" ]]; then
      return 0
    fi
    sleep 10
  done
  return 1
}

validate_mounts() {
  log_info "Validating mount points..."
  local list_file
  list_file="$(mktemp /tmp/valid_mounts.XXXXXX)"
  : > "$list_file"

  for dir in "${DEST_DIRS[@]}"; do
    (
      if retry_mount_check "$dir"; then
        echo "$dir" >> "$list_file"
      fi
    ) &
  done
  wait

  if [[ ! -s "$list_file" ]]; then
    rm -f -- "$list_file"
    log_error "All destination directories are either offline or unwritable."
    exit 12
  fi

  mapfile -t VALID_DEST_DIRS < "$list_file" || true
  rm -f -- "$list_file"
  DEST_DIRS=("${VALID_DEST_DIRS[@]}")

  log_info "Validated destinations: ${DEST_DIRS[*]}"
}

check_temp_space() {
  log_info "Checking available space for temporary backup files..."
  # Sum sizes; ignore errors for missing/unreadable dirs
  local source_size
  source_size=$(du -sb "${SOURCE_DIRS[@]}" 2>/dev/null | awk '{sum += $1} END {print sum+0}')
  # Require ~33% headroom for compression/encryption overhead
  local required=$((source_size + source_size / 3))
  local temp_free
  temp_free=$(df -B1 -- "$TEMP_DIR" | awk 'NR==2{print $4+0}')
  if (( temp_free < required )); then
    log_error "Not enough space in temp directory ($TEMP_DIR). Needed: ${required} bytes, free: ${temp_free} bytes."
    exit 80
  fi
  log_info "Sufficient space available in temp directory."
}

############################################
#        COMPRESSION / ENCRYPTION          #
############################################

stream_compress_encrypt() {
  log_info "Compressing and encrypting source directories..."
  if [[ "$DRY_RUN" == true ]]; then
    log_info "[DRY-RUN] Would create encrypted archive at: $ARCHIVE_PATH"
    return 0
  fi

  # Use tolerant tar flags for live systems:
  #  - --ignore-failed-read: do not fail if files are unreadable/vanish
  #  - --warning=no-file-changed: silence 'file changed as we read it'
  # Shield tar's potentially-nonzero exit from pipefail using '|| true'.
  (
    ${NICE_WRAP} tar --exclude='/var/log/journal/*' \
      --ignore-failed-read --warning=no-file-changed \
      -czf - -C / "${SOURCE_DIRS[@]}" 2>>"$LOG_FILE" \
    || true
  ) | ${NICE_WRAP} openssl enc "-${OPENSSL_CIPHER}" -salt -pbkdf2 -iter "${OPENSSL_PBKDF2_ITER}" \
        -out "$ARCHIVE_PATH" \
        "${OPENSSL_PASS_ARGS[@]}" \
        2>>"$LOG_FILE"

  # Confirm the archive exists and is non-empty
  if [[ ! -s "$ARCHIVE_PATH" ]]; then
    log_error "Encrypted archive was not created or is empty: $ARCHIVE_PATH"
    exit 31
  fi

  log_info "Encrypted archive created: $ARCHIVE_PATH"
}

check_disk_space_for_dests() {
  [[ "$DRY_RUN" == true ]] && { log_info "[DRY-RUN] Skipping destination space check."; return 0; }
  log_info "Verifying available disk space on destinations..."
  local required
  required=$(du -sb -- "$ARCHIVE_PATH" | awk '{print $1+0}')
  for dir in "${DEST_DIRS[@]}"; do
    local free
    free=$(df -B1 -- "$dir" | awk 'NR==2{print $4+0}')
    if (( free < required )); then
      log_error "Insufficient space in $dir. Required=${required}B Free=${free}B"
      exit 40
    fi
  done
}

copy_backup_file() {
  if [[ "$RETENTION_ONLY" == true ]]; then
    log_info "Retention-only mode: skipping copy."
    return 0
  fi

  log_info "Transferring encrypted backup to destination(s)..."
  local rsync_base=( rsync -aW --inplace --no-compress --partial --stats --info=progress2 )

  for dir in "${DEST_DIRS[@]}"; do
    if [[ "$DRY_RUN" == true ]]; then
      log_info "[DRY-RUN] Would rsync ${ARCHIVE_PATH} -> ${dir}/"
      continue
    fi

    if "${rsync_base[@]}" -- "$ARCHIVE_PATH" "$dir/" >>"$LOG_FILE" 2>&1 ; then
      echo "Backup successfully copied to $dir on $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    else
      log_error "Copy failed for $dir. See $LOG_FILE for rsync output."
      exit 50
    fi
  done
  log_info "Backup successfully copied to all destinations."
}

############################################
#            RETENTION POLICY              #
############################################

# Keep all <= RECENT_DAYS
# Keep newest per day for (RECENT_DAYS, MID_DAYS]
# Keep newest per ISO week for > MID_DAYS
apply_retention_policy() {
  if [[ "$SKIP_RETENTION" == true ]]; then
    log_info "Retention step skipped (--no-retention)."
    return 0
  fi

  log_info "Applying tiered retention policy..."

  for dir in "${DEST_DIRS[@]}"; do
    log_info "Evaluating: $dir"

    # Accumulators
    declare -A daily_keep=()
    declare -A weekly_keep=()
    declare -A best_mtime=()

    # 1) Select keepers (newest per bucket)
    while IFS= read -r -d '' file; do
      local filename date_str iso_date file_epoch age_days mtime key
      filename=$(basename -- "$file")
      date_str=$(sed -n 's/backup_\([0-9]\{2\}-[0-9]\{2\}-[0-9]\{4\}\)-.*\.tar\.gz\.enc/\1/p' <<<"$filename")
      [[ -z "$date_str" ]] && { log_warn "Skipping unrecognized file: $filename"; continue; }

      iso_date=$(awk -F- '{print $3"-"$2"-"$1}' <<<"$date_str")
      file_epoch=$(date -d "$iso_date" +%s 2>/dev/null || echo "")
      [[ -z "$file_epoch" ]] && { log_warn "Invalid date format: $date_str"; continue; }

      age_days=$(( ( $(date +%s) - file_epoch ) / 86400 ))
      mtime=$(stat -c %Y -- "$file" 2>/dev/null || echo 0)

      if (( age_days <= RECENT_DAYS )); then
        # Keep all
        continue
      elif (( age_days <= MID_DAYS )); then
        key=$(date -d "$iso_date" +%Y-%m-%d)
        if [[ -z "${daily_keep[$key]:-}" || "$mtime" -gt "${best_mtime[$key]:-0}" ]]; then
          daily_keep[$key]="$file"; best_mtime[$key]="$mtime"
        fi
      else
        key=$(date -d "$iso_date" +%G-%V)  # ISO year-week
        if [[ -z "${weekly_keep[$key]:-}" || "$mtime" -gt "${best_mtime[$key]:-0}" ]]; then
          weekly_keep[$key]="$file"; best_mtime[$key]="$mtime"
        fi
      fi
    done < <(find "$dir" -type f -name "backup_*.tar.gz.enc" -print0)

    # 2) Delete non-keepers for mid/older ranges
    while IFS= read -r -d '' file; do
      local filename date_str iso_date file_epoch age_days key
      filename=$(basename -- "$file")
      date_str=$(sed -n 's/backup_\([0-9]\{2\}-[0-9]\{2\}-[0-9]\{4\}\)-.*\.tar\.gz\.enc/\1/p' <<<"$filename")
      [[ -z "$date_str" ]] && continue
      iso_date=$(awk -F- '{print $3"-"$2"-"$1}' <<<"$date_str")
      file_epoch=$(date -d "$iso_date" +%s 2>/dev/null || echo "")
      [[ -z "$file_epoch" ]] && continue
      age_days=$(( ( $(date +%s) - file_epoch ) / 86400 ))

      if (( age_days <= RECENT_DAYS )); then
        continue
      elif (( age_days <= MID_DAYS )); then
        key=$(date -d "$iso_date" +%Y-%m-%d)
        if [[ "${daily_keep[$key]:-}" != "$file" ]]; then
          if [[ "$DRY_RUN" == true ]]; then
            log_info "[DRY-RUN] Would delete older daily duplicate: $filename"
          else
            rm -f -- "$file"
            log_info "Deleted older daily duplicate: $filename"
          fi
        fi
      else
        key=$(date -d "$iso_date" +%G-%V)
        if [[ "${weekly_keep[$key]:-}" != "$file" ]]; then
          if [[ "$DRY_RUN" == true ]]; then
            log_info "[DRY-RUN] Would delete older weekly duplicate: $filename"
          else
            rm -f -- "$file"
            log_info "Deleted older weekly duplicate: $filename"
          fi
        fi
      fi
    done < <(find "$dir" -type f -name "backup_*.tar.gz.enc" -print0)

    # unset associative arrays for next iteration
    unset daily_keep weekly_keep best_mtime
  done

  log_info "Tiered retention policy applied."
}

############################################
#                   MAIN                   #
############################################

main() {
  parse_args "$@"
  ensure_root_and_paths
  rotate_logs
  source_env_and_resolve_key

  # Make sure destination directories exist (and are private)
  for d in "${DEST_DIRS[@]}"; do
    mkdir -p -- "$d"
    chmod 700 "$d" || true
  done

  # Always prepare temp dir strictly
  chmod 700 "$TEMP_DIR"

  if [[ "$RETENTION_ONLY" == true ]]; then
    validate_mounts
    apply_retention_policy
    log_info "Retention-only process completed successfully."
    [[ "$CLEAR_TERMINAL" == true ]] && clear
    return 0
  fi

  validate_mounts
  check_temp_space
  stream_compress_encrypt
  check_disk_space_for_dests
  copy_backup_file
  apply_retention_policy
  log_info "Backup process completed successfully."

  if [[ "$CLEAR_TERMINAL" == true ]]; then
    clear
  fi
}

main "$@"
