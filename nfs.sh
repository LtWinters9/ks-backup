#!/usr/bin/env bash


set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
umask 077
export LC_ALL=C

############################################
#               CONFIGURATION              #
############################################

DEFAULT_SOURCE_DIRS=( "/var/www" "/etc/caddy" "/var/log/" "/opt/" )
DEFAULT_DEST_DIRS=( "/mnt/katapult/kefs1/" "/mnt/katapult/kefs2/" )

# Preferred subdirectory under each destination mount
DEST_SUBDIR="backups"

# Secrets
ENV_FILE="/etc/backups/.env"

# Logging
LOG_FILE="/var/log/backup.log"
SYSLOG=false

# Crypto
OPENSSL_CIPHER="aes-256-cbc"
OPENSSL_PBKDF2_ITER=100000
BACKUP_TIMESTAMP_FMT="%d-%m-%Y-%I%p"
BACKUP_NAME="backup_$(date +"${BACKUP_TIMESTAMP_FMT}").tar.gz"
BACKUP_ARCHIVE_EXT="enc"

# Niceness (auto-detected)
NICE_WRAP=""

# Retention policy (days)
RECENT_DAYS=60
MID_DAYS=150
: "${RETENTION_DAYS:=180}"

############################################
#                GLOBALS                   #
############################################

DRY_RUN=false
SKIP_RETENTION=false
RETENTION_ONLY=false
CLEAR_TERMINAL=false

SOURCE_DIRS=("${DEFAULT_SOURCE_DIRS[@]}")
DEST_DIRS=("${DEFAULT_DEST_DIRS[@]}")    # mount roots; copy step prefers subdir
TEMP_DIR="$(mktemp -d /tmp/backup_tmp.XXXXXX)"
ARCHIVE_PATH="${TEMP_DIR}/${BACKUP_NAME}.${BACKUP_ARCHIVE_EXT}"
OPENSSL_PASS_ARGS=()

############################################
#               LOGGING                    #
############################################

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'

log_plain() {
  local when level msg
  when="$(date '+%Y-%m-%d %H:%M:%S')"
  level="$1"; shift; msg="$*"
  printf "[%s] [%s] %s\n" "$when" "$level" "$msg" >> "$LOG_FILE"
  if [[ "$SYSLOG" == true ]]; then logger -t backup "[$level] $msg"; fi
}
log_info() { echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*${NC}"; log_plain "INFO" "$*"; }
log_warn() { echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*${NC}" >&2; log_plain "WARN" "$*"; }
log_error(){ echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*${NC}" >&2; log_plain "ERROR" "$*"; }

############################################
#               ERROR TRAPS                #
############################################

cleanup() {
  # Best-effort; avoid logging during EXIT to prevent ERR at teardown
  if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR" 2>/dev/null || true
  fi
}
report_err() {
  local exit_code=$?
  local src="${BASH_SOURCE[1]:-?}"
  local line="${BASH_LINENO[0]:-?}"
  # Keep logging for errors during main work
  echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Aborted with exit code ${exit_code} at ${src}:${line}${NC}" >&2
  log_plain "ERROR" "Aborted with exit code ${exit_code} at ${src}:${line}"
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
  --dry-run           No copy or deletions; log actions only.
  --no-retention      Skip retention step.
  --retention-only    Only apply retention; no backup creation.
  --syslog            Also log via `logger`.
  --clear-terminal    Clear the terminal at the end.
  --log-file PATH     Override log file path.
  --dest "D1 D2"      Override destination directories (space-separated, quoted).
  --sources "S1 S2"   Override source directories (space-separated, quoted).
  --key-file PATH     Override ENCRYPTION_KEY_FILE location.
  -h, --help          Show this help and exit.

Environment via /etc/backups/.env:
  ENCRYPTION_KEY_FILE=/etc/backups/key   # preferred
  or
  ENCRYPTION_KEY=...                     # fallback

Backups prefer <dest>/<DEST_SUBDIR>/; if not writable, fallback to <dest> root.
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
  mkdir -p -- "$(dirname -- "$LOG_FILE")"
  : > "$LOG_FILE" 2>/dev/null || true
  chmod 0640 "$LOG_FILE" 2>/dev/null || true

  local ion="" nic=""
  if command -v ionice >/dev/null 2>&1; then ion="ionice -c2 -n7"; fi
  if command -v nice   >/dev/null 2>&1; then nic="nice -n 19"; fi
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
  ls -1t "${LOG_FILE}".* 2>/dev/null | tail -n +"$((max_logs + 1))" | xargs -r rm -f --
}

source_env_and_resolve_key() {
  [[ -f "$ENV_FILE" ]] && . "$ENV_FILE"
  if [[ -n "${ENCRYPTION_KEY_FILE:-}" && -r "${ENCRYPTION_KEY_FILE}" ]]; then
    OPENSSL_PASS_ARGS=( -pass "file:${ENCRYPTION_KEY_FILE}" )
  elif [[ -n "${ENCRYPTION_KEY:-}" ]]; then
    export ENCRYPTION_KEY
    OPENSSL_PASS_ARGS=( -pass "env:ENCRYPTION_KEY" )
  else
    log_error "Missing encryption secret. Set ENCRYPTION_KEY_FILE or ENCRYPTION_KEY in ${ENV_FILE}."
    exit 10
  fi
}

############################################
#         MOUNTS / SPACE CHECKS            #
############################################

validate_mounts() {
  log_info "Validating mount points (mountpoint-only; writability checked during copy)..."
  local valid=()

  for root in "${DEST_DIRS[@]}"; do
    if mountpoint -q -- "$root"; then
      valid+=("${root%/}")   # keep mount root
    else
      log_warn "Not a mountpoint (skipping): $root"
    fi
  done

  if ((${#valid[@]} == 0)); then
    log_error "No valid destination mounts found."
    exit 12
  fi

  DEST_DIRS=("${valid[@]}")
  log_info "Validated mounts: ${DEST_DIRS[*]}"
}

check_temp_space() {
  log_info "Checking available space for temporary backup files..."
  local source_size
  source_size=$(du -sb "${SOURCE_DIRS[@]}" 2>/dev/null | awk '{sum += $1} END {print sum+0}')
  local required=$((source_size + source_size / 3))
  local temp_free
  temp_free=$(df -B1 -- "$TEMP_DIR" | awk 'NR==2{print $4+0}')
  if (( temp_free < required )); then
    log_error "Not enough space in temp dir ($TEMP_DIR). Need ${required}B, free ${temp_free}B."
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

  (
    ${NICE_WRAP} tar --exclude='/var/log/journal/*' \
      --ignore-failed-read --warning=no-file-changed \
      -czf - -C / "${SOURCE_DIRS[@]}" 2>>"$LOG_FILE" \
    || true
  ) | ${NICE_WRAP} openssl enc "-${OPENSSL_CIPHER}" -salt -pbkdf2 -iter "${OPENSSL_PBKDF2_ITER}" \
        -out "$ARCHIVE_PATH" \
        "${OPENSSL_PASS_ARGS[@]}" \
        2>>"$LOG_FILE"

  [[ -s "$ARCHIVE_PATH" ]] || { log_error "Encrypted archive not created or empty: $ARCHIVE_PATH"; exit 31; }
  log_info "Encrypted archive created: $ARCHIVE_PATH"
}

check_disk_space_for_dests() {
  [[ "$DRY_RUN" == true ]] && { log_info "[DRY-RUN] Skipping destination space check."; return 0; }
  log_info "Verifying available disk space on destinations..."
  local required; required=$(du -sb -- "$ARCHIVE_PATH" | awk '{print $1+0}')
  for dest in "${DEST_DIRS[@]}"; do
    local target="$dest"
    # Prefer subdir if it exists; otherwise use root for df
    [[ -d "${dest%/}/${DEST_SUBDIR}" ]] && target="${dest%/}/${DEST_SUBDIR}"
    local free; free=$(df -B1 -- "$target" | awk 'NR==2{print $4+0}')
    if (( free < required )); then
      log_warn "Low space at $target. Required=${required}B Free=${free}B"
    fi
  done
}

############################################
#              COPY OPERATION              #
############################################

copy_backup_file() {
  if [[ "$RETENTION_ONLY" == true ]]; then
    log_info "Retention-only mode: skipping copy."
    return 0
  fi

  log_info "Transferring encrypted backup to destination(s)..."
  local rsync_base=( rsync -aW --inplace --no-compress --partial --stats --info=progress2 )
  local successes=0

  for base in "${DEST_DIRS[@]}"; do
    local sub="${base%/}/${DEST_SUBDIR}"

    if [[ "$DRY_RUN" == true ]]; then
      log_info "[DRY-RUN] Would try: ${ARCHIVE_PATH} -> ${sub}/ (preferred), else -> ${base}/"
      continue
    fi

    # Try preferred subdir first
    if mkdir -p -- "$sub" >>"$LOG_FILE" 2>&1; then
      if "${rsync_base[@]}" -- "$ARCHIVE_PATH" "$sub/" >>"$LOG_FILE" 2>&1 ; then
        echo "Backup successfully copied to $sub on $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
        successes=$((successes+1))
        continue
      else
        log_warn "Copy to $sub failed; attempting fallback to mount root $base"
      fi
    else
      log_warn "Cannot create/access preferred subdir $sub; attempting mount root $base"
    fi

    # Fallback to mount root
    if "${rsync_base[@]}" -- "$ARCHIVE_PATH" "${base%/}/" >>"$LOG_FILE" 2>&1 ; then
      echo "Backup successfully copied to ${base%/} on $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
      successes=$((successes+1))
    else
      log_error "Copy failed for ${base%/}. See $LOG_FILE for rsync output."
    fi
  done

  if (( successes == 0 )); then
    log_error "Copy failed for all destinations."
    exit 50
  fi

  log_info "Backup successfully copied to $successes destination(s)."
}

############################################
#            RETENTION POLICY              #
############################################

apply_retention_policy() {
  if [[ "$SKIP_RETENTION" == true ]]; then
    log_info "Retention step skipped (--no-retention)."
    return 0
  fi

  log_info "Applying tiered retention policy..."

  for root in "${DEST_DIRS[@]}"; do
    local scan="$root"
    [[ -d "${root%/}/${DEST_SUBDIR}" ]] && scan="${root%/}/${DEST_SUBDIR}"
    log_info "Evaluating: $scan"

    declare -A daily_keep=() weekly_keep=() best_mtime=()

    # Select keepers (newest per bucket)
    while IFS= read -r -d '' file; do
      local filename date_str iso_date file_epoch age_days mtime key
      filename=$(basename -- "$file")
      date_str=$(sed -n 's/backup_\([0-9]\{2\}-[0-9]\{2\}-[0-9]\{4\}\)-.*\.tar\.gz\.enc/\1/p' <<<"$filename")
      [[ -z "$date_str" ]] && { log_warn "Skipping unrecognized file: $filename"; continue; }
      iso_date=$(awk -F- '{print $3"-"$2"-"$1}' <<<"$date_str")
      file_epoch=$(date -d "$iso_date" +%s 2>/dev/null || echo "")
      [[ -z "$file_epoch" ]] && { log_warn "Invalid date: $date_str"; continue; }
      age_days=$(( ( $(date +%s) - file_epoch ) / 86400 ))
      mtime=$(stat -c %Y -- "$file" 2>/dev/null || echo 0)

      if (( age_days <= RECENT_DAYS )); then
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
    done < <(find "$scan" -type f -name "backup_*.tar.gz.enc" -print0)

    # Delete non-keepers for mid/older ranges
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
            rm -f -- "$file"; log_info "Deleted older daily duplicate: $filename"
          fi
        fi
      else
        key=$(date -d "$iso_date" +%G-%V)
        if [[ "${weekly_keep[$key]:-}" != "$file" ]]; then
          if [[ "$DRY_RUN" == true ]]; then
            log_info "[DRY-RUN] Would delete older weekly duplicate: $filename"
          else
            rm -f -- "$file"; log_info "Deleted older weekly duplicate: $filename"
          fi
        fi
      fi
    done < <(find "$scan" -type f -name "backup_*.tar.gz.enc" -print0)

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

  # Ensure mount roots exist locally (mounts themselves are validated next)
  for d in "${DEFAULT_DEST_DIRS[@]}"; do mkdir -p -- "$d" || true; done
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

  # Disarm ERR trap before graceful exit, to avoid benign teardown returning non-zero
  trap - ERR

  [[ "$CLEAR_TERMINAL" == true ]] && clear
  return 0
}

# Ensure the script exits 0 if main completed the happy path
main "$@" || exit $?
exit 0
