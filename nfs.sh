#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  NFS Backup — compress, encrypt, copy, and age-out backups
# ─────────────────────────────────────────────────────────────

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
umask 077
export LC_ALL=C

############################################
#               CONFIGURATION              #
############################################

DEFAULT_SOURCE_DIRS=( "/var/www" "/etc/caddy" "/var/log/" "/opt/" )
DEFAULT_DEST_DIRS=( "/mnt/katapult/kefs1/" )

DEST_SUBDIR="backups"
ENV_FILE="/etc/backups/.env"
LOG_FILE="/var/log/backup.log"
SYSLOG=false

# Crypto
OPENSSL_CIPHER="aes-256-cbc"
OPENSSL_PBKDF2_ITER=100000
BACKUP_TIMESTAMP_FMT="%d-%m-%Y-%I%p"
BACKUP_ARCHIVE_EXT="enc"

# Retention tiers (days)
RECENT_DAYS=60        # keep every backup
MID_DAYS=150          # keep one per day
: "${RETENTION_DAYS:=180}"  # keep one per week; delete everything older

############################################
#                GLOBALS                   #
############################################

DRY_RUN=false
SKIP_RETENTION=false
RETENTION_ONLY=false
CLEAR_TERMINAL=false

SOURCE_DIRS=("${DEFAULT_SOURCE_DIRS[@]}")
DEST_DIRS=("${DEFAULT_DEST_DIRS[@]}")
TEMP_DIR=""
ARCHIVE_PATH=""
OPENSSL_PASS_ARGS=()
NICE_CMD=()          # populated by ensure_root_and_paths

############################################
#               LOGGING                    #
############################################

# Disable colours when stdout is not a terminal (e.g. cron, pipe)
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; NC=""
fi

_log_file() {
  # Safe to call before the log file exists — silently skipped
  [[ -w "$LOG_FILE" ]] || return 0
  printf "[%s] [%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >> "$LOG_FILE"
  if [[ "$SYSLOG" == true ]]; then logger -t backup "[$1] $2"; fi
}
log_info()  { printf "%s[%s] [INFO] %s%s\n"  "$GREEN"  "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "$NC";     _log_file "INFO"  "$*"; }
log_warn()  { printf "%s[%s] [WARN] %s%s\n"  "$YELLOW" "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "$NC" >&2; _log_file "WARN"  "$*"; }
log_error() { printf "%s[%s] [ERROR] %s%s\n" "$RED"    "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "$NC" >&2; _log_file "ERROR" "$*"; }

############################################
#               ERROR TRAPS                #
############################################

cleanup() {
  if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR" 2>/dev/null || true
  fi
}
report_err() {
  local exit_code=$?
  log_error "Aborted with exit code ${exit_code} at ${BASH_SOURCE[1]:-?}:${BASH_LINENO[0]:-?}"
  exit "$exit_code"
}
trap cleanup EXIT
trap report_err ERR
trap 'log_warn "Interrupted (SIGINT)"; exit 130' INT
trap 'log_warn "Terminated (SIGTERM)"; exit 143' TERM

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
  --dest "D1 D2"      Override destination dirs (space-separated, quoted).
  --sources "S1 S2"   Override source dirs (space-separated, quoted).
  --key-file PATH     Override ENCRYPTION_KEY_FILE location.
  -h, --help          Show this help and exit.

Environment via /etc/backups/.env:
  ENCRYPTION_KEY_FILE=/etc/backups/key   # preferred
  or
  ENCRYPTION_KEY=...                     # fallback

Backups are stored under <dest>/<DEST_SUBDIR>/; falls back to <dest>/ root.
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)        DRY_RUN=true;             shift ;;
      --no-retention)   SKIP_RETENTION=true;      shift ;;
      --retention-only) RETENTION_ONLY=true;      shift ;;
      --syslog)         SYSLOG=true;              shift ;;
      --clear-terminal) CLEAR_TERMINAL=true;      shift ;;
      --log-file)       LOG_FILE="${2:?}";         shift 2 ;;
      --dest)           IFS=' ' read -r -a DEST_DIRS   <<< "${2:?}"; shift 2 ;;
      --sources)        IFS=' ' read -r -a SOURCE_DIRS <<< "${2:?}"; shift 2 ;;
      --key-file)       ENCRYPTION_KEY_FILE="${2:?}"; shift 2 ;;
      -h|--help)        usage; exit 0 ;;
      --)               shift; break ;;
      *)                log_error "Unknown option: $1"; usage; exit 2 ;;
    esac
  done
}

############################################
#             PREREQUISITES                #
############################################

require_commands() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 \
      || { log_error "Required command not found: $cmd"; exit 13; }
  done
}

ensure_root_and_paths() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 11
  fi

  mkdir -p -- "$(dirname -- "$LOG_FILE")"
  touch -- "$LOG_FILE" 2>/dev/null || true
  chmod 0640 "$LOG_FILE" 2>/dev/null || true

  require_commands tar openssl rsync mountpoint find awk sed stat du df mktemp

  # Build a niceness prefix array (safe to expand when empty)
  NICE_CMD=()
  if command -v ionice >/dev/null 2>&1; then NICE_CMD+=( ionice -c2 -n7 ); fi
  if command -v nice   >/dev/null 2>&1; then NICE_CMD+=( nice -n 19 );     fi

  # Create temp dir now that we know we are root
  TEMP_DIR="$(mktemp -d /tmp/backup_tmp.XXXXXX)"
  chmod 700 "$TEMP_DIR"
  local backup_name="backup_$(date +"${BACKUP_TIMESTAMP_FMT}").tar.gz"
  ARCHIVE_PATH="${TEMP_DIR}/${backup_name}.${BACKUP_ARCHIVE_EXT}"
}

rotate_logs() {
  local max_logs=5
  local today_log="${LOG_FILE}.$(date +%Y-%m-%d)"
  if [[ -f "$LOG_FILE" && ! -f "$today_log" ]]; then
    mv -- "$LOG_FILE" "$today_log"
    touch -- "$LOG_FILE"
    chmod 0640 "$LOG_FILE" || true
  fi
  # Prune rotated logs beyond $max_logs
  find "$(dirname -- "$LOG_FILE")" -maxdepth 1 \
    -name "$(basename -- "$LOG_FILE").*" -type f -printf '%T@ %p\n' 2>/dev/null \
    | sort -rn | tail -n +"$((max_logs + 1))" | cut -d' ' -f2- \
    | xargs -r rm -f --
}

source_env_and_resolve_key() {
  # Preserve a CLI-supplied --key-file across the env-file source
  local cli_key_file="${ENCRYPTION_KEY_FILE:-}"

  [[ -f "$ENV_FILE" ]] && . "$ENV_FILE"

  # CLI flag wins over env file
  [[ -n "$cli_key_file" ]] && ENCRYPTION_KEY_FILE="$cli_key_file"

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

validate_source_dirs() {
  local existing=() src
  for src in "${SOURCE_DIRS[@]}"; do
    if [[ -e "$src" ]]; then
      existing+=("$src")
    else
      log_warn "Source path does not exist (skipping): $src"
    fi
  done

  if ((${#existing[@]} == 0)); then
    log_error "None of the configured source paths exist."
    exit 14
  fi

  SOURCE_DIRS=("${existing[@]}")
  log_info "Source paths: ${SOURCE_DIRS[*]}"
}

############################################
#         MOUNTS / SPACE CHECKS            #
############################################

validate_mounts() {
  log_info "Validating mount points..."
  local valid=()

  for root in "${DEST_DIRS[@]}"; do
    if mountpoint -q -- "$root"; then
      valid+=("${root%/}")
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
  log_info "Checking temp space..."
  local source_size
  source_size=$(du -sb "${SOURCE_DIRS[@]}" 2>/dev/null | awk '{s+=$1} END{print s+0}')
  local required=$(( source_size + source_size / 3 ))
  local avail
  avail=$(df -B1 -- "$TEMP_DIR" | awk 'NR==2{print $4+0}')

  if (( avail < required )); then
    log_error "Temp dir too small ($TEMP_DIR). Need ${required}B, have ${avail}B."
    exit 80
  fi
  log_info "Temp space OK (${avail}B available, ${required}B needed)."
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

  local tar_exit=0
  (
    "${NICE_CMD[@]}" tar \
      --exclude='/var/log/journal/*' \
      --ignore-failed-read \
      --warning=no-file-changed \
      -czf - -C / "${SOURCE_DIRS[@]}" 2>>"$LOG_FILE"
  ) | "${NICE_CMD[@]}" openssl enc \
        "-${OPENSSL_CIPHER}" -salt -pbkdf2 \
        -iter "${OPENSSL_PBKDF2_ITER}" \
        -out "$ARCHIVE_PATH" \
        "${OPENSSL_PASS_ARGS[@]}" 2>>"$LOG_FILE" \
    || tar_exit=$?

  # tar returns 1 for "file changed during read" — that's expected for live logs
  if (( tar_exit > 1 )); then
    log_error "tar exited with code ${tar_exit} (archive may be incomplete)."
    exit 30
  fi

  if [[ ! -s "$ARCHIVE_PATH" ]]; then
    log_error "Encrypted archive not created or empty: $ARCHIVE_PATH"
    exit 31
  fi

  local size
  size=$(du -h -- "$ARCHIVE_PATH" | awk '{print $1}')
  log_info "Archive created: $ARCHIVE_PATH ($size)"
}

check_disk_space_for_dests() {
  [[ "$DRY_RUN" == true ]] && return 0

  log_info "Checking destination disk space..."
  local required
  required=$(stat -c %s -- "$ARCHIVE_PATH")

  for dest in "${DEST_DIRS[@]}"; do
    local target="$dest"
    [[ -d "${dest%/}/${DEST_SUBDIR}" ]] && target="${dest%/}/${DEST_SUBDIR}"
    local free
    free=$(df -B1 -- "$target" | awk 'NR==2{print $4+0}')
    if (( free < required )); then
      log_warn "Low space at $target (need ${required}B, have ${free}B)"
    fi
  done
}

############################################
#              COPY OPERATION              #
############################################

# dest_path <mount_root>  — returns the preferred target dir
dest_path() { local s="${1%/}/${DEST_SUBDIR}"; [[ -d "$s" ]] && echo "$s" || echo "${1%/}"; }

copy_backup_file() {
  [[ "$RETENTION_ONLY" == true ]] && { log_info "Retention-only: skipping copy."; return 0; }

  log_info "Copying backup to destination(s)..."

  if [[ "$DRY_RUN" == true ]]; then
    for base in "${DEST_DIRS[@]}"; do
      log_info "[DRY-RUN] Would copy -> ${base%/}/${DEST_SUBDIR}/ (or ${base%/}/)"
    done
    return 0
  fi

  local rsync_opts=( rsync -aW --inplace --no-compress --partial --stats --info=progress2 )
  local ok=0

  for base in "${DEST_DIRS[@]}"; do
    local sub="${base%/}/${DEST_SUBDIR}"

    # Try preferred subdir
    if mkdir -p -- "$sub" >>"$LOG_FILE" 2>&1 \
       && "${rsync_opts[@]}" -- "$ARCHIVE_PATH" "$sub/" >>"$LOG_FILE" 2>&1; then
      log_info "Copied to $sub"
      (( ++ok ))
      continue
    fi
    log_warn "Subdir copy failed for $sub; falling back to $base"

    # Fallback to mount root
    if "${rsync_opts[@]}" -- "$ARCHIVE_PATH" "${base%/}/" >>"$LOG_FILE" 2>&1; then
      log_info "Copied to ${base%/}"
      (( ++ok ))
    else
      log_error "Copy failed for ${base%/}. See $LOG_FILE."
    fi
  done

  if (( ok == 0 )); then
    log_error "Copy failed for ALL destinations."
    exit 50
  fi
  log_info "Backup delivered to ${ok} destination(s)."
}

############################################
#            RETENTION POLICY              #
############################################

# parse_backup_filename <filename>
#   Outputs: <iso_date> <epoch>   (or returns 1 on parse failure)
parse_backup_filename() {
  local fn="$1"
  local dmy
  dmy=$(sed -n 's/^backup_\([0-9]\{2\}-[0-9]\{2\}-[0-9]\{4\}\)-.*\.tar\.gz\.enc$/\1/p' <<<"$fn")
  [[ -z "$dmy" ]] && return 1

  local iso
  iso=$(awk -F- '{print $3"-"$2"-"$1}' <<<"$dmy")    # YYYY-MM-DD
  local epoch
  epoch=$(date -d "$iso" +%s 2>/dev/null) || return 1

  printf '%s %s\n' "$iso" "$epoch"
}

apply_retention_policy() {
  [[ "$SKIP_RETENTION" == true ]] && { log_info "Retention skipped (--no-retention)."; return 0; }

  log_info "Applying tiered retention policy..."
  local now_epoch
  now_epoch=$(date +%s)

  for root in "${DEST_DIRS[@]}"; do
    local scan="$root"
    [[ -d "${root%/}/${DEST_SUBDIR}" ]] && scan="${root%/}/${DEST_SUBDIR}"
    log_info "Scanning: $scan"

    # ── Pass 1: classify every backup and elect keepers ──
    declare -A keep_daily=() keep_weekly=() best_mtime=()
    local -a all_files=()

    while IFS= read -r -d '' file; do
      all_files+=("$file")

      local fn iso epoch age_days mtime key
      fn=$(basename -- "$file")

      local parsed
      parsed=$(parse_backup_filename "$fn") || { log_warn "Unrecognised file: $fn"; continue; }
      read -r iso epoch <<<"$parsed"

      age_days=$(( (now_epoch - epoch) / 86400 ))
      mtime=$(stat -c %Y -- "$file" 2>/dev/null || echo 0)

      if (( age_days <= RECENT_DAYS )); then
        continue                         # kept unconditionally
      elif (( age_days <= MID_DAYS )); then
        key=$(date -d "$iso" +%Y-%m-%d)  # one per calendar day
        if [[ -z "${keep_daily[$key]:-}" || mtime -gt "${best_mtime[$key]:-0}" ]]; then
          keep_daily[$key]="$file"; best_mtime[$key]="$mtime"
        fi
      elif (( age_days <= RETENTION_DAYS )); then
        key=$(date -d "$iso" +%G-%V)     # one per ISO week
        if [[ -z "${keep_weekly[$key]:-}" || mtime -gt "${best_mtime[$key]:-0}" ]]; then
          keep_weekly[$key]="$file"; best_mtime[$key]="$mtime"
        fi
      fi
      # age > RETENTION_DAYS → not elected, will be deleted below
    done < <(find "$scan" -maxdepth 1 -type f -name "backup_*.tar.gz.enc" -print0)

    # Build a set of keeper paths for O(1) lookup
    declare -A keepers=()
    local v
    for v in "${keep_daily[@]}";  do keepers["$v"]=1; done
    for v in "${keep_weekly[@]}"; do keepers["$v"]=1; done

    # ── Pass 2 (in-memory): delete non-keepers ──
    local deleted=0
    for file in "${all_files[@]}"; do
      local fn iso epoch age_days
      fn=$(basename -- "$file")

      local parsed
      parsed=$(parse_backup_filename "$fn") || continue
      read -r iso epoch <<<"$parsed"
      age_days=$(( (now_epoch - epoch) / 86400 ))

      # Recent backups are always kept
      (( age_days <= RECENT_DAYS )) && continue

      # Elected keepers are kept
      [[ -n "${keepers[$file]:-}" ]] && continue

      # Everything else is pruned
      local reason="duplicate"
      (( age_days > RETENTION_DAYS )) && reason="expired (>${RETENTION_DAYS}d old)"

      if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would delete ${reason}: $fn"
      else
        rm -f -- "$file"
        log_info "Deleted ${reason}: $fn"
      fi
      (( ++deleted ))
    done

    log_info "Retention for $scan: reviewed ${#all_files[@]} file(s), pruned ${deleted}."
    unset keep_daily keep_weekly best_mtime keepers
  done

  log_info "Retention policy applied."
}

############################################
#                   MAIN                   #
############################################

main() {
  parse_args "$@"
  ensure_root_and_paths
  rotate_logs
  source_env_and_resolve_key

  for d in "${DEST_DIRS[@]}"; do mkdir -p -- "$d" || true; done
  validate_source_dirs

  if [[ "$RETENTION_ONLY" == true ]]; then
    validate_mounts
    apply_retention_policy
    log_info "Retention-only run completed."
    [[ "$CLEAR_TERMINAL" == true ]] && clear
    return 0
  fi

  validate_mounts
  check_temp_space
  stream_compress_encrypt
  check_disk_space_for_dests
  copy_backup_file
  apply_retention_policy
  log_info "Backup completed successfully."

  trap - ERR
  [[ "$CLEAR_TERMINAL" == true ]] && clear
  return 0
}

main "$@"
