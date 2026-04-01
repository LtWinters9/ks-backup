#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Restore — decrypt and extract encrypted NFS backups
# ─────────────────────────────────────────────────────────────

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
umask 077
export LC_ALL=C

############################################
#               CONFIGURATION              #
############################################

DEFAULT_BACKUP_ROOTS=( "/mnt/katapult/kefs1" "/mnt/katapult/kefs2" )
DEST_SUBDIR="backups"            # mirrors the backup script's layout

ENV_FILE="/etc/backups/.env"
LOG_FILE="/var/log/restore.log"

# Crypto — must match the backup script
OPENSSL_CIPHER="aes-256-cbc"
OPENSSL_PBKDF2_ITER=100000

############################################
#                GLOBALS                   #
############################################

DRY_RUN=false
FORCE=false
VERIFY_ONLY=false

BACKUP_ROOTS=("${DEFAULT_BACKUP_ROOTS[@]}")
SELECTED_ROOT=""
SELECTED_FILE=""
EXTRACT_DIR=""
SCAN_PATH=""
OPENSSL_PASS_ARGS=()
TEMP_DIR=""

############################################
#                 LOGGING                  #
############################################

# Auto-disable colour when not on a terminal (cron, pipes, --no-color)
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
  BLUE=$'\033[0;34m'; NC=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; NC=""
fi

_log_file() {
  [[ -w "${LOG_FILE:-}" ]] || return 0
  printf "[%s] [%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >> "$LOG_FILE"
}

info()  { printf "%s[INFO]%s  %s\n"  "$GREEN"  "$NC" "$*";      _log_file INFO  "$*"; }
warn()  { printf "%s[WARN]%s  %s\n"  "$YELLOW" "$NC" "$*" >&2;  _log_file WARN  "$*"; }
error() { printf "%s[ERROR]%s %s\n"  "$RED"    "$NC" "$*" >&2;  _log_file ERROR "$*"; }

# Coloured prompt helper (only used in interactive menus)
prompt() { printf "%s%s%s\n" "$YELLOW" "$*" "$NC"; }

############################################
#                 TRAPS                    #
############################################

cleanup() {
  if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR" 2>/dev/null || true
  fi
}
report_err() {
  local rc=$?
  error "Aborted (exit ${rc}) at ${BASH_SOURCE[1]:-?}:${BASH_LINENO[0]:-?}"
  exit "$rc"
}
trap cleanup EXIT
trap report_err ERR
trap 'warn "Interrupted (SIGINT)";  exit 130' INT
trap 'warn "Terminated (SIGTERM)"; exit 143' TERM

############################################
#                SPINNER                   #
############################################

spinner() {
  local pid=$1 delay=0.1
  # Use ASCII when not on a UTF-8 terminal
  local chars=( '|' '/' '-' '\' )
  while kill -0 "$pid" 2>/dev/null; do
    for c in "${chars[@]}"; do
      printf "\r  %s " "$c"
      sleep "$delay"
    done
  done
  printf "\r    \r"
}

############################################
#                  ARGS                    #
############################################

usage() {
  cat <<'USAGE'
Usage: restore.sh [options]

Options:
  --file PATH        Path to a specific backup_*.tar.gz.enc file.
  --server PATH      Root directory containing backups.
  --dest-dir PATH    Destination directory to extract into.
  --verify-only      Only verify decryption (decrypt to /dev/null).
  --dry-run          Log what would happen; no decryption/extraction.
  --force            Skip overwrite confirmation prompts.
  --roots "R1 R2"    Override default backup root list.
  --env-file PATH    Override /etc/backups/.env path.
  --key-file PATH    Override ENCRYPTION_KEY_FILE (takes precedence over env).
  --iterations N     Override PBKDF2 iterations (default 100000).
  --no-color         Disable coloured output.
  -h, --help         Show this help and exit.

Environment via /etc/backups/.env (preferred):
  ENCRYPTION_KEY_FILE=/etc/backups/key
  or
  ENCRYPTION_KEY=...
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --file)        SELECTED_FILE="${2:?}";                         shift 2 ;;
      --server)      SELECTED_ROOT="${2:?}";                         shift 2 ;;
      --dest-dir)    EXTRACT_DIR="${2:?}";                           shift 2 ;;
      --verify-only) VERIFY_ONLY=true;                               shift ;;
      --dry-run)     DRY_RUN=true;                                   shift ;;
      --force)       FORCE=true;                                     shift ;;
      --roots)       IFS=' ' read -r -a BACKUP_ROOTS <<< "${2:?}";  shift 2 ;;
      --env-file)    ENV_FILE="${2:?}";                               shift 2 ;;
      --key-file)    ENCRYPTION_KEY_FILE="${2:?}";                   shift 2 ;;
      --iterations)  OPENSSL_PBKDF2_ITER="${2:?}";                   shift 2 ;;
      --no-color)    RED=""; GREEN=""; YELLOW=""; BLUE=""; NC="";    shift ;;
      -h|--help)     usage; exit 0 ;;
      --)            shift; break ;;
      *)             error "Unknown option: $1"; usage; exit 2 ;;
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
      || { error "Required command not found: $cmd"; exit 3; }
  done
}

ensure_env() {
  mkdir -p -- "$(dirname -- "$LOG_FILE")"
  touch -- "$LOG_FILE" 2>/dev/null || true
  chmod 0640 "$LOG_FILE" 2>/dev/null || true

  require_commands openssl tar find stat readlink

  TEMP_DIR="$(mktemp -d /tmp/restore_tmp.XXXXXX)"
  chmod 700 "$TEMP_DIR"
}

source_env_and_key() {
  local cli_key_file="${ENCRYPTION_KEY_FILE:-}"

  [[ -f "$ENV_FILE" ]] && . "$ENV_FILE"

  # CLI --key-file always wins over the env file
  [[ -n "$cli_key_file" ]] && ENCRYPTION_KEY_FILE="$cli_key_file"

  if [[ -n "${ENCRYPTION_KEY_FILE:-}" && -r "${ENCRYPTION_KEY_FILE}" ]]; then
    OPENSSL_PASS_ARGS=( -pass "file:${ENCRYPTION_KEY_FILE}" )
  elif [[ -n "${ENCRYPTION_KEY:-}" ]]; then
    export ENCRYPTION_KEY
    OPENSSL_PASS_ARGS=( -pass "env:ENCRYPTION_KEY" )
  else
    error "Missing encryption secret. Set ENCRYPTION_KEY_FILE or ENCRYPTION_KEY in ${ENV_FILE}."
    exit 10
  fi
}

############################################
#             PATH RESOLUTION              #
############################################

# Prefer <root>/backups/ if it exists, else <root>/ itself
resolve_scan_path() {
  local root="${1%/}"
  local sub="${root}/${DEST_SUBDIR}"
  [[ -d "$sub" ]] && echo "$sub" || echo "$root"
}

############################################
#             INTERACTIVE UI               #
############################################

select_backup_root() {
  # Already specified via --server
  if [[ -n "$SELECTED_ROOT" ]]; then
    if [[ -d "$SELECTED_ROOT" && -r "$SELECTED_ROOT" ]]; then
      SCAN_PATH="$(resolve_scan_path "$SELECTED_ROOT")"
      info "Backup root: $SELECTED_ROOT  (scan: $SCAN_PATH)"
      return 0
    fi
    error "--server path not readable: $SELECTED_ROOT"
    exit 1
  fi

  # Filter to readable roots
  local available=()
  for r in "${BACKUP_ROOTS[@]}"; do
    [[ -d "$r" && -r "$r" ]] && available+=("$r")
  done
  if ((${#available[@]} == 0)); then
    error "No readable backup roots among: ${BACKUP_ROOTS[*]}"
    exit 1
  fi

  prompt "Choose the backup location to restore from:"
  PS3="  #> "
  select r in "${available[@]}"; do
    if [[ -n "$r" ]]; then
      SELECTED_ROOT="$r"
      break
    fi
    error "Invalid selection — try again."
  done
  SCAN_PATH="$(resolve_scan_path "$SELECTED_ROOT")"
  info "Selected root: $SELECTED_ROOT  (scan: $SCAN_PATH)"
}

list_backup_files() {
  # Specific file already provided
  if [[ -n "$SELECTED_FILE" ]]; then
    if [[ -f "$SELECTED_FILE" && -r "$SELECTED_FILE" ]]; then
      info "Backup file: $SELECTED_FILE"
      return 0
    fi
    error "--file not readable: $SELECTED_FILE"
    exit 1
  fi

  # Derive SCAN_PATH if not yet set
  if [[ -z "$SCAN_PATH" && -n "$SELECTED_ROOT" ]]; then
    SCAN_PATH="$(resolve_scan_path "$SELECTED_ROOT")"
  fi
  [[ -n "$SCAN_PATH" ]] || { error "SCAN_PATH not resolved"; exit 1; }

  # Collect files sorted newest-first (NUL-safe, no ls)
  local files=()
  while IFS= read -r -d '' f; do
    files+=("$f")
  done < <(find "$SCAN_PATH" -maxdepth 1 -type f -name "backup_*.tar.gz.enc" -printf '%T@ %p\0' \
           | sort -rzn | sed -z 's/^[^ ]* //')

  if ((${#files[@]} == 0)); then
    error "No backup_*.tar.gz.enc files in ${SCAN_PATH}"
    exit 1
  fi

  prompt "Available backups (newest first):"
  PS3="  #> "
  select f in "${files[@]}"; do
    if [[ -n "$f" ]]; then
      SELECTED_FILE="$f"
      info "Selected: $SELECTED_FILE"
      break
    fi
    error "Invalid selection — try again."
  done
}

# Reject extracting directly into critical system directories
is_protected_path() {
  local p
  p="$(readlink -m -- "$1")"
  case "$p" in
    /|/bin|/boot|/dev|/etc|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/sys|/usr|/var)
      return 0 ;;
  esac
  return 1
}

prompt_destination_dir() {
  if [[ -z "$EXTRACT_DIR" ]]; then
    prompt "Enter the destination directory to extract into:"
    read -r EXTRACT_DIR
  fi

  [[ -n "$EXTRACT_DIR" ]] || { error "Destination directory cannot be empty."; exit 1; }

  EXTRACT_DIR="$(readlink -m -- "$EXTRACT_DIR")"

  if is_protected_path "$EXTRACT_DIR"; then
    error "Destination '$EXTRACT_DIR' is a protected system path. Choose another."
    exit 1
  fi

  if [[ -d "$EXTRACT_DIR" ]]; then
    [[ -w "$EXTRACT_DIR" ]] || { error "No write permission on $EXTRACT_DIR."; exit 1; }

    if [[ "$FORCE" != true ]]; then
      prompt "Directory exists. Overwrite contents? (yes/no)"
      local confirm
      read -r confirm
      [[ "$confirm" == "yes" ]] || { error "Cancelled by user."; exit 1; }
    fi
  else
    info "Creating: $EXTRACT_DIR"
    mkdir -p -- "$EXTRACT_DIR"
    chmod 700 "$EXTRACT_DIR"
  fi
}

############################################
#            RESTORE OPERATIONS            #
############################################

verify_decryption() {
  local file="$1"

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would verify decryption: $file"
    return 0
  fi

  info "Verifying decryption: $(basename -- "$file")"
  openssl enc "-${OPENSSL_CIPHER}" -d -pbkdf2 -iter "${OPENSSL_PBKDF2_ITER}" \
    -in "$file" -out /dev/null \
    "${OPENSSL_PASS_ARGS[@]}" 2>>"$LOG_FILE" &
  local pid=$!
  spinner "$pid"
  wait "$pid"
  info "Verification OK."
}

decrypt_and_extract() {
  local file="$1"

  if [[ "$VERIFY_ONLY" == true ]]; then
    verify_decryption "$file"
    return 0
  fi

  if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] Would decrypt and extract:"
    info "  Source: $file"
    info "  Dest:   $EXTRACT_DIR"
    return 0
  fi

  info "Decrypting and extracting to: $EXTRACT_DIR"

  (
    set -o pipefail
    openssl enc "-${OPENSSL_CIPHER}" -d -pbkdf2 -iter "${OPENSSL_PBKDF2_ITER}" \
      -in "$file" -out - \
      "${OPENSSL_PASS_ARGS[@]}" 2>>"$LOG_FILE" \
    | tar -xz -C "$EXTRACT_DIR" 2>>"$LOG_FILE"
  ) &
  local pid=$!
  spinner "$pid"

  if wait "$pid"; then
    info "Restore complete: $EXTRACT_DIR"
  else
    error "Restore failed. See $LOG_FILE for details."
    exit 1
  fi
}

############################################
#                   MAIN                   #
############################################

main() {
  parse_args "$@"
  ensure_env
  source_env_and_key

  info "Starting restore..."

  # Select backup location and file
  [[ -z "$SELECTED_FILE" ]] && select_backup_root
  list_backup_files

  # Destination (unless verify-only)
  [[ "$VERIFY_ONLY" != true ]] && prompt_destination_dir

  decrypt_and_extract "$SELECTED_FILE"

  info "Restore completed successfully."
}

main "$@"
