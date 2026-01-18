#!/usr/bin/env bash


set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
umask 077
export LC_ALL=C

############################################
#               CONFIGURATION              #
############################################

# Default locations where backups are stored (match backup script)
DEFAULT_BACKUP_ROOTS=( "/mnt/katapult/kefs1" "/mnt/katapult/kefs2" )

# Secrets file (same as backup script)
ENV_FILE="/etc/backups/.env"

# Crypto (match backup script)
OPENSSL_CIPHER="aes-256-cbc"
OPENSSL_PBKDF2_ITER=100000

# Logging
LOG_FILE="/var/log/restore.log"

# UI / Colors
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m' # No Color

############################################
#                GLOBALS                   #
############################################

# Runtime options (CLI flags)
DRY_RUN=false
FORCE=false
NO_COLOR=false
VERIFY_ONLY=false

# Inputs (CLI or interactive)
BACKUP_ROOTS=("${DEFAULT_BACKUP_ROOTS[@]}")
SELECTED_ROOT=""
SELECTED_FILE=""
EXTRACT_DIR=""

# Secrets
OPENSSL_PASS_ARGS=()

# Temp
TEMP_DIR="$(mktemp -d /tmp/restore_tmp.XXXXXX)"

############################################
#                 LOGGING                  #
############################################

log() { printf "%s\n" "$*" >> "$LOG_FILE" ; }

info()  {
  if $NO_COLOR; then
    echo "[INFO]  $*"
  else
    echo -e "${GREEN}[INFO]${NC}  $*"
  fi
  log "[INFO]  $*"
}
warn()  {
  if $NO_COLOR; then
    echo "[WARN]  $*" >&2
  else
    echo -e "${YELLOW}[WARN]${NC}  $*" >&2
  fi
  log "[WARN]  $*"
}
error() {
  if $NO_COLOR; then
    echo "[ERROR] $*" >&2
  else
    echo -e "${RED}[ERROR]${NC} $*" >&2
  fi
  log "[ERROR] $*"
}

############################################
#                 TRAPS                    #
############################################

cleanup() {
  [[ -d "$TEMP_DIR" ]] && rm -rf -- "$TEMP_DIR" || true
}
report_err() {
  local exit_code=$?
  local src="${BASH_SOURCE[1]:-?}"
  local line="${BASH_LINENO[0]:-?}"
  error "Aborted with exit code ${exit_code} at ${src}:${line}"
  exit "$exit_code"
}
trap cleanup EXIT
trap report_err ERR
trap 'warn "Interrupted (SIGINT)"; exit 130' INT

############################################
#                SPINNER                   #
############################################

spinner() {
  local pid=$1
  local delay=0.1
  local spinstr=('⏳' '🔄' '🔁' '🔃')

  # Draw spinner on a single line without leaving artifacts
  while kill -0 "$pid" 2>/dev/null; do
    for s in "${spinstr[@]}"; do
      printf "\r%s " "$s"
      sleep "$delay"
    done
  done

  # Clear spinner line once
  printf "\r   \r"
}

############################################
#                  ARGS                    #
############################################

usage() {
  cat <<'USAGE'
Usage: restore.sh [options]

Options:
  --file PATH            Path to a specific backup_*.tar.gz.enc file to restore.
  --server PATH          Root directory containing backups (e.g., /mnt/katapult/kefs1).
  --dest-dir PATH        Destination directory to extract into.
  --verify-only          Only verify decryption (to /dev/null); do not extract.
  --dry-run              Log what would happen; no decryption/extraction.
  --force                Do not prompt for overwrite confirmations.
  --roots "R1 R2"        Override list of backup roots (space-separated, quoted).
  --env-file PATH        Override path to /etc/backups/.env.
  --key-file PATH        Override ENCRYPTION_KEY_FILE from env file.
  --iterations N         Override PBKDF2 iterations (default 100000).
  --no-color             Disable colored output.
  -h, --help             Show this help and exit.

Environment via /etc/backups/.env (preferred):
  ENCRYPTION_KEY_FILE=/etc/backups/key
  or
  ENCRYPTION_KEY=...

The script prefers ENCRYPTION_KEY_FILE for -pass file: and falls back to ENCRYPTION_KEY with -pass env:.
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --file) SELECTED_FILE="${2:?}"; shift 2 ;;
      --server) SELECTED_ROOT="${2:?}"; shift 2 ;;
      --dest-dir) EXTRACT_DIR="${2:?}"; shift 2 ;;
      --verify-only) VERIFY_ONLY=true; shift ;;
      --dry-run) DRY_RUN=true; shift ;;
      --force) FORCE=true; shift ;;
      --roots) IFS=' ' read -r -a BACKUP_ROOTS <<< "${2:?}"; shift 2 ;;
      --env-file) ENV_FILE="${2:?}"; shift 2 ;;
      --key-file) ENCRYPTION_KEY_FILE="${2:?}"; shift 2 ;;
      --iterations) OPENSSL_PBKDF2_ITER="${2:?}"; shift 2 ;;
      --no-color) NO_COLOR=true; shift ;;
      -h|--help) usage; exit 0 ;;
      --) shift; break ;;
      *) error "Unknown option: $1"; usage; exit 2 ;;
    esac
  done
}

############################################
#             PREREQUISITES                #
############################################

ensure_paths() {
  mkdir -p -- "$(dirname -- "$LOG_FILE")"
  touch "$LOG_FILE" 2>/dev/null || true
  chmod 0640 "$LOG_FILE" 2>/dev/null || true

  command -v openssl >/dev/null 2>&1 || { error "openssl not found"; exit 3; }
  command -v tar >/dev/null 2>&1 || { error "tar not found"; exit 3; }
}

source_env_and_key() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/etc/backups/.env
    . "$ENV_FILE"
  fi

  if [[ -n "${ENCRYPTION_KEY_FILE:-}" && -r "${ENCRYPTION_KEY_FILE}" ]]; then
    OPENSSL_PASS_ARGS=( -pass "file:${ENCRYPTION_KEY_FILE}" )
  elif [[ -n "${ENCRYPTION_KEY:-}" ]]; then
    export ENCRYPTION_KEY
    OPENSSL_PASS_ARGS=( -pass "env:ENCRYPTION_KEY" )
  else
    error "Missing encryption secret. Set ENCRYPTION_KEY_FILE (preferred) or ENCRYPTION_KEY in ${ENV_FILE}."
    exit 10
  fi
}

############################################
#             INTERACTIVE UI               #
############################################

select_backup_root() {
  # If provided via CLI, validate
  if [[ -n "$SELECTED_ROOT" ]]; then
    if [[ -d "$SELECTED_ROOT" && -r "$SELECTED_ROOT" ]]; then
      info "Using backup root: $SELECTED_ROOT"
      return 0
    else
      error "Provided --server path is not readable: $SELECTED_ROOT"
      exit 1
    fi
  fi

  # Filter to existing, readable roots
  local available=()
  for r in "${BACKUP_ROOTS[@]}"; do
    [[ -d "$r" && -r "$r" ]] && available+=("$r")
  done
  if ((${#available[@]} == 0)); then
    error "No readable backup roots found among: ${BACKUP_ROOTS[*]}"
    exit 1
  fi

  echo -e "${YELLOW}📡 Please choose the backup location to restore from:${NC}"
  PS3="➡️  Type the number corresponding to your chosen location: "
  select r in "${available[@]}"; do
    if [[ -n "$r" ]]; then
      SELECTED_ROOT="$r"
      break
    else
      echo -e "${RED}❌ Invalid selection. Try again.${NC}"
    fi
  done
  info "Selected backup root: $SELECTED_ROOT"
}

list_backup_files() {
  # If file provided, validate and return
  if [[ -n "$SELECTED_FILE" ]]; then
    if [[ -f "$SELECTED_FILE" && -r "$SELECTED_FILE" ]]; then
      info "Using backup file: $SELECTED_FILE"
      return 0
    else
      error "Provided --file is not readable: $SELECTED_FILE"
      exit 1
    fi
  fi

  # List files in the selected root
  local files=()
  # Sorted newest first
  while IFS= read -r f; do
    files+=("$f")
  done < <(ls -t "${SELECTED_ROOT}"/backup_*.tar.gz.enc 2>/dev/null || true)

  if ((${#files[@]} == 0)); then
    error "No backup_*.tar.gz.enc files found in ${SELECTED_ROOT}"
    exit 1
  fi

  echo -e "${YELLOW}📂 Available backup archives (newest first):${NC}"
  PS3="➡️  Choose the archive to restore: "
  select f in "${files[@]}"; do
    if [[ -n "$f" ]]; then
      SELECTED_FILE="$f"
      echo -e "${GREEN}✅ Selected: $SELECTED_FILE${NC}"
      break
    else
      echo -e "${RED}❌ Invalid selection. Try again.${NC}"
    fi
  done
}

is_protected_path() {
  # Reject extracting into system-critical dirs (exact or top-level)
  local p
  p="$(readlink -m -- "$1")"
  case "$p" in
    /|/etc|/bin|/usr|/sbin|/lib|/lib64|/root|/dev|/proc|/sys|/boot|/run|/mnt|/media|/var|/opt)
      return 0 ;;
    *)
      return 1 ;;
  esac
}

prompt_destination_dir() {
  if [[ -n "$EXTRACT_DIR" ]]; then
    :
  else
    echo -e "${YELLOW}📁 Enter the destination directory to extract into:${NC}"
    read -r EXTRACT_DIR
  fi

  if [[ -z "$EXTRACT_DIR" ]]; then
    error "Destination directory cannot be empty."
    exit 1
  fi

  # Normalize
  EXTRACT_DIR="$(readlink -m -- "$EXTRACT_DIR")"

  if is_protected_path "$EXTRACT_DIR"; then
    error "🚫 Destination '$EXTRACT_DIR' is protected. Choose another path."
    exit 1
  fi

  if [[ -d "$EXTRACT_DIR" ]]; then
    if [[ ! -w "$EXTRACT_DIR" ]]; then
      error "🚫 No write permission on $EXTRACT_DIR."
      exit 1
    fi
    if ! $FORCE; then
      echo -e "${YELLOW}⚠️  Directory exists. Overwrite its contents? (yes/no)${NC}"
      read -r CONFIRM
      [[ "$CONFIRM" == "yes" ]] || { error "Operation cancelled."; exit 1; }
    fi
  else
    echo -e "${BLUE}📁 Creating directory: $EXTRACT_DIR...${NC}"
    mkdir -p -- "$EXTRACT_DIR" && chmod 700 "$EXTRACT_DIR" || {
      error "Could not create $EXTRACT_DIR"
      exit 1
    }
  fi
}

############################################
#            RESTORE OPERATIONS            #
############################################

verify_decryption() {
  local file="$1"
  if $DRY_RUN; then
    info "[DRY-RUN] Would verify decryption for: $file"
    return 0
  fi

  info "🔍 Verifying decryption for: $file"
  (
    set -o pipefail
    openssl enc "-${OPENSSL_CIPHER}" -d -pbkdf2 -iter "${OPENSSL_PBKDF2_ITER}" \
      -in "$file" -out /dev/null \
      "${OPENSSL_PASS_ARGS[@]}" 2>>"$LOG_FILE"
  ) &
  local pid=$!
  spinner "$pid"
  wait "$pid"
  info "✅ Verification OK"
}

decrypt_and_extract() {
  local file="$1"

  if $VERIFY_ONLY; then
    verify_decryption "$file"
    return 0
  fi

  if $DRY_RUN; then
    info "[DRY-RUN] Would decrypt and extract:"
    info "         Source: $file"
    info "         Dest:   $EXTRACT_DIR"
    return 0
  fi

  info "🔐 Decrypting and extracting to: $EXTRACT_DIR"

  # Stream decryption into tar; pipefail ensures failures bubble up.
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
    info "✅ Files successfully restored to: $EXTRACT_DIR"
  else
    error "❌ Restore failed. Check $LOG_FILE for details."
    exit 1
  fi
}

############################################
#                   MAIN                   #
############################################

main() {
  parse_args "$@"
  ensure_paths
  source_env_and_key

  info "🔄 Initiating the backup restoration process..."

  # Pick root (unless file path already provided and absolute)
  if [[ -z "$SELECTED_FILE" ]]; then
    select_backup_root
  fi
  # Pick file (if not provided)
  list_backup_files

  # Destination dir (unless verify-only)
  if ! $VERIFY_ONLY; then
    prompt_destination_dir
  fi

  decrypt_and_extract "$SELECTED_FILE"

  info "🎉 Backup restoration completed."
}

main "$@"
