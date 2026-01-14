#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# bulk_delete_users.sh
# Delete users from CSV with safety controls:
#  - Optional: remove home directory + mail spool
#  - Optional: kill user processes before deletion
#  - Optional: remove extra data paths (e.g., /tools_data/<user>)
#  - Dry-run mode
#  - Summary + exit codes
#
# CSV format (header optional):
#   username
#   jdoe
#   asmith
#
# Usage examples:
#   sudo ./bulk_delete_users.sh users_delete.csv --dry-run
#   sudo ./bulk_delete_users.sh users_delete.csv --remove-home --kill-procs
#   sudo ./bulk_delete_users.sh users_delete.csv --remove-home --extra-path "/tools_data/{user}" --extra-path "/backup/users/{user}"
#
# Exit codes:
#   0 = success (no failures)
#   1 = partial failure (some deletions failed)
#   2 = usage/config/precheck error
# -------------------------------------------------------------------

# ----------------------------
# Defaults / Config
# ----------------------------
DRY_RUN=false
REMOVE_HOME=false          # if true -> userdel -r (removes home + mail spool)
KILL_PROCS=false           # if true -> pkill -KILL -u <user> before userdel
REMOVE_EXTRA=false         # toggled when --extra-path used
EXTRA_PATHS=()             # templates allowed: /path/{user} or /path/${user}

# Strong safety guard: refuse to delete these accounts
PROTECTED_USERS_REGEX='^(root|bin|daemon|adm|lp|sync|shutdown|halt|mail|operator|games|ftp|nobody|systemd.*|sshd|dbus|polkitd|chrony|ntp|rpc|rpcuser)$'

LOG_FILE="./bulk_user_delete_$(date +%Y%m%d_%H%M%S).log"

# ----------------------------
# Helpers
# ----------------------------
log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 2; }
require_root() { [[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo)."; }

trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf "%s" "$s"
}

run_cmd() {
  if [[ "$DRY_RUN" == true ]]; then
    log "DRYRUN: $*"
    return 0
  fi
  "$@"
}

usage() {
  cat <<EOF
Usage:
  sudo $0 <csv_file> [options]

Options:
  --dry-run             Log actions but do not change anything
  --remove-home         Remove home directory and mail spool (userdel -r)
  --kill-procs          Kill user processes before deletion (pkill -KILL -u user)
  --extra-path <tmpl>   Remove extra user data path(s). Can be repeated.
                        Template supports {user} or \${user}
                        Examples:
                          --extra-path "/tools_data/{user}"
                          --extra-path "/data/home/{user}/shared"
  -h, --help            Show this help

CSV format (header optional):
  username
  jdoe
  asmith
EOF
}

# ----------------------------
# Args
# ----------------------------
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${#}" -eq 0 ]]; then
  usage
  exit 0
fi

CSV_FILE="$1"; shift || true

while [[ "${1:-}" != "" ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --remove-home) REMOVE_HOME=true ;;
    --kill-procs) KILL_PROCS=true ;;
    --extra-path)
      shift || true
      [[ -n "${1:-}" ]] || die "--extra-path requires a value"
      EXTRA_PATHS+=("$1")
      REMOVE_EXTRA=true
      ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
  shift || true
done

# ----------------------------
# Main
# ----------------------------
require_root
[[ -f "$CSV_FILE" ]] || die "CSV file not found: $CSV_FILE"

log "Starting bulk user deletion"
log "CSV_FILE=$CSV_FILE"
log "DRY_RUN=$DRY_RUN REMOVE_HOME=$REMOVE_HOME KILL_PROCS=$KILL_PROCS REMOVE_EXTRA=$REMOVE_EXTRA"
if [[ "${#EXTRA_PATHS[@]}" -gt 0 ]]; then
  log "EXTRA_PATHS=${EXTRA_PATHS[*]}"
fi
log "LOG_FILE=$LOG_FILE"

# Header detection: first cell equals "username"
first_line="$(head -n 1 "$CSV_FILE" | tr -d '\r')"
first_col="$(echo "$first_line" | awk -F',' '{print $1}')"
skip_header=false
if [[ "$(trim "$first_col")" == "username" ]]; then
  skip_header=true
  log "Detected CSV header: $(trim "$first_line")"
fi

# Summary counters
total=0
deleted=0
not_found=0
skipped_protected=0
skipped_invalid=0
skipped_empty=0
killed_procs=0
extra_removed=0
failures=0

# Per-user loop should continue on errors
set +e

line_no=0
while IFS=',' read -r username _rest; do
  line_no=$((line_no + 1))
  [[ "$skip_header" == true && "$line_no" -eq 1 ]] && continue

  username="$(trim "${username:-}")"

  # Skip empty/comment lines
  if [[ -z "$username" || "$username" =~ ^# ]]; then
    skipped_empty=$((skipped_empty + 1))
    continue
  fi

  # Conservative validation
  if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    log "WARN: Skipping invalid username '$username' (line $line_no)"
    skipped_invalid=$((skipped_invalid + 1))
    continue
  fi

  total=$((total + 1))

  # Hard safety guard for system/service accounts
  if [[ "$username" =~ $PROTECTED_USERS_REGEX ]]; then
    log "WARN: Skipping protected/system account '$username'"
    skipped_protected=$((skipped_protected + 1))
    continue
  fi

  if ! id "$username" >/dev/null 2>&1; then
    log "User not found: $username (nothing to delete)"
    not_found=$((not_found + 1))
    continue
  fi

  # Capture current home for logging
  current_home="$(getent passwd "$username" | cut -d: -f6)"

  log "Deleting user: $username | current_home='$current_home'"

  # Kill processes (optional)
  if [[ "$KILL_PROCS" == true ]]; then
    # pkill returns 0 if matched/killed, 1 if nothing matched; both are OK.
    run_cmd pkill -KILL -u "$username"
    rc=$?
    if [[ $rc -eq 0 ]]; then
      killed_procs=$((killed_procs + 1))
      log "Killed processes for $username"
    else
      log "No running processes to kill for $username (rc=$rc)"
    fi
  fi

  # Remove extra data paths (optional)
  if [[ "$REMOVE_EXTRA" == true && "${#EXTRA_PATHS[@]}" -gt 0 ]]; then
    for tmpl in "${EXTRA_PATHS[@]}"; do
      path="${tmpl//\{user\}/$username}"
      path="${path//\$\{user\}/$username}"

      if [[ -e "$path" ]]; then
        log "Removing extra path for $username: $path"
        run_cmd rm -rf --one-file-system "$path"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: Failed removing extra path '$path' for $username (rc=$rc)"
          failures=$((failures + 1))
        else
          extra_removed=$((extra_removed + 1))
        fi
      else
        log "Extra path not present (skip): $path"
      fi
    done
  fi

  # Delete user
  if [[ "$REMOVE_HOME" == true ]]; then
    run_cmd userdel -r "$username"
  else
    run_cmd userdel "$username"
  fi
  rc=$?
  if [[ $rc -ne 0 ]]; then
    log "ERROR: userdel failed for $username (rc=$rc)"
    failures=$((failures + 1))
    continue
  fi

  deleted=$((deleted + 1))
  log "Deleted: $username"

done < <(tr -d '\r' < "$CSV_FILE")

set -e

log "-------------------- SUMMARY --------------------"
log "Processed rows (valid users): $total"
log "Deleted users:               $deleted"
log "Users not found:             $not_found"
log "Skipped protected accounts:  $skipped_protected"
log "Skipped invalid usernames:   $skipped_invalid"
log "Skipped empty/comment lines: $skipped_empty"
log "Killed processes (attempts): $killed_procs"
log "Extra paths removed:         $extra_removed"
log "Failures:                    $failures"
log "-------------------------------------------------"

if [[ $failures -gt 0 ]]; then
  log "Completed with failures. Exit code: 1"
  exit 1
fi

log "Completed successfully. Exit code: 0"
exit 0
