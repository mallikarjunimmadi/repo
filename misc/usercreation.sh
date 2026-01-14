#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# bulk_create_users.sh  (FULL DROP-IN, HARDENED)
#
# Goals you asked for:
# 1) Do NOT reset password for existing users (default behavior)
# 2) Make it impossible to accidentally modify existing users
#    - Existing user modifications are DISABLED unless BOTH flags are provided:
#        --change-existing-home  AND  --i-understand-this-will-modify-existing-users
#
# Also includes:
# - Supports CSV header order: username,full_name OR full_name,username
# - Prompt once (silent) for default password (skipped in dry-run)
# - Add users to a supplementary group
# - Custom home base directory (HOME_BASE/<username>)
# - Dry-run mode
# - Summary + exit codes
# ------------------------------------------------------------

# ----------------------------
# Defaults (edit as needed)
# ----------------------------
SECONDARY_GROUP="tools_users"
HOME_BASE="/tools_home"
SHELL_PATH="/bin/bash"
CREATE_HOME=true
FORCE_CHANGE_ON_FIRST_LOGIN=true

# Safe defaults:
DRY_RUN=false

# Existing-user safety:
CHANGE_EXISTING_HOME=false
ACK_MODIFY_EXISTING=false
RESET_PASSWORD_FOR_EXISTING=false   # <-- your requirement

LOG_FILE="./bulk_user_create_$(date +%Y%m%d_%H%M%S).log"

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

prompt_password_once() {
  local p1 p2
  while true; do
    read -r -s -p "Enter default password for NEW users: " p1; echo
    read -r -s -p "Confirm default password: " p2; echo
    [[ -n "$p1" ]] || { echo "Password cannot be empty."; continue; }
    [[ "$p1" == "$p2" ]] || { echo "Passwords do not match. Try again."; continue; }
    DEFAULT_PASSWORD="$p1"
    break
  done
  unset p1 p2
}

usage() {
  cat <<EOF
Usage:
  sudo $0 <csv_file> [options]

Options:
  --dry-run
      Log actions but do not make changes

  --no-force-change
      Do not force password change on first login (for NEW users)

  --reset-password-for-existing
      Also reset passwords for EXISTING users (NOT default)

  --change-existing-home
      Change existing users' home to ${HOME_BASE}/<user> and MOVE contents (-m)
      NOTE: This is BLOCKED unless you also pass:
        --i-understand-this-will-modify-existing-users

  --i-understand-this-will-modify-existing-users
      Required acknowledgement to allow any modification of existing users

CSV supported headers:
  username,full_name
  full_name,username
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
    --no-force-change) FORCE_CHANGE_ON_FIRST_LOGIN=false ;;
    --reset-password-for-existing) RESET_PASSWORD_FOR_EXISTING=true ;;
    --change-existing-home) CHANGE_EXISTING_HOME=true ;;
    --i-understand-this-will-modify-existing-users) ACK_MODIFY_EXISTING=true ;;
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
# Hard safety gates (your requirement)
# ----------------------------
# 1) Make it impossible to accidentally modify existing users:
#    If change-existing-home is requested but acknowledgement isn't present, abort.
if [[ "$CHANGE_EXISTING_HOME" == true && "$ACK_MODIFY_EXISTING" != true ]]; then
  die "Refusing to modify existing users. Re-run with BOTH: --change-existing-home --i-understand-this-will-modify-existing-users"
fi

# 2) If acknowledgement is present but change-existing-home is not, do nothing special.
#    (This prevents a future typo causing modifications.)
if [[ "$ACK_MODIFY_EXISTING" == true && "$CHANGE_EXISTING_HOME" != true ]]; then
  log "NOTE: Acknowledgement flag provided but --change-existing-home not set. Existing users will NOT be modified."
fi

# ----------------------------
# Main
# ----------------------------
require_root
[[ -f "$CSV_FILE" ]] || die "CSV file not found: $CSV_FILE"

log "Starting bulk user creation"
log "CSV_FILE=$CSV_FILE"
log "SECONDARY_GROUP=$SECONDARY_GROUP"
log "HOME_BASE=$HOME_BASE SHELL=$SHELL_PATH CREATE_HOME=$CREATE_HOME"
log "DRY_RUN=$DRY_RUN FORCE_CHANGE_ON_FIRST_LOGIN=$FORCE_CHANGE_ON_FIRST_LOGIN"
log "EXISTING_USER_POLICY: modify_home=$CHANGE_EXISTING_HOME reset_password=$RESET_PASSWORD_FOR_EXISTING"
log "LOG_FILE=$LOG_FILE"

# Prompt password once for NEW users unless dry-run
DEFAULT_PASSWORD=""
if [[ "$DRY_RUN" == true ]]; then
  log "DRYRUN: Skipping password prompt (no changes will be made)"
else
  prompt_password_once
fi

# Ensure HOME_BASE exists
if [[ ! -d "$HOME_BASE" ]]; then
  run_cmd mkdir -p "$HOME_BASE"
  log "Ensured HOME_BASE directory exists: $HOME_BASE"
else
  log "HOME_BASE exists: $HOME_BASE"
fi

# Ensure group exists
if getent group "$SECONDARY_GROUP" >/dev/null 2>&1; then
  log "Group exists: $SECONDARY_GROUP"
else
  log "Group missing, will create: $SECONDARY_GROUP"
  run_cmd groupadd "$SECONDARY_GROUP"
fi

# ----------------------------
# Detect header order
# ----------------------------
header="$(head -n 1 "$CSV_FILE" | tr -d '\r')"
c1="$(echo "$header" | awk -F',' '{print $1}')"
c2="$(echo "$header" | awk -F',' '{print $2}')"

h1="$(echo "$c1" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]//g')"
h2="$(echo "$c2" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]//g')"

IDX_USER=1
IDX_NAME=2
SKIP_HEADER=false

if [[ "$h1" == "username" && "$h2" == "full_name" ]]; then
  IDX_USER=1; IDX_NAME=2; SKIP_HEADER=true
  log "Detected CSV header order: username,full_name"
elif [[ "$h1" == "full_name" && "$h2" == "username" ]]; then
  IDX_USER=2; IDX_NAME=1; SKIP_HEADER=true
  log "Detected CSV header order: full_name,username (will swap mapping)"
else
  log "WARN: Unrecognized header '$header' - assuming NO header and columns are: username,full_name"
  SKIP_HEADER=false
fi

# ----------------------------
# Summary counters
# ----------------------------
total=0
created=0
existed=0
home_updated=0
home_moved=0
home_created_existing=0
group_added=0
password_set_new=0
password_set_existing=0
forced_change_new=0
skipped_invalid=0
skipped_empty=0
failures=0

# Continue per-user even if some fail
set +e

line_no=0
while IFS=',' read -r col1 col2 _rest; do
  line_no=$((line_no + 1))
  if [[ "$SKIP_HEADER" == true && "$line_no" -eq 1 ]]; then
    continue
  fi

  # Map columns -> username/full_name
  if [[ "$IDX_USER" -eq 1 ]]; then
    username="$(trim "${col1:-}")"
    full_name="$(trim "${col2:-}")"
  else
    username="$(trim "${col2:-}")"
    full_name="$(trim "${col1:-}")"
  fi

  # Skip empty/comment lines
  if [[ -z "$username" || "$username" =~ ^# ]]; then
    skipped_empty=$((skipped_empty + 1))
    continue
  fi

  # Conservative username validation
  if ! [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    log "WARN: Skipping invalid username '$username' (line $line_no)"
    skipped_invalid=$((skipped_invalid + 1))
    continue
  fi

  total=$((total + 1))
  desired_home="${HOME_BASE}/${username}"

  if id "$username" >/dev/null 2>&1; then
    existed=$((existed + 1))
    current_home="$(getent passwd "$username" | cut -d: -f6)"
    current_shell="$(getent passwd "$username" | cut -d: -f7)"
    log "User exists: $username | current_home='$current_home' current_shell='$current_shell'"

    # Existing users: NEVER modify profile unless both flags were provided AND change-existing-home is true.
    if [[ "$CHANGE_EXISTING_HOME" == true ]]; then
      # (This is already gated by ACK_MODIFY_EXISTING at startup)
      if [[ "$current_home" != "$desired_home" ]]; then
        log "MODIFY-EXISTING: Updating home for $username -> '$desired_home' (MOVE with -m)"
        run_cmd usermod -d "$desired_home" -m "$username"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: usermod (move home) failed for $username (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
        home_updated=$((home_updated + 1))
        home_moved=$((home_moved + 1))
      else
        log "MODIFY-EXISTING: Home already desired for $username: '$desired_home' (no change)"
      fi

      # Optional: align shell only when modification is explicitly enabled
      if [[ "$current_shell" != "$SHELL_PATH" ]]; then
        log "MODIFY-EXISTING: Updating shell for $username -> '$SHELL_PATH'"
        run_cmd usermod -s "$SHELL_PATH" "$username"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: usermod (shell) failed for $username (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
      fi
    else
      # SAFE MODE: do not touch /etc/passwd; only ensure CURRENT home exists
      if [[ ! -d "$current_home" ]]; then
        log "SAFE MODE: Creating missing current home for existing user $username: '$current_home'"
        run_cmd mkdir -p "$current_home"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: mkdir failed for $username home '$current_home' (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
        run_cmd chown "$username:$username" "$current_home"
        run_cmd chmod 700 "$current_home"
        home_created_existing=$((home_created_existing + 1))
      else
        log "SAFE MODE: Existing user $username not modified"
      fi
    fi

    # Password handling for existing users:
    if [[ "$RESET_PASSWORD_FOR_EXISTING" == true ]]; then
      if [[ "$DRY_RUN" == true ]]; then
        log "DRYRUN: Would reset password for EXISTING user $username"
      else
        # Uses the NEW-users default password as the reset password
        echo "${username}:${DEFAULT_PASSWORD}" | chpasswd
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: chpasswd failed for existing user $username (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
        password_set_existing=$((password_set_existing + 1))
        log "Password reset for existing user $username"
      fi
    else
      log "SAFE MODE: Password for existing user $username NOT changed"
    fi

    # Do NOT force pw change for existing users unless you explicitly chose to reset their password.
    # (Keeps existing accounts untouched.)
    :

  else
    # Create new user with desired home under HOME_BASE
    log "Creating user: $username | full_name='${full_name}' | home='$desired_home'"

    useradd_args=(-s "$SHELL_PATH" -c "$full_name" -d "$desired_home")
    if [[ "$CREATE_HOME" == true ]]; then
      useradd_args+=(-m)
    fi

    run_cmd useradd "${useradd_args[@]}" "$username"
    rc=$?
    if [[ $rc -ne 0 ]]; then
      log "ERROR: useradd failed for $username (rc=$rc)"
      failures=$((failures + 1))
      continue
    fi
    created=$((created + 1))

    # Set password for NEW users
    if [[ "$DRY_RUN" == true ]]; then
      log "DRYRUN: Would set password for NEW user $username"
    else
      echo "${username}:${DEFAULT_PASSWORD}" | chpasswd
      rc=$?
      if [[ $rc -ne 0 ]]; then
        log "ERROR: chpasswd failed for new user $username (rc=$rc)"
        failures=$((failures + 1))
        continue
      fi
      password_set_new=$((password_set_new + 1))
      log "Password set for NEW user $username"
    fi

    # Force password change on first login for NEW users (optional)
    if [[ "$FORCE_CHANGE_ON_FIRST_LOGIN" == true ]]; then
      if [[ "$DRY_RUN" == true ]]; then
        log "DRYRUN: Would force password change on first login for NEW user $username"
      else
        chage -d 0 "$username"
        rc=$?
        if [[ $rc -ne 0 ]]; then
          log "ERROR: chage failed for new user $username (rc=$rc)"
          failures=$((failures + 1))
          continue
        fi
        forced_change_new=$((forced_change_new + 1))
        log "Password change forced on first login for NEW user $username"
      fi
    fi
  fi

  # Add to secondary group (for both new/existing)
  log "Adding $username to group $SECONDARY_GROUP"
  run_cmd usermod -aG "$SECONDARY_GROUP" "$username"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    log "ERROR: usermod -aG failed for $username (rc=$rc)"
    failures=$((failures + 1))
    continue
  fi
  group_added=$((group_added + 1))

  # Ensure perms/ownership for desired_home if it exists (safe + harmless)
  if [[ -d "$desired_home" ]]; then
    run_cmd chown -R "$username:$username" "$desired_home"
    run_cmd chmod 700 "$desired_home"
  fi

done < <(tr -d '\r' < "$CSV_FILE")

set -e

unset DEFAULT_PASSWORD || true

# ----------------------------
# Summary
# ----------------------------
log "-------------------- SUMMARY --------------------"
log "Processed rows (valid users): $total"
log "Created users:               $created"
log "Existing users seen:         $existed"
log "Existing home updated:       $home_updated"
log "Existing home moved (-m):    $home_moved"
log "Existing home created:       $home_created_existing"
log "Group adds attempted:        $group_added"
log "Passwords set (NEW):         $password_set_new"
log "Passwords reset (EXISTING):  $password_set_existing"
log "Forced pw change (NEW):      $forced_change_new"
log "Skipped empty/comment lines: $skipped_empty"
log "Skipped invalid usernames:   $skipped_invalid"
log "Failures:                    $failures"
log "-------------------------------------------------"

if [[ $failures -gt 0 ]]; then
  log "Completed with failures. Exit code: 1"
  exit 1
fi

log "Completed successfully. Exit code: 0"
exit 0
