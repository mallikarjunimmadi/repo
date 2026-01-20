#!/bin/bash

##
# vidm-cluster-validation.sh
#
# Purpose: This script is designed to save time for both customers and Broadcom, Inc. support engineers when troubleshooting vIDM issues. 
#
# By running this script before opening a support request, you can:
#
#     Expedite Troubleshooting: Give support a head-start on investigating your issue.
#     Automate Collection: Quickly gather several relevant pieces of information from your cluster.
#     Standardize Data: Provide a consistent, easy-to-read log report that support engineers can use for analysis.
#
# Log File: /var/log/pgService/cluster-check.log
##

# Color codes for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file configuration
LOG_FILE="/var/log/pgService/cluster-check.log"
LOG_DIR="$(dirname "$LOG_FILE")"

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0
CHECK_VAL=0

# Configuration paths
HOSTS_FILE="/etc/hosts"
NETSERVICE_SCRIPT="/etc/init.d/NetworkService"
FAILOVER_SCRIPT="/usr/local/etc/failover.sh"
AUTO_RECOVERY_SCRIPT="/usr/local/etc/auto-recovery.sh"
ALIASES_FILE="/usr/local/etc/aliases"
AUTO_RECOVERY_DISABLE_FILE="/usr/local/etc/LCM_DISABLE_AUTO_RECOVERY"
PGPOOL_BIN="/usr/local/bin/pgpool"
PGPOOL_PWD="/usr/local/etc/pgpool.pwd"
PGPOOL_CONF="/usr/local/etc/pgpool.conf"
PCPPASS_FILE="$HOME/.pcppass"
PSQL_BIN="/opt/vmware/vpostgres/current/bin/psql"
POSTGRES_SCRIPT="/etc/init.d/vpostgres"
DB_DATA_DIR="/db/data"
PGSERVICE_SCRIPT="/etc/init.d/pgService"

################################################################################
# Logging Functions
################################################################################

# Initialize log file
init_log() {
    # Create log directory if it doesn't exist
    if [ ! -d "$LOG_DIR" ]; then
        echo -e "${YELLOW}[WARN]${NC} Log directory $LOG_DIR does NOT exist. Creating it ..."
        if mkdir -p "$LOG_DIR" 2>/dev/null; then
            chmod 755 "$LOG_DIR"
            echo -e "${GREEN}[INFO]${NC} Created log directory $LOG_DIR"
        else
            echo -e "${RED}[ERROR]${NC} Failed to create log directory. Logging to /tmp/cluster-check.log instead"
            LOG_FILE="/tmp/cluster-check.log"
            LOG_DIR="/tmp"
        fi
    fi

    # Clear existing log file
    if [ -f "$LOG_FILE" ]; then
        rm $LOG_FILE
    fi

    # Create log banner
    local banner="$(
        echo -e "${RED}═══════════════════════════════════════════════════════════════════${NC}"
        echo -e "VIDM Pgpool-II Cluster Validation"
        echo -e "${RED}═══════════════════════════════════════════════════════════════════${NC}"
        echo -e "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo -e "Hostname: $(hostname)"
        echo -e "User: $(whoami)"
        echo -e "Script: $(pwd)/$0"
    )"
    echo -e "$banner" | tee >(sed -r "s/\x1B\[[0-9;]*[mK]//g" >> "$LOG_FILE")
}

# Logging function
log() {
    local level="$1"
    local message="$2"
    local dest="$3"

    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Format entry
    case "$level" in
        "PASS")
            entry="${GREEN}[✓]${NC} $message"
            ;;
        "FAIL")
            entry="${RED}[✗]${NC} $message"
            ;;
        "WARN")
            entry="${YELLOW}[!]${NC} $message"
            ;;
        "INFO")
            entry="${BLUE}[i]${NC} $message"
            ;;
        "SECTION")
            entry="$(
                echo -e "${NC}"
                echo -e "${RED}═══════════════════════════════════════════════════════════════════${NC}"
                echo -e "${NC}$message${NC}"
                echo -e "${RED}═══════════════════════════════════════════════════════════════════${NC}"
            )"
            ;;
    esac

    # Output
    case "$dest" in
        # Output to console
        "console")
            echo -e "$entry"
            ;;
        # Output to console and log file
        "all")
            echo -e "$entry"
            case "$level" in
                SECTION)
                    echo -e "$entry" | tee >(sed -r "s/\x1B\[[0-9;]*[mK]//g" >> "$LOG_FILE") > /dev/null 2>&1
                ;;
                *)
                    echo -e "[$timestamp] [$level] $message" | tee >(sed -r "s/\x1B\[[0-9;]*[mK]//g" >> "$LOG_FILE") > /dev/null 2>&1
                ;;
            esac
            ;;
        # Default outputs to log file only
        *)
            echo -e "[$timestamp] [$level] $message" | tee >(sed -r "s/\x1B\[[0-9;]*[mK]//g" >> "$LOG_FILE") > /dev/null 2>&1
            ;;
    esac
}

# Test result tracking
record_result() {
    local status="$1"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    case "$status" in
        "PASS")
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            ;;
        "FAIL")
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            ;;
        "WARN")
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            ;;
    esac
}

################################################################################
# Helper Functions
################################################################################

# Check if a file exists
check_file_exists() {
    local file="$1"
    if [ -f "$file" ]; then
        log "PASS" "$file: File exists" "all"
        record_result "PASS"
        return 0
    else
        log "FAIL" "$file: File NOT found" "all"
        record_result "FAIL"
        return 1
    fi
}

# Check if file exists on remote node
check_remote_file_exists() {
    local host="$1"
    local file="$2"
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$host" "[ -f '$file' ]" 2>/dev/null; then
        log "PASS" "  $file: File exists on $host" "all"
        record_result "PASS"
        return 0
    else
        log "FAIL" "  $file: File NOT found on $host" "all"
        record_result "FAIL"
        return 1
    fi
}

# Get remote file content
get_remote_file_content() {
    local host="$1"
    local file="$2"
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$host" "cat '$file' 2>/dev/null" 2>&1
}

# Collect pgpool version
get_pgpool_version() {
    local version=$($PGPOOL_BIN --version 2>&1 | head -1 | xargs)
    echo "$version"
}

# Extract value from pgpool.conf
get_pgpool_conf_value() {
    local param="$1"
    local value=$(grep "^[[:space:]]*${param}[[:space:]]*=" "$PGPOOL_CONF" 2>/dev/null | head -1 | sed "s/^[[:space:]]*${param}[[:space:]]*=[[:space:]]*//;s/[[:space:]]*#.*//;s/'//g;s/\"//g" | xargs)
    echo "$value"
}

# Get pgpool.conf value from a remote node
get_remote_pgpool_conf_value() {
    local host="$1"
    local param="$2"
    local value=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$host" \
        "grep '^[[:space:]]*${param}[[:space:]]*=' '$PGPOOL_CONF' 2>/dev/null | head -1 | sed \"s/^[[:space:]]*${param}[[:space:]]*=[[:space:]]*//;s/[[:space:]]*#.*//;s/'//g;s/\\\"//g\" | xargs" 2>&1)
    echo "$value"
}

# Check port connectivity
check_connectivity() {
    local host=$1
    local port=$2
    local application=$3

    log "INFO" "Checking port status on $host:$port"

    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
        log "PASS" "  Node $backend_host is listening on port $port for $application" "all"
        record_result "PASS"
        return 0
    else
        log "FAIL" "  Node $backend_host is NOT listening on port $port for $application" "all"
        record_result "FAIL"
        return 1
    fi
}

# Check passwordless SSH
check_passwordless_ssh() {
    local user="$1"
    local host="$2"

    local result=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error "${user}@${host}" 'echo Authentication Succeeded' 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ] && [[ "$result" == *"Authentication Succeeded"* ]]; then
        log "PASS" "  ${user}@${backend_host}: $result" "all"
        record_result "PASS"
        return 0
    else
        log "FAIL" "  ${user}@${backend_host}: $result" "all"
        record_result "FAIL"
        return 1
    fi
}

# Check SSH hop between nodes
check_hop_ssh() {
    local user="$1"
    local host="$2"
    local dest="$3"

    local result=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error "${user}@${host}" "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error ${user}@${dest} 'echo Authentication Succeeded'" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ] && [[ "$result" == *"Authentication Succeeded"* ]]; then
        log "PASS" "    ${user}@${backend_host} to ${user}@${hop}: $result" "all"
        record_result "PASS"
        return 0
    else
        log "FAIL" "    ${user}@${backend_host} to ${user}@${hop}: $result" "all"
        record_result "FAIL"
        return 1
    fi
}

# Compare two values and log differences
compare_values() {
    local node="$1"
    local param="$2"
    local expected="$3"
    local actual="$4"

    if [ "$expected" = "$actual" ]; then
        if [ "$expected" = "" ]; then
            value="Not configured (expected)"
        else
            value=$actual
        fi
        log "PASS" "  $param matches on $node: $value" "all"
        #log "$param on $node: $actual (matches reference)"
        record_result "PASS"
        return 0
    else
        log "FAIL" "  $param MISMATCH on $node" "all"
        log "FAIL" "Expected: $expected"
        log "FAIL" "Actual: $actual"
        record_result "FAIL"
        return 1
    fi
}

################################################################################
# Global Variables
################################################################################

# Extract backend hostnames
backend0=$(get_pgpool_conf_value "backend_hostname0")
backend1=$(get_pgpool_conf_value "backend_hostname1")
backend2=$(get_pgpool_conf_value "backend_hostname2")

###############################################################################
# Prerequisite Check Functions
################################################################################

# Check : Verify port state and inter-node connectivity
check_internode_conn() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify Ports State and Inter-node Conectivity" "all"

    # Validation booleans
    local all_backends_valid=true

    local current_host=$(hostname)
    local ssh_users=("root" "postgres")

    # Check each node
    for i in 0 1 2; do

        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            log "FAIL" "backend_hostname$i is NOT set or empty" "all"
            all_backends_valid=false
            record_result "FAIL"
            continue
        fi

        log "INFO" "Checking backend_hostname$i: $backend_host" "all"

        # Collect PostgreSQL port
        local psql_port=$(get_pgpool_conf_value "backend_port$i")

        # Check listening ports for SSH and PostgreSQL
        if ! check_connectivity "$backend_host" "22" "SSH"; then
            all_backends_valid=false
        fi
        if ! check_connectivity "$backend_host" "$psql_port" "PostgreSQL"; then
            all_backends_valid=false
        fi

        # Check passwordless SSH for root and postgress
        for user in "${ssh_users[@]}"; do
            # In previous releases, password-less SSH is enabled only for root.
            if [[ "$(get_pgpool_version)" == *"4.0.4"* ]] && [ "$user" != "root" ]; then
                log "INFO" "Skipping passwordless SSH check for $user as pgpool version is 4.0.4"
                continue
            fi

            log "INFO" "Testing passwordless SSH for ${user}"

            if ! check_passwordless_ssh "$user" "$backend_host"; then
                all_backends_valid=false
            fi

            log "INFO" "Testing SSH hop for ${user}"

            # Verify inter-node connectivity
            for j in 0 1 2; do
                local dest="backend$j"
                local hop="${!dest}"

                if ! check_hop_ssh "$user" "$backend_host" "$hop"; then
                    all_backends_valid=false
                fi
            done
        done
    done

    # Check Summary
    if [ "$all_backends_valid" = true ]; then
        log "PASS" "Confirming port state and inter-node connectivity is consistent across all nodes" "all"
        return 0
    else
        log "FAIL" "Some nodes have port state and/or inter-node connectivity inconsistency issues" "all"
        return 1
    fi
}

# Check : Verify scripts integrity
check_scripts_integrity() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify Scripts Integrity" "all"

    # Validation booleans
    local md5sum_match=true

    declare -A checksums
    local script_files=($NETSERVICE_SCRIPT $POSTGRES_SCRIPT $PGSERVICE_SCRIPT $AUTO_RECOVERY_SCRIPT $ALIASES_FILE)

    log "INFO" "Collecting reference file(s) details" "all"

    # Check if reference files exist
    for script in ${script_files[@]}; do
        if ! check_file_exists "$script"; then
            config_consistent=false
            return 1
        else
            checksums["$script"]="$(md5sum "$script" | awk '{print $1}')"
        fi
    done

    # Check each node
    for i in 0 1 2; do

        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Comparing script/conf md5sum on $backend_host" "all"

        for script in ${script_files[@]}; do

            local remote_sum=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "md5sum $script | awk '{print \$1}'")
            local ssh_exit=$?

            if [ $ssh_exit -eq 0 ]; then
                if [ "$remote_sum" = "${checksums["$script"]}" ]; then
                    log "PASS" "  $script: md5sum match" "all"
                    log "INFO" "  Local : ${checksums["$script"]}"
                    log "INFO" "  Remote: $remote_sum"
                    record_result "PASS"
                else
                    log "FAIL" "  $script: md5sum do NOT match" "all"
                    log "INFO" "  Local : ${checksums["$script"]}"
                    log "INFO" "  Remote: $remote_sum"
                    md5sum_match=false
                    record_result "FAIL"
                fi
            else
                log "FAIL" "  Could NOT verify remote checksum on $backend_host" "all"
                md5sum_match=false
                record_result "FAIL"
            fi
        done
    done

    # Check Summary
    if [ "$md5sum_match" = true ]; then
        log "PASS" "Confirming all script checksums match across all nodes" "all"
        return 0
    else
        log "FAIL" "Some nodes have md5sum mismatch, all nodes need the same script versions" "all"
        return 1
    fi
}

# Check : Verify auto-recovery NetworkService status
check_autorecovery_status() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify Auto-Recovery and NetworkService Status" "all"

    # Validation booleans
    local recovery_paused=false

    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking auto-recovery status on $backend_host" "all"

        # Check disable file
        local disable_check=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "[ -f $AUTO_RECOVERY_DISABLE_FILE ]" 2>&1)
        exit_status=$?

        if [ $exit_status -eq 0 ]; then
            log "WARN" "  $AUTO_RECOVERY_DISABLE_FILE: File exists, auto-recovery is PAUSED" "all"
            recovery_paused=true
            record_result "WARN"
        elif [ $exit_status -eq 1 ]; then
            log "PASS" "  $AUTO_RECOVERY_DISABLE_FILE: File NOT found, auto-recovery is NOT PAUSED" "all"
            record_result "PASS"
        else
            log "FAIL" "  Could NOT verify auto-recovery status on $backend_host" "all"
            record_result "FAIL"
        fi
    done

    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking NetworkService status on $backend_host" "all"

        # Check NetworkService
        local remote_status=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "/etc/init.d/NetworkService status 2>&1" 2>&1)
        local ssh_exit=$?

        if [ $ssh_exit -eq 0 ]; then
            if echo "$remote_status" | grep -qi "running"; then
                log "PASS" "  Status: $remote_status" "all"
                record_result "PASS"
            else
                log "WARN" "  Status: $remote_status" "all"
                record_result "WARN"
            fi
        else
            log "WARN" "  Could NOT check NetworkService status on $backend_host"
            record_result "WARN"
        fi
    done

    if [ "$recovery_paused" = false ]; then
        log "PASS" "Confirming auto-recovery is NOT PAUSED across all nodes" "all"
    else
        log "WARN" "Some nodes may have auto-recovery PAUSED, confirm if this is desireable" "all"
    fi

    return 0
}

# Check : Verify failover.sh netmask configuration
check_failover_netmask() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify failover.sh VIDM_NETMASK Configuration" "all"

    # Validation booleans
    local config_consistent=true

    # Verify failover.sh exists and is consistent on all nodes
    log "INFO" "Verifying failover.sh consistency across all nodes"

    # Check if reference failover.sh file exists
    if ! check_file_exists "$FAILOVER_SCRIPT"; then
        return 1
    fi

    # Collect reference failover.sh file size, permission, netmask
    local failover_size=$(stat -f%z "$FAILOVER_SCRIPT" 2>/dev/null || stat -c%s "$FAILOVER_SCRIPT" 2>/dev/null)
    local failover_perm=$(stat -f%Sp "$FAILOVER_SCRIPT" 2>/dev/null || stat -c%A "$FAILOVER_SCRIPT" 2>/dev/null)
    local ref_netmask=$(grep "^[[:space:]]*VIDM_NETMASK=" "$FAILOVER_SCRIPT" 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d '"' | tr -d "'" | xargs)

    log "INFO" "File size: $failover_size bytes"
    log "INFO" "File permissions: $failover_perm"
    log "INFO" "Reference VIDM_NETMASK value: '$ref_netmask'"

    if [ -z "$ref_netmask" ]; then
        log "FAIL" "Reference VIDM_NETMASK is NOT set in $FAILOVER_SCRIPT on local node"
        config_consistent=false
        record_result "FAIL"
        return 1
    fi

    # Validate reference netmask format (basic validation)
    local netmask_valid=true
    if [[ "$ref_netmask" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log "PASS" "Reference VIDM_NETMASK is valid" "all"
        record_result "PASS"
    else
        log "WARN" "Reference VIDM_NETMASK is invalid" "all"
        netmask_valid=false
        record_result "WARN"
    fi

    # Check each node
    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking failover.sh on $backend_host" "all"

        # Check if failover.sh exists
        if check_remote_file_exists "$backend_host" "$FAILOVER_SCRIPT"; then

            # Collect VIDM_NETMASK from remote node
            local remote_netmask=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
                "grep '^[[:space:]]*VIDM_NETMASK=' '$FAILOVER_SCRIPT' 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d '\"' | tr -d \"'\" | xargs" 2>&1)

            log "INFO" "  VIDM_NETMASK on $backend_host: $remote_netmask"

            compare_values "$backend_host" "VIDM_NETMASK" "$ref_netmask" "$remote_netmask" || config_consistent=false

        else
            config_consistent=false
        fi
    done

    # Check Summary
    if [ "$netmask_valid" = true ] && [ "$config_consistent" = true ]; then
        log "PASS" "failover.sh VIDM_NETMASK is valid and consistent across all nodes" "all"
        return 0
    else
        log "FAIL" "Some nodes have configuration inconsistencies with failover.sh" "all"
        return 1
    fi
}

# Check : Verify /etc/hosts and master node
check_hosts_and_master() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify /etc/hosts Configuration and Master Node Verification" "all"

    # Validation booleans
    local all_hosts_ok=true
    local config_consistent=true

    log "INFO" "Collecting reference file(s) details" "all"

    # Check if /etc/hosts exists
    if ! check_file_exists "$HOSTS_FILE"; then
        config_consistent=false
        return 1
    fi

    # Check for delegate IP entry
    local delegate_ip=$(grep "delegateIP" "$HOSTS_FILE" | awk '{print $1}')
    local master_ip=$(grep "master" "$HOSTS_FILE" | head -1 | awk '{print $1}')

    if [ -n "$delegate_ip" ]; then
        log "PASS" "Delegate IP ($delegate_ip) found in $HOSTS_FILE"
        record_result "PASS"
    else
        log "FAIL" "Delegate IP NOT found in $HOSTS_FILE"
        config_consistent=false
        record_result "FAIL"
        return 1
    fi

    if [ -n "$master_ip" ]; then
        log "PASS" "Master IP ($master_ip) found in $HOSTS_FILE"
        record_result "PASS"
    else
        log "FAIL" "Master IP NOT found in $HOSTS_FILE"
        config_consistent=false
        record_result "FAIL"
        return 1
    fi

    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking $HOSTS_FILE on $backend_host for matching configurations" "all"

        # Check for delegate ip matching config on remote node
        local remote_delegate=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
            "grep delegateIP $HOSTS_FILE 2>/dev/null | awk '{print \$1}'" 2>&1)

        if [ -n "$remote_delegate" ] && [ "$remote_delegate" = "$delegate_ip" ]; then
            log "PASS" "  Delegate IP ($remote_delegate) matches on $backend_host" "all"
            record_result "PASS"
        else
            log "FAIL" "  Delegate IP ($remote_delegate) does NOT match $backend_host" "all"
            all_hosts_ok=false
            record_result "FAIL"
        fi

        # Check for master ip matching config on remote node
        local remote_master=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
            "grep 'master' $HOSTS_FILE 2>/dev/null | head -1 | awk '{print \$1}'" 2>&1)

        if [ -n "$remote_master" ] && [ "$remote_master" = "$master_ip" ]; then
            log "PASS" "  Master IP ($remote_master) matches on $backend_host" "all"
            record_result "PASS"
        else
            log "FAIL" "  Master IP ($remote_master) does NOT match on $backend_host" "all"
            all_hosts_ok=false
            record_result "FAIL"
        fi

        # Extract recovery_password
        local pg_user_password="$(get_pgpool_conf_value "recovery_password")"

        # Verify if this node is the master
        local recovery_status=$(PGPASSWORD="$pg_user_password" $PSQL_BIN -h "$backend_host" -U postgres -d postgres -t -c "SELECT pg_is_in_recovery();" 2>&1)
        local psql_exit=$?

        if [ $psql_exit -eq 0 ]; then
            recovery_status=$(echo "$recovery_status" | xargs)
            if [ "$recovery_status" = "f" ]; then
                log "INFO" "  This is the MASTER (not in recovery)" "all"
                record_result "PASS"
            elif [ "$recovery_status" = "t" ]; then
                log "INFO" "  This is a STANDBY node (in recovery mode)" "all"
                record_result "PASS"
            else
                log "WARN" "  Unexpected recovery status: $recovery_status" "all"
                record_result "WARN"
            fi
        else
            log "WARN" "Failed to query PostgreSQL recovery status" "all"
            log "INFO" "Error: $recovery_status"
            record_result "WARN"
        fi

        # Check here if this node owns the delegate ip
        local eth0_delegate=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
        "ifconfig eth0:0 2>/dev/null | grep inet | awk '{print \$2}' | cut -c 6-")
        if [ $eth0_delegate = $delegate_ip ]; then
            log "INFO" "  This node owns the delegateIP @ eth0:0" "all"
        else
            log "INFO" "  This node does NOT own the delegateIP" "all"
        fi

    done

    # Check Summary
    if [ "$all_hosts_ok" = true ] && [ "$config_consistent" = true ]; then
        log "PASS" "Confirming $HOSTS_FILE is consistent across all nodes"
        return 0
    else
        log "FAIL" "Some nodes have configuration inconsistencies with $HOSTS_FILE"
        return 1
    fi
}

# Check : Verify pgpool binary version across nodes
check_pgpool_version() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify pgpool Binary Version Consistency" "all"

    # Validation booleans
    local version_mismatch=false

    if ! check_file_exists "$PGPOOL_BIN"; then
        config_consistent=false
        return 1
    fi

    # Get local version
    local local_version=$(get_pgpool_version)

    log "INFO" "Local pgpool version: $local_version" "all"

    # Check version on each backend node
    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking pgpool version on $backend_host" "all"

        local remote_version=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "$PGPOOL_BIN --version 2>&1 | head -1" 2>&1)
        local ssh_exit=$?

        if [ $ssh_exit -eq 0 ]; then
            if [ "$remote_version" = "$local_version" ]; then
                log "PASS" "  Remote version matches local version: $remote_version" "all"
                record_result "PASS"
            else
                log "FAIL" "  Remote version MISMATCH: $remote_version" "all"
                log "INFO" "  Local: $local_version"
                version_mismatch=true
                record_result "FAIL"
            fi
        else
            log "WARN" "  Could NOT check version on $backend_host" "all"
            log "INFO" "SSH error: $remote_version"
            record_result "WARN"
        fi
    done

    # Check Summary
    if [ "$version_mismatch" = false ]; then
        log "PASS" "Confirming Pgpool version is consistent across all nodes" "all"
        return 0
    else
        log "FAIL" "Some nodes have version mismatch with Pgpool" "all"
        return 1
    fi
}

# Check : Verify pgpool.conf consistency
check_pgpool_conf() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify pgpool.conf Consistency" "all"

    # Validation booleans
    local config_consistent=true
    local all_backends_valid=true

    # Verify pgpool.conf exists
    log "INFO" "Verifying pgpool.conf consistency across all nodes" "all"

    # Check if reference pgpool.conf file exists
    if ! check_file_exists "$PGPOOL_CONF"; then
        return 1
    fi

    # Collect reference pgpool.conf file size, date modified
    local conf_size=$(stat -c%s "$PGPOOL_CONF" 2>/dev/null)
    local conf_modified=$(stat -c%y "$PGPOOL_CONF" 2>/dev/null)

    log "INFO" "File size: $conf_size bytes"
    log "INFO" "Last modified: $conf_modified"

    # Collect reference pgpool.conf file content parameters
    local ref_delegate_ip=$(get_pgpool_conf_value "delegate_IP")
    local ref_use_watchdog=$(get_pgpool_conf_value "use_watchdog")
    local ref_master_slave_mode=$(get_pgpool_conf_value "master_slave_mode")
    local ref_load_balance_mode=$(get_pgpool_conf_value "load_balance_mode")

    log "INFO" "Reference configuration (local node):"
    log "INFO" "  delegate_IP: $ref_delegate_ip"
    log "INFO" "  use_watchdog: $ref_use_watchdog"
    log "INFO" "  master_slave_mode: $ref_master_slave_mode"
    log "INFO" "  load_balance_mode: $ref_load_balance_mode"

    # Check each node
    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking pgpool.conf on $backend_host" "all"

        # Check if pgpool.conf exists
        if check_remote_file_exists "$backend_host" "$PGPOOL_CONF"; then

            # Collect critical parameters
            local remote_delegate_ip=$(get_remote_pgpool_conf_value "$backend_host" "delegate_IP")
            local remote_use_watchdog=$(get_remote_pgpool_conf_value "$backend_host" "use_watchdog")
            local remote_master_slave=$(get_remote_pgpool_conf_value "$backend_host" "master_slave_mode")
            local remote_load_balance=$(get_remote_pgpool_conf_value "$backend_host" "load_balance_mode")
            local remote_backend_host=$(get_remote_pgpool_conf_value "$backend_host" "backend_host$i")

            log "INFO" "  delegate_IP: $remote_delegate_ip"
            log "INFO" "  use_watchdog: $remote_use_watchdog"
            log "INFO" "  master_slave_mode: $remote_master_slave"
            log "INFO" "  load_balance_mode: $remote_load_balance"

            # Compare values
            compare_values "$backend_host" "delegate_IP" "$ref_delegate_ip" "$remote_delegate_ip" || config_consistent=false
            compare_values "$backend_host" "use_watchdog" "$ref_use_watchdog" "$remote_use_watchdog" || config_consistent=false
            compare_values "$backend_host" "master_slave_mode" "$ref_master_slave_mode" "$remote_master_slave" || config_consistent=false
            compare_values "$backend_host" "load_balance_mode" "$ref_load_balance_mode" "$remote_load_balance" || config_consistent=false

        else
            all_backends_valid=false
            config_consistent=false
        fi
    done

    # Check Summary
    if [ "$all_backends_valid" = true ] && [ "$config_consistent" = true ]; then
        log "PASS" "Confirming pgpool.conf is consistent across all nodes" "all"
        return 0
    else
        log "FAIL" "Some nodes have configuration inconsistencies with pgpool.conf" "all"
        return 1
    fi
}

# Check : Verify pgpool.pwd password file
check_pgpool_pwd() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify pgpool.pwd Password File" "all"

    # Validation booleans
    local config_consistent=true

    # Check if pgpool.pwd exists
    if ! check_file_exists "$PGPOOL_PWD"; then
        config_consistent=false
        return 1
    fi

    # Collect reference pgpool.pwd file permissions, size, length
    local pwd_size=$(stat -c%s "$PGPOOL_PWD" 2>/dev/null)
    local pwd_length=$(cat "$PGPOOL_PWD" 2>/dev/null)
    local pwd_perms=$(stat -c%a "$PGPOOL_PWD")

    # Log pgpool.pwd reference values
    log "INFO" "File size: $pwd_size bytes"
    log "INFO" "File content length: ${#pwd_length} characters"
    log "INFO" "File permissions: $pwd_perms"

    # Validate pgpool.pwd permissions
    if [ "$pwd_perms" = "400" ] || [ "$pwd_perms" = "440" ]; then
        log "PASS" "pgpool.pwd has acceptable permissions: $pwd_perms" "all"
        record_result "PASS"
    else
        log "WARN" "pgpool.pwd has undesireable permission: $pwd_perms, consider restricting it to 400 or 440" "all"
        record_result "FAIL"
    fi

    # Validate pgpool.pwd content
    if [ -z "$pwd_length" ]; then
        log "FAIL" "pgpool.pwd is empty on local node" "all"
        record_result "FAIL"
        return 1
    fi

    # Validate pgpool password by attempting to connect
    log "INFO" "Validating pgpool password by connecting to database" "all"
    if timeout -k 3s 3s su root -c "cat /usr/local/etc/pgpool.pwd|/opt/vmware/vpostgres/current/bin/psql -h localhost -p 9999 -U pgpool postgres -c \"show pool_nodes\"" &> /tmp/poolnodes.txt; then
        log "PASS" "pgpool password is valid and connection successful" "all"
        record_result "PASS"
        # Clean up temporary file
        rm -f /tmp/poolnodes.txt
    else
        log "WARN" "pgpool password validation failed - unable to connect to database" "all"
        log "INFO" "Check /tmp/poolnodes.txt for connection error details" "all"
        record_result "WARN"
        config_consistent=false
    fi

    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking pgpool.pwd on $backend_host" "all"

        if check_remote_file_exists "$backend_host" "$PGPOOL_PWD"; then

            # Get content from remote node
            local remote_content=$(get_remote_file_content "$backend_host" "$PGPOOL_PWD")

            log "INFO" "  pgpool.pwd content length on $backend_host: ${#remote_content} characters"

            compare_values "$backend_host" "pgpool.pwd" "$pwd_length" "$remote_content" || config_consistent=false

        else
            config_consistent=false
        fi
    done

    # Check Summary
    if [ "$config_consistent" = true ]; then
        log "PASS" "Confirming pgpool.pwd is consistent across all nodes" "all"
        return 0
    else
        log "FAIL" "Some nodes have configuration inconsistencies with pgpool.pwd" "all"
        return 1
    fi
}

# Check : Verify pgpool service status
check_pgpool_service() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify pgpool Service Status" "all"

    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking pgService status on $backend_host" "all"

        local remote_status=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "/etc/init.d/pgService status | tail -1 2>&1" 2>&1)
        local ssh_exit=$?

        if [ $ssh_exit -eq 0 ]; then
            if echo "$remote_status" | grep -qi "running"; then
                log "PASS" "  Status: $remote_status" "all"
                record_result "PASS"
            else
                log "FAIL" "  Status: $remote_status" "all"
                record_result "FAIL"
            fi
        else
            log "FAIL" "  Could NOT check pgService status on $backend_host: $remote_status" "all"
            record_result "FAIL"
        fi
    done

    return 0
}

# Check : Verify /db disk usage
check_db_disk_usage() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify /db Disk Usage" "all"

    # Validation booleans
    local all_nodes_ok=true

    # Check /db disk usage on each node
    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking /db disk usage on $backend_host" "all"

        # Execute df with timeout
        local disk_usage=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "df -B M | awk '/db/ {print int(\$5)}'" 2>&1)
        local ssh_exit=$?

        # Check if SSH failed
        if [ $ssh_exit -ne 0 ]; then
            log "ERROR" "Failed to connect to $backend_host to check disk usage." "all"
            all_nodes_ok=false
            record_result "FAIL"
            continue
        fi

        if [ "$disk_usage" -ge 80 ]; then
            log "WARN" "  usage is higher than expected: $disk_usage%" "all"
            all_nodes_ok=false
            record_result "WARN"
        else
            log "PASS" "  usage is within acceptable margin: $disk_usage%" "all"
            record_result "PASS"
        fi

    done

    # Check Summary
    if [ "$all_nodes_ok" = true ]; then
        log "PASS" "Confirming /db disk usage is within acceptable margin on all nodes" "all"
        return 0
    else
        log "WARN" "Some nodes have /db disk usage above acceptable margins, please review and increase disk space if necessary" "all"
        return 1
    fi
}


# Check : Verify /db/data ownership
check_db_data_ownership() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify /db/data Directory Ownership" "all"

    # Validation booleans
    local all_nodes_ok=true
    local file_count_ok=true

    local incorrect_ownership=0
    local total_files=0
    local sample_size=100

    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking $DB_DATA_DIR details on $backend_host" "all"

        # Check if directory exists on remote node
        if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "[ -d '$DB_DATA_DIR' ]" 2>/dev/null; then
            log "PASS" "  $DB_DATA_DIR: Directory exists" "all"
            record_result "PASS"

            # Get directory ownership from remote node
            local remote_owner=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
                "stat -c%U '$DB_DATA_DIR' 2>/dev/null" 2>&1)
            local remote_group=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
                "stat -c%G '$DB_DATA_DIR' 2>/dev/null" 2>&1)

            # Check if owned by postgres:users (case insensitive)
            if [[ "$remote_owner" == "postgres" ]] && [[ "$remote_group" == "users" ]]; then
                log "PASS" "    Directory has expected user and group ownership: $remote_owner:$remote_group" "all"
                record_result "PASS"
            else
                log "FAIL" "    Directory has incorrect user and/or group ownership: $remote_owner:$remote_group (expected postgres:users)" "all"
                all_nodes_ok=false
                record_result "FAIL"
            fi

            # Get file count here, we need around 29 files at least
            local remote_count=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" "ls $DB_DATA_DIR | wc -l" 2>&1)

            if [ "$remote_count" -gt 27 ]; then
                log "PASS" "    Directory content count seems accurate, found $remote_count entries" "all"
                record_result "PASS"
            else
                log "WARN" "    Directory content may be unexpected, found $remote_count entries, please review" "all"
                file_count_ok=false
                record_result "WARN"
            fi

            local remote_check=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=Error root@"$backend_host" \
                "bash -c 'incorrect=0; total=0; while IFS= read -r -d \"\" file; do total=\$((total + 1)); owner=\$(stat -c%U \"\$file\" 2>/dev/null); group=\$(stat -c%G \"\$file\" 2>/dev/null); if [[ \"\${owner,,}\" != \"postgres\" ]] || [[ \"\${group,,}\" != \"users\" ]]; then incorrect=\$((incorrect + 1)); fi; if [ \$total -ge $sample_size ]; then break; fi; done < <(find \"$DB_DATA_DIR\" -type f -print0 2>/dev/null); echo \"\$total:\$incorrect\"'" 2>&1)

            local remote_total=$(echo "$remote_check" | cut -d':' -f1)
            local remote_incorrect=$(echo "$remote_check" | cut -d':' -f2)

            # Sample check files on remote node
            log "INFO" "  Sampled $remote_total file(s) for ownership in $DB_DATA_DIR on $backend_host"

            if [ "$remote_incorrect" = "0" ] || [ -z "$remote_incorrect" ]; then
                log "PASS" "    All files and sub-directories have expected ownership" "all"
                record_result "PASS"
            else
                log "FAIL" "    $remote_incorrect file(s) in $DB_DATA_DIR with incorrect ownership on $backend_host" "all"
                all_nodes_ok=false
                record_result "FAIL"
            fi

        else
            log "FAIL" "  $DB_DATA_DIR: Directory does NOT exist on $backend_host" "all"
            all_nodes_ok=false
            record_result "FAIL"
        fi
    done

    # Check Summary
    if [ "$file_count_ok" = true ] && [ "$all_nodes_ok" = true ]; then
        log "PASS" "Confirming $DB_DATA_DIR directory and sub-file ownership is correct on all nodes" "all"
        log "INFO" "Primary node's $DB_DATA_DIR entry count can differ by a few files, this is expected" "all"
        return 0
    else
        log "FAIL" "Some nodes have configuration inconsistencies with $DB_DATA_DIR directory and sub-files" "all"
        return 1
    fi
}

# Check : Verify pgpool service responsiveness
check_pgpool_responsiveness() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Pgpool Service Responsiveness" "all"

    # Validation booleans
    local all_responsive=true
    local config_consistent=true
    local has_repl_delay=false

    local sigterm_delay=3
    local response_size=1500

    # Check if reference files exist
    local file_checks=($PSQL_BIN $PGPOOL_PWD)

    for files in ${file_checks[@]}; do
        if ! check_file_exists "$files"; then
            config_consistent=false
            return 1
        fi
    done

    # Check pgpool responsiveness on each node
    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking pgpool responsiveness on $backend_host" "all"

        # Execute show pool_nodes command with timeout
        local pool_nodes_output=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
            'timeout -k 3s 3s su root -c "cat /usr/local/etc/pgpool.pwd|/opt/vmware/vpostgres/current/bin/psql -h localhost -p 9999 -U pgpool postgres -c \"show pool_nodes\""' 2>&1)
        local ssh_exit=$?

        local response=$(echo "" && echo "${pool_nodes_output}")
        log "INFO" "Pgpool query output : $response"

        # Fetch replication delay value
        local repl_delay=$(echo "$pool_nodes_output" | grep $backend_host | awk '{print $21}')

        if [[ $repl_delay -eq 0 ]]; then
            log "PASS" "  No replication delay detected" "all"
            record_result "PASS"
        elif [[ $repl_delay -gt 0 ]]; then
            log "WARN" "  Detected replication delay on this node: $repl_delay" "all"
            record_result "WARN"
        else
            log "FAIL" "  Unable to determine if this node has replication delay" "all"
            has_repl_delay=false
            record_result "FAIL"
        fi

        # Check if command succeeded
        if [ $ssh_exit -eq 0 ]; then
            # Verify output contains expected pool_nodes data
            if echo "$pool_nodes_output" | grep -qi "node_id"; then
                log "PASS" "  Pgpool PASSED test on $backend_host within $sigterm_delay seconds" "all"
                record_result "PASS"
            else
                log "FAIL" "  Pgpool FAILED test on $backend_host within $sigterm_delay seconds" "all"
                all_responsive=false
                record_result "FAIL"
            fi
        elif [ $ssh_exit -eq 124 ] || [ $ssh_exit -eq 137 ]; then
            # Timeout occurred (124 = timeout, 137 = killed)
            log "FAIL" "  Pgpool query TIMED OUT on $backend_host (not responsive)"
            all_responsive=false
            record_result "FAIL"
        else
            log "FAIL" "  Pgpool is NOT responsive on $backend_host"
            all_responsive=false
            record_result "FAIL"
        fi

    done

    if [ "$has_repl_delay" = true ]; then
        log "WARN" "Some nodes show replication delay, please review this issue" "all"
    fi

    # Check Summary
    if [ "$all_responsive" = true ] && [ "$config_consistent" = true ]; then
        log "PASS" "Confirming Pgpool service is responsive on all nodes" "all"
        return 0
    else
        log "FAIL" "Pgpool service is NOT responsive on one or more nodes" "all"
        return 1
    fi
}

# Check : Verify pgpool ~/.pcppass credentials
check_pcppass() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: Verify pgpool ~/.pcppass Credentials File" "all"

    # Validation booleans
    local all_nodes_ok=true
    local config_consistent=true

    log "INFO" "Collecting reference file values" "all"

    # Verify .pcppass exists
    if ! check_file_exists "$PCPPASS_FILE"; then
        config_consistent=false
        return 1
    fi

    local reference_value="$(cat $PCPPASS_FILE 2>/dev/null)"

    log "INFO" "Reference value: $reference_value"

    log "INFO" "Checking file values on all nodes" "all"

    for i in 0 1 2; do
        local backend_var="backend$i"
        local backend_host="${!backend_var}"

        if [ -z "$backend_host" ]; then
            continue
        fi

        log "INFO" "Checking .pcppass on $backend_host"

        # Check if .pcppass exists on remote node (in root's home)
        if check_remote_file_exists "$backend_host" "$PCPPASS_FILE"; then

            local regex_match='^([^:]+):([0-9]+):([^:]+):([^:]+)$'

            # Collect reference .pcppass file permissions, size
            local remote_size=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
                "stat -c%s $PCPPASS_FILE 2>/dev/null" 2>&1)
            local remote_perms=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o LogLevel=Error root@"$backend_host" \
                "stat -c%a $PCPPASS_FILE 2>/dev/null" 2>&1)
            local remote_value="$(get_remote_file_content $backend_host $PCPPASS_FILE)"

            log "INFO" "    File size: $remote_size bytes"
            log "INFO" "    File permissions: $remote_perms"
            log "INFO" "    File value: $remote_value"

            if [[ "$remote_value" =~ $regex_match ]]; then
                log "PASS" "    Has expected field(s) format" "all"
                record_result "PASS"
            else
                log "FAIL" "    Has unexpected field(s) format" "all"
                log "FAIL" "    Expected format: hostname:port:username:password"
                config_consistent=false
                record_result "FAIL"
            fi

            if [ "$remote_perms" = "600" ]; then
                log "PASS" "    Has expected permissions ($remote_perms)" "all"
                record_result "PASS"
            else
                log "WARN" "    Has unexpected permissions ($remote_perms)" "all"
                config_consistent=false
                record_result "WARN"
            fi

            if [[ "$remote_value" =~ $reference_value ]]; then
                log "PASS" "    Matches reference file" "all"
                record_result "PASS"
            else
                log "FAIL" "    Does NOT match reference file" "all"
                config_consistent=false
                record_result "FAIL"
            fi

        else
            all_nodes_ok=false
        fi
    done

    # Check Summary
    if [ "$all_nodes_ok" = true ] && [ "$config_consistent" = true ]; then
        log "PASS" "Confirming .pcppass is consistent across all nodes" "all"
        return 0
    else
        log "WARN" "Some nodes have configuration inconsistencies with .pcppass" "all"
        return 1
    fi
}

# Check : Verify PostgreSQL user passwords
check_postgres_users() {

    CHECK_VAL=$((CHECK_VAL+1))

    log "SECTION" "CHECK $CHECK_VAL: PostgreSQL User Password Validation" "all"

    # Validation booleans
    local config_consistent=true

    # Check if reference files exist
    local file_checks=($PSQL_BIN $HOSTS_FILE $PGPOOL_PWD)

    for files in ${file_checks[@]}; do
        if ! check_file_exists "$files"; then
            config_consistent=false
            return 1
        fi
    done

    # Get values for authentication tests
    local delegate_ip=$(grep "delegateIP" "$HOSTS_FILE" | awk '{print $1}')
    local pgpool_password=$(cat $PGPOOL_PWD)
    local pgusers=("pgpool" "repl" "postgres")

    # Log reference values
    if [ -n "$delegate_ip" ]; then
        log "PASS" "Delegate IP ($delegate_ip) found in $HOSTS_FILE" "all"
        record_result "PASS"
    else
        log "FAIL" "Delegate IP NOT found in $HOSTS_FILE" "all"
        config_consistent=false
        record_result "FAIL"
        return 1
    fi

    for pguser in "${pgusers[@]}"; do

        log "INFO" "Testing '$pguser' authentication to $delegate_ip" "all"

        local result=$(PGPASSWORD="$pgpool_password" $PSQL_BIN -h "$delegate_ip" -U pgpool -d postgres -w -c 'SELECT 1;' 2>&1)
        local exit_code=$?

        if [ $exit_code -eq 0 ]; then
            log "PASS" "  $pguser@$delegate_ip: Authentication Succeeded" "all"
            record_result "PASS"
        else
            log "FAIL" "  $pguser@$delegate_ip: Authentication Failed" "all"
            config_consistent=false
            record_result "FAIL"
            return 1
        fi
    done

    # Check Summary
    if [ "$config_consistent" = true ]; then
        log "PASS" "Confirming PostgreSQL user authentication tests succeeded" "all"
        return 0
    else
        log "WARN" "Some PostgreSQL user authentication tests did NOT succeed" "all"
        return 1
    fi
}

# Check : Verify pgpool_recovery extension
check_pgpool_recovery_extension() {

    CHECK_VAL=$((CHECK_VAL+1))

    # This is already 'partially' checked in check_hosts_and_master()
    log "SECTION" "CHECK $CHECK_VAL: pgpool_recovery Extension on Master Node" "all"

    # Validation booleans
    local config_consistent=true

    # Verify .pcppass exists
    if ! check_file_exists "$PSQL_BIN"; then
        config_consistent=false
        return 1
    fi

    local recovery_status=$($PSQL_BIN -h localhost -U postgres -d postgres -t -c "SELECT pg_is_in_recovery();" 2>&1)
    local psql_exit=$?

    if [ $psql_exit -ne 0 ]; then
        log "FAIL" "Could NOT connect to PostgreSQL to check master status: $recovery_status"
        record_result "FAIL"
        return 1
    fi

    recovery_status=$(echo "$recovery_status" | xargs)

    if [ "$recovery_status" = "t" ]; then
        log "INFO" "Current node is a STANDBY node, checking master node for extension" "all"

        # Try to find and connect to master
        local master_host=$(grep "master" $HOSTS_FILE 2>/dev/null | head -1 | awk '{print $1}')
        local pg_user_password="$(get_pgpool_conf_value "recovery_password")"

        if [ -n "$master_host" ]; then
            local ext_check=$(PGPASSWORD="$pg_user_password" $PSQL_BIN -h "$master_host" -U postgres -d template1 -t -c "SELECT 1 FROM pg_extension WHERE extname='pgpool_recovery';" 2>&1)
            local ext_exit=$?

            if [ $ext_exit -eq 0 ] && [[ "$ext_check" =~ 1 ]]; then
                log "PASS" "  pgpool_recovery extension EXISTS on master node" "all"
                record_result "PASS"
            else
                log "FAIL" "  pgpool_recovery extension NOT FOUND on master node" "all"
                record_result "FAIL"
                return 1
            fi
        else
            log "WARN" "  Could NOT determine master node IP from /etc/hosts" "all"
            record_result "WARN"
            return 1
        fi
    else
        log "INFO" "Current node is the MASTER, checking for extension" "all"

        local ext_check=$($PSQL_BIN -h localhost -U postgres -d template1 -t -c "SELECT 1 FROM pg_extension WHERE extname='pgpool_recovery';" 2>&1)
        local ext_exit=$?

        if [ $ext_exit -eq 0 ] && [[ "$ext_check" =~ 1 ]]; then
            log "PASS" "  pgpool_recovery extension EXISTS on master node" "all"
            record_result "PASS"
        else
            log "FAIL" "  pgpool_recovery extension NOT FOUND on master node" "all"
            record_result "FAIL"
            return 1
        fi
    fi

    # Check Summary
    if [ "$config_consistent" = true ]; then
        log "PASS" "Confirming pgpool_recovery Extension on Master Node" "all"
        return 0
    else
        log "FAIL" "pgpool_recovery extension NOT FOUND on master node" "all"
        return 1
    fi
}

################################################################################
# Main Execution
################################################################################

main() {

    # Initialize logging
    init_log

    log "INFO" "Node 0 = $backend0" "all"
    log "INFO" "Node 1 = $backend1" "all"
    log "INFO" "Node 2 = $backend2" "all"
    log "INFO" "Starting cluster prerequisites verification" "all"
    log "INFO" "Logging to: $LOG_FILE" "all"

    # Run all checks
    check_internode_conn
    check_scripts_integrity
    check_autorecovery_status
    check_failover_netmask
    check_hosts_and_master
    check_pgpool_version
    check_pgpool_conf
    check_pgpool_pwd
    check_pgpool_service
    check_db_disk_usage
    check_db_data_ownership
    check_pgpool_responsiveness
    check_pcppass
    check_postgres_users
    check_pgpool_recovery_extension

    # Print summary
    echo ""
    log "SECTION" "VERIFICATION SUMMARY" "all"
    log "INFO" "Total Checks: $TOTAL_CHECKS" "all"
    log "INFO" "Passed: $PASSED_CHECKS" "all"
    log "INFO" "Failed: $FAILED_CHECKS" "all"
    log "INFO" "Warnings: $WARNING_CHECKS" "all"

    echo ""

    if [ $FAILED_CHECKS -eq 0 ]; then
        log "PASS" "All critical checks passed!" "all"
        if [ $WARNING_CHECKS -gt 0 ]; then
            log "WARN" "However, there are $WARNING_CHECKS warning(s) that should be reviewed" "all"
        fi
        echo ""
        log "INFO" "Full details logged to: $LOG_FILE" "all"
        return 0
    else
        log "FAIL" "$FAILED_CHECKS check(s) failed" "all"
        log "FAIL" "Verification completed with $FAILED_CHECKS failure(s), review failures at: $LOG_FILE" "all"
        echo ""
        return 1
    fi
}

# Run main function
main
exit $?
