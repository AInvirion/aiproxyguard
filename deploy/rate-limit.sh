#!/bin/bash
# AIProxyGuard Rate Limiting Script
#
# This script configures iptables rate limiting on the Docker host.
# It must be run on the HOST machine, not inside the container.
#
# Environment Variables:
#   RATE_LIMIT_ENABLED    Enable/disable rate limiting (default: true)
#   RATE_LIMIT_PORT       Port to protect (default: 8080)
#   RATE_LIMIT_RATE       Requests per second per IP (default: 100)
#   RATE_LIMIT_BURST      Burst allowance (default: 200)
#   RATE_LIMIT_CONN       Max concurrent connections per IP (default: 50)
#   RATE_LIMIT_WHITELIST  Comma-separated IPs to whitelist (bypass rate limit)
#   RATE_LIMIT_BLOCKLIST  Comma-separated IPs to block entirely
#
# Usage: sudo ./rate-limit.sh [OPTIONS]
#
# Options:
#   --port PORT          Port to protect
#   --rate RATE          Requests per second per IP
#   --burst BURST        Burst allowance
#   --conn-limit LIMIT   Max concurrent connections per IP
#   --whitelist IPS      Comma-separated IPs to whitelist
#   --blocklist IPS      Comma-separated IPs to block
#   --disable            Disable rate limiting (remove rules)
#   --remove             Alias for --disable
#   --status             Show current rules
#
# Examples:
#   sudo ./rate-limit.sh                                    # Apply defaults
#   sudo ./rate-limit.sh --rate 50 --whitelist 10.0.0.1    # Custom config
#   RATE_LIMIT_ENABLED=false sudo ./rate-limit.sh          # Disable via env
#   sudo ./rate-limit.sh --status                          # Show status

set -e

# Configuration from environment (with defaults)
ENABLED=${RATE_LIMIT_ENABLED:-true}
PORT=${RATE_LIMIT_PORT:-8080}
RATE=${RATE_LIMIT_RATE:-100}
BURST=${RATE_LIMIT_BURST:-200}
CONN_LIMIT=${RATE_LIMIT_CONN:-50}
WHITELIST=${RATE_LIMIT_WHITELIST:-}
BLOCKLIST=${RATE_LIMIT_BLOCKLIST:-}

CHAIN_NAME="AIPROXY_LIMIT"
WHITELIST_CHAIN="AIPROXY_WHITELIST"
BLOCKLIST_CHAIN="AIPROXY_BLOCKLIST"
LOCK_FILE="/var/run/aiproxy-ratelimit.lock"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments (override env vars)
REMOVE=false
STATUS=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --port) PORT="$2"; shift 2 ;;
        --rate) RATE="$2"; shift 2 ;;
        --burst) BURST="$2"; shift 2 ;;
        --conn-limit) CONN_LIMIT="$2"; shift 2 ;;
        --whitelist) WHITELIST="$2"; shift 2 ;;
        --blocklist) BLOCKLIST="$2"; shift 2 ;;
        --disable|--remove) REMOVE=true; shift ;;
        --status) STATUS=true; shift ;;
        -h|--help)
            head -35 "$0" | tail -30
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Input validation
validate_port() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        log_error "Invalid port: $port (must be 1-65535)"
        exit 1
    fi
}

validate_number() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 1 ]]; then
        log_error "Invalid $name: $value (must be a positive integer)"
        exit 1
    fi
}

validate_ip() {
    local ip="$1"
    # Allow IP address or CIDR notation
    # IPv4: 1.2.3.4 or 1.2.3.4/24
    # Also allow 0.0.0.0/0 for "any"
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        log_error "Invalid IP address: $ip"
        return 1
    fi
    return 0
}

validate_ip_list() {
    local list="$1"
    local name="$2"
    if [[ -z "$list" ]]; then
        return 0
    fi
    IFS=',' read -ra IPS <<< "$list"
    for ip in "${IPS[@]}"; do
        ip=$(echo "$ip" | xargs)  # trim whitespace
        if [[ -n "$ip" ]] && ! validate_ip "$ip"; then
            log_error "Invalid IP in $name: $ip"
            exit 1
        fi
    done
}

# Check if disabled via env
if [[ "$ENABLED" != "true" && "$ENABLED" != "1" && "$STATUS" != true ]]; then
    REMOVE=true
    log_info "Rate limiting disabled via RATE_LIMIT_ENABLED=$ENABLED"
fi

# Check for root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (sudo)"
    exit 1
fi

# Check for iptables
if ! command -v iptables &> /dev/null; then
    log_error "iptables not found. Please install it first."
    exit 1
fi

# Check for hashlimit module
if ! iptables -m hashlimit --help &> /dev/null 2>&1; then
    log_error "iptables hashlimit module not available"
    exit 1
fi

# Validate inputs before doing anything
if [[ "$STATUS" != true ]]; then
    validate_port "$PORT"
    validate_number "rate" "$RATE"
    validate_number "burst" "$BURST"
    validate_number "conn-limit" "$CONN_LIMIT"
    validate_ip_list "$WHITELIST" "whitelist"
    validate_ip_list "$BLOCKLIST" "blocklist"
fi

show_status() {
    echo "=== Configuration ==="
    echo "  Enabled: $ENABLED"
    echo "  Port: $PORT"
    echo "  Rate: $RATE/sec"
    echo "  Burst: $BURST"
    echo "  Connection limit: $CONN_LIMIT"
    echo "  Whitelist: ${WHITELIST:-none}"
    echo "  Blocklist: ${BLOCKLIST:-none}"
    echo ""
    echo "=== DOCKER-USER Chain ==="
    iptables -L DOCKER-USER -n -v 2>/dev/null || echo "DOCKER-USER chain not found"
    echo ""
    echo "=== $CHAIN_NAME Chain ==="
    iptables -L $CHAIN_NAME -n -v 2>/dev/null || echo "$CHAIN_NAME chain not found"
    echo ""
    if [[ -n "$WHITELIST" ]]; then
        echo "=== $WHITELIST_CHAIN Chain ==="
        iptables -L $WHITELIST_CHAIN -n -v 2>/dev/null || echo "$WHITELIST_CHAIN chain not found"
        echo ""
    fi
    if [[ -n "$BLOCKLIST" ]]; then
        echo "=== $BLOCKLIST_CHAIN Chain ==="
        iptables -L $BLOCKLIST_CHAIN -n -v 2>/dev/null || echo "$BLOCKLIST_CHAIN chain not found"
        echo ""
    fi
    echo "=== Hashlimit Stats ==="
    if [[ -f /proc/net/ipt_hashlimit/aiproxy ]]; then
        cat /proc/net/ipt_hashlimit/aiproxy
    else
        echo "No hashlimit entries (no traffic yet or rules not applied)"
    fi
}

remove_rules() {
    log_info "Removing rate limiting rules..."

    # Remove from DOCKER-USER (all variations, ignore errors)
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -j "$BLOCKLIST_CHAIN" 2>/dev/null || true
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -j "$WHITELIST_CHAIN" 2>/dev/null || true
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -m connlimit --connlimit-above "$CONN_LIMIT" --connlimit-mask 32 -j DROP 2>/dev/null || true
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -j "$CHAIN_NAME" 2>/dev/null || true

    # Flush and delete custom chains
    for chain in "$CHAIN_NAME" "$WHITELIST_CHAIN" "$BLOCKLIST_CHAIN"; do
        iptables -F "$chain" 2>/dev/null || true
        iptables -X "$chain" 2>/dev/null || true
    done

    log_info "Rules removed"
}

apply_rules() {
    log_info "Applying rate limiting rules..."
    log_info "  Port: $PORT"
    log_info "  Rate: $RATE/sec per IP"
    log_info "  Burst: $BURST"
    log_info "  Connection limit: $CONN_LIMIT per IP"
    [[ -n "$WHITELIST" ]] && log_info "  Whitelist: $WHITELIST"
    [[ -n "$BLOCKLIST" ]] && log_info "  Blocklist: $BLOCKLIST"

    # Check if DOCKER-USER chain exists
    if ! iptables -L DOCKER-USER -n &> /dev/null; then
        log_warn "DOCKER-USER chain not found. Is Docker running?"
        log_warn "Creating chain anyway (Docker will recreate it on restart)"
        iptables -N DOCKER-USER 2>/dev/null || true
    fi

    # Build new chains BEFORE removing old ones (atomic swap)
    # This minimizes the window where no rules exist

    # --- Build rate limiting chain ---
    iptables -N "${CHAIN_NAME}_NEW" 2>/dev/null || iptables -F "${CHAIN_NAME}_NEW"

    # Allow established connections (fast path)
    iptables -A "${CHAIN_NAME}_NEW" -m state --state ESTABLISHED,RELATED -j RETURN

    # Per-IP rate limiting with hashlimit
    iptables -A "${CHAIN_NAME}_NEW" -m hashlimit \
        --hashlimit-name aiproxy \
        --hashlimit-mode srcip \
        --hashlimit-upto "${RATE}/sec" \
        --hashlimit-burst "$BURST" \
        --hashlimit-htable-expire 30000 \
        -j RETURN

    # Drop packets exceeding rate limit
    iptables -A "${CHAIN_NAME}_NEW" -j DROP

    # --- Build whitelist chain ---
    if [[ -n "$WHITELIST" ]]; then
        iptables -N "${WHITELIST_CHAIN}_NEW" 2>/dev/null || iptables -F "${WHITELIST_CHAIN}_NEW"
        IFS=',' read -ra ALLOWED_IPS <<< "$WHITELIST"
        for ip in "${ALLOWED_IPS[@]}"; do
            ip=$(echo "$ip" | xargs)  # trim whitespace
            if [[ -n "$ip" ]]; then
                log_info "  Whitelisting IP: $ip"
                iptables -A "${WHITELIST_CHAIN}_NEW" -s "$ip" -j ACCEPT
            fi
        done
        iptables -A "${WHITELIST_CHAIN}_NEW" -j RETURN
    fi

    # --- Build blocklist chain ---
    if [[ -n "$BLOCKLIST" ]]; then
        iptables -N "${BLOCKLIST_CHAIN}_NEW" 2>/dev/null || iptables -F "${BLOCKLIST_CHAIN}_NEW"
        IFS=',' read -ra BLOCKED_IPS <<< "$BLOCKLIST"
        for ip in "${BLOCKED_IPS[@]}"; do
            ip=$(echo "$ip" | xargs)  # trim whitespace
            if [[ -n "$ip" ]]; then
                log_info "  Blocking IP: $ip"
                iptables -A "${BLOCKLIST_CHAIN}_NEW" -s "$ip" -j DROP
            fi
        done
        iptables -A "${BLOCKLIST_CHAIN}_NEW" -j RETURN
    fi

    # --- Atomic swap: remove old rules, rename new chains ---
    # Remove old DOCKER-USER references
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -j "$BLOCKLIST_CHAIN" 2>/dev/null || true
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -j "$WHITELIST_CHAIN" 2>/dev/null || true
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -m connlimit --connlimit-above "$CONN_LIMIT" --connlimit-mask 32 -j DROP 2>/dev/null || true
    iptables -D DOCKER-USER -p tcp --dport "$PORT" -j "$CHAIN_NAME" 2>/dev/null || true

    # Delete old chains
    for chain in "$CHAIN_NAME" "$WHITELIST_CHAIN" "$BLOCKLIST_CHAIN"; do
        iptables -F "$chain" 2>/dev/null || true
        iptables -X "$chain" 2>/dev/null || true
    done

    # Rename new chains to final names
    iptables -E "${CHAIN_NAME}_NEW" "$CHAIN_NAME"
    [[ -n "$WHITELIST" ]] && iptables -E "${WHITELIST_CHAIN}_NEW" "$WHITELIST_CHAIN"
    [[ -n "$BLOCKLIST" ]] && iptables -E "${BLOCKLIST_CHAIN}_NEW" "$BLOCKLIST_CHAIN"

    # --- Insert rules into DOCKER-USER in CORRECT order ---
    # Order matters! Rules are evaluated top-to-bottom.
    # We use -A (append) to a specific position for correct ordering.
    #
    # Desired order:
    # 1. Blocklist (DROP blocked IPs immediately)
    # 2. Whitelist (ACCEPT trusted IPs, bypass rate limiting)
    # 3. Connection limit (DROP if too many connections)
    # 4. Rate limit chain (rate limit everyone else)

    # Insert in REVERSE order using -I (each -I pushes previous to position 2)
    # Final order will be: blocklist, whitelist, connlimit, rate-limit

    # 4. Rate limit (inserted first, will end up last)
    iptables -I DOCKER-USER -p tcp --dport "$PORT" -j "$CHAIN_NAME"

    # 3. Connection limit
    iptables -I DOCKER-USER -p tcp --dport "$PORT" \
        -m connlimit --connlimit-above "$CONN_LIMIT" --connlimit-mask 32 \
        -j DROP

    # 2. Whitelist (if configured)
    if [[ -n "$WHITELIST" ]]; then
        iptables -I DOCKER-USER -p tcp --dport "$PORT" -j "$WHITELIST_CHAIN"
    fi

    # 1. Blocklist (inserted last, will be first/top)
    if [[ -n "$BLOCKLIST" ]]; then
        iptables -I DOCKER-USER -p tcp --dport "$PORT" -j "$BLOCKLIST_CHAIN"
    fi

    log_info "Rules applied successfully"
    log_info ""
    log_info "Rule order in DOCKER-USER:"
    log_info "  1. Blocklist (DROP blocked IPs)"
    [[ -n "$WHITELIST" ]] && log_info "  2. Whitelist (ACCEPT trusted IPs)"
    log_info "  3. Connection limit (DROP if > $CONN_LIMIT connections)"
    log_info "  4. Rate limit ($RATE/sec per IP)"
    echo ""
    show_status
}

# Use flock for mutual exclusion
acquire_lock() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        log_error "Another instance is running. Exiting."
        exit 1
    fi
}

# Main
if [[ "$STATUS" == true ]]; then
    show_status
elif [[ "$REMOVE" == true ]]; then
    acquire_lock
    remove_rules
else
    acquire_lock
    apply_rules
fi
