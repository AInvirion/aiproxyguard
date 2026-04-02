# AIProxyGuard Deployment

## Rate Limiting (DDoS Protection)

AIProxyGuard uses Linux iptables for rate limiting. This provides kernel-level protection without application overhead.

### Quick Start

```bash
# Apply rate limiting (run on Docker HOST, not inside container)
sudo ./rate-limit.sh

# Check status
sudo ./rate-limit.sh --status

# Disable rate limiting
sudo ./rate-limit.sh --disable
```

### Environment Variables

All settings can be configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | `true` | Enable/disable rate limiting |
| `RATE_LIMIT_PORT` | `8080` | Port to protect |
| `RATE_LIMIT_RATE` | `100` | Requests/second per IP |
| `RATE_LIMIT_BURST` | `200` | Burst allowance |
| `RATE_LIMIT_CONN` | `50` | Max concurrent connections per IP |
| `RATE_LIMIT_WHITELIST` | - | Comma-separated IPs to whitelist |
| `RATE_LIMIT_BLOCKLIST` | - | Comma-separated IPs to block |

### Examples

```bash
# Disable rate limiting
RATE_LIMIT_ENABLED=false sudo ./rate-limit.sh

# Stricter limits with whitelist
RATE_LIMIT_RATE=50 \
RATE_LIMIT_WHITELIST=10.0.0.1,192.168.1.100 \
sudo ./rate-limit.sh

# Block known bad actors
RATE_LIMIT_BLOCKLIST=1.2.3.4,5.6.7.8 sudo ./rate-limit.sh

# Command-line options (override env vars)
sudo ./rate-limit.sh --rate 50 --whitelist 10.0.0.1 --blocklist 1.2.3.4
```

### Docker Compose Integration

```yaml
# docker-compose.yml
services:
  aiproxyguard:
    image: aiproxyguard:latest
    ports:
      - "8080:8080"
    environment:
      - AIPROXYGUARD_CONTROL_PLANE_ENABLED=true
      # Rate limit config (applied on host, not in container)
      
  # Run rate-limit setup on host via one-shot container
  rate-limit:
    image: alpine
    network_mode: host
    cap_add:
      - NET_ADMIN
    volumes:
      - ./deploy:/deploy:ro
    environment:
      - RATE_LIMIT_ENABLED=true
      - RATE_LIMIT_RATE=100
      - RATE_LIMIT_WHITELIST=10.0.0.0/8
    command: /deploy/rate-limit.sh
    profiles:
      - setup
```

### Persistent Configuration (systemd)

To persist rules across reboots and Docker restarts:

```bash
# 1. Create config directory
sudo mkdir -p /etc/aiproxyguard

# 2. Copy files
sudo cp rate-limit.sh /etc/aiproxyguard/
sudo cp rate-limit.conf /etc/aiproxyguard/
sudo chmod +x /etc/aiproxyguard/rate-limit.sh

# 3. Edit configuration
sudo nano /etc/aiproxyguard/rate-limit.conf

# 4. Install systemd service
sudo cp aiproxyguard-ratelimit.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aiproxyguard-ratelimit
sudo systemctl start aiproxyguard-ratelimit

# 5. Check status
sudo systemctl status aiproxyguard-ratelimit
```

### How It Works

The script creates iptables rules in the `DOCKER-USER` chain:

1. **Blocklist**: Immediately drops traffic from blocked IPs
2. **Whitelist**: Allows whitelisted IPs to bypass rate limiting
3. **Connection limit**: Drops new connections if IP has > N concurrent connections
4. **Rate limit**: Uses `hashlimit` module for per-IP request rate limiting
5. **Fast path**: Established connections bypass all checks

### Rule Order (DOCKER-USER chain)

```
1. AIPROXY_LIMIT     → Rate limiting (hashlimit)
2. connlimit DROP    → Connection limit per IP
3. AIPROXY_WHITELIST → Whitelist bypass (ACCEPT)
4. AIPROXY_BLOCKLIST → Blocklist drop (DROP)
```

### Monitoring

View rate-limited IPs:
```bash
cat /proc/net/ipt_hashlimit/aiproxy
```

View dropped packets:
```bash
sudo iptables -L AIPROXY_LIMIT -n -v
sudo iptables -L AIPROXY_BLOCKLIST -n -v
```

View current config:
```bash
sudo ./rate-limit.sh --status
```

### Troubleshooting

**Rules not working?**
- Ensure Docker is running (`DOCKER-USER` chain must exist)
- Run `sudo ./rate-limit.sh --status` to verify rules
- Check if another firewall (ufw, firewalld) is interfering

**Rules disappear after Docker restart?**
- Use the systemd service for persistence
- The service re-applies rules after Docker starts

**Need to whitelist a CIDR range?**
```bash
RATE_LIMIT_WHITELIST=10.0.0.0/8,192.168.0.0/16 sudo ./rate-limit.sh
```
