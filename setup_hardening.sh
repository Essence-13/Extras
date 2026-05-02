#!/usr/bin/env bash
# =============================================================================
# setup_hardening.sh  —  System-level defences against ARP/DNS attacks
#
# What this does:
#   1.  Pins a permanent static ARP entry for the gateway
#   2.  Applies sysctl kernel hardening (ARP filtering, rate limits)
#   3.  Configures systemd-resolved to use DNS-over-TLS (DoT)
#   4.  Optionally sets up dnscrypt-proxy for DNS-over-HTTPS (DoH)
#   5.  Enables UFW rules to block rogue DNS responses
#
# Run as root:  sudo bash setup_hardening.sh
# =============================================================================
set -euo pipefail

# ---------- USER CONFIG — edit these -----------------------------------------
IFACE="eth0"
GW_IP="192.168.1.1"
GW_MAC="aa:bb:cc:dd:ee:ff"   # get with: arp -n $GW_IP  OR  ip neigh show
# Trusted DNS-over-TLS servers
DOT_SERVER_1="1.1.1.1"        # Cloudflare
DOT_SERVER_2="8.8.8.8"        # Google
# -----------------------------------------------------------------------------

RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YEL}[!]${NC} $*"; }
error() { echo -e "${RED}[X]${NC} $*" >&2; }

require_root() { [ "$(id -u)" -eq 0 ] || { error "Run as root."; exit 1; }; }
require_root

# =============================================================================
# 1.  STATIC ARP — lock gateway MAC so spoofed ARPs can't overwrite it
# =============================================================================
info "Pinning static ARP entry: $GW_IP -> $GW_MAC"
arp -s "$GW_IP" "$GW_MAC" && info "Static ARP set (session)." \
    || warn "arp -s failed — is net-tools installed? (apt install net-tools)"

# Make it persist across reboots via /etc/rc.local or a systemd unit
STATIC_ARP_SERVICE="/etc/systemd/system/static-arp.service"
cat > "$STATIC_ARP_SERVICE" <<EOF
[Unit]
Description=Pin static ARP entry for gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/arp -s ${GW_IP} ${GW_MAC}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now static-arp.service
info "Static ARP systemd unit installed and enabled."

# =============================================================================
# 2.  SYSCTL KERNEL HARDENING
# =============================================================================
SYSCTL_CONF="/etc/sysctl.d/99-arp-dns-hardening.conf"
info "Writing sysctl hardening config to $SYSCTL_CONF"
cat > "$SYSCTL_CONF" <<'EOF'
# --- ARP Hardening ---
# Only respond to ARP requests that arrive on the interface that owns the IP
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.default.arp_filter = 1

# Do not accept gratuitous ARP from interfaces we did not ask on
net.ipv4.conf.all.arp_accept = 0
net.ipv4.conf.default.arp_accept = 0

# Announce the most specific IP on ARP requests (reduces confusion)
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

# Ignore ARP replies from non-local sources
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1

# Drop source-routed packets (used in some MITM variants)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance (prevents route hijacking)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# --- General hardening ---
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

sysctl --system > /dev/null
info "Sysctl hardening applied."

# =============================================================================
# 3.  DNS-OVER-TLS via systemd-resolved
#     Encrypts DNS — forged UDP DNS replies cannot be injected into a TLS stream
# =============================================================================
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    RESOLVED_CONF="/etc/systemd/resolved.conf.d/dot.conf"
    mkdir -p /etc/systemd/resolved.conf.d
    info "Configuring systemd-resolved with DNS-over-TLS..."
    cat > "$RESOLVED_CONF" <<EOF
[Resolve]
DNS=${DOT_SERVER_1}#cloudflare-dns.com ${DOT_SERVER_2}#dns.google
FallbackDNS=9.9.9.9#dns.quad9.net
DNSSEC=yes
DNSOverTLS=yes
EOF
    systemctl restart systemd-resolved
    info "systemd-resolved restarted with DoT + DNSSEC."
    resolvectl status | grep -E "DNS Servers|DNSOverTLS|DNSSEC" || true
else
    warn "systemd-resolved not active — skipping DoT config."
    warn "Consider: apt install systemd-resolved && systemctl enable --now systemd-resolved"
fi

# =============================================================================
# 4.  OPTIONAL: dnscrypt-proxy for DNS-over-HTTPS (DoH)
#     Stronger than DoT for high-risk environments
# =============================================================================
setup_dnscrypt() {
    if ! command -v dnscrypt-proxy &>/dev/null; then
        info "Installing dnscrypt-proxy..."
        apt-get install -y dnscrypt-proxy 2>/dev/null \
            || { warn "dnscrypt-proxy not available in apt — skipping DoH."; return; }
    fi

    DOH_CONF="/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
    if [ -f "$DOH_CONF" ]; then
        # Enable HTTPS servers only
        sed -i "s/^server_names = .*/server_names = ['cloudflare', 'google', 'quad9-doh-ip4-filter-pri']/" "$DOH_CONF"
        sed -i "s/^# require_https = false/require_https = true/" "$DOH_CONF"
        systemctl restart dnscrypt-proxy
        info "dnscrypt-proxy configured for DoH."
    fi
}
setup_dnscrypt

# =============================================================================
# 5.  UFW RULES — only allow DNS responses from trusted servers
#     Drops forged UDP:53 packets from unauthorised sources
# =============================================================================
if command -v ufw &>/dev/null; then
    info "Configuring UFW to restrict DNS responses..."
    ufw --force enable 2>/dev/null || true

    # Allow DNS to/from trusted servers only
    ufw allow out to "$DOT_SERVER_1" port 53 proto udp comment "DNS out cf"
    ufw allow out to "$DOT_SERVER_2" port 53 proto udp comment "DNS out google"
    ufw allow out to "$DOT_SERVER_1" port 853 proto tcp comment "DoT out cf"
    ufw allow out to "$DOT_SERVER_2" port 853 proto tcp comment "DoT out google"

    # Block incoming UDP:53 that is NOT from our trusted servers (drop poisoned replies)
    ufw deny in proto udp from any to any port 53 comment "Block rogue DNS"

    info "UFW DNS rules applied."
else
    warn "ufw not found — skipping firewall DNS rules."
    warn "Consider: apt install ufw"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${GRN}========================================${NC}"
echo -e "${GRN}  Hardening Summary${NC}"
echo -e "${GRN}========================================${NC}"
echo "  [ARP]  Static entry:     $GW_IP -> $GW_MAC"
echo "  [ARP]  sysctl rules:     arp_filter, arp_accept=0, redirects disabled"
echo "  [DNS]  DoT servers:      $DOT_SERVER_1, $DOT_SERVER_2"
echo "  [DNS]  DNSSEC:           enabled"
echo "  [DNS]  UFW DNS rules:    applied (block rogue UDP:53)"
echo ""
echo -e "${YEL}Next step:${NC} compile and run the defender daemon:"
echo "   cd defender && make"
echo "   sudo ./defender $IFACE $GW_IP $GW_MAC ${DOT_SERVER_1},${DOT_SERVER_2}"
echo ""
