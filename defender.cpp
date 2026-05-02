/**
 * defender.cpp — ARP Spoof + DNS Poison Detection & Response Daemon
 *
 * Usage:
 *   sudo ./defender <iface> <gateway_ip> <gateway_mac> \
 *                   <trusted_dns1>[,<trusted_dns2>,...] \
 *                   [watched_domain1,watched_domain2,...]
 *
 * Example:
 *   sudo ./defender eth0 192.168.1.1 aa:bb:cc:dd:ee:ff \
 *                   8.8.8.8,8.8.4.4 google.com,github.com
 *
 * Defenses active:
 *   [ARP-1]  IP→MAC mapping change detection
 *   [ARP-2]  Unsolicited / gratuitous ARP reply detection
 *   [ARP-3]  ARP reply flood detection (attacker re-poison loop)
 *   [ARP-4]  Automatic broadcast of correct gateway ARP mapping on attack
 *   [DNS-1]  Response from untrusted/unexpected DNS server
 *   [DNS-2]  Duplicate response for same TxID (race attack)
 *   [DNS-3]  Response source mismatch vs queried server
 *   [DNS-4]  Suspicious TTL fingerprint matching known attack payloads
 *   [DNS-5]  Alert on responses for watched (high-value) domains
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstring>
#include <csignal>
#include <ctime>
#include <iomanip>
#include <mutex>

#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <unistd.h>

// Pull in AlertLevel before the guard headers
enum class AlertLevel { INFO, WARNING, CRITICAL };
static inline const char* level_str(AlertLevel l) {
    switch (l) {
        case AlertLevel::INFO:     return "INFO    ";
        case AlertLevel::WARNING:  return "WARNING ";
        case AlertLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

#include "arp_guard.hpp"
#include "dns_guard.hpp"

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static std::atomic<bool>  g_running{true};
static std::mutex         g_log_mutex;
static std::ofstream      g_logfile;
static ARPGuard*          g_arp  = nullptr;
static DNSGuard*          g_dns  = nullptr;
static pcap_t*            g_pcap = nullptr;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
static void log_alert(AlertLevel lvl, const std::string& msg) {
    // Timestamp
    auto now  = std::chrono::system_clock::now();
    auto tt   = std::chrono::system_clock::to_time_t(now);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));

    // Colour codes for terminal
    const char* col = "\033[0m";
    if (lvl == AlertLevel::WARNING)  col = "\033[33m";  // yellow
    if (lvl == AlertLevel::CRITICAL) col = "\033[31m";  // red

    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::cout << col << "[" << ts << "] [" << level_str(lvl) << "] "
              << msg << "\033[0m\n" << std::flush;

    if (g_logfile.is_open())
        g_logfile << "[" << ts << "] [" << level_str(lvl) << "] " << msg << "\n" << std::flush;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static uint32_t parse_ip(const std::string& s) {
    struct in_addr a; inet_aton(s.c_str(), &a); return a.s_addr;
}

static Mac parse_mac(const std::string& s) {
    Mac m = {};
    unsigned int v[6];
    sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
           &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
    for (int i = 0; i < 6; ++i) m[i] = (uint8_t)v[i];
    return m;
}

static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim))
        if (!token.empty()) out.push_back(token);
    return out;
}

static Mac get_iface_mac(const std::string& iface) {
    Mac m = {};
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(m.data(), ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return m;
}

// ---------------------------------------------------------------------------
// pcap callback — routes packets to both guards
// ---------------------------------------------------------------------------
static void pkt_handler(u_char* /*user*/,
                         const struct pcap_pkthdr* hdr,
                         const u_char* pkt) {
    if (g_arp) g_arp->process(pkt, hdr->caplen);
    if (g_dns) g_dns->process(pkt, hdr->caplen);
}

// ---------------------------------------------------------------------------
// Status thread — prints ARP table summary every 30 s
// ---------------------------------------------------------------------------
static void status_thread_fn() {
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!g_running || !g_arp) break;
        const auto& tbl = g_arp->table();
        std::lock_guard<std::mutex> lk(g_log_mutex);
        std::cout << "\n--- ARP Table Snapshot (" << tbl.size() << " entries) ---\n";
        for (auto& [ip, mac] : tbl)
            std::cout << "  " << ip_str(ip) << " -> " << mac_str(mac) << "\n";
        std::cout << "---\n\n" << std::flush;
    }
}

// ---------------------------------------------------------------------------
// Signal handler
// ---------------------------------------------------------------------------
static void on_signal(int) {
    g_running = false;
    if (g_pcap) pcap_breakloop(g_pcap);
}

// ---------------------------------------------------------------------------
// Static ARP pinning  (calls system `arp -s`)
// ---------------------------------------------------------------------------
static void pin_static_arp(const std::string& ip, const std::string& mac) {
    std::string cmd = "arp -s " + ip + " " + mac + " 2>/dev/null";
    if (system(cmd.c_str()) == 0)
        log_alert(AlertLevel::INFO,
                  "[INIT] Pinned static ARP: " + ip + " -> " + mac);
    else
        log_alert(AlertLevel::WARNING,
                  "[INIT] Could not pin static ARP for " + ip +
                  " (may need root or net-tools installed)");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr <<
            "Usage: sudo ./defender <iface> <gateway_ip> <gateway_mac>\n"
            "                       <trusted_dns1>[,dns2,...]\n"
            "                       [watched_domain1,domain2,...]\n\n"
            "Example:\n"
            "  sudo ./defender eth0 192.168.1.1 aa:bb:cc:dd:ee:ff \\\n"
            "                  8.8.8.8,8.8.4.4 google.com,github.com\n";
        return 1;
    }

    std::string iface      = argv[1];
    std::string gw_ip_str  = argv[2];
    std::string gw_mac_str = argv[3];
    auto dns_list          = split(argv[4], ',');
    std::vector<std::string> watched;
    if (argc >= 6) watched = split(argv[5], ',');

    // Open log file
    g_logfile.open("defender.log", std::ios::app);
    log_alert(AlertLevel::INFO, "=== Defender starting on " + iface + " ===");

    // ---- Resolve our own MAC --------------------------------------------------
    Mac my_mac = get_iface_mac(iface);
    log_alert(AlertLevel::INFO,
              "[INIT] Interface MAC: " + mac_str(my_mac));

    // ---- Pin static ARP for gateway ------------------------------------------
    pin_static_arp(gw_ip_str, gw_mac_str);

    // ---- Open pcap -----------------------------------------------------------
    char err[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(iface.c_str(), 65535, 1, 100, err);
    if (!g_pcap) {
        std::cerr << "[!] pcap_open_live failed: " << err << "\n";
        return 1;
    }

    // Capture ARP + DNS (in and out)
    struct bpf_program fp;
    const char* filter = "arp or (udp port 53)";
    if (pcap_compile(g_pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_pcap, &fp) < 0) {
        std::cerr << "[!] pcap filter error: " << pcap_geterr(g_pcap) << "\n";
        return 1;
    }

    // ---- Configure ARPGuard --------------------------------------------------
    ARPGuard::Config arp_cfg;
    arp_cfg.flood_threshold  = 10;
    arp_cfg.flood_window_sec = 2;
    arp_cfg.gateway_ip       = parse_ip(gw_ip_str);
    arp_cfg.gateway_mac      = parse_mac(gw_mac_str);
    arp_cfg.gateway_set      = true;
    arp_cfg.restore_count    = 5;

    ARPGuard arp_guard(g_pcap, arp_cfg, log_alert);
    // Pre-seed the known-good gateway mapping
    arp_guard.pin(parse_ip(gw_ip_str), parse_mac(gw_mac_str));
    g_arp = &arp_guard;

    // ---- Configure DNSGuard --------------------------------------------------
    DNSGuard::Config dns_cfg;
    for (auto& d : dns_list) {
        dns_cfg.trusted_dns_ips.push_back(parse_ip(d));
        log_alert(AlertLevel::INFO, "[INIT] Trusted DNS: " + d);
    }
    dns_cfg.suspicious_ttl   = 3600;   // attacker hardcodes this
    dns_cfg.query_timeout_ms = 5000;
    dns_cfg.watched_domains  = watched;
    for (auto& w : watched)
        log_alert(AlertLevel::INFO, "[INIT] Watched domain: " + w);

    DNSGuard dns_guard(dns_cfg, log_alert);
    g_dns = &dns_guard;

    // ---- Signal handling -----------------------------------------------------
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    // ---- Status thread -------------------------------------------------------
    std::thread status_t(status_thread_fn);

    log_alert(AlertLevel::INFO,
              "[INIT] All defenses active. Monitoring... (Ctrl-C to stop)");

    // ---- Main capture loop ---------------------------------------------------
    pcap_loop(g_pcap, -1, pkt_handler, nullptr);

    // ---- Cleanup -------------------------------------------------------------
    g_running = false;
    status_t.join();
    pcap_close(g_pcap);
    log_alert(AlertLevel::INFO, "=== Defender stopped ===");
    return 0;
}
