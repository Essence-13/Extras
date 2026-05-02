#pragma once
#include <cstdint>
#include <cstring>
#include <map>
#include <array>
#include <deque>
#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <functional>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <pcap.h>

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
using Mac = std::array<uint8_t, 6>;
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static inline std::string mac_str(const Mac& m) {
    std::ostringstream ss;
    for (int i = 0; i < 6; ++i)
        ss << (i ? ":" : "") << std::hex << std::setw(2) << std::setfill('0') << (int)m[i];
    return ss.str();
}
static inline std::string ip_str(uint32_t ip) {
    struct in_addr a; a.s_addr = ip; return inet_ntoa(a);
}

// ---------------------------------------------------------------------------
// Alert severity
// ---------------------------------------------------------------------------
enum class AlertLevel { INFO, WARNING, CRITICAL };
static inline const char* level_str(AlertLevel l) {
    switch (l) {
        case AlertLevel::INFO:     return "INFO";
        case AlertLevel::WARNING:  return "WARNING";
        case AlertLevel::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// ARPGuard
//   Detects:
//     1. IP→MAC mapping changes  (ARP spoofing)
//     2. Unsolicited ARP replies  (classic poison)
//     3. ARP reply flood from one MAC (attacker loop)
//   Responds:
//     - Calls user-supplied alert callback
//     - Optionally re-broadcasts the correct mapping via pcap
// ---------------------------------------------------------------------------
class ARPGuard {
public:
    struct Config {
        // How many ARP replies per second from one source before flood alert
        int      flood_threshold  = 10;
        // Window (seconds) over which flood rate is measured
        int      flood_window_sec = 2;
        // Known-good gateway: if set, any MAC change for this IP is CRITICAL
        uint32_t gateway_ip       = 0;
        Mac      gateway_mac      = {};
        bool     gateway_set      = false;
        // How many times to re-send the corrective ARP reply
        int      restore_count    = 5;
    };

    using AlertCb = std::function<void(AlertLevel, const std::string&)>;

    explicit ARPGuard(pcap_t* handle, Config cfg, AlertCb cb)
        : handle_(handle), cfg_(cfg), alert_cb_(std::move(cb)) {}

    // Call this from your pcap packet handler
    void process(const u_char* pkt, uint32_t caplen) {
        if (caplen < 14 + sizeof(struct ether_arp)) return;

        auto* eth = reinterpret_cast<const struct ether_header*>(pkt);
        if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;

        auto* arp = reinterpret_cast<const struct ether_arp*>(pkt + 14);
        uint16_t op = ntohs(arp->arp_op);
        if (op != ARPOP_REPLY && op != ARPOP_REQUEST) return;

        uint32_t sender_ip;
        memcpy(&sender_ip, arp->arp_spa, 4);
        Mac sender_mac; memcpy(sender_mac.data(), arp->arp_sha, 6);

        // ---- 1. Detect MAC change for a known IP ----------------------------
        auto it = ip_mac_table_.find(sender_ip);
        if (it != ip_mac_table_.end()) {
            if (it->second != sender_mac) {
                bool is_gw = cfg_.gateway_set && (sender_ip == cfg_.gateway_ip);
                AlertLevel lvl = is_gw ? AlertLevel::CRITICAL : AlertLevel::WARNING;
                std::string msg =
                    "[ARP-SPOOF] IP " + ip_str(sender_ip) +
                    " changed MAC from " + mac_str(it->second) +
                    " -> " + mac_str(sender_mac);
                if (is_gw) msg += "  *** GATEWAY MAC HIJACKED ***";
                fire(lvl, msg);

                // Re-assert the correct mapping for the gateway
                if (is_gw) restore_gateway();

                it->second = sender_mac; // update table (attacker may have taken over)
            }
        } else {
            ip_mac_table_[sender_ip] = sender_mac;
        }

        // ---- 2. Detect unsolicited reply (no prior request from us) ----------
        if (op == ARPOP_REPLY) {
            uint32_t target_ip;
            memcpy(&target_ip, arp->arp_tpa, 4);
            auto req_it = pending_requests_.find(sender_ip);
            if (req_it == pending_requests_.end()) {
                fire(AlertLevel::WARNING,
                     "[ARP-UNSOLICITED] Gratuitous/unsolicited reply from " +
                     ip_str(sender_ip) + " (" + mac_str(sender_mac) + ")");
            } else {
                pending_requests_.erase(req_it);
            }

            // ---- 3. Flood detection ------------------------------------------
            auto& times = reply_times_[sender_mac];
            auto now = Clock::now();
            auto cutoff = now - std::chrono::seconds(cfg_.flood_window_sec);
            while (!times.empty() && times.front() < cutoff) times.pop_front();
            times.push_back(now);
            if ((int)times.size() > cfg_.flood_threshold) {
                fire(AlertLevel::CRITICAL,
                     "[ARP-FLOOD] MAC " + mac_str(sender_mac) +
                     " sent " + std::to_string(times.size()) +
                     " ARP replies in " + std::to_string(cfg_.flood_window_sec) + "s");
                times.clear(); // suppress repeat alert
            }
        }

        // Track outgoing requests so we know which replies are solicited
        if (op == ARPOP_REQUEST) {
            uint32_t target_ip;
            memcpy(&target_ip, arp->arp_tpa, 4);
            pending_requests_.insert(target_ip);
        }
    }

    // Register a known-good IP→MAC entry (call for gateway, servers, etc.)
    void pin(uint32_t ip, const Mac& mac) {
        ip_mac_table_[ip] = mac;
    }

    // Expose the learned table for status display
    const std::map<uint32_t, Mac>& table() const { return ip_mac_table_; }

private:
    void fire(AlertLevel lvl, const std::string& msg) {
        if (alert_cb_) alert_cb_(lvl, msg);
    }

    // Send a gratuitous ARP reply to correct the gateway mapping on the LAN
    void restore_gateway() {
        if (!handle_ || !cfg_.gateway_set) return;
        struct {
            struct ether_header eth;
            struct ether_arp    arp;
        } __attribute__((packed)) frame;

        // Broadcast destination
        memset(frame.eth.ether_dhost, 0xff, 6);
        memcpy(frame.eth.ether_shost, cfg_.gateway_mac.data(), 6);
        frame.eth.ether_type = htons(ETHERTYPE_ARP);

        frame.arp.arp_hrd = htons(ARPHRD_ETHER);
        frame.arp.arp_pro = htons(ETHERTYPE_IP);
        frame.arp.arp_hln = 6;
        frame.arp.arp_pln = 4;
        frame.arp.arp_op  = htons(ARPOP_REPLY);
        memcpy(frame.arp.arp_sha, cfg_.gateway_mac.data(), 6);
        memcpy(frame.arp.arp_spa, &cfg_.gateway_ip, 4);
        memset(frame.arp.arp_tha, 0xff, 6);
        memcpy(frame.arp.arp_tpa, &cfg_.gateway_ip, 4);

        for (int i = 0; i < cfg_.restore_count; ++i) {
            pcap_sendpacket(handle_,
                            reinterpret_cast<const u_char*>(&frame),
                            sizeof(frame));
            usleep(50000);
        }
        fire(AlertLevel::INFO, "[ARP-RESTORE] Broadcast correct gateway mapping for " +
             ip_str(cfg_.gateway_ip) + " -> " + mac_str(cfg_.gateway_mac));
    }

    pcap_t*                                handle_;
    Config                                 cfg_;
    AlertCb                                alert_cb_;
    std::map<uint32_t, Mac>                ip_mac_table_;
    std::set<uint32_t>                     pending_requests_;
    std::map<Mac, std::deque<TimePoint>>   reply_times_;
};
