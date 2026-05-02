#pragma once
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <functional>
#include <chrono>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

// ---------------------------------------------------------------------------
// Compact DNS header (wire format)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct DnsHdr {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count, ans_count, auth_count, add_count;
};
#pragma pack(pop)

static inline bool dns_is_response(const DnsHdr* h) {
    return (ntohs(h->flags) & 0x8000) != 0;
}

// Walk a DNS wire-format name and return the dotted string.
// Returns number of bytes consumed (including terminal 0x00).
static inline int dns_parse_name(const u_char* base, int base_len,
                                  const u_char* ptr, std::string& out) {
    out.clear();
    int consumed = 0;
    bool jumped  = false;
    const u_char* p = ptr;
    int safety   = 0;

    while (safety++ < 128) {
        if (p >= base + base_len) break;
        uint8_t len = *p;

        if (len == 0) {                          // end of name
            if (!jumped) consumed++;
            if (!out.empty() && out.back() == '.') out.pop_back();
            return consumed;
        }
        if ((len & 0xC0) == 0xC0) {             // pointer (compression)
            if (p + 1 >= base + base_len) break;
            uint16_t offset = ((len & 0x3F) << 8) | *(p + 1);
            if (!jumped) consumed += 2;
            p = base + offset;
            jumped = true;
            continue;
        }
        // label
        if (!jumped) consumed += len + 1;
        for (int i = 1; i <= len; ++i) out += (char)p[i];
        out += '.';
        p += len + 1;
    }
    return consumed;
}

// ---------------------------------------------------------------------------
// DNSGuard
//   Detects:
//     1. Response source IP != the DNS server we queried
//     2. Two different responses for the same TxID  (race-win by attacker)
//     3. Answers with suspiciously uniform TTLs matching known attack patterns
// ---------------------------------------------------------------------------
class DNSGuard {
public:
    struct Config {
        // Authoritative DNS server IPs that are allowed to answer us
        std::vector<uint32_t> trusted_dns_ips;
        // TTL value that triggers an alert if seen for a protected domain (seconds)
        // The attacker hardcodes 3600.  Set 0 to disable.
        uint32_t              suspicious_ttl   = 3600;
        // How long (ms) to keep a pending query record before expiring it
        int                   query_timeout_ms = 5000;
        // Domain suffixes we especially care about (alert even on first response)
        std::vector<std::string> watched_domains;
    };

    using AlertCb = std::function<void(AlertLevel, const std::string&)>;

    explicit DNSGuard(Config cfg, AlertCb cb)
        : cfg_(std::move(cfg)), alert_cb_(std::move(cb)) {}

    // Call this from your pcap packet handler for every captured packet
    void process(const u_char* pkt, uint32_t caplen) {
        if (caplen < 14 + 20 + 8 + sizeof(DnsHdr)) return;

        auto* eth_type_ptr = pkt + 12;
        uint16_t eth_type;
        memcpy(&eth_type, eth_type_ptr, 2);
        if (ntohs(eth_type) != 0x0800) return;  // IPv4 only

        auto* ip  = reinterpret_cast<const struct iphdr*>(pkt + 14);
        int ip_hl = ip->ihl * 4;
        if (ip->protocol != IPPROTO_UDP) return;

        auto* udp = reinterpret_cast<const struct udphdr*>(pkt + 14 + ip_hl);
        uint16_t sport = ntohs(udp->source);
        uint16_t dport = ntohs(udp->dest);

        const u_char* dns_start = pkt + 14 + ip_hl + 8;
        int dns_len = (int)caplen - 14 - ip_hl - 8;
        if (dns_len < (int)sizeof(DnsHdr)) return;

        auto* dns = reinterpret_cast<const DnsHdr*>(dns_start);
        uint16_t txid = ntohs(dns->id);

        expire_old_queries();

        // ---- Outgoing query (src port ephemeral, dst port 53) ---------------
        if (dport == 53) {
            QueryRecord rec;
            rec.txid      = txid;
            rec.dns_server = ip->daddr;
            rec.timestamp  = Clock::now();
            // Extract first questioned domain
            if (ntohs(dns->q_count) >= 1) {
                dns_parse_name(dns_start, dns_len,
                               dns_start + sizeof(DnsHdr), rec.domain);
            }
            pending_[txid] = rec;
            return;
        }

        // ---- Incoming response (src port 53) --------------------------------
        if (sport != 53) return;
        if (!dns_is_response(dns)) return;

        uint32_t resp_src = ip->saddr;

        // Check 1: Is this response from a trusted DNS server?
        if (!cfg_.trusted_dns_ips.empty()) {
            bool trusted = false;
            for (auto t : cfg_.trusted_dns_ips) if (t == resp_src) { trusted = true; break; }
            if (!trusted) {
                std::string domain;
                if (ntohs(dns->q_count) >= 1)
                    dns_parse_name(dns_start, dns_len,
                                   dns_start + sizeof(DnsHdr), domain);
                fire(AlertLevel::CRITICAL,
                     "[DNS-POISON] Response for '" + domain +
                     "' (TxID " + std::to_string(txid) +
                     ") came from UNTRUSTED IP " + ip_str_s(resp_src));
            }
        }

        // Check 2: Have we already seen a response for this TxID?
        auto dup_it = answered_[txid];
        if (dup_it != 0 && dup_it != resp_src) {
            fire(AlertLevel::CRITICAL,
                 "[DNS-DUPLICATE] TxID " + std::to_string(txid) +
                 " answered by TWO different IPs: " +
                 ip_str_s(dup_it) + " and " + ip_str_s(resp_src) +
                 " — classic DNS poisoning race detected");
        }
        answered_[txid] = resp_src;

        // Check 3: Cross-check against which DNS server we queried
        auto q_it = pending_.find(txid);
        if (q_it != pending_.end()) {
            if (q_it->second.dns_server != resp_src) {
                fire(AlertLevel::CRITICAL,
                     "[DNS-MISMATCH] Queried " + ip_str_s(q_it->second.dns_server) +
                     " but response for '" + q_it->second.domain +
                     "' came from " + ip_str_s(resp_src));
            }

            // Check 4: Suspicious TTL in answer section
            if (cfg_.suspicious_ttl != 0 && ntohs(dns->ans_count) > 0) {
                check_answer_ttls(dns_start, dns_len, dns, q_it->second.domain);
            }

            // Check 5: Watched domain alert
            for (auto& wd : cfg_.watched_domains) {
                if (q_it->second.domain == wd ||
                    ends_with(q_it->second.domain, "." + wd)) {
                    fire(AlertLevel::WARNING,
                         "[DNS-WATCHED] Response for protected domain '" +
                         q_it->second.domain + "' received from " + ip_str_s(resp_src));
                }
            }
            pending_.erase(q_it);
        }
    }

private:
    struct QueryRecord {
        uint16_t  txid;
        uint32_t  dns_server;
        TimePoint timestamp;
        std::string domain;
    };

    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    void fire(AlertLevel lvl, const std::string& msg) {
        if (alert_cb_) alert_cb_(lvl, msg);
    }

    static std::string ip_str_s(uint32_t ip) {
        struct in_addr a; a.s_addr = ip; return inet_ntoa(a);
    }

    static bool ends_with(const std::string& s, const std::string& suffix) {
        if (suffix.size() > s.size()) return false;
        return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    void expire_old_queries() {
        auto cutoff = Clock::now() -
                      std::chrono::milliseconds(cfg_.query_timeout_ms);
        for (auto it = pending_.begin(); it != pending_.end(); ) {
            if (it->second.timestamp < cutoff) it = pending_.erase(it);
            else ++it;
        }
    }

    // Walk answer RRs and flag if TTL matches the attacker's hardcoded value
    void check_answer_ttls(const u_char* dns_start, int dns_len,
                            const DnsHdr* dns, const std::string& domain) {
        // Skip question section first
        const u_char* p = dns_start + sizeof(DnsHdr);
        const u_char* end = dns_start + dns_len;
        for (int q = 0; q < ntohs(dns->q_count) && p < end; ++q) {
            std::string tmp;
            int consumed = dns_parse_name(dns_start, dns_len, p, tmp);
            p += consumed;
            p += 4; // type + class
        }
        // Now parse answers
        for (int a = 0; a < ntohs(dns->ans_count) && p + 10 < end; ++a) {
            std::string tmp;
            int consumed = dns_parse_name(dns_start, dns_len, p, tmp);
            p += consumed;
            if (p + 10 > end) break;
            // uint16_t type  = ntohs(*(uint16_t*)p);
            // uint16_t cls   = ntohs(*(uint16_t*)(p+2));
            uint32_t ttl;
            memcpy(&ttl, p + 4, 4);
            ttl = ntohl(ttl);
            uint16_t rdlen;
            memcpy(&rdlen, p + 8, 2);
            rdlen = ntohs(rdlen);
            if (ttl == cfg_.suspicious_ttl) {
                fire(AlertLevel::WARNING,
                     "[DNS-TTL] Answer for '" + domain +
                     "' has suspicious TTL=" + std::to_string(ttl) +
                     "s (matches known attack pattern)");
            }
            p += 10 + rdlen;
        }
    }

    Config                          cfg_;
    AlertCb                         alert_cb_;
    std::map<uint16_t, QueryRecord> pending_;    // txid -> query we sent
    std::map<uint16_t, uint32_t>    answered_;   // txid -> first responder IP
};
