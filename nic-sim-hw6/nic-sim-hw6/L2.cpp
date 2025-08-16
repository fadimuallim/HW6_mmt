#include "L2.h"
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <memory>

using namespace common;

static inline uint32_t parse_u32(const std::string& s) {
    return static_cast<uint32_t>(std::stoul(s));
}

l2_packet::l2_packet(const std::string& s) {
    // Format: src_mac|dst_mac|<L3 packet>|checksum
    size_t first = s.find('|');
    size_t second = s.find('|', first + 1);
    size_t last = s.rfind('|');
    if (first == std::string::npos || second == std::string::npos ||
        last == std::string::npos || last <= second) {
        valid_parse_ = false;
        return;
    }
    std::string src_s = s.substr(0, first);
    std::string dst_s = s.substr(first + 1, second - first - 1);
    std::string inner = s.substr(second + 1, last - second - 1);
    std::string cs_s = s.substr(last + 1);

    if (!parse_mac(src_s, src_mac_) || !parse_mac(dst_s, dst_mac_)) {
        valid_parse_ = false;
        return;
    }
    try {
        checksum_ = parse_u32(cs_s);
    } catch (...) {
        valid_parse_ = false;
        return;
    }

    inner_ = std::unique_ptr<l3_packet>(new l3_packet(inner));
    l3_string_ = inner;
    valid_parse_ = true;
}

bool l2_packet::parse_mac(const std::string& s, uint8_t out[MAC_SIZE]) {
    size_t a = 0;
    for (int i = 0; i < MAC_SIZE; i++) {
        if (a + 1 >= s.size()) return false;
        auto hexval = [](char c) -> int {
            if ('0' <= c && c <= '9') return c - '0';
            if ('a' <= c && c <= 'f') return 10 + (c - 'a');
            if ('A' <= c && c <= 'F') return 10 + (c - 'A');
            return -1;
        };
        int v1 = hexval(s[a]);
        int v2 = hexval(s[a + 1]);
        if (v1 < 0 || v2 < 0) return false;
        out[i] = static_cast<uint8_t>((v1 << 4) | v2);
        a += 2;
        if (i < MAC_SIZE - 1) {
            if (a >= s.size() || s[a] != ':') return false;
            ++a;
        }
    }
    return a == s.size();
}

void l2_packet::mac_to_string_upper(const uint8_t mac[MAC_SIZE], std::string& out) {
    out.clear();
    for (int i=0;i<MAC_SIZE;i++) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned int>(mac[i]));
        out += buf;
        if (i+1 != MAC_SIZE) out += ":";
    }
}

static bool parse_ip_token(const std::string& s, uint8_t out[IP_V4_SIZE]) {
    size_t a = 0, b;
    for (int i = 0; i < IP_V4_SIZE; i++) {
        b = s.find(i < 3 ? '.' : '\0', a);
        std::string part = (i < 3) ? s.substr(a, b - a) : s.substr(a);
        if (part.empty()) return false;
        int val = std::stoi(part);
        if (val < 0 || val > 255) return false;
        out[i] = static_cast<uint8_t>(val);
        if (i < 3) a = b + 1;
    }
    return true;
}

static bool l3_sum_from_string(const std::string& s, uint32_t &sum) {
    size_t p[7];
    size_t last = 0;
    for (int i = 0; i < 7; i++) {
        p[i] = s.find('|', last);
        if (p[i] == std::string::npos) return false;
        last = p[i] + 1;
    }
    std::string src_s = s.substr(0, p[0]);
    std::string dst_s = s.substr(p[0] + 1, p[1] - p[0] - 1);
    std::string ttl_s = s.substr(p[1] + 1, p[2] - p[1] - 1);
    std::string dstp_s = s.substr(p[3] + 1, p[4] - p[3] - 1);
    std::string srcp_s = s.substr(p[4] + 1, p[5] - p[4] - 1);
    std::string idx_s = s.substr(p[5] + 1, p[6] - p[5] - 1);
    std::string data_s = s.substr(p[6] + 1);

    uint8_t src_ip[IP_V4_SIZE], dst_ip[IP_V4_SIZE];
    if (!parse_ip_token(src_s, src_ip) || !parse_ip_token(dst_s, dst_ip)) return false;
    sum = 0;
    for (int i = 0; i < IP_V4_SIZE; i++) {
        sum += src_ip[i];
        sum += dst_ip[i];
    }
    try {
        uint32_t ttl = static_cast<uint32_t>(std::stoul(ttl_s));
        sum += static_cast<uint8_t>(ttl & 0xFF);
        uint16_t dst_port = static_cast<uint16_t>(std::stoul(dstp_s));
        sum += static_cast<uint8_t>((dst_port >> 8) & 0xFF);
        sum += static_cast<uint8_t>(dst_port & 0xFF);
        uint16_t src_port = static_cast<uint16_t>(std::stoul(srcp_s));
        sum += static_cast<uint8_t>((src_port >> 8) & 0xFF);
        sum += static_cast<uint8_t>(src_port & 0xFF);
        uint32_t idx = static_cast<uint32_t>(std::stoul(idx_s));
        sum += static_cast<uint8_t>((idx >> 24) & 0xFF);
        sum += static_cast<uint8_t>((idx >> 16) & 0xFF);
        sum += static_cast<uint8_t>((idx >> 8) & 0xFF);
        sum += static_cast<uint8_t>(idx & 0xFF);
    } catch (...) {
        return false;
    }

    std::vector<uint8_t> bytes;
    auto hexval = [](char c) -> int {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return 10 + (c - 'a');
        if ('A' <= c && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    size_t i = 0;
    while (i < data_s.size()) {
        while (i < data_s.size() && std::isspace(static_cast<unsigned char>(data_s[i]))) ++i;
        if (i >= data_s.size()) break;
        if (i + 1 >= data_s.size()) return false;
        int v1 = hexval(data_s[i]);
        int v2 = hexval(data_s[i + 1]);
        if (v1 < 0 || v2 < 0) return false;
        bytes.push_back(static_cast<uint8_t>((v1 << 4) | v2));
        i += 2;
        while (i < data_s.size() && std::isspace(static_cast<unsigned char>(data_s[i]))) ++i;
        if (i < data_s.size() && data_s[i] == ' ') ++i;
    }
    if (bytes.size() != PACKET_DATA_SIZE) return false;
    for (auto b : bytes) sum += b;
    return true;
}

bool l2_packet::validate_packet(open_port_vec open_ports,
                                uint8_t ip[IP_V4_SIZE],
                                uint8_t mask,
                                uint8_t mac[MAC_SIZE]) {
    (void)open_ports; (void)ip; (void)mask;
    if (!valid_parse_ || mac == nullptr || !inner_) return false;
    for (int i = 0; i < MAC_SIZE; i++) {
        if (dst_mac_[i] != mac[i]) return false;
    }
    uint32_t sum = 0;
    for (int i = 0; i < MAC_SIZE; i++) {
        sum += src_mac_[i];
        sum += dst_mac_[i];
    }
    uint32_t l3_sum;
    if (!l3_sum_from_string(l3_string_, l3_sum)) return false;
    sum += l3_sum;
    return sum == checksum_;
}

bool l2_packet::proccess_packet(open_port_vec &open_ports,
                                uint8_t ip[IP_V4_SIZE],
                                uint8_t mask,
                                memory_dest &dst) {
    if (!inner_) return false;
    if (!inner_->validate_packet(open_ports, ip, mask, nullptr)) return false;
    memory_dest inner_dst;
    if (!inner_->proccess_packet(open_ports, ip, mask, inner_dst)) return false;

    std::string inner_str;
    inner_->as_string(inner_str);

    out_l3_string_ = inner_str;
    to_rq_ = (inner_dst == RQ);
    to_tq_ = (inner_dst == TQ);
    dst = inner_dst;
    return true;
}

bool l2_packet::as_string(std::string &packet) {
    if (to_rq_ || to_tq_) {
        packet = out_l3_string_;
    } else {
        packet.clear();
    }
    return true;
}