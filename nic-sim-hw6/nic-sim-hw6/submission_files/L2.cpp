#include "L2.h"
#include <cctype>
#include <cstring>
#include <cstdlib>

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

    inner_ = new l3_packet(inner);
    owns_inner_ = true;
    l3_string_ = inner;
    valid_parse_ = true;
}

bool l2_packet::parse_mac(const std::string& s, uint8_t out[MAC_SIZE]) {
    size_t a = 0;
    for (int i=0;i<MAC_SIZE;i++) {
        if (a + 1 >= s.size()) return false;
        auto hexval = [](char c)->int{
            if ('0'<=c && c<='9') return c - '0';
            if ('a'<=c && c<='f') return 10 + (c - 'a');
            if ('A'<=c && c<='F') return 10 + (c - 'A');
            return -1;
        };
        int v1 = hexval(s[a]);
        int v2 = hexval(s[a+1]);
        if (v1<0 || v2<0) return false;
        out[i] = static_cast<uint8_t>((v1<<4)|v2);
        if (i<MAC_SIZE-1) {
            if (a+2 >= s.size() || s[a+2] != ':') return false;
            a += 3;
        }
    }
    return true;
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
    uint32_t l3_sum = inner_->raw_fields_checksum();
    sum += l3_sum;
    sum += static_cast<uint8_t>((l3_sum >> 8) & 0xFF);
    sum += static_cast<uint8_t>(l3_sum & 0xFF);
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
        return true;
    }
    std::string s_mac, d_mac;
    mac_to_string_upper(src_mac_, s_mac);
    mac_to_string_upper(dst_mac_, d_mac);
    packet.clear();
    packet += s_mac + "|" + d_mac + "|" + out_l3_string_ + "|";
    packet += std::to_string(0);
    return true;
}

l2_packet::~l2_packet() {
    if (owns_inner_) {
        delete inner_;
        inner_ = nullptr;
    }
}
