#include "L3.h"
#include <cstdlib>
#include <cstring>
#include <cctype>

using namespace common;

static inline uint16_t parse_u16(const std::string& s) {
    return static_cast<uint16_t>(std::stoi(s));
}

l3_packet::l3_packet(const std::string& s) {
    std::string src_s = extract_between_delimiters(s, '|', 0, 0);
    std::string dst_s = extract_between_delimiters(s, '|', 1, 1);
    std::string ttl_s = extract_between_delimiters(s, '|', 2, 2);
    std::string cs_s  = extract_between_delimiters(s, '|', 3, 3);
    std::string dstp_s= extract_between_delimiters(s, '|', 4, 4);
    std::string srcp_s= extract_between_delimiters(s, '|', 5, 5);
    std::string zero_s= extract_between_delimiters(s, '|', 6, 6);
    std::string bytes_s=extract_between_delimiters(s, '|', 7, -1);

    if (!parse_ip(src_s, src_ip_) || !parse_ip(dst_s, dst_ip_)) {
        valid_parse_ = false; return;
    }
    try {
        ttl_ = static_cast<uint32_t>(std::stoul(ttl_s));
        checksum_ = static_cast<uint32_t>(std::stoul(cs_s));
        dst_port_ = parse_u16(dstp_s);
        src_port_ = parse_u16(srcp_s);
        l4_index_ = static_cast<uint32_t>(std::stoul(zero_s));
    } catch (...) { valid_parse_ = false; return; }

    // parse 32 bytes payload
    std::vector<uint8_t> bytes;
    auto hexval = [](char c)->int{
        if ('0'<=c && c<='9') return c - '0';
        if ('a'<=c && c<='f') return 10 + (c - 'a');
        if ('A'<=c && c<='F') return 10 + (c - 'A');
        return -1;
    };
    size_t i = 0;
    while (i < bytes_s.size()) {
        while (i < bytes_s.size() && std::isspace(static_cast<unsigned char>(bytes_s[i]))) ++i;
        if (i >= bytes_s.size()) break;
        if (i + 1 >= bytes_s.size()) { valid_parse_ = false; return; }
        int v1 = hexval(bytes_s[i]);
        int v2 = hexval(bytes_s[i+1]);
        if (v1<0 || v2<0) { valid_parse_ = false; return; }
        bytes.push_back(static_cast<uint8_t>((v1<<4)|v2));
        i += 2;
        while (i < bytes_s.size() && std::isspace(static_cast<unsigned char>(bytes_s[i]))) ++i;
        if (i < bytes_s.size() && bytes_s[i] == ' ') ++i;
        while (i < bytes_s.size() && std::isspace(static_cast<unsigned char>(bytes_s[i]))) ++i;
    }
    if (bytes.size() != PACKET_DATA_SIZE) { valid_parse_ = false; return; }
    data_ = std::move(bytes);

    valid_parse_ = true;
}

bool l3_packet::parse_ip(const std::string& s, uint8_t out[4]) {
    size_t a = 0, b;
    for (int i=0;i<4;i++) {
        b = s.find(i<3?'.': '\0', a);
        std::string part = (i<3) ? s.substr(a, b-a) : s.substr(a);
        if (part.empty()) return false;
        int val = std::stoi(part);
        if (val < 0 || val > 255) return false;
        out[i] = static_cast<uint8_t>(val);
        if (i<3) a = b+1;
    }
    return true;
}

bool l3_packet::is_local_ip(const uint8_t addr[4],
                            const uint8_t nic_ip[4],
                            uint8_t mask_bits) {
    if (mask_bits == 0) return true;
    uint32_t a = (addr[0]<<24)|(addr[1]<<16)|(addr[2]<<8)|addr[3];
    uint32_t n = (nic_ip[0]<<24)|(nic_ip[1]<<16)|(nic_ip[2]<<8)|nic_ip[3];
    uint32_t mask = (mask_bits==32) ? 0xFFFFFFFFu : (~0u << (32 - mask_bits));
    return (a & mask) == (n & mask);
}

uint32_t l3_packet::compute_checksum(const uint8_t src_ip[4],
                                     const uint8_t dst_ip[4],
                                     uint32_t ttl,
                                     uint16_t dst_port,
                                     uint16_t src_port,
                                     uint32_t l4_index,
                                     const std::vector<uint8_t>& data) {
    uint32_t sum = 0;
    for (int i = 0; i < 4; i++) sum += src_ip[i];
    for (int i = 0; i < 4; i++) sum += dst_ip[i];
    sum += static_cast<uint8_t>(ttl & 0xFF);
    sum += static_cast<uint8_t>((dst_port >> 8) & 0xFF);
    sum += static_cast<uint8_t>(dst_port & 0xFF);
    sum += static_cast<uint8_t>((src_port >> 8) & 0xFF);
    sum += static_cast<uint8_t>(src_port & 0xFF);
    sum += static_cast<uint8_t>((l4_index >> 24) & 0xFF);
    sum += static_cast<uint8_t>((l4_index >> 16) & 0xFF);
    sum += static_cast<uint8_t>((l4_index >> 8) & 0xFF);
    sum += static_cast<uint8_t>(l4_index & 0xFF);
    for (auto b : data) sum += b;
    return sum;
}

uint32_t l3_packet::raw_fields_checksum() const {
    return compute_checksum(src_ip_, dst_ip_, ttl_, dst_port_, src_port_, l4_index_, data_);
}

void l3_packet::ip_to_string_upper(const uint8_t ip[4], std::string& out) {
    out.clear();
    out += std::to_string(ip[0]); out += ".";
    out += std::to_string(ip[1]); out += ".";
    out += std::to_string(ip[2]); out += ".";
    out += std::to_string(ip[3]);
}

bool l3_packet::validate_packet(open_port_vec open_ports,
                                uint8_t ip[IP_V4_SIZE],
                                uint8_t mask,
                                uint8_t mac[MAC_SIZE]) {
    (void)open_ports; (void)mac; (void)ip; (void)mask;
    if (!valid_parse_) return false;
    uint32_t calc = compute_checksum(src_ip_, dst_ip_, ttl_, dst_port_, src_port_, l4_index_, data_);
    if (calc != checksum_) return false;
    return true;
}

bool l3_packet::proccess_packet(open_port_vec &open_ports,
                                uint8_t nic_ip[IP_V4_SIZE],
                                uint8_t mask,
                                memory_dest &dst) {
    (void)open_ports;
    bool dst_is_nic = (dst_ip_[0]==nic_ip[0] && dst_ip_[1]==nic_ip[1] &&
                       dst_ip_[2]==nic_ip[2] && dst_ip_[3]==nic_ip[3]);
    bool dst_local = is_local_ip(dst_ip_, nic_ip, mask);
    bool src_local = is_local_ip(src_ip_, nic_ip, mask);

    if (ttl_ == 0) {
        return false;
    }
    uint32_t new_ttl = ttl_ - 1;
    if (new_ttl == 0) {
        return false;
    }

    std::memcpy(out_dst_ip_, dst_ip_, sizeof(dst_ip_));
    std::memcpy(out_src_ip_, src_ip_, sizeof(src_ip_));
    out_ttl_ = new_ttl;

    if (dst_is_nic) {
        l4_packet inner(l4_index_, src_port_, dst_port_, data_);
        memory_dest inner_dst;
        if (!(inner.validate_packet(open_ports, nic_ip, mask, nullptr) &&
              inner.proccess_packet(open_ports, nic_ip, mask, inner_dst))) {
            return false;
        }
        dst = LOCAL_DRAM;
        to_local_ = true;
        return true;
    }

    if (dst_local && !src_local) {
        out_checksum_ = compute_checksum(out_src_ip_, out_dst_ip_, out_ttl_, dst_port_, src_port_, l4_index_, data_);
        to_rq_ = true;
        dst = RQ;
        return true;
    }

    if (src_local && !dst_local) {
        std::memcpy(out_src_ip_, nic_ip, 4);
        out_checksum_ = compute_checksum(out_src_ip_, out_dst_ip_, out_ttl_, dst_port_, src_port_, l4_index_, data_);
        to_tq_ = true;
        dst = TQ;
        return true;
    }

    if (!src_local && !dst_local) {
        out_checksum_ = compute_checksum(out_src_ip_, out_dst_ip_, out_ttl_, dst_port_, src_port_, l4_index_, data_);
        to_tq_ = true;
        dst = TQ;
        return true;
    }

    return false;
}

bool l3_packet::as_string(std::string &packet) {
    if (!(to_rq_ || to_tq_)) {
        out_checksum_ = compute_checksum(src_ip_, dst_ip_, ttl_, dst_port_, src_port_, l4_index_, data_);
        std::memcpy(out_src_ip_, src_ip_, 4);
        std::memcpy(out_dst_ip_, dst_ip_, 4);
        out_ttl_ = ttl_;
    }
    std::string sip, dip;
    ip_to_string_upper(out_src_ip_, sip);
    ip_to_string_upper(out_dst_ip_, dip);
    packet.clear();
    packet += sip + "|" + dip + "|" + std::to_string(out_ttl_) + "|" + std::to_string(out_checksum_) + "|";
    packet += std::to_string(dst_port_) + "|" + std::to_string(src_port_) + "|" + std::to_string(l4_index_) + "|";
    for (size_t i = 0; i < data_.size(); ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned int>(data_[i]));
        packet += buf;
        if (i + 1 != data_.size()) packet += " ";
    }
    return true;
}
