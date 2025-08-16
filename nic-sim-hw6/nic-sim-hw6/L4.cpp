#include "L4.h"
#include <cctype>
#include <cstdlib>
#include <limits>

using namespace common;

static inline bool parse_u16(const std::string& s, uint16_t& out) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b-1]))) --b;
    if (a >= b) return false;
    std::string t = s.substr(a, b - a);
    if (t.find_first_not_of("0123456789") != std::string::npos)
        return false;
    try {
        unsigned long val = std::stoul(t);
        if (val > std::numeric_limits<uint16_t>::max()) return false;
        out = static_cast<uint16_t>(val);
        return true;
    } catch (...) {
        return false;
    }
}

static inline bool parse_u32(const std::string& s, uint32_t& out) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b-1]))) --b;
    if (a >= b) return false;
    std::string t = s.substr(a, b - a);
    if (t.find_first_not_of("0123456789") != std::string::npos)
        return false;
    try {
        unsigned long val = std::stoul(t);
        if (val > std::numeric_limits<uint32_t>::max()) return false;
        out = static_cast<uint32_t>(val);
        return true;
    } catch (...) {
        return false;
    }
}

l4_packet::l4_packet(const std::string& s) {
    // Expected format: "src_port|dst_port|index|<32-bytes>"
    std::string src_s  = extract_between_delimiters(s, '|', 0, 0);
    std::string dst_s  = extract_between_delimiters(s, '|', 1, 1);
    std::string idx_s  = extract_between_delimiters(s, '|', 2, 2);
    std::string bytes_s = extract_between_delimiters(s, '|', 3, -1);

    uint16_t src_tmp, dst_tmp;
    uint32_t idx_tmp;
    if (!parse_u16(src_s, src_tmp) || !parse_u16(dst_s, dst_tmp) ||
        !parse_u32(idx_s, idx_tmp)) {
        valid_parse_ = false;
        return;
    }
    src_port_ = src_tmp;
    dst_port_ = dst_tmp;
    index_ = idx_tmp;

    std::vector<uint8_t> bytes;
    if (!parse_hex_bytes_32(bytes_s, bytes)) {
        valid_parse_ = false;
        return;
    }
    data_ = std::move(bytes);
    valid_parse_ = true;
}

l4_packet::l4_packet(uint32_t index, uint16_t src_port, uint16_t dst_port,
                     const std::vector<uint8_t>& data)
: index_(index), src_port_(src_port), dst_port_(dst_port), data_(data), valid_parse_(true) {}

bool l4_packet::validate_packet(open_port_vec open_ports,
                                uint8_t ip[IP_V4_SIZE],
                                uint8_t mask,
                                uint8_t mac[MAC_SIZE]) {
    (void)ip; (void)mask; (void)mac;
    if (!valid_parse_) return false;
    bool found = false;
    for (const auto& op : open_ports) {
        if (op.src_prt == src_port_ && op.dst_prt == dst_port_) {
            found = true;
            break;
        }
    }
    if (!found) return false;
    if (index_ > DATA_ARR_SIZE) return false;
    if (index_ + PACKET_DATA_SIZE > DATA_ARR_SIZE) return false;
    return true;
}

bool l4_packet::proccess_packet(open_port_vec &open_ports,
                                uint8_t ip[IP_V4_SIZE],
                                uint8_t mask,
                                memory_dest &dst) {
    (void)ip; (void)mask;
    for (auto& op : open_ports) {
        if (op.src_prt == src_port_ && op.dst_prt == dst_port_) {
            for (size_t i = 0; i < data_.size(); ++i) {
                op.data[index_ + i] = data_[i];
            }
            dst = LOCAL_DRAM;
            return true;
        }
    }
    return false;
}

bool l4_packet::as_string(std::string &packet) {
    packet.clear();
    // Serialize back to the format: src|dst|index|data
    packet += std::to_string(src_port_) + "|";
    packet += std::to_string(dst_port_) + "|";
    packet += std::to_string(index_) + "|";
    for (size_t i = 0; i < data_.size(); ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned int>(data_[i]));
        packet += buf;
        if (i + 1 != data_.size()) packet += " ";
    }
    return true;
}

bool l4_packet::parse_hex_bytes_32(const std::string& s, std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(PACKET_DATA_SIZE);
    size_t i = 0;
    auto hexval = [](char c)->int{
        if ('0'<=c && c<='9') return c - '0';
        if ('a'<=c && c<='f') return 10 + (c - 'a');
        if ('A'<=c && c<='F') return 10 + (c - 'A');
        return -1;
    };
    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        if (i >= s.size()) break;
        if (i + 1 >= s.size()) return false;
        int v1 = hexval(s[i]);
        int v2 = hexval(s[i+1]);
        if (v1 < 0 || v2 < 0) return false;
        out.push_back(static_cast<uint8_t>((v1<<4)|v2));
        i += 2;
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        if (i < s.size() && s[i] == ' ') ++i;
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    }
    return out.size() == PACKET_DATA_SIZE;
}
