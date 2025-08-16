#include "L4.h"
#include <cctype>
#include <cstdlib>

using namespace common;

static inline uint16_t parse_u16(const std::string& s) {
    return static_cast<uint16_t>(std::stoi(s));
}

l4_packet::l4_packet(const std::string& s) {
    // Expected format: "src_port|dst_port|index|<32-bytes>"
    std::string src_s  = extract_between_delimiters(s, '|', 0, 0);
    std::string dst_s  = extract_between_delimiters(s, '|', 1, 1);
    std::string idx_s  = extract_between_delimiters(s, '|', 2, 2);
    std::string bytes_s = extract_between_delimiters(s, '|', 3, -1);

    try {
        src_port_ = parse_u16(src_s);
        dst_port_ = parse_u16(dst_s);
        index_    = static_cast<uint32_t>(std::stoul(idx_s));
    } catch (...) {
        valid_parse_ = false;
        return;
    }

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
