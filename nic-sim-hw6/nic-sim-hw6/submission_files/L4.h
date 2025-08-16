#ifndef __L4__
#define __L4__

#include <string>
#include <vector>
#include "common.hpp"
#include "packets.hpp"

class l4_packet : public generic_packet {
public:
    explicit l4_packet(const std::string& s);

    bool validate_packet(common::open_port_vec open_ports,
                         uint8_t ip[common::IP_V4_SIZE],
                         uint8_t mask,
                         uint8_t mac[common::MAC_SIZE]) override;

    bool proccess_packet(common::open_port_vec &open_ports,
                         uint8_t ip[common::IP_V4_SIZE],
                         uint8_t mask,
                         common::memory_dest &dst) override;

    bool as_string(std::string &packet) override;

    ~l4_packet() override = default;

    l4_packet(uint32_t index, uint16_t src_port, uint16_t dst_port,
              const std::vector<uint8_t>& data);

private:
    static bool parse_hex_bytes_32(const std::string& s, std::vector<uint8_t>& out);

    uint32_t index_{0};
    uint16_t src_port_{0};
    uint16_t dst_port_{0};
    std::vector<uint8_t> data_;
    bool valid_parse_{false};
};

#endif
