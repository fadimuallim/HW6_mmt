#ifndef __L2__
#define __L2__

#include <string>
#include <vector>
#include <memory>
#include "common.hpp"
#include "packets.hpp"
#include "L3.h"

class l2_packet : public generic_packet {
public:
    explicit l2_packet(const std::string& s);

    bool validate_packet(common::open_port_vec open_ports,
                         uint8_t ip[common::IP_V4_SIZE],
                         uint8_t mask,
                         uint8_t mac[common::MAC_SIZE]) override;

    bool proccess_packet(common::open_port_vec &open_ports,
                         uint8_t ip[common::IP_V4_SIZE],
                         uint8_t mask,
                         common::memory_dest &dst) override;

    bool as_string(std::string &packet) override;

    ~l2_packet() override = default;

private:
    static bool parse_mac(const std::string& s, uint8_t out[common::MAC_SIZE]);
    static void mac_to_string_upper(const uint8_t mac[common::MAC_SIZE], std::string& out);

    uint8_t src_mac_[common::MAC_SIZE]{};
    uint8_t dst_mac_[common::MAC_SIZE]{};
    uint32_t checksum_{0};
    std::string l3_string_;
    bool valid_parse_{false};

    std::unique_ptr<l3_packet> inner_;

    std::string out_l3_string_;
    uint32_t out_checksum_{0};
    bool to_rq_{false};
    bool to_tq_{false};
};

#endif