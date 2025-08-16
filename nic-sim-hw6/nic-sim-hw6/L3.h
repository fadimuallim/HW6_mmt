#ifndef __L3__
#define __L3__

#include <string>
#include <vector>
#include "common.hpp"
#include "packets.hpp"
#include "L4.h"

class l3_packet : public generic_packet {
public:
    explicit l3_packet(const std::string& s);

    bool validate_packet(common::open_port_vec open_ports,
                         uint8_t ip[common::IP_V4_SIZE],
                         uint8_t mask,
                         uint8_t mac[common::MAC_SIZE]) override;

    bool proccess_packet(common::open_port_vec &open_ports,
                         uint8_t ip[common::IP_V4_SIZE],
                         uint8_t mask,
                         common::memory_dest &dst) override;

    bool as_string(std::string &packet) override;

    ~l3_packet() override = default;

    static uint32_t compute_checksum(const uint8_t src_ip[4],
                                     const uint8_t dst_ip[4],
                                     uint32_t ttl,
                                     uint16_t dst_port,
                                     uint16_t src_port,
                                     uint32_t l4_index,
                                     const std::vector<uint8_t>& data);

    uint32_t raw_fields_checksum() const;

private:
    static bool parse_ip(const std::string& s, uint8_t out[common::IP_V4_SIZE]);
    static bool is_local_ip(const uint8_t addr[4],
                            const uint8_t nic_ip[4],
                            uint8_t mask_bits);
    static void ip_to_string_upper(const uint8_t ip[4], std::string& out);

    uint8_t src_ip_[4]{};
    uint8_t dst_ip_[4]{};
    uint32_t ttl_{0};
    uint32_t checksum_{0};
    uint32_t l4_index_{0};
    uint16_t dst_port_{0};
    uint16_t src_port_{0};
    std::vector<uint8_t> data_;
    bool valid_parse_{false};

    bool to_rq_{false};
    bool to_tq_{false};
    bool to_local_{false};

    uint8_t out_src_ip_[4]{};
    uint8_t out_dst_ip_[4]{};
    uint32_t out_ttl_{0};
    uint32_t out_checksum_{0};
};

#endif
