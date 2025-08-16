#include "NIC_sim.h"
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <memory>

using namespace common;

static bool parse_mac_line(const std::string& s, uint8_t mac[MAC_SIZE]) {
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
        mac[i] = static_cast<uint8_t>((v1<<4)|v2);
        if (i<MAC_SIZE-1) {
            if (a+2 >= s.size() || s[a+2] != ':') return false;
            a += 3;
        }
    }
    return true;
}

static bool parse_ip_mask_line(const std::string& s, uint8_t ip[IP_V4_SIZE], uint8_t &mask_bits) {
    size_t slash = s.find('/');
    if (slash == std::string::npos) return false;
    std::string ip_s = s.substr(0, slash);
    std::string bits_s = s.substr(slash+1);
    size_t a = 0, b;
    for (int i=0;i<4;i++) {
        b = ip_s.find(i<3?'.':'\0', a);
        std::string part = (i<3) ? ip_s.substr(a, b-a) : ip_s.substr(a);
        int val = std::stoi(part);
        if (val<0 || val>255) return false;
        ip[i] = static_cast<uint8_t>(val);
        if (i<3) a = b+1;
    }
    int bits = std::stoi(bits_s);
    if (bits < 0 || bits > 32) return false;
    mask_bits = static_cast<uint8_t>(bits);
    return true;
}

static bool parse_open_port_line(const std::string& s, uint16_t &src, uint16_t &dst) {
    size_t sp = s.find("src");
    size_t c1 = s.find(':', sp);
    size_t comma = s.find(',', c1);
    size_t dp = s.find("dst", comma);
    size_t c2 = s.find(':', dp);
    if (sp == std::string::npos || c1 == std::string::npos ||
        comma == std::string::npos || dp == std::string::npos || c2 == std::string::npos)
        return false;
    std::string s_src = s.substr(c1+1, comma - (c1+1));
    std::string s_dst = s.substr(c2+1);
    try {
        int s_val = std::stoi(s_src);
        int d_val = std::stoi(s_dst);
        if (s_val < 0 || s_val > 65535 || d_val < 0 || d_val > 65535) return false;
        src = static_cast<uint16_t>(s_val);
        dst = static_cast<uint16_t>(d_val);
    } catch (...) { return false; }
    return true;
}

class nic_sim_priv {
public:
    uint8_t mac[MAC_SIZE]{};
    uint8_t ip[IP_V4_SIZE]{};
    uint8_t mask_bits{0};
};

using nic_priv_ptr = std::unique_ptr<nic_sim_priv>;

static std::vector<std::pair<nic_sim*, nic_priv_ptr>>& registry() {
    static std::vector<std::pair<nic_sim*, nic_priv_ptr>> reg;
    return reg;
}

static nic_sim_priv* get_priv(nic_sim* self) {
    auto& reg = registry();
    for (auto& p : reg) if (p.first == self) return p.second.get();
    nic_priv_ptr ptr(new nic_sim_priv());
    reg.emplace_back(self, std::move(ptr));
    return reg.back().second.get();
}

// Delete packets according to their concrete type so any owned payloads are
// released even when the base `generic_packet` lacks a virtual destructor.
static void destroy_packet(generic_packet* pkt) {
    if (!pkt) return;
    if (auto p = dynamic_cast<l2_packet*>(pkt)) {
        delete p;
    } else if (auto p = dynamic_cast<l3_packet*>(pkt)) {
        delete p;
    } else if (auto p = dynamic_cast<l4_packet*>(pkt)) {
        delete p;
    } else {
        delete pkt;
    }
}

nic_sim::nic_sim(std::string param_file) {
    std::ifstream in(param_file);
    std::string line;
    auto* priv = get_priv(this);

    if (std::getline(in, line)) {
        parse_mac_line(line, priv->mac);
    }
    if (std::getline(in, line)) {
        parse_ip_mask_line(line, priv->ip, priv->mask_bits);
    }
    while (std::getline(in, line)) {
        uint16_t src, dst;
        if (parse_open_port_line(line, src, dst)) {
            open_ports.emplace_back(dst, src);
        }
    }
}

void nic_sim::nic_flow(std::string packet_file) {
    auto* priv = get_priv(this);
    std::ifstream in(packet_file);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        generic_packet* pkt = packet_factory(line);
        if (!pkt) continue;

        if (!pkt->validate_packet(open_ports, priv->ip, priv->mask_bits, priv->mac)) {
            destroy_packet(pkt);
            continue;
        }
        memory_dest dst;
        if (!pkt->proccess_packet(open_ports, priv->ip, priv->mask_bits, dst)) {
            destroy_packet(pkt);
            continue;
        }
        if (dst == common::RQ || dst == common::TQ) {
            std::string s;
            pkt->as_string(s);
            if (dst == common::RQ) RQ.push_back(s); else TQ.push_back(s);
        }
        destroy_packet(pkt);
    }
}

void nic_sim::nic_print_results() {
    std::cout << "LOCAL DRAM:\n";
    for (const auto& op : open_ports) {
        std::cout << op.src_prt << " " << op.dst_prt << ": ";
        for (int i = 0; i < DATA_ARR_SIZE; i++) {
            char buf[3];
            std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned int>(op.data[i]));
            std::cout << buf;
            if (i + 1 != DATA_ARR_SIZE) std::cout << " ";
        }
        std::cout << "\n";
    }
    std::cout << "\nRQ:\n";
    for (const auto& s : RQ) {
        std::cout << s << "\n";
    }
    std::cout << "\nTQ:\n";
    for (const auto& s : TQ) {
        std::cout << s << "\n";
    }
}

nic_sim::~nic_sim() {
    auto& reg = registry();
    for (auto it = reg.begin(); it != reg.end(); ++it) {
        if (it->first == this) {
            // erase will destroy the unique_ptr, releasing memory
            reg.erase(it);
            break;
        }
    }
}

#include <cctype>

static bool looks_like_mac_packet(const std::string& s) {
    int colons = 0;
    for (char c : s) if (c == ':') colons++;
    return colons >= 10;
}

static bool looks_like_l3_packet(const std::string& s) {
    size_t p1 = s.find('|');
    if (p1 == std::string::npos) return false;
    auto is_ip = [](const std::string& t)->bool{
        int dots = 0;
        for (char c: t) if (c=='.') dots++;
        return dots==3;
    };
    std::string first = s.substr(0, p1);
    return is_ip(first);
}

generic_packet* nic_sim::packet_factory(std::string &packet) {
    if (looks_like_mac_packet(packet)) {
        return new l2_packet(packet);
    } else if (looks_like_l3_packet(packet)) {
        return new l3_packet(packet);
    } else {
        return new l4_packet(packet);
    }
}
