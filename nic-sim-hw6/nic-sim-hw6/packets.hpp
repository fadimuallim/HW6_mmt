/**
 * @file packets.hpp
 * @brief This header defines the generic packet interface and specific packet
 *        types for the NIC simulation project.
 *
 * The purpose of this file is to provide an abstract base class
 * (`generic_packet`) for packet handling, along with placeholders for different
 * packet types such as L2, L3, and L4 packets. Each packet type is expected to
 * implement validation, processing, and string conversion functionalities.
 */

#ifndef __PACKETS__
#define __PACKETS__

#include <iostream>
#include <string>
#include "common.hpp"

using namespace common;

class generic_packet {
    public:
    /**
     * @fn validate_packet
     * @brief Check whether the packet is valid.
     *
     * @param [in] open_ports - Vector containing all the NIC's open ports.
     * @param [in] ip - NIC's IP address.
     * @param [in] mask - NIC's mask; together with the IP,
     *               determines the NIC's local net.
     * @param [in] mac - NIC's MAC address.
     *
     * @return true if the packet is valid and ready for processing.
     *         false if the packet isn't valid and should be discarded.
     */
    virtual bool validate_packet(open_port_vec open_ports,
                                uint8_t ip[IP_V4_SIZE],
                                uint8_t mask,
                                uint8_t mac[MAC_SIZE]) = 0;

    /**
     * @fn proccess_packet
     * @brief Modify the packet and return the memory location it should be
     *        stored in. In the case of local DRAM, the function will store
     *        the packet as a string in the relevant 'open_port' struct.
     *
     * @param [in] open_ports - Vector containing all the NIC's open ports.
     * @param [in] ip - NIC's IP address.
     * @param [in] mask - NIC's mask; together with the IP, determines the NIC's
     *        local net.
     * @param [out] dst - Reference to enum that indicate the memory space where
     *        the packet should be stored:
     *         LOCAL_DRAM - the function stored it to the currect struct.
     *         RQ - Should be stored as a string in RQ.
     *         TQ - Should be stored as string in TQ.
     *
     * @return true in success, false in failure (e.g memory allocation failed).
     */
    virtual bool proccess_packet(open_port_vec &open_ports,
                                uint8_t ip[IP_V4_SIZE],
                                uint8_t mask,
                                memory_dest &dst) = 0;

    /**
     * @fn as_string
     * @brief Convert the packet to string.
     *
     * @param [out] packet - Packet as a string, ready to be stored in RQ/TQ.
     *
     * @return true in success, false in failure (e.g memory allocation failed).
     */
    virtual bool as_string(std::string &packet) = 0;

    /**
     * @fn ~generic_packet
     * @brief Virtual destructor of the class.
     *
     * @return None.
     */
    virtual ~generic_packet() = default;

    protected:
    /**
     * @fn extract_between_delimiters
     * @brief Extracts a substring between two delimiters in a string.
     * 
     * This function extracts the substring starting immediately after the
     * delimiter at start_index and ending just before the delimiter at end_index.
     * If end_index is -1, it extracts until the end of the string. if start_index
     * is 0 it extract from the beginning of the string.
     * 
     * @param input The input string to extract substring from.
     * @param delimiter The character used as delimiter in the string.
     * @param start_index The index (1-based) of the delimiter after which
     *                    extraction begins.
     *                    if 0 start from the beginning of the string.
     * @param end_index The index (0-based: the first delimiter will be count as
     *                  0) of the delimiter before which extraction ends.
     *                  If -1, extracts until the end of the string.
     * 
     * @return Substring starting after the delimiter at start_index and 
     *         ending just before the delimiter at end_index or end of string if end_index is -1.
     *         Returns an empty string if indices are invalid.
     */
    static std::string extract_between_delimiters(const std::string& input,
                                        char delimiter,
                                        int start_index,
                                        int end_index = -1)
    {
        std::vector<size_t> positions;
        size_t pos = input.find(delimiter);
        size_t start = 0;

        /* Create position vector. */
        while (pos != std::string::npos) {
            positions.push_back(pos);
            pos = input.find(delimiter, pos + 1);
        }

        /* Check start index. */
        if (start_index < 0 || start_index > static_cast<int>(positions.size())) {
            return "";
        }

        if (start_index > 0) {
            if (start_index > positions.size()) return ""; // invalid
            start = positions[start_index - 1] + 1;
        }

        /* Extract everything after start delimiter to end of string. */
        if (end_index == -1) {
            return input.substr(start);
        }

        /* Validate end_index. */
        if (end_index < start_index || end_index >= static_cast<int>(positions.size())) {
            return "";
        }

        size_t len = positions[end_index] - start;

        return input.substr(start, len);
    }
};
#endif