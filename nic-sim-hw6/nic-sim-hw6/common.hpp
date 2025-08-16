/**
 * @file common.hpp
 * @brief This header contains common definitions, constants, and utility types
 *        shared across the NIC simulation project.
 *
 * The purpose of this file is to centralize shared code, improve reusability,
 * and maintain consistency between different components such as packets, NIC,
 * and simulation infrastructure.
 *
 * This file is accessible to all components in the project and can be included
 * freely. It is allowed (and expected) to be extended or modified as needed,
 * provided the changes remain compatible with the existing codebase.
 */

#ifndef __COMMON__
#define __COMMON__

#include <vector>
#include <iostream>
#include <iomanip>

namespace common {
    /* 'open_port' maximum data size. */
    const int DATA_ARR_SIZE = 64;
    /* L5 size. */
    const int PACKET_DATA_SIZE = 32;
    /* Amount of IP elements - in this exercise it will be 4. */
    const int IP_V4_SIZE = 4;
    /* Amount of MAC elements - in this exercise it will be 6. */
    const int MAC_SIZE =  6;

    /* There are 3 memory spaces in the NIC, each enum indicates a specific one. */
    enum memory_dest {
        LOCAL_DRAM = 0,
        RQ,
        TQ
    };

    /**
     * @brief Struct to track open communication and store relevant data.
     * @param dst_prt - Destination port.
     * @param src_prt - Source port.
     * @param data - All data received from src_prt to dst_prt will be stored here.
     */
    struct open_port {
        unsigned short dst_prt;
        unsigned short src_prt;
        unsigned char data[DATA_ARR_SIZE];

        /**
         * @fn open_port
         * @brief Constructor if the struct.
         * 
         * @param dst - Destination port number.
         * @param src - Source port number.
         *
         * @return New stract.
         */
        open_port(uint16_t dst = 0, uint16_t src = 0):dst_prt(dst), src_prt(src), data{} {}

        /**
         * @fn print_hex_byte
         * @brief Prints a single byte as a 2-digit lowercase hexadecimal number.
         *
         * @param idx - Index of the char in 'data' to print.
         *
         * @return None.
         * 
         * @note It is internally cast to `unsigned char` to ensure correct
         *      formatting even for negative values, and then to `int` for
         *      output.
         */
        void print_hex_byte(int idx) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(data[idx]) << std::dec;
        }
    };

    /* Typedef to create vector of open ports. */
    typedef std::vector<open_port> open_port_vec;
}
#endif