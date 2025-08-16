/**
 * @file NIC_sim.hpp
 * @brief This header defines the NIC simulator class, responsible for managing
 *        NIC parameters, processing packets, and storing simulation results.
 *
 * The purpose of this class is to simulate the behavior of a Network Interface
 * Card by updating configurations, handling packet flows, and outputting the 
 * final state of memory and queues.
 */


#ifndef __NIC_SIM__
#define __NIC_SIM__

#include "common.hpp"
#include "packets.hpp"
#include "L2.h"
#include "L3.h"
#include "L4.h"

class nic_sim {
    public:
    /**
     * @fn nic_sim
     * @brief Constructor of the class.
     * 
     * @param param_file - File name containing the NIC's parameters.
     *
     * @return New simulation object.
     */
    nic_sim(std::string param_file);

    /**
     * @fn nic_flow
     * @brief Process and store to relevant location all packets in packet_file.
     *
     * @param packet_file - Name of file containing packets as strings.
     *
     * @return None.
     */
    void nic_flow(std::string packet_file);

    /**
     * @fn nic_print_results
     * @brief Prints all data stored in memory to stdout in the following format:
     *
     *        LOCAL DRAM:
     *        [src] [dst]: [data - DATA_ARR_SIZE bytes]
     *        [src] [dst]: [data - DATA_ARR_SIZE bytes]
     *        ...
     *
     *        RQ:
     *        [each packet in separate line]
     *
     *        TQ:
     *        [each packet in separate line]
     *
     * @return None.
     */
    void nic_print_results();

    /**
     * @fn ~nic_sim
     * @brief Destructor of the class.
     *
     * @return None.
     */
    ~nic_sim();

    private:
    /**
     * @fn packet_factory
     * @brief Gets a string representing a packet, creates the corresponding
     *        packet type, and returns a pointer to a generic_packet.
     *
     * @param packet - String representation of a packet.
     *
     * @return Pointer to a generic_packet object.
     */
    generic_packet *packet_factory(std::string &packet);

    /**
     * @param open_ports - Vector containing all open communications.
     * @param RQ - Vector of strings to store packets that sent to RQ.
     * @param TQ - Vector of strings to store packets that sent to TQ.
     */
    common::open_port_vec open_ports;
    std::vector<std::string> RQ;
    std::vector<std::string> TQ;

    /**
     * @note It is recommended and even encouraged to add new functions or
     *       additional parameters to the object, but the existing functionality
     *       must be implemented.
     */
};

#endif
