/**
 * @file main.hpp
 * @brief This C++ file contains the main function of the NIC simulation project.
 */

#include <iostream>
#include <cassert>
#include <fstream>
#include "NIC_sim.hpp"
#include "packets.hpp"

int main(int argc, char *argv[]) {
    std::string param_file;
    std::string packet_file;
    
    assert((argc == 3) && "Expected 2 arguments: <param_file> <packet_file>");

    param_file = argv[1];
    packet_file = argv[2];

    /* Updating simulation parameters. */ 
    nic_sim simulation(param_file);

    /* Proccess all packets. */ 
    simulation.nic_flow(packet_file);

    /* Print all memory spaces. */
    simulation.nic_print_results();

    return 0;
}