#ifndef ASSIGN_PORTS_H
#define ASSIGN_PORTS_H

#include <string>
#include <unordered_map>

// Function declarations
void assign_challenges(std::string ip, int port_1, int port_2, int port_3,
                       int port_4,
                       std::unordered_map<int, int> &challenge_ports);

#endif
