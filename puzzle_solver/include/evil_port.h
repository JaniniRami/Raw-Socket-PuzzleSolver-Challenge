#ifndef EVIL_PORT_H
#define EVIL_PORT_H

#include <string>

bool solve_evil_port(const std::string &dest_ip, int port,
                     std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                     uint32_t &SECRET);

#endif
