#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <string>
#include <unordered_map>

std::string solve_checksum(const std::string &ip, int port,
                           std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                           uint32_t &SECRET);

#endif
