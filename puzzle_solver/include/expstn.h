#ifndef EXPSTN_H
#define EXPSTN_H

#include <string>

bool solve_expstn(const std::string &dest_ip, int port,
                  std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                  uint32_t &SECRET, std::string secret_phrase);

#endif
