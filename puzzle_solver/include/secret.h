#ifndef SECRET_H
#define SECRET_H

#include <string>

bool solve_secret_challenge(const std::string &ip, int port,
                            std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                            uint32_t &SECRET);
bool extractPort(const std::string &response, std::vector<int> &hidden_ports);

#endif
