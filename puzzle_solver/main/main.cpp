#include <cstring>
#include <iostream>
#include <string>

#include "assign_ports.h"
#include "bonus.h"
#include "checksum.h"
#include "evil_port.h"
#include "expstn.h"
#include "secret.h"

int main(int argc, char *argv[]) {
    std::string ip_address = argv[1];
    int port_1 = std::stoi(argv[2]);
    int port_2 = std::stoi(argv[3]);
    int port_3 = std::stoi(argv[4]);
    int port_4 = std::stoi(argv[5]);

    std::unordered_map<int, int> challenge_ports;
    std::vector<int> hidden_ports;
    std::string secret_phrase;

    // use regex to assign the ports to each challenge.
    assign_challenges(ip_address, port_1, port_2, port_3, port_4,
                      challenge_ports);

    uint32_t CHALLENGE;
    uint32_t SECRET;

    // try solving every challenge until we get the secret phrase, and if
    // failed repeat for max 10 times.
    for (int i = 0; i < 10; i++) {
        if (solve_secret_challenge(ip_address, challenge_ports[1], hidden_ports,
                                   CHALLENGE, SECRET)) {
            if (solve_evil_port(ip_address, challenge_ports[2], hidden_ports,
                                CHALLENGE, SECRET)) {
                secret_phrase = solve_checksum(ip_address, challenge_ports[3],
                                               hidden_ports, CHALLENGE, SECRET);
                if (secret_phrase != "") {
                    std::cout << "Secret phrase: " << secret_phrase
                              << std::endl;
                    if (solve_expstn(ip_address, challenge_ports[4],
                                     hidden_ports, CHALLENGE, SECRET,
                                     secret_phrase)) {
                        std::cout << "HOOORAYYY YOU DID IT - Exploitation successful" << std::endl;
                        break;
                    }
                }
            }
        }
    }

    // solve the bonus question.
    solve_bonus(ip_address, 4094);

    return 0;
}
