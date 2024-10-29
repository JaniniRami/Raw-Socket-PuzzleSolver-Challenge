#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <regex>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define TIMEOUT_SEC 1 // Timeout for the socket

bool extractPort(const std::string &response, std::vector<int> &hidden_ports) {
    std::regex portRegex(
        R"(port:\s*(\d+))"); // Regex pattern to match "port: <number>"
    std::smatch match;

    if (std::regex_search(response, match, portRegex)) {
        if (match.size() > 1) {
            int portNumber =
                std::stoi(match[1].str()); // Convert the group to an integer

            // check if portNumber exists in hidden port first
            for (int i = 0; i < hidden_ports.size(); i++) {
                if (hidden_ports[i] == portNumber) {
                    return false;
                }
            }
            hidden_ports.push_back(portNumber);
            return true; // Successfully extracted the port number
        }
    }
    return false; // Port number not found
}

bool solve_secret_challenge(const std::string &ip, int port,
                            std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                            uint32_t &SECRET) {
    int socket_fd;
    struct sockaddr_in target_addr;

    // create UDP socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return false;
    }

    // Set the target address
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(socket_fd);
        return false;
    }

    // Set the timeout for the socket
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));

    // send the group number
    char buffer[1024];
    unsigned char msg = 56;

    if (sendto(socket_fd, &msg, sizeof(msg), 0, (struct sockaddr *)&target_addr,
               sizeof(target_addr)) < 0) {
        std::cerr << "Error: Could not send data to target" << std::endl;
        close(socket_fd);
        return false;
    }

    // receive the response
    socklen_t addr_len = sizeof(target_addr);
    ssize_t bytes_received =
        recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                 (struct sockaddr *)&target_addr, &addr_len);

    uint32_t challenge = 0;
    for (int i = 0; i < bytes_received && i < 4; i++) {
        challenge = (challenge << 8) |
                    (uint32_t)(unsigned char)
                        buffer[i]; // Shift left and add the new byte
    }

    // recieved from the TA
    uint32_t secret = 0xe69586d7;

    // store the challenge and secret for later puzzles
    CHALLENGE = challenge;
    SECRET = secret;

    uint8_t group_number = 56;
    unsigned char message_2[5];
    message_2[0] = group_number;

    // sign the challenge using XOR with the secret
    uint32_t signed_challenge = challenge ^ secret;

    // convert the signed challenge to network byte order
    signed_challenge = htonl(signed_challenge);

    // copy the signed challenge to the message buffer
    char buffer_2[1024];
    memcpy(&message_2[1], &signed_challenge, 4);

    // send the message to the server
    if (sendto(socket_fd, &message_2, sizeof(message_2), 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        std::cerr << "Error: Could not send data to target" << std::endl;
        close(socket_fd);
        return false;
    }

    // recieve the response from the server
    socklen_t addr_len_2 = sizeof(target_addr);
    ssize_t bytes_received_2 =
        recvfrom(socket_fd, buffer_2, sizeof(buffer_2), 0,
                 (struct sockaddr *)&target_addr, &addr_len_2);

    // close the socket
    close(socket_fd);

    // check if the response was recieved
    if (bytes_received_2 > 0) {
        buffer_2[bytes_received_2] = '\0'; // Null terminate the received string
        std::string response(buffer_2);
        std::cout << "Response: " << response << std::endl;

        // Extract the port number
        if (extractPort(response, hidden_ports)) {
            close(socket_fd);
            return true;
        } else {
            std::cerr << "Error: Could not extract port number from response"
                      << std::endl;
            close(socket_fd);
            return false;
        }
    } else {
        std::cerr << "Error: Did not recieve response from target" << std::endl;
        close(socket_fd);
        return false;
    }
}
