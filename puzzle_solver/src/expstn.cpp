#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <regex>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "expstn.h"

#define TIMEOUT_SEC 1

bool port_knock(const std::string &dest_ip, int port, std::vector<int> knocks,
                uint32_t &signed_challenge, std::string &secret_phrase) {
    std::cout << "Knocking on port " << port << std::endl;

    int knock_socket;
    struct sockaddr_in knock_addr;

    knock_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (knock_socket < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return false;
    }

    memset(&knock_addr, 0, sizeof(knock_addr));
    knock_addr.sin_family = AF_INET;
    knock_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip.c_str(), &knock_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(knock_socket);
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(knock_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));
    // close(knock_socket);

    // Prepare the message: first 4 bytes for signed challenge, followed by the
    // secret phrase
    std::vector<uint8_t> message(4 + secret_phrase.size());

    // Insert the signed challenge (convert to network byte order for
    // consistency)
    uint32_t challenge_network_order = htonl(signed_challenge);
    memcpy(message.data(), &challenge_network_order, 4);

    // Append the secret phrase
    memcpy(message.data() + 4, secret_phrase.c_str(), secret_phrase.size());

    // Send the message to the specified IP and port
    ssize_t sent_bytes =
        sendto(knock_socket, message.data(), message.size(), 0,
               (struct sockaddr *)&knock_addr, sizeof(knock_addr));

    if (sent_bytes < 0) {
        std::cerr << "Error: Failed to send the message" << std::endl;
        // print the error
        std::cerr << strerror(errno) << std::endl;
        close(knock_socket);
        return false;
    }

    char buffer[1024];
    ssize_t received_bytes =
        recvfrom(knock_socket, buffer, sizeof(buffer) - 1, 0, nullptr, nullptr);
    if (received_bytes < 0) {
        std::cerr << "Error: Failed to receive response" << std::endl;
        close(knock_socket);
        return false;
    }

    buffer[received_bytes] = '\0'; // Null-terminate the received data
    std::cout << "Server response: " << buffer << std::endl;
    return true;
}

bool solve_expstn(const std::string &dest_ip, int port,
                  std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                  uint32_t &SECRET, std::string secret_phrase) {
    std::cout << "Solving E.X.P.S.T.N" << std::endl;

    int socket_fd;
    struct sockaddr_in target_addr;

    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return false;
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(socket_fd);
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));

    std::ostringstream oss;
    for (size_t i = 0; i < hidden_ports.size(); ++i) {
        oss << hidden_ports[i];
        if (i < hidden_ports.size() - 1) {
            oss << ","; // Add comma between ports
        }
    }
    std::string hidden_ports_str = oss.str();
    std::cout << "Hidden ports: " << hidden_ports_str << std::endl;

    ssize_t sent_bytes =
        sendto(socket_fd, hidden_ports_str.c_str(), hidden_ports_str.size(), 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr));
    if (sent_bytes < 0) {
        std::cerr << "Error: Failed to send hidden ports" << std::endl;
        close(socket_fd);
        return false;
    }

    char buffer[1024];
    ssize_t received_bytes =
        recvfrom(socket_fd, buffer, sizeof(buffer) - 1, 0, nullptr, nullptr);
    if (received_bytes < 0) {
        std::cerr << "Error: Failed to receive response" << std::endl;
        close(socket_fd);
        return false;
    }

    buffer[received_bytes] = '\0'; // Null-terminate the received data
    std::cout << "Server response: " << buffer << std::endl;

    std::vector<int> knocks;
    std::stringstream ss(buffer);
    std::string item;

    while (std::getline(ss, item, ',')) {
        knocks.push_back(std::stoi(item));
    }

    close(socket_fd);
    uint32_t signed_challenge = CHALLENGE ^ SECRET;

    for (int i = 0; i < knocks.size(); i++) {
        std::cout << "--------------------------------------------"
                  << std::endl;
        bool success = false;
        while (success == false) {
            success = port_knock(dest_ip, knocks[i], hidden_ports,
                                 signed_challenge, secret_phrase);
        }
        std::cout << "--------------------------------------------"
                  << std::endl;
    }
    return true;
}