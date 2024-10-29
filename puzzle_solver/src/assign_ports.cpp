
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <regex>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define TIMEOUT_SEC 1

std::unordered_map<std::string, int> patternMap = {
    {"XOR", 1}, {"evil port", 2}, {"4-byte message", 3}, {"E.X.P.S.T.N", 4}};

std::string get_response(std::string ip, int port) {
    int socket_fd;
    struct sockaddr_in target_addr;

    // Create a udp socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return "";
    }

    // Set the target address
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(socket_fd);
        return "";
    }

    // Set the timeout for the socket
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));

    // Send the message to the server
    std::string msg = "test";
    if (sendto(socket_fd, msg.c_str(), msg.size(), 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        std::cerr << "Error: Could not send message" << std::endl;
        close(socket_fd);
        return "";
    }

    // Receive the response from the server
    char buffer[1024];
    socklen_t addr_len = sizeof(target_addr);
    ssize_t bytes_received =
        recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                 (struct sockaddr *)&target_addr, &addr_len);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        std::string response(buffer);
        close(socket_fd);
        return response;
    }
    close(socket_fd);
    return "";
}

// Assign the challenges to the ports
void regex_challenges(std::string response, int port,
                      std::unordered_map<int, int> &challenge_ports) {
    // Iterate over the map and search for each pattern in the response
    for (const auto &pair : patternMap) {
        const std::string &pattern = pair.first;
        int value = pair.second;

        // Create a regex for the current pattern
        std::regex reg(pattern);

        // If the pattern is found in the response
        if (std::regex_search(response, reg)) {
            // Add or update the value of the corresponding port in
            // challenge_ports map
            challenge_ports[value] = port;
        }
    }
}

void assign_challenges(std::string ip, int port_1, int port_2, int port_3,
                       int port_4,
                       std::unordered_map<int, int> &challenge_ports) {
    std::vector<int> ports = {port_1, port_2, port_3, port_4};

    for (int i = 0; i < ports.size(); i++) {
        // keep sending the udp request until we get a response with max 10
        // tries
        for (int j = 0; j < 10; j++) {
            std::string response = get_response(ip, ports[i]);
            // assign the challenges to the ports
            regex_challenges(response, ports[i], challenge_ports);
            if (response != "")
                break;
        }
    }

    // Print the assigned challenges
    for (const auto &pair : challenge_ports) {
        std::cout << "Challenge " << pair.first << " is assigned to port "
                  << pair.second << std::endl;
    }
}
