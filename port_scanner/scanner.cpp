#include <cstring>
#include <iostream>
#include <string>

// Netowkring header files
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> // close()

// timeout in seconds to wait for each port
#define TIMEOUT_SEC 1

bool check_port(const std::string &ip, int port) {
    int socket_fd;
    struct sockaddr_in target_addr;

    // create UDP socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return -1;
    }

    // Set the target address
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET; // IPv4
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(socket_fd);
        return false;
    }

    // data reciever socket
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));

    // ping the target port
    const char *msg = "ping";
    if (sendto(socket_fd, msg, strlen(msg), 0, (struct sockaddr *)&target_addr,
               sizeof(target_addr)) < 0) {
        std::cerr << "Error: Could not send data to target" << std::endl;
        close(socket_fd);
        return false;
    }

    // recieve data from target and print it
    char buffer[1024];
    struct ip *ip_hdr;
    socklen_t addr_len = sizeof(target_addr);
    ssize_t bytes_recieved =
        recvfrom(socket_fd, buffer, sizeof(buffer), 0x0, NULL, NULL);

    if (bytes_recieved > 0) {
        buffer[bytes_recieved] = '\0'; // null terminate the recieved string
        std::string response(buffer);
        std::cout << "Response: " << response << std::endl;
        close(socket_fd);
        return true;
    } else {
        close(socket_fd);
        return false;
    }

    close(socket_fd);
    return false;
}

int main(int argc, char *argv[]) {
    //  Recieve ip address, low port and high port values from user arguments.
    std::string ip = argv[1];
    std::cout << "Scanning IP: " << ip << std::endl;
    int low_port = std::stoi(argv[2]);
    int high_port = std::stoi(argv[3]);
    std::cout << "Scanning ports from " << low_port << " to " << high_port
              << std::endl;

    // scan each port 3 times to make the port was not dropped
    // Loop through the ports to scan them
    for (int port = low_port; port <= high_port; ++port) {
        int scanned_times = 0;
        while (scanned_times < 3) {
            if (check_port(ip, port)) {
                std::cout << "Port " << port << " is open" << std::endl;
                break;
            }
            ++scanned_times;
        }
    }

    return 0;
}