#include "checksum.h"
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
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// ICMP Header Length
#define ICMP_HDRLEN 8

// ICMP Echo Request Type and Code
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

uint16_t csum(void *b, int len) {
    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)b;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

bool solve_bonus(const std::string &dest_ip, int port) {
    std::cout << "Solving Bonus" << std::endl;

    const char *payload = "$group_56$";

    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return false;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(socket_fd);
        return false;
    }

    // create icmp header
    char icmp_hdr[ICMP_HDRLEN];

    icmp_hdr[0] = ICMP_ECHO; // Type
    icmp_hdr[1] = 0;         // Code
    icmp_hdr[2] = 0;         // Checksum (will be calculated later)
    icmp_hdr[3] = 0;         // Checksum (will be calculated later)
    icmp_hdr[4] = 0;         // Identifier (arbitrary, can set to 0)
    icmp_hdr[5] = 0;         // Identifier (arbitrary)
    icmp_hdr[6] = 0;         // Sequence number (arbitrary)
    icmp_hdr[7] = 0;         // Sequence number (arbitrary)

    size_t packet_size = ICMP_HDRLEN + strlen(payload);
    char packet[packet_size];

    memcpy(packet, icmp_hdr, ICMP_HDRLEN);
    memcpy(packet + ICMP_HDRLEN, payload, strlen(payload));

    unsigned short checksum = csum((unsigned short *)packet, packet_size);
    packet[2] = checksum & 0xFF;        // Set checksum (low byte)
    packet[3] = (checksum >> 8) & 0xFF; // Set checksum (high byte)

    ssize_t bytes_sent =
        sendto(socket_fd, packet, packet_size, 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr));
    if (bytes_sent < 0) {
        perror("Sendto error");
        return false;
    }
    std::cout << "Sent ICMP packet" << std::endl;
    return true;
}