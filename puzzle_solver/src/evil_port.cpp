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

#include "secret.h"

#define TIMEOUT_SEC 1
#define PCKT_LEN 8192
#define UDP_SRC_PORT 3212

// get the local ip address
std::string getLocalIPAddress() {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    std::string local_ip;
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr)
            continue;

        int family = ifa->ifa_addr->sa_family;

        // Check for IPv4 address
        if (family == AF_INET) {
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host,
                                NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
            if (s != 0) {
                perror("getnameinfo");
                continue;
            }

            // Skip localhost (127.0.0.1)
            if (strcmp(host, "127.0.0.1") != 0) {
                local_ip = host;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return local_ip;
}

bool solve_evil_port(const std::string &dest_ip, int port,
                     std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                     uint32_t &SECRET) {
    std::string src_ip = getLocalIPAddress();
    int sd;
    char buffer[PCKT_LEN];

    u_int32_t signed_challenge = htonl(CHALLENGE ^ SECRET);

    // Create a raw socket
    struct ip *iph = (struct ip *)buffer;
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ip));
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PCKT_LEN);

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return false;
    } else {
        std::cout << "Socket created" << std::endl;
    }

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    sin.sin_port = htons(UDP_SRC_PORT);
    din.sin_port = htons(port);

    sin.sin_addr.s_addr = inet_addr(src_ip.c_str());
    din.sin_addr.s_addr = inet_addr(dest_ip.c_str());

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 16;
    iph->ip_off = htons(0x80);
    iph->ip_len =
        (sizeof(struct ip) + sizeof(struct udphdr) + sizeof(signed_challenge));
    iph->ip_id = htons(54321);
    iph->ip_ttl = 64;
    iph->ip_p = 17;
    iph->ip_src.s_addr = inet_addr(src_ip.c_str());
    iph->ip_dst.s_addr = inet_addr(dest_ip.c_str());

    udph->uh_sport = htons(UDP_SRC_PORT);

    udph->uh_dport = htons(port);
    udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(signed_challenge));

    iph->ip_sum = 0;

    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))) {
        std::cerr << "Error: Could not set socket options" << std::endl;
        return false;
    } else {
        std::cout << "Socket options set" << std::endl;
    }

    // Send the packet
    int total_len = (sizeof(struct ip) + sizeof(struct udphdr) + 4);
    std::cout << "Total length: " << total_len << std::endl;
    std::cout << "IP length: " << ntohs(iph->ip_len) << std::endl;

    memcpy(buffer + sizeof(struct ip) + sizeof(struct udphdr),
           &signed_challenge, sizeof(signed_challenge));

    if (sendto(sd, buffer, (total_len), 0, (struct sockaddr *)&din,
               sizeof(din))) {
        std::cerr << "Error: Could not send message" << std::endl;
        std::cout << "Error: " << strerror(errno) << std::endl;
    }

    close(sd);

    // set socket to recieve response
    int recv_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recv_sd < 0) {
        std::cerr << "Error: Could not create recieve socket" << std::endl;
        close(sd);
        close(recv_sd);
        return false;
    }

    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(UDP_SRC_PORT);
    recv_addr.sin_addr.s_addr = inet_addr(src_ip.c_str());

    if (bind(recv_sd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        std::cerr << "Error: Could not bind recieve socket" << std::endl;
        close(recv_sd);
        close(sd);
        return false;
    }

    struct timeval timeout = {TIMEOUT_SEC, 0};
    if (setsockopt(recv_sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                   sizeof(timeout)) < 0) {
        std::cerr << "Error: Could not set recieve socket timeout" << std::endl;
        close(recv_sd);
        close(sd);
        return false;
    }

    char recv_buffer[PCKT_LEN];
    socklen_t addr_len = sizeof(recv_addr);
    ssize_t bytes_received =
        recvfrom(recv_sd, recv_buffer, sizeof(recv_buffer), 0,
                 (struct sockaddr *)&recv_addr, &addr_len);

    if (bytes_received < 0) {
        std::cerr << "Error: Could not recieve response" << std::endl;
        close(recv_sd);
        close(sd);
        return false;
    } else {
        recv_buffer[bytes_received] = '\0';
        std::string response(recv_buffer);
        std::cout << "Response: " << response << std::endl;
        if (extractPort(response, hidden_ports)) {
            close(recv_sd);
            close(sd);
            return true;
        }

        close(recv_sd);
        close(sd);
        return false;
    }
}
