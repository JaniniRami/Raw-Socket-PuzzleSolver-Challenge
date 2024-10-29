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

#define TIMEOUT_SEC 1
#define UDP_SRC_PORT 3212

// Calculate the checksum function
uint16_t checksum(void *b, int len) {
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

// Calculate the checksum of the sent packet.
uint16_t udp_checksum(struct ip *iph, struct udphdr *udph, uint32_t *payload,
                      size_t payload_len) {
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } pseudo_hdr;

    pseudo_hdr.src_addr = (iph->ip_src.s_addr);
    pseudo_hdr.dst_addr = (iph->ip_dst.s_addr);
    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = IPPROTO_UDP;
    pseudo_hdr.udp_length = udph->uh_ulen;

    // Calculate size of pseudo header + UDP header + payload
    size_t psize = sizeof(pseudo_hdr) + sizeof(struct udphdr) + payload_len;
    char *buf = new char[psize];

    // Copy pseudo header
    memcpy(buf, &pseudo_hdr, sizeof(pseudo_hdr));

    // Copy UDP header
    memcpy(buf + sizeof(pseudo_hdr), udph, sizeof(struct udphdr));

    // Copy payload
    memcpy(buf + sizeof(pseudo_hdr) + sizeof(struct udphdr), payload,
           payload_len);

    uint16_t result = checksum((void *)buf, psize);
    delete[] buf;
    return result;
}

std::string solve_checksum(const std::string &dest_ip, int port,
                           std::vector<int> &hidden_ports, uint32_t &CHALLENGE,
                           uint32_t &SECRET) {
    int socket_fd;
    struct sockaddr_in target_addr;
    std::string src_ip_str;
    uint16_t checksum;

    // create UDP socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        std::cerr << "Error: Could not create socket" << std::endl;
        return "";
    }

    // Set the target address
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip.c_str(), &target_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(socket_fd);
        return "";
    }

    // Set the timeout for the socket
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
               sizeof(timeout));

    char buffer[1024];

    // send signed challenge
    u_int32_t signed_challenge = CHALLENGE ^ SECRET;
    signed_challenge = htonl(signed_challenge);

    if (sendto(socket_fd, &signed_challenge, sizeof(signed_challenge), 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        std::cerr << "Error: Could not send data to target" << std::endl;
        close(socket_fd);
        return "";
    }

    // recieve the response from the server
    socklen_t addr_len = sizeof(target_addr);
    ssize_t bytes_received =
        recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                 (struct sockaddr *)&target_addr, &addr_len);

    // close the socket
    close(socket_fd);

    // check if the response was recieved
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        std::string response(buffer);
        // std::cout << "Response: " << response << std::endl;

        // Ensure the response is long enough to contain the checksum and IP
        if (response.size() >= 6) {
            // Extract the last 6 bytes
            std::string last_six_bytes =
                response.substr(response.size() - 6, 6);

            // Extract checksum (first 2 bytes)
            checksum =
                (*reinterpret_cast<const uint16_t *>(last_six_bytes.data()));

            // Extract source IP (last 4 bytes)
            uint32_t source_ip = (*reinterpret_cast<const uint32_t *>(
                last_six_bytes.data() + 2));

            // Convert source IP to human-readable format
            struct in_addr ip_addr;
            ip_addr.s_addr = source_ip;
            src_ip_str = inet_ntoa(ip_addr);

            // Print the checksum and source IP
            // std::cout << "Extracted Checksum: 0x" << std::hex << checksum <<
            // std::dec << std::endl; std::cout << "Extracted Source IP: " <<
            // src_ip_str << std::endl;
        } else {
            std::cerr
                << "Error: Response is too short to contain checksum and IP."
                << std::endl;
        }
    }

    // reply to the server
    int reply_socket;
    struct sockaddr_in reply_addr;

    reply_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (reply_socket < 0) {
        std::cerr << "Error: Could not create reply socket" << std::endl;
        return "";
    }

    memset(&reply_addr, 0, sizeof(reply_addr));
    reply_addr.sin_family = AF_INET;
    reply_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, dest_ip.c_str(), &reply_addr.sin_addr) <= 0) {
        std::cerr << "Error: Could not convert IP address" << std::endl;
        close(reply_socket);
        return "";
    }

    // Set the timeout for the socket
    struct timeval reply_timeout;
    reply_timeout.tv_sec = TIMEOUT_SEC;
    reply_timeout.tv_usec = 0;
    setsockopt(reply_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&reply_timeout,
               sizeof(reply_timeout));

    // construct a packet that holds the ipv4 header, udp header, and the
    // checksum
    uint32_t signature = CHALLENGE ^ SECRET;
    int max_tries = 65000;
    bool checksum_found = false;

    // Bruteforce the checksum
    for (int i = 0; i < 65000; i++) {
        char packet[sizeof(struct ip) + sizeof(struct udphdr) + 2];
        struct ip *iph = (struct ip *)packet;
        struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ip));
        uint32_t *p_payload =
            (uint32_t *)(packet + sizeof(struct udphdr) + sizeof(struct ip));

        *p_payload = htons(i);

        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + 2);
        iph->ip_id = htons(54331);
        iph->ip_ttl = 16;
        iph->ip_off = 0;
        iph->ip_p = IPPROTO_UDP;
        iph->ip_src.s_addr = inet_addr(src_ip_str.c_str());
        iph->ip_dst.s_addr = inet_addr(dest_ip.c_str());

        udp_hdr->uh_sport = htons(UDP_SRC_PORT);
        udp_hdr->uh_dport = htons(port);
        udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + 2);
        udp_hdr->uh_sum = 0;

        uint16_t calculated_checksum = udp_checksum(iph, udp_hdr, p_payload, 2);
        udp_hdr->uh_sum = (calculated_checksum);
      
        if (calculated_checksum == checksum) {
            // std::cout << "Calculated Checksum: 0x" << std::hex <<
            // calculated_checksum << std::dec << std::endl;
            checksum_found = true;

            *p_payload = htons(i);

            // std::cout << "Calculated Checksum after setting: 0x" << std::hex
            // << calculated_checksum << std::dec << std::endl;

            if (sendto(reply_socket, (packet), sizeof(packet), 0,
                       (struct sockaddr *)&reply_addr,
                       sizeof(reply_addr)) < 0) {
                std::cerr << "Error: Could not send packet" << std::endl;
                close(reply_socket);
                return "";
            }

            char buffer_2[1024];
            memcpy(buffer_2, packet, sizeof(packet));

            socklen_t addr_len_2 = sizeof(reply_addr);
            ssize_t bytes_received_ =
                recvfrom(reply_socket, buffer_2, sizeof(buffer_2), 0,
                         (struct sockaddr *)&reply_addr, &addr_len_2);

            close(reply_socket);

            // check if the response was recieved
            if (bytes_received_ > 0) {
                buffer_2[bytes_received_] = '\0';
                std::string response(buffer_2);
                // std::cout << "Response: " << response << std::endl;
                std::smatch matches;

                std::regex pattern("\"([^\"]+)\"");

                if (std::regex_search(response, matches, pattern)) {
                    std::string secret_phrase =
                        matches[1]; // Extract the phrase
                    return secret_phrase;
                } else {
                    std::cout << "" << std::endl;
                }
            }
            return "";
        }
    }
    return "";
}
