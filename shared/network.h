#ifndef GIVEME_NETWORK_H
#define GIVEME_NETWORK_H
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include "config.h"

#define GIVEME_UDP_PORT 9987
#define GIVEME_TCP_PORT 9989

struct network
{
    // IP Addresses on the network vector of struct in_addr
    struct vector *ip_addresses;

    // Contains our public IP Address. to begin with this will equal 127.0.0.1 until
    // someone tells us who we are. We can't issue certain packets when our IP is 127.0.0.1 
    char my_ip[GIVEME_IP_STRING_SIZE];
};

enum
{
    GIVEME_UDP_PACKET_TYPE_HELLO,
    GIVEME_UDP_PACKET_TYPE_BROADCAST_BLOCK,
    GIVEME_UDP_PACKET_TYPE_PUBLISH_PACKAGE
};
struct giveme_udp_packet
{
    int type;
    union
    {
        struct giveme_udp_packet_hello
        {
            
        } hello;

        struct giveme_udp_packet_publish_package
        {
            char name[PACKAGE_NAME_MAX];

        } package;
    };
};

enum
{
    GIVEME_TCP_PACKET_TYPE_HELLO
};
struct giveme_tcp_packet
{
    int type;
    union 
    {
        struct giveme_tcp_hello_packet
        {
            // This is the IP address of the destination, it is sent to them so they know who they are.
            char dst_ip[GIVEME_IP_STRING_SIZE];
        } hello;
    };
};

void giveme_network_initialize();
int giveme_udp_network_listen();

/**
 * @brief Announces ourself to the entire network that we are aware of
 * 
 */
void giveme_udp_network_announce();

void giveme_udp_broadcast(struct giveme_udp_packet *packet);
/**
 * @brief Broadcasts packets to random clients, this is good for security to ensure that
 * we dont always connect to a rouge client.
 * 
 * @param packet 
 * @param max_packets_sent 
 */
void giveme_udp_broadcast_random(struct giveme_udp_packet *packet, int max_packets_sent);

int giveme_udp_network_send(struct in_addr addr, struct giveme_udp_packet *packet);

#endif