#ifndef GIVEME_NETWORK_H
#define GIVEME_NETWORK_H
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "blockchain.h"
#define GIVEME_UDP_PORT 9987
#define GIVEME_TCP_PORT 9989

#define GIVEME_RECV_PACKET_OKAY 0
#define GIVEME_RECV_PACKET_UNEXPECTED -1
#define GIVEME_RECV_PACKET_WRONG_CHAIN -2

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
    GIVEME_UDP_PACKET_TYPE_BLOCK,
    GIVEME_UDP_PACKET_TYPE_PUBLISH_PACKAGE,
    GIVEME_UDP_PACKET_TYPE_REQUEST_CHAIN,
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

        struct giveme_udp_packet_block
        {
            struct block block;
        } block;

        struct giveme_udp_packet_request_chain
        {
            // The last block hash the sender of this packet was aware of.
            char hash[SHA256_STRING_LENGTH];
        } request_chain;
    };
};

enum
{
    GIVEME_TCP_PACKET_TYPE_HELLO,
    GIVEME_TCP_PACKET_TYPE_BLOCK,
    GIVEME_TCP_PACKET_TYPE_BLOCK_TRANSFER
};
struct giveme_tcp_packet
{
    int type;
    union 
    {
        struct giveme_tcp_hello_packet
        {
       
        } hello;

        struct giveme_tcp_block_packet
        {
            struct block block;
        } block;

        struct giveme_tcp_block_transfer_packet
        {
            // The starting hash in the blockchain that we will be sending blocks for
            char prev_hash[SHA256_STRING_LENGTH];
            // The last block hash that will be sent in the block transfer
            char end_hash[SHA256_STRING_LENGTH];
        } block_transfer;
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
void giveme_udp_broadcast_random_no_localhost(struct giveme_udp_packet *packet, int max_packets_sent);

int giveme_udp_network_send(struct in_addr addr, struct giveme_udp_packet *packet);

/**
 * @brief Sends a block to the network, the block must be mined to be accepted by recipients.
 * 
 * @param block 
 */
void giveme_network_block_send(struct block* block);

/**
 * @brief Requests an updated blockchain
 * 
 */
void giveme_network_request_blockchain();

#endif