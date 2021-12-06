#ifndef GIVEME_NETWORK_H
#define GIVEME_NETWORK_H
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "config.h"
#include "blockchain.h"
#define GIVEME_UDP_PORT 9987
#define GIVEME_TCP_PORT 9989

#define GIVEME_RECV_PACKET_OKAY 0
#define GIVEME_RECV_PACKET_UNEXPECTED -1
#define GIVEME_RECV_PACKET_WRONG_CHAIN -2

enum
{
    GIVEME_DOWNLOAD_CHAIN_FLAG_IGNORE_FIRST_BLOCK = 0b00000001
};

struct network
{
    // IP Addresses on the network vector of struct in_addr
    struct vector *ip_addresses;

    // Vector of IP addresses of struct in_addr that should not be broadcast too for the next broadcast
    struct vector* ignore_broadcast_ips;

    // Vector of giveme_udp_queued_packet, these are packets that are queued for processing
    // recently received from the network.
    struct vector* queued_udp_packets;
    pthread_mutex_t queued_udp_packets_lock;

};

enum
{
    GIVEME_UDP_PACKET_TYPE_HELLO,
    GIVEME_UDP_PACKET_TYPE_BLOCK,
    GIVEME_UDP_PACKET_TYPE_PUBLISH_PACKAGE,
    GIVEME_UDP_PACKET_TYPE_REQUEST_CHAIN,
    GIVEME_UDP_PACKET_TYPE_CHAIN_BLOCK_COUNT
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

        // This packet is sent to specify how many blocks you have on your chain
        // people whos counts are less will connect to you
        struct giveme_udp_packet_chain_block_count
        {
            size_t total;
        } block_count;
    };
};

struct giveme_queued_udp_packet
{
    struct in_addr addr;
    struct giveme_udp_packet packet;

    // If its been over five seconds the packet is just discarded and not processed
    // as the UDP data by this point is likely too old to work with anyway
    time_t created;
};

enum
{
    GIVEME_TCP_PACKET_TYPE_HELLO,
    GIVEME_TCP_PACKET_TYPE_BLOCK,
    GIVEME_TCP_PACKET_TYPE_BLOCK_TRANSFER,
    GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE,
    GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREEABLE_BLOCK,
    // Returned when the client requested something we dont understand
    GIVEME_TCP_PACKET_TYPE_UNKNOWN_ENTITY,
    GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREED_ON_BLOCK
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
            char hash[SHA256_STRING_LENGTH];
            // The last block hash that will be sent in the block transfer
            char end_hash[SHA256_STRING_LENGTH];
        } block_transfer;

        struct giveme_tcp_block_count_exchange
        {
            size_t count;
        } block_count_exchange;

        /**
         * @brief Used for two nodes to figure out which part of the chain is relateable to them.
         * 
         */
        struct giveme_tcp_block_count_exchange_agreeable_block
        {
            // The hash of a block
            char hash[SHA256_STRING_LENGTH];
            // The previous hash of a block
            char prev_hash[SHA256_STRING_LENGTH];
        } agreeable_block;

        /**
         * @brief Used for two nodes to agree on a particular block when theirs chain disagreements
         * 
         */
        struct giveme_tcp_block_count_exchange_agreed_block
        {
            // The hash of the block
            char hash[SHA256_STRING_LENGTH];
            // The total number of blocks to the end of the chain from the block represented by the hash
            size_t total_blocks_to_end;

        } agreed_block;
    };
};

void giveme_network_initialize();
int giveme_udp_network_listen();
int giveme_process_thread_start();

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
void giveme_network_block_send(struct block *block);

/**
 * @brief Requests an updated blockchain
 * 
 */
int giveme_network_request_blockchain();
int giveme_network_request_blockchain_try(size_t tries);

#endif