#ifndef GIVEME_NETWORK_H
#define GIVEME_NETWORK_H

#include "config.h"
#include "key.h"
#include "blockchain.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdatomic.h>

#define GIVEME_RECV_PACKET_OKAY 0
#define GIVEME_RECV_PACKET_UNEXPECTED -1
#define GIVEME_RECV_PACKET_WRONG_CHAIN -2


struct network_last_hash
{
    char hash[SHA256_STRING_LENGTH];
    // The total number of connected peers who have this hash.
    size_t total;
};

/**
 * @brief Represents all the last hashes on every peer on the blockchain
 * 
 */
struct network_last_hashes
{
    // Vector of struct network_last_hash
    struct vector* hashes;
    // The last hash everyone agrees on the most
    // if our blockchain last hash differs from this we will need to ask the network for an updated chain
    char famous_hash[SHA256_STRING_LENGTH];
    pthread_mutex_t lock;
};

enum
{
    GIVEME_CONNECT_FLAG_ADD_TO_CONNECTIONS = 0b00000001
};

struct network_connection_data
{
    int sock;
    struct sockaddr_in addr;

    // The timestamp of the last communication with this socket.
    time_t last_contact;

    // Most recent block on this peers blockchain
    char block_hash[SHA256_STRING_LENGTH];
};

struct network_connection
{
    pthread_mutex_t lock;
    struct network_connection_data *data;
};

enum
{
    GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_CHAIN_REQUEST,
    GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_UNABLE_TO_HELP,
    GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_SENDING_CHAIN,
};

struct giveme_dataexchange_tcp_packet
{
    int type;
    union
    {
        struct giveme_dataexchange_chain_request
        {
            // Requesting hash - until end of chain
            char hash[SHA256_STRING_LENGTH];
        } chain_request;

        struct giveme_dataexchange_unable_to_help
        {

        } unable_to_help;

        struct giveme_dataexchange_sending_chain
        {
            // The total blocks that need to be received before the chain is updated.
            size_t blocks_left_to_end;

            //  The hash of the final block we are sending.
            char last_hash[SHA256_STRING_LENGTH];

            // The start hash where the chain is sent from
            char start_hash[SHA256_STRING_LENGTH];

        } sending_chain;
    };
};
enum
{
    GIVEME_NETWORK_TCP_PACKET_TYPE_PING,
    GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE,
    GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PUBLIC_KEY,
    GIVEME_NETWORK_TCP_PACKET_TYPE_VERIFIED_BLOCK,
    GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN,
    GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN_RESPONSE,
};

struct block block;
struct giveme_tcp_packet
{
    int type;

    union
    {

        struct giveme_tcp_packet_ping
        {
            // The last known hash on the blockchain for the peer who pinged us.
            char last_hash[SHA256_STRING_LENGTH];
        } ping;

        struct giveme_tcp_packet_publish_package
        {
            char name[GIVEME_PACKAGE_NAME_MAX];
        } publish_package;

        struct giveme_tcp_packet_publish_key
        {
            struct key pub_key;
            char name[GIVEME_KEY_NAME_MAX];
        } publish_public_key;

        struct giveme_tcp_packet_verified_block
        {
            struct block block;
        } verified_block;

        struct giveme_tcp_packet_update_chain
        {
            // The last known hash in our blockchain
            char last_hash[SHA256_STRING_LENGTH];
        } update_chain;

        struct giveme_tcp_packet_update_chain_response
        {
            // The total blocks that need to be received before the chain is updated.
            size_t blocks_left_to_end;

            //  Last hash of this blockchain
            char last_hash[SHA256_STRING_LENGTH];
            // The start hash where the chain is sent from
            char start_hash[SHA256_STRING_LENGTH];

            // The port the receiver should connect to if they want to receive the chain
            int data_port;
        } update_chain_response;

        // In case we want to add special packets in the future
        // we should reserve some data in the tcp packet
        // which will also affect the block size
        char s[GIVEME_MINIMUM_TCP_PACKET_SIZE];
    };
};

/**
 * @brief A single transaction holds a packet and a creation time.
 * These transactions will be added to blocks every five minutes.
 */
struct network_transaction
{
    struct giveme_tcp_packet packet;
    time_t created;
};

struct network
{
    // IP Addresses on the network vector of struct in_addr
    struct vector *ip_addresses;
    pthread_mutex_t ip_address_lock;

    struct network_connection connections[GIVEME_TCP_SERVER_MAX_CONNECTIONS];
    atomic_int total_connected;

    // The last hashes that are known to the network for all connected peers
    // we want to pull towards one last hash thats equal for everyone
    // Network will always download the chain to the most popular current last hash.
    struct network_last_hashes hashes;

    struct network_transactions
    {
        struct network_transaction *awaiting[GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK];
        int total;
        pthread_mutex_t lock;
    } transactions;

    // Locked when preforming TCP actions that must not conflict such as modiying
    // the connection array

    struct sockaddr_in listen_address;
    int listen_socket;

    struct sockaddr_in dataexchange_listen_address;
    int dataexchange_listen_socket;

    // The timestamp for when we last sent a block during our current session
    // Equal to zero on startup.
    atomic_long last_block_processed;

    atomic_long last_block_receive;

    // The last time we requested the most up to date chain
    atomic_long last_chain_update_request;
    atomic_bool chain_requesting_update;

    // The last time the network hashes were updated to calculate the most known
    // last block
    atomic_long last_known_hashes_update;
};

void giveme_network_initialize();
int giveme_network_listen();
int giveme_network_connection_thread_start();
int giveme_network_process_thread_start();
void giveme_network_broadcast(struct giveme_tcp_packet *packet);
void giveme_network_update_chain();

#endif