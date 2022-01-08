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
    struct vector *hashes;
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
    // The public key of this connection... No key is valid.
    struct key key;
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
    GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_REQUEST_BLOCK,
    GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_SENDING_BLOCK,
    GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_REQUEST_CHUNK,
    GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_SEND_CHUNK
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

        struct giveme_dataexchange_request_block
        {
            // The index of the block on the chain that you want.
            // We do not allow hashes because the point of requesting blocks
            // by index is to prevent attacks where fake chains are sent to us.
            // We can ask 1000s of peers for differnet block indexes and if
            // we cant add the block to the chain we know they sent us a fake block
            int block_index;
        } request_block;

        struct giveme_dataexchange_sending_block
        {
            // The block index of the block, following will be one block
            int block_index;
        } sending_block;

        struct giveme_dataexchange_package_request_chunk
        {
            struct giveme_dataexchange_package_request_chunk_package
            {
                char data_hash[SHA256_STRING_LENGTH];
            } package;

            // The chunk index. Offset = index * GIVEME_PACKAGE_CHUNK_SIZE
            // Chunk size is GIVEME_PACKAGE_CHUNK_SIZE
            off_t index;
        } package_request_chunk;

        /**
         * @brief Upon receving this packet the following data of size "chunk_size" can be read
         * from the stream. This data is the chunk data
         * 
         */
        struct giveme_dataexchange_package_send_chunk
        {
            struct giveme_dataexchange_package_send_chunk_package
            {
                char data_hash[SHA256_STRING_LENGTH];
            } package;

            off_t index;
            size_t chunk_size;
        } package_send_chunk;
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
    struct packet_data
    {
        int type;
        int flags;

        union
        {

            struct giveme_tcp_packet_ping
            {
                // The last known hash on the blockchain for the peer who pinged us.
                char last_hash[SHA256_STRING_LENGTH];
            } ping;

            struct giveme_tcp_packet_publish_package
            {
                struct block_transaction_new_package_data data;
                // The IP address where the package can be downloaded from..
                // If this is NULL then the receiver of this packet must fill it with the
                // IP address of the peer who sent us this packet.
                char ip_address[GIVEME_IP_STRING_SIZE];
                // The public key and signature to verify this public key signed the given data.
                struct key_signature_hash signature;
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

    } data;

    // The hash of the data
    char data_hash[SHA256_STRING_LENGTH];
    // THe public key who signed the data hash confirming its state.
    struct key pub_key;
    // The signature of the resulting sign.
    struct signature sig;
};

enum
{
    GIVEME_NETWORK_PACKAGE_DOWNLOAD_COMPLETED,
    GIVEME_NETWORK_PACKAGE_DOWNLOAD_INCOMPLETE,

    /**
     * @brief No chunks available means all threads are currently downloading
     * all available chunks, therefore nothing pending for download.
     */
    GIVEME_NETWORK_PACKAGE_DOWNLOAD_NO_CHUNKS_AVAILABLE
};

enum
{
    GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_DOWNLOADED,
    GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_NOT_DOWNLOADED,
    GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_DOWNLOAD_IN_PROGRESS
};


typedef int CHUNK_MAP_ENTRY;

struct network_package_download
{
    struct network_package_download_info
    {
        struct network_package_download_connections_info
        {
            struct sockaddr_in peers[PACKAGE_MAX_KNOWN_IP_ADDRESSES];
        } connections;

        struct package* package;
        struct network_package_download_download_info
        {
            struct network_package_download_chunks_info
            {
                // The total chunks we have downloaded already, once its equal to total_chunks
                // the file has been downloaded
                size_t downloaded;

                // The total block chunks in this file. Last chunk does not have to be of required chunk size.
                size_t total;

                // Chunk map which specifies which chunks have been downloaded and which
                // have not yet been downloaded.
                // Total chunks = filesize / GIVEME_PACKAGE_CHUNK_SIZE
                // CHUNK MAP IS "total" elements in size.
                // GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_DOWNLOADED is present
                // for a given index if that particular chunk has been downloaded.
                CHUNK_MAP_ENTRY *chunk_map;

            } chunks;

            // Memory mapped pointer to the downloaded file. We can change any value
            // at this address to directly change the file in question.
            // Memory mapped data is mapped to the tmp_filename
            void *data;

            // The filename of the memory mapped file. This is a temporary filename
            // and must be moved when download is finished.
            char tmp_filename[L_tmpnam];
            // Temporary opened file to the tmp_filename
            int tmp_fp;

            pthread_mutex_t mutex;

        } download;
    } info;
};

struct network_package_download_uploading_peer
{
    char ip_address[GIVEME_IP_STRING_SIZE];
    struct network_package_download *download;
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

    struct network_blockchain_data
    {
        // Vector of struct network_connection_data. These are the current peers
        // with blocks we need, during a chain request we will randomly download each block
        // between them one block at a time.
        // Rather than download from one peer who could lie to us.
        struct vector *peers_with_blocks;

        // The timestamp for when we last sent a block during our current session
        // Equal to zero on startup.
        atomic_long last_block_processed;
        atomic_long last_block_receive;

        // The last time we requested the most up to date chain
        atomic_bool chain_requesting_update;
        atomic_long last_chain_update_request;

        // The last time the network hashes were updated to calculate the most known
        // last block
        atomic_long last_known_hashes_update;
    } blockchain;
};

void giveme_network_initialize();
int giveme_network_listen();
int giveme_network_connection_thread_start();
int giveme_network_process_thread_start();
void giveme_network_broadcast(struct giveme_tcp_packet *packet);
void giveme_network_update_chain();

#endif