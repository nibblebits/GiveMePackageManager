#ifndef GIVEME_BLOCKCHAIN_H
#define GIVEME_BLOCKCHAIN_H
#include <stdbool.h>
#include <sys/types.h>
#include <semaphore.h>
#include <stdatomic.h>
#include "sha256.h"
#include "config.h"
#include "misc.h"
#include "key.h"

#define GIVEME_BLOCKCHAIN_BLOCK_VALID 0
#define GIVEME_BLOCKCHAIN_NOT_MINED -1
#define GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH -2
#define GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL -3
#define GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND -4
#define GIVEME_BLOCKCHAIN_BAD_BLOCK_SIGNATURE -5
#define GIVEME_BLOCKCHAIN_BAD_BLOCK_TRANSACTIONS -6

enum
{
    BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN = 0b00000001
};

struct blockchain_keydata
{
    struct key key;
    // Balance of the blockchain account
    double balance;
    char name[GIVEME_KEY_NAME_MAX];
    struct blockchain_keydata_verified_blocks_data
    {
        size_t total;
    } verified_blocks;

    // The time the public key was published on the network.
    time_t created;
};

enum
{
    GIVEME_BLOCKCHAIN_INDIVIDUAL_FLAG_HAS_KEY_ON_CHAIN = 0b00000001
};

/**
 * @brief Individuals are essentially published public keys on the network
 * who have carried out actions.
 */
struct blockchain_individual
{
    int flags;
    struct blockchain_keydata key_data;
};

struct block;
struct blockchain
{
    // The total number of blocks on the chain
    size_t total;
    // Maximum blocks before the file on disk needs to be resized
    size_t max_blocks;

    struct blockchain_crawler
    {
        // The index on the chain we are currently at for a crawl operation
        off_t pos;
        // Start hash for a crawl. Use NULL to start from the beginning of the chain
        const char *start;
        // End hash for a crawl. Use NULL to crawl until the end
        const char *end;
        bool crawling;
        size_t crawled_total;
    } crawl;
    struct block *block;

    // Information on the blockchain about ourselves.
    struct blockchain_individual me;

    // Vector of struct giveme_tcp_packet_publish_key* for all published public keys on this blockchain
    struct vector *public_keys;

    // When the blockchain is being downloaded some may want to wait
    // until that is done
    sem_t blockchain_ready_sem;

    // True if the blockchain has been downloaded/confirmed up to date
    atomic_bool blockchain_ready;

    // Temporary data for when changes on the blockchain are to be made
    struct blockchain_changes_data
    {
        bool is_changing;
        // Index before changes were made.
        size_t index;

        // The total number of blocks added during this change.
        size_t blocks_added;
    } changes;
};

enum
{
    BLOCK_TRANSACTION_TYPE_NEW_PACKAGE,
    BLOCK_TRANSACTION_TYPE_DOWNLOADED_PACKAGE,
    BLOCK_TRANSACTION_TYPE_NEW_KEY,
};

struct block_transaction_downloaded_package_data
{
    // The hash of the transaction that created the package we are downloading
    char hash[SHA256_STRING_LENGTH];
    // The IP address of the person who downloaded the package so people downloading this package can find us.
    char ip_address[GIVEME_IP_STRING_SIZE];

    // The key of the person you downloaded the package from.
    struct key provider_key;
};

struct block_transaction_new_package_data
{
    char name[GIVEME_PACKAGE_NAME_MAX];
};
struct block_transaction
{
    struct block_transaction_data
    {
        int type;
        union
        {
            struct block_transaction_new_package
            {
                // Data signed with the signature below
                struct block_transaction_new_package_data data;

                struct key_signature_hash signature;

                // The originating IP address for this package. This is the IP address where you will
                // find the package... When downloading a package if the peer is offline/unreachable
                // we will download from someone whos already downloaded the package.
                // We are not able to sign this since the peer does not know his own IP address.
                char ip_address[GIVEME_IP_STRING_SIZE];

            } publish_package;

            struct block_transaction_downloaded_package
            {
                // Data signed with the signature below.
                struct block_transaction_downloaded_package_data data;
                struct key_signature_hash signature;

            } downloaded_package;

            struct block_transaction_new_key
            {
                struct key pub_key;
                char name[GIVEME_KEY_NAME_MAX];
            } publish_public_key;
        };

        // The UNIX timestamp of when the transaction was created
        time_t timestamp;
    } data;

    // This is the hash of transaction, its not signed by any public key
    // The hash should be used to reference the transaction only and not for security
    // purposes. The hash will be used as an ID in some situations such as when requesting pacakges.
    // Packages will not be requested by their friendly name but the hash of the transaction
    // that made them.
    char hash[SHA256_STRING_LENGTH];
};

struct block
{
    union
    {
        struct
        {
            struct block_transactions
            {
                struct block_transaction transactions[GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK];
                int total;
            } transactions;

            char prev_hash[SHA256_STRING_LENGTH];
            int nounce;

            // The timestamp of when the block was created.
            time_t timestamp;
        } data;

        // 2046 bytes of wasted memory, so that theirs room to make changes
        // without destroying the entire blockchain.
        char wasteful[2046];
    };

    // The signature signed by the key who mined/validated this block
    // he shall receive a coin reward of 0.05 * total_transactions
    struct key_signature_hash signature;
};

/**
 * @brief Gives the last block added to the blockchain
 * 
 * @return struct block* 
 */
struct block *giveme_blockchain_back_safe();
struct block *giveme_blockchain_back() NO_THREAD_SAFETY;

struct blockchain_individual *giveme_blockchain_me();

void giveme_lock_chain();
void giveme_unlock_chain();
int giveme_block_verify(struct block *block) NO_THREAD_SAFETY;
int giveme_block_verify_for_chain(struct blockchain *chain, struct block *block) NO_THREAD_SAFETY;
int giveme_blockchain_add_block(struct block *block) NO_THREAD_SAFETY;
off_t giveme_blockchain_index_for_block(const char *hash) NO_THREAD_SAFETY;
struct block *giveme_blockchain_block(const char *hash, size_t *blocks_left_to_end);

size_t giveme_blockchain_block_count_for_chain(struct blockchain *chain) NO_THREAD_SAFETY;
size_t giveme_blockchain_block_count() NO_THREAD_SAFETY;

void giveme_blockchain_initialize() NO_THREAD_SAFETY;
void giveme_blockchain_load() NO_THREAD_SAFETY;

int giveme_blockchain_begin_crawl(const char *start_hash, const char *end_hash) NO_THREAD_SAFETY;
struct block *giveme_blockchain_crawl_next(int flags) NO_THREAD_SAFETY;
int giveme_mine(struct block *block) NO_THREAD_SAFETY;

struct blockchain *giveme_blockchain_create(size_t total_blocks) NO_THREAD_SAFETY;
void giveme_blockchain_free(struct blockchain *chain) NO_THREAD_SAFETY;
struct blockchain *giveme_blockchain_master();
int giveme_blockchain_add_block_for_chain(struct blockchain *chain, struct block *block);

/**
 * @brief Returns how many blocks are left on the chain until we reach the latest block
 * based on the given index provided. The index being a single block in the blockchain array
 * 
 * @param index 
 * @return size_t 
 */
size_t giveme_blockchain_total_blocks_left(int index);

/**
 * @brief Gets an individual from the blockchain whose key matches the key provided
 * The individual explains the keys money balance along with other important information
 * 
 * @param key 
 * @param individual_out 
 * @return int 
 */
int giveme_blockchain_get_individual(struct key *key, struct blockchain_individual *individual_out);

/**
 * @brief Loads important data from the blockchain such as the public keys, our balance ect..
 * Blockchain network will not connect until this is done.
 * 
 */
void giveme_blockchain_load_data();

/**
 * @brief Returns true if we (our public key) is known on the blockchain
 * 
 * @return true 
 * @return false 
 */
bool giveme_blockchain_are_we_known();

/**
 * @brief Returns the public key of the next verifier who should verify the next block
 * 
 * @return struct key* The verifier key
 */
struct key *giveme_blockchain_get_verifier_key();

/**
 * @brief Returns the maximum number of blocks the blockchain is allowed  to have 
 *  at the date and time right now. This function can be used to prevent people making illegal chains
 * 
 * @return size_t 
 */
size_t giveme_blockchain_max_allowed_blocks_for_now();

/**
 * @brief Returns true if we are able to add the amount of blocks provided
 * 
 * @param amount 
 * @return true 
 * @return false 
 */
bool giveme_blockchain_can_add_blocks(size_t amount);

/**
 * @brief Blocks until the blockchain is ready and up to date
 * 
 */
void giveme_blockchain_wait_until_ready();

/**
 * @brief Signals everyone waiting that the blockchain is ready
 * 
 */
void giveme_blockchain_give_ready_signal();

/**
 * @brief Returns the current index in the blockchain. I.e if you have 10 blocks index will be 9
 * 
 * @return size_t 
 */
size_t giveme_blockchain_index();

void giveme_blockchain_changes_prepare();
void giveme_blockchain_changes_discard();
void giveme_blockchain_changes_apply();

struct block *giveme_blockchain_get_block_with_index(int index);

/**
 * @brief Returns the SHA256 hash of the given block
 * 
 * @param block 
 * @return const char* 
 */
const char* giveme_blockchain_block_hash(struct block* block);

#endif