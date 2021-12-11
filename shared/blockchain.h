#ifndef GIVEME_BLOCKCHAIN_H
#define GIVEME_BLOCKCHAIN_H
#include <stdbool.h>
#include <sys/types.h>
#include "sha256.h"
#include "config.h"
#include "misc.h"
#include "network.h"
#include "key.h"

#define GIVEME_BLOCKCHAIN_BLOCK_VALID 0
#define GIVEME_BLOCKCHAIN_NOT_MINED -1
#define GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH -2
#define GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL -3
#define GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND -4

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
};


struct block
{
    struct
    {
        struct block_transactions
        {
            struct network_transaction transactions[GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK];
            int total;
        } transactions;

        // The public key who mined/validated this block
        // he shall receive a coin reward of 0.05 * total_transactions
        // unless its christmas day in which case the reward will be 0.10 * total_transactions
        struct key validator_key;

        char prev_hash[SHA256_STRING_LENGTH];
        int nounce;
    } data;
    char hash[SHA256_STRING_LENGTH];
};

/**
 * @brief Gives the last block added to the blockchain
 * 
 * @return struct block* 
 */
struct block *giveme_blockchain_back_safe();
struct block *giveme_blockchain_back() NO_THREAD_SAFETY;

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
int giveme_mine(struct block *block) USES_LOCKS;

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
#endif