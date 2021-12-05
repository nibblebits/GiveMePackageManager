#ifndef GIVEME_BLOCKCHAIN_H
#define GIVEME_BLOCKCHAIN_H
#include <stdbool.h>
#include <sys/types.h>
#include "sha256.h"
#include "config.h"
#include "misc.h"

#define GIVEME_BLOCKCHAIN_BLOCK_VALID 0
#define GIVEME_BLOCKCHAIN_NOT_MINED -1
#define GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH -2
#define GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL -3
#define GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND -4


enum
{
    BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN = 0b00000001
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
    struct block* block;
};

struct block
{
    struct
    {
        union
        {
            struct package_block
            {
                char name[PACKAGE_NAME_MAX];
            } package;
        };

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
int giveme_block_verify_for_chain(struct blockchain* chain, struct block *block) NO_THREAD_SAFETY;
int giveme_blockchain_add_block(struct block *block) NO_THREAD_SAFETY;
off_t giveme_blockchain_index_for_block(const char *hash) NO_THREAD_SAFETY;
struct block* giveme_blockchain_block(const char* hash, size_t* blocks_left_to_end);

size_t giveme_blockchain_block_count_for_chain(struct blockchain* chain) NO_THREAD_SAFETY;
size_t giveme_blockchain_block_count() NO_THREAD_SAFETY;

void giveme_blockchain_initialize() NO_THREAD_SAFETY;
void giveme_blockchain_load() NO_THREAD_SAFETY;

int giveme_blockchain_begin_crawl(const char *start_hash, const char *end_hash) NO_THREAD_SAFETY;
struct block *giveme_blockchain_crawl_next(int flags) NO_THREAD_SAFETY;
int giveme_mine(struct block *block) USES_LOCKS;

struct blockchain* giveme_blockchain_create(size_t total_blocks) NO_THREAD_SAFETY;
void giveme_blockchain_free(struct blockchain* chain) NO_THREAD_SAFETY;
struct blockchain* giveme_blockchain_master();
int giveme_blockchain_add_block_for_chain(struct blockchain* chain, struct block *block);

/**
 * @brief Returns how many blocks are left on the chain until we reach the latest block
 * based on the given index provided. The index being a single block in the blockchain array
 * 
 * @param index 
 * @return size_t 
 */
size_t giveme_blockchain_total_blocks_left(int index);


#endif