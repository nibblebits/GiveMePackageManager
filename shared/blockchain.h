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
struct block *giveme_blockchain_back();
struct block *giveme_blockchain_back_nosafety() NO_THREAD_SAFETY;

void giveme_lock_chain();
void giveme_unlock_chain();
int giveme_block_verify_nosafety(struct block *block) NO_THREAD_SAFETY;
int giveme_blockchain_add_block_nosafety(struct block *block) NO_THREAD_SAFETY;
off_t giveme_blockchain_index_for_block(const char *hash);

void giveme_blockchain_initialize();
void giveme_blockchain_load();

int giveme_blockchain_begin_crawl(const char *start_hash, const char *end_hash);
struct block *giveme_blockchain_crawl_next(int flags);
int giveme_mine(struct block *block);

#endif