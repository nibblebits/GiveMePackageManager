#include "blockchain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <linux/limits.h>
#include "vector.h"
#include "network.h"
#include "misc.h"
#include "sha256.h"
#include "log.h"

// Holds the last 10000 blocks any further back we need to go we will need to
// load from the database
//struct vector *memory_blockchain;

// Memory mapped pointer to the blockchain
struct blockchain blockchain;
pthread_mutex_t blockchain_mine_lock;

void giveme_lock_chain()
{
    pthread_mutex_lock(&blockchain_mine_lock);
}

void giveme_unlock_chain()
{
    pthread_mutex_unlock(&blockchain_mine_lock);
}

off_t giveme_blockchain_index_for_block_for_chain(struct blockchain* chain, const char *hash)
{
    struct block blank_block = {};
    // First block requested? then return 0
    if (hash == NULL || (memcmp(&blank_block, hash, sizeof(blank_block)) == 0))
    {
        return 0;
    }

    for (int i = chain->total - 1; i >= 0; i--)
    {
        if (S_EQ(chain->block[i].hash, hash))
        {
            return i;
        }
    }

    return -1;
}

off_t giveme_blockchain_index_for_block(const char *hash)
{
    return giveme_blockchain_index_for_block_for_chain(&blockchain, hash);
}

struct blockchain* giveme_blockchain_master()
{
    return &blockchain;
}

struct block* giveme_blockchain_block(const char* hash, size_t* blocks_left_to_end)
{
    off_t index = giveme_blockchain_index_for_block(hash);
    if (index < 0)
        return NULL;
    
    if (blocks_left_to_end)
    {
        *blocks_left_to_end = giveme_blockchain_total_blocks_left(index);
    }
    return &blockchain.block[index];
}

int giveme_blockchain_begin_crawl_for_chain(struct blockchain* chain, const char *start_hash, const char *end_hash)
{
    int res = 0;
    chain->crawl.crawling = true;
    chain->crawl.start = start_hash;
    chain->crawl.end = end_hash;
    chain->crawl.pos = 0;
    if (start_hash)
    {
        chain->crawl.pos = giveme_blockchain_index_for_block_for_chain(chain, start_hash);
        res = chain->crawl.pos;
    }

out:
    return res;
}

int giveme_blockchain_begin_crawl(const char *start_hash, const char *end_hash)
{
    return giveme_blockchain_begin_crawl_for_chain(&blockchain, start_hash, end_hash);
}

struct block *giveme_blockchain_crawl_next_for_chain(struct blockchain* chain, int flags)
{
    if (!chain->crawl.crawling)
    {
        return NULL;
    }

    if (chain->crawl.pos >= chain->total || chain->crawl.pos < 0)
    {
        return NULL;
    }

    struct block *block = &chain->block[blockchain.crawl.pos];
    if (chain->crawl.end && S_EQ(block->hash, chain->crawl.end))
    {
        // We have finished crawling
        chain->crawl.crawling = false;
        return block;
    }

    if (flags & BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN)
    {
        chain->crawl.pos -= 1;
    }
    else
    {
        chain->crawl.pos += 1;
    }

    return block;
}

struct block *giveme_blockchain_crawl_next(int flags)
{
    return giveme_blockchain_crawl_next_for_chain(&blockchain, flags);
}

bool giveme_block_has_hash(struct block *block, const char *hash)
{
    char hash_comptued[SHA256_STRING_LENGTH];
    sha256_data(&block->data, hash_comptued, sizeof(block->data));
    return S_EQ(hash, hash_comptued);
}

bool giveme_mined(struct block *block)
{
    bool hash_correct = true;
    for (int i = 0; i < GIVEME_TOTAL_ZEROS_FOR_MINED_BLOCK; i++)
    {
        if (block->hash[i] != '0')
        {
            hash_correct = false;
            break;
        }
    }

    if (hash_correct)
    {
        hash_correct = giveme_block_has_hash(block, block->hash);
    }

    return hash_correct;
}

struct block *giveme_blockchain_back_for_chain(struct blockchain *chain)
{
    if (chain->total <= 0)
        return NULL;
    struct block *block = NULL;
    block = &chain->block[blockchain.total - 1];
    return block;
}
struct block *giveme_blockchain_back()
{
    return giveme_blockchain_back_for_chain(&blockchain);
}

struct block *giveme_blockchain_back_safe()
{
    struct block *block = NULL;
    giveme_lock_chain(&blockchain_mine_lock);
    block = giveme_blockchain_back();
    giveme_unlock_chain(&blockchain_mine_lock);
    return block;
}

bool giveme_blockchain_verify_for_chain(struct blockchain* chain)
{
    giveme_blockchain_begin_crawl_for_chain(chain, NULL, NULL);
    struct block *block = giveme_blockchain_crawl_next_for_chain(chain, 0);
    struct block *prev_block = NULL;
    while (block)
    {
        if (!prev_block)
        {
            char empty_hash[SHA256_STRING_LENGTH];
            memset(empty_hash, 0, sizeof(empty_hash));
            if (memcmp(block->data.prev_hash, empty_hash, sizeof(block->data.prev_hash)) != 0)
            {
                return false;
            }
        }
        if (!S_EQ(block->data.prev_hash, prev_block->hash))
        {
            return false;
        }
        prev_block = block;
        block = giveme_blockchain_crawl_next_for_chain(chain, 0);
    }

    return true;
}

bool giveme_blockchain_verify()
{
    return giveme_blockchain_verify_for_chain(&blockchain);
}

char *giveme_blockchain_path()
{
    static char blockchain_file_path[PATH_MAX];
    sprintf(blockchain_file_path, "%s/%s/%s", getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_DATA_BASE, GIVEME_BLOCKCHAIN_FILEPATH);
    return blockchain_file_path;
}

bool giveme_blockchain_exists()
{
    bool blockchain_exists = false;
    FILE *fp = fopen(giveme_blockchain_path(), "r");
    if (fp)
    {
        blockchain_exists = true;
        fclose(fp);
    }
    return blockchain_exists;
}

size_t giveme_blockchain_total_bytes_for_blocks(size_t total_blocks)
{
    return total_blocks * sizeof(struct block);
}
size_t giveme_blockchain_total_bytes()
{
    size_t size = 0;
    FILE *fp = fopen(giveme_blockchain_path(), "r");
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fclose(fp);
    }
    return size;
}
size_t giveme_blockchain_compute_block_count()
{
    size_t total_blocks = 0;
    for (int i = 0; i < blockchain.max_blocks; i++)
    {
        struct block blank_block = {};
        if (memcmp(&blockchain.block[i], &blank_block, sizeof(blank_block)) == 0)
        {
            break;
        }
        total_blocks++;
    }

    return total_blocks;
}

size_t giveme_blockchain_block_count_for_chain(struct blockchain* chain)
{
    return chain->total;
}

size_t giveme_blockchain_block_count()
{
   return giveme_blockchain_block_count_for_chain(&blockchain);
}

struct blockchain* giveme_blockchain_create(size_t total_blocks)
{
    struct blockchain* chain = calloc(1, sizeof(struct blockchain));
    chain->block = calloc(total_blocks, sizeof(struct block));
    chain->total = 0;
    chain->max_blocks = total_blocks;
    return chain;
}

void giveme_blockchain_free(struct blockchain* chain)
{
    free(chain->block);
    free(chain);
}

void giveme_blockchain_initialize()
{
    bool blockchain_exists = giveme_blockchain_exists();
    int fd = open(giveme_blockchain_path(), O_RDWR | O_CREAT, (mode_t)0600);
    if (!blockchain_exists)
    {
        // No block chain? then truncate it
        ftruncate(fd, giveme_blockchain_total_bytes_for_blocks(BLOCKCHAIN_RESIZE_TOTAL_BLOCKS));
    }
    size_t total_bytes = giveme_blockchain_total_bytes();
    size_t total_possible_blocks = total_bytes / sizeof(struct block);
    blockchain.max_blocks = total_possible_blocks;
    blockchain.block = mmap(0, total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (blockchain.block == MAP_FAILED)
    {
        giveme_log("Failed to map blockchain into memory\n");
    }

    blockchain.total = giveme_blockchain_compute_block_count();

    if (pthread_mutex_init(&blockchain_mine_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize blockchain mine lock mutex\n");
    }
}

int giveme_block_verify_for_chain(struct blockchain* chain, struct block *block)
{
    struct block *last_block = giveme_blockchain_back_for_chain(chain);
    if (last_block && S_EQ(last_block->hash, block->hash))
    {
        // We already have this on the tail of the blockchain
        // most likely multiple nodes resent this block and it reached us twice.
        return GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL;
    }

    if (!giveme_mined(block))
    {
        return GIVEME_BLOCKCHAIN_NOT_MINED;
    }

    if (last_block && !S_EQ(last_block->hash, block->data.prev_hash))
    {
        return GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH;
    }

    return GIVEME_BLOCKCHAIN_BLOCK_VALID;
}

int giveme_block_verify(struct block *block)
{
    return giveme_block_verify_for_chain(&blockchain, block);
}

int giveme_blockchain_add_block_for_chain(struct blockchain* chain, struct block *block)
{
    int res = giveme_block_verify(block);
    if (res < 0)
        return res;

    chain->block[blockchain.total] = *block;
    chain->total++;
    return res;
}

size_t giveme_blockchain_total_blocks_left(int index)
{
    return blockchain.total - (index+1);
}
int giveme_blockchain_add_block(struct block *block)
{
    int res = giveme_blockchain_add_block_for_chain(&blockchain, block);
    if (res < 0)
        return res;
    giveme_log("%s Block added %s prev=%s, total blocks %i\n", __FUNCTION__, block->hash, block->data.prev_hash, blockchain.total);
    return res;
}

int giveme_mine(struct block *block)
{
    giveme_lock_chain(&blockchain_mine_lock);

    // Let's set the previous hash
    struct block *previous_block = giveme_blockchain_back();
    if (previous_block)
    {
        strncpy(block->data.prev_hash, previous_block->hash, sizeof(block->data.prev_hash));
    }

    do
    {
        block->data.nounce = rand() % 0xffffff;
        sha256_data(&block->data, block->hash, sizeof(block->data));
    } while (!giveme_mined(block));

    giveme_log("Mined a block %s previous block %s\n", block->hash, previous_block ? previous_block->hash : "NULL");
    // We mined a block? Then add it to the blockchain and tell everyone else about it
    int res = giveme_blockchain_add_block(block);
    if (res < 0)
    {
        giveme_log("Failed to add the block to the blockchain failed with %i\n", res);
    }

out:
    giveme_unlock_chain(&blockchain_mine_lock);
    return res;
}