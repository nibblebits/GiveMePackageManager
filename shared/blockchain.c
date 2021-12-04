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

off_t giveme_blockchain_index_for_block(const char *hash)
{
    for (int i = blockchain.total - 1; i >= 0; i--)
    {
        if (S_EQ(blockchain.block[i].hash, hash))
        {
            return i;
        }
    }

    return -1;
}

int giveme_blockchain_begin_crawl(const char *start_hash, const char *end_hash)
{
    int res = 0;
    blockchain.crawl.crawling = true;
    blockchain.crawl.start = start_hash;
    blockchain.crawl.end = end_hash;
    blockchain.crawl.pos = 0;
    if (start_hash)
    {
        blockchain.crawl.pos = giveme_blockchain_index_for_block(start_hash);
        res = blockchain.crawl.pos;
    }

out:
    return res;
}

struct block *giveme_blockchain_crawl_next(int flags)
{
    if (!blockchain.crawl.crawling)
    {
        return NULL;
    }

    if (blockchain.crawl.pos >= blockchain.total || blockchain.crawl.pos <= 0)
    {
        return NULL;
    }

    struct block *block = &blockchain.block[blockchain.crawl.pos];
    if (blockchain.crawl.end && S_EQ(block->hash, blockchain.crawl.end))
    {
        // We have finished crawling
        blockchain.crawl.crawling = false;
        return block;
    }

    if (flags & BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN)
    {
        blockchain.crawl.pos -= 1;
    }
    else
    {
        blockchain.crawl.pos += 1;
    }

    return block;
}
bool giveme_block_has_hash_nosafety(struct block *block, const char *hash)
{
    char hash_comptued[SHA256_STRING_LENGTH];
    sha256_data(&block->data, hash_comptued, sizeof(block->data));
    return S_EQ(hash, hash_comptued);
}

bool giveme_mined_nosafety(struct block *block)
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
        hash_correct = giveme_block_has_hash_nosafety(block, block->hash);
    }

    return hash_correct;
}

struct block *giveme_blockchain_back_nosafety()
{
    struct block *block = NULL;
    block = &blockchain.block[blockchain.total - 1];
    return block;
}

struct block *giveme_blockchain_back()
{
    struct block *block = NULL;
    giveme_lock_chain(&blockchain_mine_lock);
    block = giveme_blockchain_back_nosafety();
    giveme_unlock_chain(&blockchain_mine_lock);
    return block;
}

bool giveme_blockchain_verify_nosafety()
{
    giveme_blockchain_begin_crawl(NULL, NULL);
    struct block *block = giveme_blockchain_crawl_next(0);
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
        block = giveme_blockchain_crawl_next(0);
    }

    return true;
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
size_t giveme_blockchain_block_count()
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

    blockchain.total = giveme_blockchain_block_count();

    if (pthread_mutex_init(&blockchain_mine_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize blockchain mine lock mutex\n");
    }
}

int giveme_block_verify_nosafety(struct block *block)
{
    struct block *last_block = giveme_blockchain_back_nosafety();
    if (last_block && S_EQ(last_block->hash, block->hash))
    {
        // We already have this on the tail of the blockchain
        // most likely multiple nodes resent this block and it reached us twice.
        return GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL;
    }

    if (!giveme_mined_nosafety(block))
    {
        return GIVEME_BLOCKCHAIN_NOT_MINED;
    }

    if (last_block && !S_EQ(last_block->hash, block->data.prev_hash))
    {
        return GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH;
    }

    return GIVEME_BLOCKCHAIN_BLOCK_VALID;
}

int giveme_blockchain_add_block_nosafety(struct block *block)
{
    int res = giveme_block_verify_nosafety(block);
    if (res < 0)
        return res;

    blockchain.block[blockchain.total] = *block;
    blockchain.total++;
    giveme_log("%s Block added %s prev=%s, total blocks %i\n", __FUNCTION__, block->hash, block->data.prev_hash, blockchain.total);
    return res;
}

int giveme_mine(struct block *block)
{
    giveme_lock_chain(&blockchain_mine_lock);

    // Let's set the previous hash
    struct block *previous_block = giveme_blockchain_back_nosafety();
    if (previous_block)
    {
        strncpy(block->data.prev_hash, previous_block->hash, sizeof(block->data.prev_hash));
    }

    do
    {
        block->data.nounce = rand() % 0xffffff;
        sha256_data(&block->data, block->hash, sizeof(block->data));
    } while (!giveme_mined_nosafety(block));

    giveme_log("Mined a block %s previous block %s\n", block->hash, previous_block ? previous_block->hash : "NULL");
    // We mined a block? Then add it to the blockchain and tell everyone else about it
    int res = giveme_blockchain_add_block_nosafety(block);
    if (res < 0)
    {
        giveme_log("Failed to add the block to the blockchain failed with %i\n", res);
    }

out:
    giveme_unlock_chain(&blockchain_mine_lock);
    return res;
}