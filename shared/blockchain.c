#include "blockchain.h"
#include "sha256.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include "vector.h"
#include "misc.h"

// Holds the last 10000 blocks any further back we need to go we will need to
// load from the database
struct vector *memory_blockchain;
pthread_mutex_t blockchain_mine_lock;

bool giveme_mined(struct block *block)
{
    for (int i = 0; i < GIVEME_TOTAL_ZEROS_FOR_MINED_BLOCK; i++)
    {
        if (block->hash[i] != '0')
            return false;
    }
    return true;
}

void giveme_blockchain_reset_peek_pointer()
{
    vector_set_peek_pointer(memory_blockchain, 0);
}
struct block *giveme_blockchain_peek()
{
    struct block *block = vector_peek(memory_blockchain);
    return block;
}

struct block *giveme_blockchain_back()
{
    return vector_back_or_null(memory_blockchain);
}

bool giveme_blockchain_verify()
{
    vector_set_peek_pointer(memory_blockchain, 0);
    struct block *block = giveme_blockchain_peek();
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
        block = giveme_blockchain_peek();
    }

    return true;
}

void giveme_blockchain_load()
{
    // Load the blockchain into memory.. TODO
}
void giveme_blockchain_initialize()
{
    memory_blockchain = vector_create(sizeof(struct block));
    if (pthread_mutex_init(&blockchain_mine_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize blockchain mine lock mutex\n");
    }
}

int giveme_block_verify(struct block *block)
{
    if (!giveme_mined(block))
    {
        return GIVEME_BLOCKCHAIN_NOT_MINED;
    }

    struct block *last_block = giveme_blockchain_back();
    if (last_block && !S_EQ(last_block->hash, block->data.prev_hash))
    {
        return GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH;
    }

    return GIVEME_BLOCKCHAIN_BLOCK_VALID;
}

int giveme_blockchain_add_block(struct block *block)
{
    int res = giveme_block_verify(block);
    if (res < 0)
        return res;

    vector_push(memory_blockchain, block);
    return res;
}

int giveme_mine(struct block *block)
{
    pthread_mutex_lock(&blockchain_mine_lock);

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

    giveme_log("Mined a block %s\n", block->hash);
    // We mined a block? Then add it to the blockchain and tell everyone else about it
    int res = giveme_blockchain_add_block(block);
    if (res < 0)
    {
        giveme_log("Failed to add the block to the blockchain failed with %i\n", res);
    }

out:
    pthread_mutex_unlock(&blockchain_mine_lock);
    return res;
}