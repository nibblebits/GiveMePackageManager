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
#include "network.h"
#include "misc.h"

// Holds the last 10000 blocks any further back we need to go we will need to
// load from the database
struct vector *memory_blockchain;
pthread_mutex_t blockchain_mine_lock;

void giveme_lock_chain()
{
    pthread_mutex_lock(&blockchain_mine_lock);
}

void giveme_unlock_chain()
{
    pthread_mutex_unlock(&blockchain_mine_lock);
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

void giveme_blockchain_reset_peek_pointer_nosafety()
{
    vector_set_peek_pointer(memory_blockchain, 0);
}

void giveme_blockchain_reset_peek_pointer_to_end_nosafety()
{
    vector_set_peek_pointer_end(memory_blockchain);
}

void giveme_blockchain_peek_pointer_set_nosafety(int index)
{
    vector_set_peek_pointer(memory_blockchain, index);
}

void giveme_blockchain_set_peek_backwards_nosafety()
{
    vector_set_flag(memory_blockchain, VECTOR_FLAG_PEEK_DECREMENT);
}

void giveme_blockchain_set_peek_forwards_nosafety()
{
    vector_unset_flag(memory_blockchain, memory_blockchain->flags & ~VECTOR_FLAG_PEEK_DECREMENT);
}


int giveme_blockchain_set_peek_pointer_to_block_nosafety(const char* hash)
{
    int res = GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND;
    giveme_blockchain_reset_peek_pointer_to_end_nosafety();
    giveme_blockchain_set_peek_backwards_nosafety();

    struct block* block = giveme_blockchain_peek_nosafety();
    int i = 0;
    bool found_block = false;
    while(block)
    {
        if (S_EQ(block->hash, hash))
        {
            res = 0;
            break;
        }
        i++;
        block = giveme_blockchain_peek_nosafety();
    }

    giveme_blockchain_set_peek_forwards_nosafety();
    giveme_blockchain_peek_pointer_set_nosafety(i);
    return res;
}


int giveme_blockchain_set_peek_pointer_to_block_with_previous_hash_nosafety(const char* hash)
{
    int res = GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND;
    giveme_blockchain_reset_peek_pointer_to_end_nosafety();
    giveme_blockchain_set_peek_backwards_nosafety();

    struct block* block = giveme_blockchain_peek_nosafety();
    int i = 0;
    bool found_block = false;
    while(block)
    {
        if (S_EQ(block->data.prev_hash, hash))
        {
            res = 0;
            break;
        }
        i++;
        block = giveme_blockchain_peek_nosafety();
    }

    giveme_blockchain_set_peek_forwards_nosafety();
    giveme_blockchain_peek_pointer_set_nosafety(i);
    return res;
}

struct block *giveme_blockchain_peek_nosafety()
{
    struct block *block = vector_peek(memory_blockchain);
    return block;
}

struct block *giveme_blockchain_back_nosafety()
{
    struct block *block = NULL;
    block = vector_back_or_null(memory_blockchain);
    return block;
}

struct block *giveme_blockchain_back()
{
    struct block *block = NULL;
    giveme_lock_chain(&blockchain_mine_lock);
    block = giveme_blockchain_back_nosafety(memory_blockchain);
    giveme_unlock_chain(&blockchain_mine_lock);
    return block;
}

bool giveme_blockchain_verify_nosafety()
{
    vector_set_peek_pointer(memory_blockchain, 0);
    struct block *block = giveme_blockchain_peek_nosafety();
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
        block = giveme_blockchain_peek_nosafety();
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

    vector_push(memory_blockchain, block);
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

    giveme_log("Mined a block %s\n", block->hash);
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