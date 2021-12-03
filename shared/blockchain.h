#ifndef GIVEME_BLOCKCHAIN_H
#define GIVEME_BLOCKCHAIN_H
#include "sha256.h"
#include "config.h"

#define GIVEME_BLOCKCHAIN_BLOCK_VALID 0
#define GIVEME_BLOCKCHAIN_NOT_MINED -1
#define GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH -2
#define GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL -3
#define GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND -4

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
struct block *giveme_blockchain_back_nosafety();

void giveme_lock_chain();
void giveme_unlock_chain();
void giveme_blockchain_reset_peek_pointer_nosafety();
struct block *giveme_blockchain_peek_nosafety();
int giveme_block_verify_nosafety(struct block* block);
int giveme_blockchain_add_block_nosafety(struct block* block);
int giveme_blockchain_set_peek_pointer_to_block_nosafety(const char* hash);
void giveme_blockchain_initialize();
void giveme_blockchain_load();
int giveme_mine(struct block* block);

#endif