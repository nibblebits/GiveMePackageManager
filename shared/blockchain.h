#ifndef GIVEME_BLOCKCHAIN_H
#define GIVEME_BLOCKCHAIN_H
#include "sha256.h"
#include "config.h"

#define GIVEME_BLOCKCHAIN_BLOCK_VALID 0
#define GIVEME_BLOCKCHAIN_NOT_MINED -1
#define GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH -2

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


int giveme_block_verify(struct block* block);
int giveme_blockchain_add_block(struct block* block);
void giveme_blockchain_initialize();
void giveme_blockchain_load();

int giveme_mine(struct block* block);

#endif