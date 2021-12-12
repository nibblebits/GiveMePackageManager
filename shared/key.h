#ifndef GIVEME_KEY_H
#define GIVEME_KEY_H
#include <stddef.h>
#include <stdbool.h>
#include "config.h"
struct key
{
    char key[GIVEME_MAX_KEY_LENGTH];
    size_t size;
};

void giveme_load_keypair();
struct key* giveme_public_key();
struct key* giveme_private_key();
bool key_cmp(struct key* key, struct key* key2);

#endif