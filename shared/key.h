#ifndef GIVEME_KEY_H
#define GIVME_KEY_H
#include <stddef.h>
struct key
{
    char* key;
    size_t size;
};

void giveme_load_keypair();
struct key* giveme_public_key();
struct key* giveme_private_key();

#endif