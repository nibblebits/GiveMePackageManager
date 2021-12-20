#ifndef GIVEME_KEY_H
#define GIVEME_KEY_H
#include <stddef.h>
#include <stdbool.h>
#include "config.h"

struct signature
{
    char pr_sig[GIVEME_MAX_SIGNATURE_PART_LENGTH];
    char ps_sig[GIVEME_MAX_SIGNATURE_PART_LENGTH];
};

struct key
{
    char key[GIVEME_MAX_KEY_LENGTH];
    size_t size;
};

int private_sign(const char *data, size_t size, struct signature* sig_out);
int public_verify(const char *data, size_t size, struct signature *sig_in);

void giveme_load_keypair();
struct key* giveme_public_key();
struct key* giveme_private_key();
bool key_cmp(struct key* key, struct key* key2);

#endif