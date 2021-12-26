#ifndef GIVEME_KEY_H
#define GIVEME_KEY_H
#include <stddef.h>
#include <stdbool.h>
#include "config.h"
#include "sha256.h"

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


struct key_signature_hash
{
    // The hash of the data
    char data_hash[SHA256_STRING_LENGTH];

    // The signature proving the provided key signed the given data hash
    struct signature signature;

    // the public key of the person creating the package. The data was signed
    // with this key
    struct key key;
};


int private_sign(const char *data, size_t size, struct signature *sig_out);
int public_verify(struct key *public_key, const char *data, size_t size, struct signature *sig_in);
int public_verify_key_sig_hash(struct key_signature_hash* key_sig_hash, const char* hash_to_compare);
int private_sign_key_sig_hash(struct key_signature_hash* key_sig_hash, void* data, size_t size);
struct key* key_from_key_sig_hash(struct key_signature_hash* key_sig_hash);

void giveme_load_keypair();
struct key *giveme_public_key();
struct key *giveme_private_key();
bool key_cmp(struct key *key, struct key *key2);
bool key_loaded(struct key *key);

#endif