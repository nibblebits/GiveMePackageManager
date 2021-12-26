#include "key.h"

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <stdbool.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include "log.h"
#include "misc.h"
#include "config.h"
#include "sha256.h"
#include "string.h"

struct key public_key = {};
struct key private_key = {};

struct key *giveme_public_key()
{
    return &public_key;
}

struct key *giveme_private_key()
{
    return &private_key;
}

bool key_loaded(struct key* key)
{
    struct key blank_key;
    bzero(&blank_key, sizeof(blank_key));
    return memcmp(key, &blank_key, sizeof(struct key)) != 0;
}

bool key_cmp(struct key *key, struct key *key2)
{
    return strncmp(key->key, key2->key, sizeof(key->key)) == 0;
}

int public_verify(struct key* public_key, const char *data, size_t size, struct signature *sig_in)
{
    int res = 0;
    ECDSA_SIG *sig = NULL;
    BIGNUM *pr_sig = NULL;
    BIGNUM *ps_sig = NULL;
    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    EC_POINT *point = EC_POINT_new(ecgroup);

    if (EC_POINT_hex2point(ecgroup, public_key->key, point, ctx) == NULL)
    {
        giveme_log("%s failed to set point for public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_KEY_set_public_key(eckey, point) <= 0)
    {
        giveme_log("%s failed to set public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    sig = ECDSA_SIG_new();
    if (BN_hex2bn(&pr_sig, sig_in->pr_sig) <= 0)
    {
        giveme_log("%s failed to convert hex string back BIGINTEGER\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (BN_hex2bn(&ps_sig,sig_in->ps_sig) <= 0)
    {
        giveme_log("%s failed to convert hex string back BIGINTEGER\n", __FUNCTION__);
        res = -1;
        goto out;
    }
    if (ECDSA_SIG_set0(sig, pr_sig, ps_sig) <= 0)
    {
        giveme_log("%s failed to restore signature into BIGNUM\n", __FUNCTION__);
        res = -1;
        goto out;
    }


    if (ECDSA_do_verify(data, size, sig, eckey) <= 0)
    {
        giveme_log("%s bad verification with public key err=%s\n", __FUNCTION__, ERR_reason_error_string(ERR_get_error()));
        res = -1;
        goto out;
    }

out:
    if (sig)
    {
        ECDSA_SIG_free(sig);
    }
    if (ctx)
    {
        BN_CTX_free(ctx);
    }

    if (point)
    {
        EC_POINT_free(point);
    }


    return res;
}

int public_verify_key_sig_hash(struct key_signature_hash* key_sig_hash, const char* hash_to_compare)
{
    int res = public_verify(&key_sig_hash->key, key_sig_hash->data_hash, sizeof(key_sig_hash->data_hash), &key_sig_hash->signature);
    if (res < 0)
    {
        return res;
    }

    // Now we have confirmed that the hash was signed correctly, we need to now ensure that
    // the hash the key signed is the same as the one we computed.
    return memcmp(hash_to_compare, &key_sig_hash->data_hash, SHA256_STRING_LENGTH) == 0;
}

struct key* key_from_key_sig_hash(struct key_signature_hash* key_sig_hash)
{
    return &key_sig_hash->key;
}

int private_sign_key_sig_hash(struct key_signature_hash* key_sig_hash, void* hash)
{
    bzero(key_sig_hash, sizeof(struct key_signature_hash));
    sha256_data(hash, key_sig_hash->data_hash, SHA256_STRING_LENGTH);
    int res = private_sign(key_sig_hash->data_hash, SHA256_STRING_LENGTH, &key_sig_hash->signature);
    if (res < 0)
    {
        return res;
    }

    key_sig_hash->key = *giveme_public_key();
    return res;
}

int private_sign(const char *data, size_t size, struct signature *sig_out)
{
    int res = 0;
    ECDSA_SIG *sig = NULL;
    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    EC_POINT *point = EC_POINT_new(ecgroup);
    BIGNUM *pnum = NULL;
    if (BN_hex2bn(&pnum, giveme_private_key()->key) <= 0)
    {
        giveme_log("%s failed to create big number from private key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_POINT_hex2point(ecgroup, giveme_public_key()->key, point, ctx) == NULL)
    {
        giveme_log("%s failed to set point for public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_KEY_set_public_key(eckey, point) <= 0)
    {
        giveme_log("%s failed to set public key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (EC_KEY_set_private_key(eckey, pnum) <= 0)
    {
        giveme_log("%s failed to set private key\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    sig = ECDSA_do_sign(data, size, eckey);
    if (!sig)
    {
        giveme_log("%s failed to sign data with key\n", __FUNCTION__);
        res = -1;
        goto out;
    }


    const BIGNUM *sig_pr = NULL;
    const BIGNUM *sig_ps = NULL;
    ECDSA_SIG_get0(sig, &sig_pr, &sig_ps);

    char *pr_sig = BN_bn2hex(sig_pr);
    char *ps_sig = BN_bn2hex(sig_ps);

    bzero(sig_out, sizeof(struct signature));
    strncpy(sig_out->pr_sig, pr_sig, sizeof(sig_out->pr_sig));
    strncpy(sig_out->ps_sig, ps_sig, sizeof(sig_out->ps_sig));

    OPENSSL_free(pr_sig);
    OPENSSL_free(ps_sig);

out:
    if (sig)
    {
        ECDSA_SIG_free(sig);
    }
    if (ctx)
    {
        BN_CTX_free(ctx);
    }

    if (point)
    {
        EC_POINT_free(point);
    }

    return res;
}

const char *giveme_private_key_filepath()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_DATA_BASE, GIVEME_PRIVATE_KEY_FILEPATH);
    return filepath;
}

const char *giveme_public_key_filepath()
{
    static char filepath[PATH_MAX];
    sprintf(filepath, "%s/%s%s", getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_DATA_BASE, GIVEME_PUBLIC_KEY_FILEPATH);
    return filepath;
}

int giveme_write_private_key(const char *key, size_t size)
{
    int res = 0;
    FILE *f = fopen(giveme_private_key_filepath(), "w");
    if (!f)
    {
        return -1;
    }

    res = fwrite(key, size, 1, f);
    if (res != 1)
    {
        res = -1;
    }

    fclose(f);
    return res;
}

int giveme_write_public_key(const char *key, size_t size)
{
    int res = 0;
    FILE *f = fopen(giveme_public_key_filepath(), "w");
    if (!f)
    {
        return -1;
    }

    res = fwrite(key, size, 1, f);
    if (res != 1)
    {
        res = -1;
    }

    fclose(f);
    return res;
}

int generate_key()
{
    int ret;
    ECDSA_SIG *sig;
    EC_KEY *eckey = EC_KEY_new();
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey, ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    BN_CTX *ctx;
    ctx = BN_CTX_new();

    if (eckey == NULL)
    {
        giveme_log("%S problem creating curve\n", __FUNCTION__);
    }
    /* error */
    if (EC_KEY_generate_key(eckey) == 0)
    {
        giveme_log("%s problem generating key\n", __FUNCTION__);
    }

    //     if(1 != EC_KEY_set_private_key(key, prv)) handleErrors();
    // if(1 != EC_KEY_set_public_key(key, pub)) handleErrors();

    const BIGNUM *private_key = EC_KEY_get0_private_key(eckey);
    char *priv_key_hex = BN_bn2hex(private_key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(eckey);
    char *pub_key_hex = EC_POINT_point2hex(ecgroup, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx);
    giveme_log("%s public_key=%s\n", __FUNCTION__, pub_key_hex);
    giveme_log("%s private_key=%s\n", __FUNCTION__, priv_key_hex);

    giveme_write_public_key(pub_key_hex, strlen(pub_key_hex));
    giveme_write_private_key(priv_key_hex, strlen(priv_key_hex));
    OPENSSL_free(priv_key_hex);
    OPENSSL_free(pub_key_hex);
    EC_KEY_free(eckey);
    return 0;
}
void giveme_load_public_key()
{
    memset(&public_key, 0, sizeof(public_key));
    FILE *fp = fopen(giveme_public_key_filepath(), "r");
    if (!fp)
    {
        giveme_log("Failed to open public key file\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);

    assert(size <= sizeof(public_key.key));
    if (fread(public_key.key, size, 1, fp) != 1)
    {
        giveme_log("Failed to read public key file\n");
    }
    // -1 because of null terminator
    public_key.size = size - 1;
}

void giveme_load_private_key()
{
    memset(&private_key, 0, sizeof(private_key));

    FILE *fp = fopen(giveme_private_key_filepath(), "r");
    if (!fp)
    {
        giveme_log("Failed to open private key file\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);

    assert(size <= sizeof(private_key.key));

    if (fread(private_key.key, size, 1, fp) != 1)
    {
        giveme_log("Failed to read private key file\n");
    }

    // -1 because of null terminator
    private_key.size = size - 1;
}

void giveme_load_keypair()
{
    if (!file_exists(giveme_private_key_filepath()))
    {
        generate_key();
    }

    giveme_load_public_key();
    giveme_load_private_key();
}