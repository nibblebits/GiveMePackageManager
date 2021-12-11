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
#include "log.h"
#include "misc.h"
#include "config.h"

struct key public_key = {};
struct key private_key = {};

struct key* giveme_public_key()
{
    return &public_key;
}

struct key* giveme_private_key()
{
    return &private_key;
}

// void Rsa::decrypt_public(const std::string &pub_key, const std::string &input, std::string &out)
// {
//     // Reset out to nothing
//     out = "";

//     RSA *pb_rsa = NULL;
//     RSA *p_rsa = NULL;
//     EVP_PKEY *evp_pbkey = NULL;
//     EVP_PKEY *evp_pkey = NULL;

//     BIO *pkeybio = NULL;
//     pkeybio = BIO_new_mem_buf((void *)pub_key.c_str(), pub_key.size());
//     if (pkeybio == NULL)
//     {
//         throw std::logic_error("decrypt_public(): Problem allocating buffer");
//     }

//     p_rsa = PEM_read_bio_RSAPublicKey(pkeybio, &p_rsa, NULL, NULL);
//     if (p_rsa == NULL)
//     {
//         char buffer[120];
//         ERR_error_string(ERR_get_error(), buffer);
//         throw std::logic_error("decrypt_public(): " + std::string(buffer, sizeof(buffer)));
//     }

//     std::unique_ptr<char[]> decrypted = std::make_unique<char[]>(RSA_size(p_rsa));
//     memset(decrypted.get(), 0, RSA_size(p_rsa));

//     int decrypt_len;
//     if ((decrypt_len = RSA_public_decrypt(input.size(), (unsigned char *)input.c_str(),
//                                           (unsigned char *)decrypted.get(), p_rsa, RSA_PKCS1_PADDING)) == -1)
//     {
//         throw std::logic_error("decrypt_public(): problem encrypting with private key");
//     }

//     out = std::string(decrypted.get(), decrypt_len);
//     BIO_free(pkeybio);
// }

const char* decrypt_public(struct key* key, const char* input, size_t input_len, size_t* out_size)
{

    RSA *pb_rsa = NULL;
    RSA *p_rsa = NULL;
    EVP_PKEY *evp_pbkey = NULL;
    EVP_PKEY *evp_pkey = NULL;

    BIO *pkeybio = NULL;
    pkeybio = BIO_new_mem_buf((void *)key->key, key->size);
    if (pkeybio == NULL)
    {
        giveme_log("encrypt_public(): Problem allocating buffer");
    }

    p_rsa = PEM_read_bio_RSAPublicKey(pkeybio, &p_rsa, NULL, NULL);
    if (p_rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        return NULL;
    }

    size_t size = RSA_size(p_rsa);
    *out_size = size;

    char* encrypt = calloc(1, size);

    int encrypt_len;
    if ((encrypt_len = RSA_public_decrypt(input_len, (unsigned char *)input,
                                           (unsigned char *)encrypt, p_rsa, RSA_PKCS1_PADDING)) == -1)
    {
        giveme_log("decrypt_public(): problem encrypting with public key");
    }

    BIO_free(pkeybio);
    return encrypt;
}


const char* encrypt_private(const char* input, size_t input_len, size_t* size_out)
{

    RSA *pb_rsa = NULL;
    RSA *p_rsa = NULL;
    EVP_PKEY *evp_pbkey = NULL;
    EVP_PKEY *evp_pkey = NULL;

    BIO *pkeybio = NULL;
    pkeybio = BIO_new_mem_buf((void *)private_key.key, private_key.size);
    if (pkeybio == NULL)
    {
        giveme_log("encrypt_private(): Problem allocating buffer");
    }

    p_rsa = PEM_read_bio_RSAPrivateKey(pkeybio, &p_rsa, NULL, NULL);
    if (p_rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        return NULL;
    }

    size_t size = RSA_size(p_rsa);
    *size_out = size;

    char* encrypt = calloc(1, size);

    int encrypt_len;
    if ((encrypt_len = RSA_private_encrypt(input_len, (unsigned char *)input,
                                           (unsigned char *)encrypt, p_rsa, RSA_PKCS1_PADDING)) == -1)
    {
        giveme_log("encrypt_private(): problem encrypting with private key");
    }

    BIO_free(pkeybio);
    return encrypt;
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

    RSA *keypair = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;

    unsigned long e = RSA_F4;

    BIGNUM *bne = BN_new();
    int ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        return -1;
    }

    keypair = RSA_new();

    ret = RSA_generate_key_ex(keypair, 2048, bne, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char pri_key[pri_len + 1];
    char pub_key[pub_len + 1];
    bzero(pri_key, sizeof(pri_key));
    bzero(pub_key, sizeof(pub_key));

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    giveme_log("Generated RSA keypair for first time use\n");
    int res = 0;
    res = giveme_write_private_key(pri_key, pri_len);
    if (res < 0)
    {
        giveme_log("Failed to write private key to disk\n");
    }

    res = giveme_write_public_key(pub_key, pub_len);
    if (res < 0)
    {
        giveme_log("Failed to write public key to disk\n");
    }

    giveme_log("Public key: %s\n Private key:%s\n", pub_key, pri_key);
    giveme_log("Private key at: %s\n", giveme_private_key_filepath());
}

void giveme_load_public_key()
{
    FILE *fp = fopen(giveme_public_key_filepath(), "r");
    if (!fp)
    {
        giveme_log("Failed to open public key file\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);

    public_key.key = calloc(1, size + 1);
    if (fread(public_key.key, size, 1, fp) != 1)
    {
        giveme_log("Failed to read public key file\n");
    }
    public_key.size = size;
}

void giveme_load_private_key()
{
    FILE *fp = fopen(giveme_private_key_filepath(), "r");
    if (!fp)
    {
        giveme_log("Failed to open private key file\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);

    private_key.key = calloc(1, size + 1);
    if (fread(private_key.key, size, 1, fp) != 1)
    {
        giveme_log("Failed to read private key file\n");
    }

    private_key.size = size;
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