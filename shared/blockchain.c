#include "blockchain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <linux/limits.h>
#include <assert.h>
#include "vector.h"
#include "network.h"
#include "package.h"
#include "misc.h"
#include "sha256.h"
#include "log.h"

// Holds the last 10000 blocks any further back we need to go we will need to
// load from the database
//struct vector *memory_blockchain;

// Memory mapped pointer to the blockchain
struct blockchain blockchain;
pthread_mutex_t blockchain_lock;

void giveme_lock_chain()
{
    pthread_mutex_lock(&blockchain_lock);
}

void giveme_unlock_chain()
{
    pthread_mutex_unlock(&blockchain_lock);
}

double giveme_blockchain_balance_change_for_block(struct key *key, struct block *block)
{
    double balance_change = 0;
    struct key blank_key = {};
    // Got a blank key.. What we going to do with that..
    if (memcmp(key, &blank_key, sizeof(key)) == 0)
    {
        return 0;
    }

    if (memcmp(&block->signature.key, key, sizeof(block->signature.key)) == 0)
    {
        // The validator key matches? Let's apply a balance change.
        // they validated this block so got rewarded for it.
        balance_change += GIVEME_VALIDATION_MINING_REWARD;
    }

    return balance_change;
}

struct blockchain_individual *giveme_blockchain_me()
{
    return &blockchain.me;
}

struct key *giveme_blockchain_get_verifier_key()
{
    size_t total_verifiers = vector_count(blockchain.public_keys);
    if (total_verifiers <= 0)
        return NULL;

    size_t total_five_minute_chunks_since_1971 = time(NULL) / GIVEME_SECONDS_TO_MAKE_BLOCK;

    // The current five minute block since 1970s
    int next_verifier_index = (total_five_minute_chunks_since_1971 % total_verifiers);
    return vector_at(blockchain.public_keys, next_verifier_index);
}

int giveme_blockchain_get_individual(struct key *key, struct blockchain_individual *individual_out)
{
    memset(individual_out, 0, sizeof(struct blockchain_individual));
    giveme_blockchain_begin_crawl(NULL, NULL);
    struct block *block = giveme_blockchain_crawl_next(0);
    struct block *prev_block = NULL;
    while (block)
    {
        for (int i = 0; i < block->data.transactions.total; i++)
        {
            struct block_transaction *transaction;
            transaction = &block->data.transactions.transactions[i];
            if (transaction->data.type == BLOCK_TRANSACTION_TYPE_NEW_KEY)
            {
                struct block_transaction_new_key *published_key;
                published_key = &transaction->data.publish_public_key;

                // We found a public key packet does it match our key
                if (key_cmp(&published_key->pub_key, key))
                {
                    // Yep it matches this was when this key was first ever published
                    memcpy(&individual_out->key_data.key, &published_key->pub_key, sizeof(struct key));
                    strncpy(individual_out->key_data.name, published_key->name, sizeof(individual_out->key_data.name));
                    individual_out->flags |= GIVEME_BLOCKCHAIN_INDIVIDUAL_FLAG_HAS_KEY_ON_CHAIN;
                }
            }
            else if (key_cmp(&block->signature.key, key))
            {
                // This key verified this block lets increment
                individual_out->key_data.verified_blocks.total++;
            }

            individual_out->key_data.balance += giveme_blockchain_balance_change_for_block(key, block);
        }
        block = giveme_blockchain_crawl_next(0);
    }

    return (individual_out->flags & GIVEME_BLOCKCHAIN_INDIVIDUAL_FLAG_HAS_KEY_ON_CHAIN) ? 0 : -1;
}

struct block *giveme_blockchain_get_block_with_index(int index)
{
    if (blockchain.total <= index)
        return NULL;

    return &blockchain.block[index];
}

const char *giveme_blockchain_block_hash(struct block *block)
{
    return block->signature.data_hash;
}
off_t giveme_blockchain_index_for_block_for_chain(struct blockchain *chain, const char *hash)
{
    struct block blank_block = {};
    // First block requested? then return 0
    if (hash == NULL || (memcmp(&blank_block, hash, sizeof(blank_block)) == 0))
    {
        return 0;
    }

    for (int i = chain->total - 1; i >= 0; i--)
    {
        if (S_EQ(giveme_blockchain_block_hash(&chain->block[i]), hash))
        {
            return i;
        }
    }

    return -1;
}

off_t giveme_blockchain_index_for_block(const char *hash)
{
    return giveme_blockchain_index_for_block_for_chain(&blockchain, hash);
}

struct blockchain *giveme_blockchain_master()
{
    return &blockchain;
}

struct block *giveme_blockchain_block(const char *hash, size_t *blocks_left_to_end)
{
    off_t index = giveme_blockchain_index_for_block(hash);
    if (index < 0)
        return NULL;

    if (blocks_left_to_end)
    {
        *blocks_left_to_end = giveme_blockchain_total_blocks_left(index);
    }
    return &blockchain.block[index];
}

int giveme_blockchain_begin_crawl_for_chain(struct blockchain *chain, const char *start_hash, const char *end_hash)
{
    int res = 0;
    chain->crawl.crawling = true;
    chain->crawl.start = start_hash;
    chain->crawl.end = end_hash;
    chain->crawl.pos = 0;
    if (start_hash)
    {
        chain->crawl.pos = giveme_blockchain_index_for_block_for_chain(chain, start_hash);
        res = chain->crawl.pos;
    }

out:
    return res;
}

int giveme_blockchain_begin_crawl(const char *start_hash, const char *end_hash)
{
    return giveme_blockchain_begin_crawl_for_chain(&blockchain, start_hash, end_hash);
}

struct block *giveme_blockchain_crawl_next_for_chain(struct blockchain *chain, int flags)
{
    if (!chain->crawl.crawling)
    {
        return NULL;
    }

    if (chain->crawl.pos >= chain->total || chain->crawl.pos < 0)
    {
        return NULL;
    }

    struct block *block = &chain->block[blockchain.crawl.pos];
    if (chain->crawl.end && S_EQ(giveme_blockchain_block_hash(block), chain->crawl.end))
    {
        // We have finished crawling
        chain->crawl.crawling = false;
        return block;
    }

    if (flags & BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN)
    {
        chain->crawl.pos -= 1;
    }
    else
    {
        chain->crawl.pos += 1;
    }

    return block;
}

struct block *giveme_blockchain_crawl_next(int flags)
{
    return giveme_blockchain_crawl_next_for_chain(&blockchain, flags);
}

bool giveme_block_confirm_hash(struct block *block, const char *hash)
{
    char hash_comptued[SHA256_STRING_LENGTH];
    sha256_data(&block->data, hash_comptued, sizeof(block->data));
    return S_EQ(hash, hash_comptued);
}

bool giveme_mined(struct block *block)
{
    bool hash_correct = true;
    const char *hash = giveme_blockchain_block_hash(block);
    for (int i = 0; i < GIVEME_TOTAL_ZEROS_FOR_MINED_BLOCK; i++)
    {
        if (hash[i] != '0')
        {
            hash_correct = false;
            break;
        }
    }

    if (hash_correct)
    {
        hash_correct = giveme_block_confirm_hash(block, giveme_blockchain_block_hash(block));
    }

    return hash_correct;
}

struct block *giveme_blockchain_back_for_chain(struct blockchain *chain)
{
    if (chain->total <= 0)
        return NULL;
    struct block *block = NULL;
    block = &chain->block[blockchain.total - 1];
    return block;
}
struct block *giveme_blockchain_back()
{
    return giveme_blockchain_back_for_chain(&blockchain);
}

struct block *giveme_blockchain_back_safe()
{
    struct block *block = NULL;
    giveme_lock_chain(&blockchain_lock);
    block = giveme_blockchain_back();
    giveme_unlock_chain(&blockchain_lock);
    return block;
}

bool giveme_blockchain_verify_for_chain(struct blockchain *chain)
{
    giveme_blockchain_begin_crawl_for_chain(chain, NULL, NULL);
    struct block *block = giveme_blockchain_crawl_next_for_chain(chain, 0);
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
        if (!S_EQ(block->data.prev_hash, giveme_blockchain_block_hash(prev_block)))
        {
            return false;
        }
        prev_block = block;
        block = giveme_blockchain_crawl_next_for_chain(chain, 0);
    }

    return true;
}

bool giveme_blockchain_verify()
{
    return giveme_blockchain_verify_for_chain(&blockchain);
}

char *giveme_blockchain_path()
{
    static char blockchain_file_path[PATH_MAX];
    sprintf(blockchain_file_path, "%s/%s/%s", getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_DATA_BASE, GIVEME_BLOCKCHAIN_FILEPATH);
    return blockchain_file_path;
}

bool giveme_blockchain_exists()
{
    bool blockchain_exists = false;
    FILE *fp = fopen(giveme_blockchain_path(), "r");
    if (fp)
    {
        blockchain_exists = true;
        fclose(fp);
    }
    return blockchain_exists;
}

size_t giveme_blockchain_total_bytes_for_blocks(size_t total_blocks)
{
    return total_blocks * sizeof(struct block);
}
size_t giveme_blockchain_total_bytes()
{
    size_t size = 0;
    FILE *fp = fopen(giveme_blockchain_path(), "r");
    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fclose(fp);
    }
    return size;
}
size_t giveme_blockchain_compute_block_count()
{
    size_t total_blocks = 0;
    for (int i = 0; i < blockchain.max_blocks; i++)
    {
        struct block blank_block = {};
        if (memcmp(&blockchain.block[i], &blank_block, sizeof(blank_block)) == 0)
        {
            break;
        }
        total_blocks++;
    }

    return total_blocks;
}

size_t giveme_blockchain_block_count_for_chain(struct blockchain *chain)
{
    return chain->total;
}

size_t giveme_blockchain_block_count()
{
    return giveme_blockchain_block_count_for_chain(&blockchain);
}

struct blockchain *giveme_blockchain_create(size_t total_blocks)
{
    struct blockchain *chain = calloc(1, sizeof(struct blockchain));
    chain->block = calloc(total_blocks, sizeof(struct block));
    chain->total = 0;
    chain->max_blocks = total_blocks;
    return chain;
}

void giveme_blockchain_free(struct blockchain *chain)
{
    free(chain->block);
    free(chain);
}

bool giveme_blockchain_are_we_known()
{
    return blockchain.me.flags & GIVEME_BLOCKCHAIN_INDIVIDUAL_FLAG_HAS_KEY_ON_CHAIN;
}

void giveme_blockchain_handle_added_block_transaction_new_key(struct block *block, struct block_transaction *transaction)
{
    struct key *key = giveme_public_key();

    vector_push(blockchain.public_keys, &transaction->data.publish_public_key);
    struct block_transaction_new_key *published_key;
    published_key = &transaction->data.publish_public_key;

    // We found a public key transaction does it match our key
    if (key_cmp(&published_key->pub_key, key))
    {
        // Yep it matches this was when this key was first ever published
        memcpy(&blockchain.me.key_data.key, &published_key->pub_key, sizeof(struct key));
        strncpy(blockchain.me.key_data.name, published_key->name, sizeof(blockchain.me.key_data.name));
        blockchain.me.flags |= GIVEME_BLOCKCHAIN_INDIVIDUAL_FLAG_HAS_KEY_ON_CHAIN;
    }
}

void giveme_blockchain_handle_added_block_transaction_new_package(struct block *block, struct block_transaction *transaction)
{
    int res = 0;
    struct key *key = giveme_public_key();
    struct block_transaction_new_package* publish_package_transaction = &transaction->data.publish_package;
    struct block_transaction_new_package_data* package_data = &publish_package_transaction->data;

    const char* filepath = NULL;
    if (giveme_package_downloaded(package_data->filehash))
    {
        filepath = giveme_package_path(package_data->filehash);
    }
    res = giveme_packages_push(block, package_data->name, transaction->hash, package_data->filehash, filepath, publish_package_transaction->ip_address);
    if (res < 0)
    {
        giveme_log("%s problem pushing package to cache\n", __FUNCTION__);
    }
}

void giveme_blockchain_handle_added_block(struct block *block)
{
    giveme_log("%s handling block with %i transactions.\n", __FUNCTION__, block->data.transactions.total);

    // Get our public key.
    struct key *key = giveme_public_key();
    struct block_transaction *transaction;
    for (int i = 0; i < block->data.transactions.total; i++)
    {
        transaction = &block->data.transactions.transactions[i];
        switch (transaction->data.type)
        {
        case BLOCK_TRANSACTION_TYPE_NEW_KEY:
            giveme_blockchain_handle_added_block_transaction_new_key(block, transaction);
            break;

        case BLOCK_TRANSACTION_TYPE_NEW_PACKAGE:
            giveme_blockchain_handle_added_block_transaction_new_package(block, transaction);
            break;
        }
        if (key_cmp(&block->signature.key, key))
        {
            // This key verified this block lets increment
            blockchain.me.key_data.verified_blocks.total++;
        }
    }

    blockchain.me.key_data.balance += giveme_blockchain_balance_change_for_block(key, block);
}

int giveme_blockchain_cache_reload()
{
    int res = 0;
    res = giveme_packages_cache_clear();
    if (res < 0)
    {
        goto out;
    }

    giveme_blockchain_begin_crawl(NULL, NULL);
    struct block *block = giveme_blockchain_crawl_next(0);
    struct block *prev_block = NULL;
    while (block)
    {
        giveme_blockchain_handle_added_block(block);
        block = giveme_blockchain_crawl_next(0);
    }
out:
    return res;
}

size_t giveme_blockchain_max_allowed_blocks_for_now()
{
    return (time(NULL) - GIVEME_BLOCK_BEGIN_TIMESTAMP) / GIVEME_SECONDS_TO_MAKE_BLOCK;
}

bool giveme_blockchain_can_add_blocks(size_t amount)
{
    size_t max_allowed_blocks = giveme_blockchain_max_allowed_blocks_for_now();
    if (blockchain.total + amount > max_allowed_blocks)
    {
        return false;
    }

    return true;
}

void giveme_blockchain_create_genesis_block()
{
    giveme_log("%s creating genesis block for first time blockchain use\n", __FUNCTION__);
    struct block genesis_block;
    memset(&genesis_block, 0, sizeof(genesis_block));
    genesis_block.data.transactions.total = 1;

    struct block_transaction *transaction = &genesis_block.data.transactions.transactions[0];
    transaction->data.type = BLOCK_TRANSACTION_TYPE_NEW_KEY;
    struct block_transaction_new_key *key = &transaction->data.publish_public_key;
    strncpy(key->name, "Genesis Individual", sizeof(key->name));
    key->pub_key.size = strlen(GIVEME_BLOCKCHAIN_GENESIS_KEY);
    strncpy(key->pub_key.key, GIVEME_BLOCKCHAIN_GENESIS_KEY, sizeof(key->pub_key.key));
    sha256_data(&transaction->data, transaction->hash, sizeof(transaction->data));

    genesis_block.data.nounce = atoi(GIVEME_BLOCKCHAIN_GENESIS_NOUNCE);
    // strncpy(genesis_block.hash, GIVEME_BLOCKCHAIN_GENESIS_HASH, sizeof(genesis_block.hash));
    int res = giveme_mine(&genesis_block);
    if (res < 0)
    {
        giveme_log("%s failed to add genesis block to chain\n", __FUNCTION__);
    }
}

void giveme_blockchain_wait_until_ready()
{
    // Blockchain is already ready..
    if (blockchain.blockchain_ready)
    {
        return;
    }

    sem_wait(&blockchain.blockchain_ready_sem);
}

void giveme_blockchain_give_ready_signal()
{
    sem_post(&blockchain.blockchain_ready_sem);
    blockchain.blockchain_ready = true;
}

void giveme_blockchain_changes_prepare()
{
    assert(!blockchain.changes.is_changing);
    blockchain.changes.is_changing = true;
    blockchain.changes.index = giveme_blockchain_index();
    blockchain.changes.blocks_added = 0;
}

void giveme_blockchain_changes_discard()
{
    assert(blockchain.changes.is_changing);
    // Discard the chain from the given index.
    if (blockchain.changes.blocks_added > 0)
    {
        memset(&blockchain.block[blockchain.changes.index + 1], 0, sizeof(struct block) * blockchain.changes.blocks_added);
        blockchain.total = blockchain.changes.index + 1;
    }

    blockchain.changes.is_changing = false;
}

void giveme_blockchain_changes_apply()
{
    assert(blockchain.changes.is_changing);
    blockchain.changes.is_changing = false;
}

size_t giveme_blockchain_index()
{
    return blockchain.total - 1;
}

void giveme_blockchain_initialize()
{
    // Must have a 1 at the end of the value due to the validator algorithm
    assert(GIVEME_SECONDS_TO_MAKE_BLOCK & 0x01);
    bool blockchain_exists = giveme_blockchain_exists();
    int fd = open(giveme_blockchain_path(), O_RDWR | O_CREAT, (mode_t)0600);
    if (!blockchain_exists)
    {
        // No block chain? then truncate it
        ftruncate(fd, giveme_blockchain_total_bytes_for_blocks(BLOCKCHAIN_RESIZE_TOTAL_BLOCKS));
    }
    size_t total_bytes = giveme_blockchain_total_bytes();
    size_t total_possible_blocks = total_bytes / sizeof(struct block);
    blockchain.max_blocks = total_possible_blocks;
    blockchain.block = mmap(0, total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (blockchain.block == MAP_FAILED)
    {
        giveme_log("Failed to map blockchain into memory\n");
    }

    blockchain.total = giveme_blockchain_compute_block_count();

    if (pthread_mutex_init(&blockchain_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize blockchain mine lock mutex\n");
    }

    blockchain.public_keys = vector_create(sizeof(struct giveme_tcp_packet_publish_key));

    if (!blockchain_exists)
    {
        // We had no blockchain when this function was called, therefore
        // lets create the genesis block
        giveme_blockchain_create_genesis_block();
    }

    if (sem_init(&blockchain.blockchain_ready_sem, 0, 0) != 0)
    {
        // Error: initialization failed
        giveme_log("%s failed to initialize blockchain_ready_sem\n");
    }
}

int giveme_block_verify_transaction(struct block *block, struct block_transaction *transaction)
{
    if (transaction->data.type == BLOCK_TRANSACTION_TYPE_NEW_PACKAGE)
    {
        char tmp_hash[SHA256_STRING_LENGTH];
        sha256_data(&transaction->data, tmp_hash, sizeof(transaction->data));
        if (public_verify_key_sig_hash(&transaction->data.publish_package.signature, tmp_hash) < 0)
        {
            return -1;
        }
    }

    return 0;
}
int giveme_block_verify_transactions(struct block *block)
{
    if (block->data.transactions.total > GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK)
    {
        return -1;
    }

    for (int i = 0; i < block->data.transactions.total; i++)
    {
        if (giveme_block_verify_transaction(block, &block->data.transactions.transactions[i]) < 0)
        {
            return -1;
        }
    }

    return 0;
}

int giveme_block_verify_for_chain(struct blockchain *chain, struct block *block)
{
    struct block *last_block = giveme_blockchain_back_for_chain(chain);
    if (last_block && S_EQ(giveme_blockchain_block_hash(last_block), giveme_blockchain_block_hash(block)))
    {
        // We already have this on the tail of the blockchain
        // most likely multiple nodes resent this block and it reached us twice.
        return GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL;
    }

    if (last_block && !S_EQ(giveme_blockchain_block_hash(last_block), block->data.prev_hash))
    {
        return GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH;
    }

    char tmp_hash[SHA256_STRING_LENGTH];
    sha256_data(&block->data, tmp_hash, sizeof(block->data));
    if (public_verify_key_sig_hash(&block->signature, tmp_hash) < 0)
    {
        return GIVEME_BLOCKCHAIN_BAD_BLOCK_SIGNATURE;
    }

    if (giveme_block_verify_transactions(block) < 0)
    {
        giveme_log("%s bad illegal transactions were provided therefore block verification has failed\n", __FUNCTION__);
        return GIVEME_BLOCKCHAIN_BAD_BLOCK_TRANSACTIONS;
    }
    return GIVEME_BLOCKCHAIN_BLOCK_VALID;
}

int giveme_block_verify(struct block *block)
{
    return giveme_block_verify_for_chain(&blockchain, block);
}

int giveme_blockchain_add_block_for_chain(struct blockchain *chain, struct block *block)
{
    int res = giveme_block_verify(block);
    if (res < 0)
        return res;

    int index = blockchain.total;
    chain->block[index] = *block;
    chain->total++;

    giveme_blockchain_handle_added_block(block);

    if (chain->changes.is_changing)
    {
        chain->changes.blocks_added++;
    }
    return res;
}

size_t giveme_blockchain_total_blocks_left(int index)
{
    return blockchain.total - (index + 1);
}
int giveme_blockchain_add_block(struct block *block)
{
    int res = giveme_blockchain_add_block_for_chain(&blockchain, block);
    if (res < 0)
        return res;
    giveme_log("%s Block added %s prev=%s, total blocks %i\n", __FUNCTION__, giveme_blockchain_block_hash(block), block->data.prev_hash, blockchain.total);
    return res;
}

int giveme_mine(struct block *block)
{
    int res = 0;
    // Let's set the previous hash
    struct block *previous_block = giveme_blockchain_back();
    if (previous_block)
    {
        strncpy(block->data.prev_hash, giveme_blockchain_block_hash(previous_block), sizeof(block->data.prev_hash));
    }

    block->data.nounce = rand() % 0xffffff;
    char tmp_hash[SHA256_STRING_LENGTH];
    sha256_data(&block->data, tmp_hash, sizeof(tmp_hash));
    res = private_sign_key_sig_hash(&block->signature, tmp_hash);
    if (res < 0)
    {
        giveme_log("%s failed to sign block with my private key\n", __FUNCTION__);
        goto out;
    }
    giveme_log("Mined a block %s previous block %s\n", giveme_blockchain_block_hash(block), previous_block ? giveme_blockchain_block_hash(previous_block) : "NULL");
    // We mined a block? Then add it to the blockchain and tell everyone else about it
    res = giveme_blockchain_add_block(block);
    if (res < 0)
    {
        giveme_log("Failed to add the block to the blockchain failed with %i\n", res);
        goto out;
    }

out:
    return res;
}