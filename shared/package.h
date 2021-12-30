#ifndef GIVEME_PACKAGE_H
#define GIVEME_PACKAGE_H
#include "config.h"
#include "blockchain.h"

#include <limits.h>

// Packages we have downloaded already.
struct package
{
    // The block that proves this package.
    struct block block;
    struct package_details
    {
        char name[GIVEME_PACKAGE_NAME_MAX];
        char description[GIVEME_PACKAGE_DESCRIPTION_MAX];
        char filehash[SHA256_STRING_LENGTH];

    } details;

    // The hash of the transaction that created this package..
    // This is used as an identifier.
    char transaction_hash[SHA256_STRING_LENGTH];

    struct package_downloaded
    {
        // True if we have already downloaded this file
        bool yes;
        char filepath[PATH_MAX];
    } downloaded;

    // The known IP addresses that hold the package data for us to download.
    char ip_addresses[PACKAGE_MAX_KNOWN_IP_ADDRESSES][GIVEME_IP_STRING_SIZE];
};

void giveme_packages_lock();
void giveme_packages_unlock();

/**
 * @brief Adds a package to the package cache, if the package we are adding already exists
 * then only the known IP address provided is added to the existing package. 
 * Otherwise a new package cache entry is created with all the details provided.
 * 
 * @param block The block that made us want to make a package update
 * @param package_name The name of the package if we are aware of it
 * @param transaction_hash The hash of the transaction responsible for this update
 * @param filehash The data hash of the entire file data related to this pacakge
 * @param filepath The filepath on our local hard disk where this file can be located. NULL if not downloaded yet.
 * @param known_ip_address The IP address that we know of where this package can be located.
 * @return int Returns zero on success otherwise a negative number.
 */
int giveme_packages_push(struct block *block, char *package_name, char *transaction_hash, const char *filehash, const char *filepath, const char *known_ip_address);

int giveme_package_initialize();
int giveme_package_create(const char *path, const char *package_name);

/**
 * @brief Clears the packages cache file. So its blank again.
 * 
 * @return int 
 */
int giveme_packages_cache_clear();

/**
 * @brief Returns the path to the package with the given filehash.
 * Even if the file does not exist the path is still returned.
 * 
 * Hash is not mandatory you can provide something that is not a hash and it will
 * be used as a relative filename relative to the packages directory.
 * 
 * @param filehash 
 * @return const char* 
 */
const char* giveme_package_path(const char* filehash);

/**
 * @brief Returns true if the package with the given SHA256 filehash has been downloaded on our
 * computer.
 * 
 * @param filehash 
 * @return true 
 * @return false 
 */
bool giveme_package_downloaded(const char* filehash);

/**
 * @brief Returns true if the packages cache file exists.
 * 
 * @return true 
 * @return false 
 */
bool giveme_packages_exists();


/**
 * @brief Returns the total packages published on this network
 * 
 * @return size_t 
 */
size_t giveme_packages_total();

/**
 * @brief Sets the package_out to the package with the given index, if out of bounds -1 is returned, otherwise 0
 * 
 * @param x 
 * @param package_out 
 * @return int 0 on success otherwise a negative number
 */
int giveme_packages_get_by_index(int x, struct package* package_out);

#endif