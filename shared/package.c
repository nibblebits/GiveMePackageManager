#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <linux/limits.h>
#include <sys/mman.h>
#include <zip.h>
#include <pthread.h>
#include "config.h"
#include "misc.h"
#include "sha256.h"
#include "network.h"
#include "log.h"
#include "package.h"

struct known_packages
{
    // The packages that we are aware of
    struct package *packages;
    size_t total;
    size_t total_possible_packages;
    int fd;
    pthread_mutex_t mutex;
} packages;

void giveme_packages_calculate_total()
{
    struct package blank_package;
    bzero(&blank_package, sizeof(blank_package));
    for (int i = 0; i < packages.total_possible_packages; i++)
    {
        if (memcmp(&packages.packages[i], &blank_package, sizeof(blank_package)) == 0)
        {
            break;
        }
        packages.total++;
    }
}
size_t giveme_packages_size()
{
    return packages.total_possible_packages * sizeof(struct package);
}

size_t giveme_packages_total()
{
    return packages.total;
}

int giveme_packages_get_by_index(int x, struct package* package_out)
{
    if (x >= packages.total)
    {
        return -1;
    }

    memcpy(&package_out, &packages.packages[x], sizeof(struct package));
    return 0;
}

void giveme_packages_extend()
{
    size_t old_bytes = giveme_packages_size();
    size_t new_total_bytes = sizeof(struct package) * (PACKAGES_TOTAL_ENTITIES + packages.total_possible_packages);
    size_t new_total_possible_packages = new_total_bytes / sizeof(struct package);
    ftruncate(packages.fd, new_total_bytes);
    munmap(packages.packages, old_bytes);
    packages.packages = mmap(0, new_total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, packages.fd, 0);
    if (packages.packages == MAP_FAILED)
    {
        giveme_log("%s Failed to map blockchain into memory\n", __FUNCTION__);
        exit(1);
    }
    packages.total_possible_packages = new_total_possible_packages;
}
struct package *giveme_packages_find_free_slot()
{
    struct package blank_package;
    bzero(&blank_package, sizeof(blank_package));
    for (int i = 0; i < packages.total_possible_packages; i++)
    {
        if (memcmp(&packages.packages[i], &blank_package, sizeof(packages.packages[i])) == 0)
        {
            return &packages.packages[i];
        }
    }

    // Nothing?? Then extend the file
    giveme_packages_extend();
    return giveme_packages_find_free_slot();
}

struct package *giveme_packages_get_by_transaction_hash(const char *transaction_hash)
{
    for (int i = 0; i < packages.total_possible_packages; i++)
    {
        if (memcmp(packages.packages[i].transaction_hash, transaction_hash, sizeof(packages.packages[i].transaction_hash)) == 0)
            return &packages.packages[i];
    }

    return NULL;
}
int giveme_packages_add_ip_address(struct package *package, const char *ip)
{
    int res = -1;
    char blank_ip[GIVEME_IP_STRING_SIZE];
    bzero(blank_ip, sizeof(blank_ip));
    for (int i = 0; i < PACKAGE_MAX_KNOWN_IP_ADDRESSES; i++)
    {
        if (memcmp(package->ip_addresses[i], &blank_ip, sizeof(package->ip_addresses[i])) == 0)
        {
            strncpy(package->ip_addresses[i], ip, sizeof(package->ip_addresses[i]));
            res = 0;
        }
    }

    if (res < 0)
    {
        // Nothing was found?? Okay lets find a random IP to replace
        // In future could select based on age.. would be better.
        int random_index = rand() % PACKAGE_MAX_KNOWN_IP_ADDRESSES - 1;
        strncpy(package->ip_addresses[random_index], ip, sizeof(package->ip_addresses[random_index]));
        res = 0;
    }

    return res;
}
int giveme_packages_push(struct block *block, char *package_name, char *transaction_hash, const char *filehash, const char *filepath, const char *known_ip_address)
{
    int res = 0;
    struct package *package = giveme_packages_get_by_transaction_hash(transaction_hash);
    if (!package)
    {
        package = giveme_packages_find_free_slot();
        if (!package)
        {
            giveme_log("%s could not find a free package slot\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        strncpy(package->block_hash, block->signature.data_hash, sizeof(package->block_hash));
        strncpy(package->details.name, package_name, sizeof(package->details.name));
        strncpy(package->details.filehash, filehash, sizeof(package->details.filehash));
        strncpy(package->transaction_hash, transaction_hash, sizeof(package->transaction_hash));

        if (filepath)
        {
            strncpy(package->downloaded.filepath, filepath, sizeof(package->downloaded.filepath));
            package->downloaded.yes = true;
        }
    }

    giveme_packages_add_ip_address(package, known_ip_address);

out:
    return res;
}
static bool is_dir(const char *dir)
{
    struct stat st;
    stat(dir, &st);
    return S_ISDIR(st.st_mode);
}

static int walk_directory(const char *start_dir, const char *input_dir, zip_t *zipper)
{
    DIR *dp = opendir(input_dir);
    if (dp == NULL)
    {
        return -1;
    }

    struct dirent *dirp;
    while ((dirp = readdir(dp)) != NULL)
    {
        if (!S_EQ(dirp->d_name, ".") && !S_EQ(dirp->d_name, ".."))
        {
            char fullname[PATH_MAX];
            sprintf(fullname, "%s/%s", input_dir, dirp->d_name);
            if (is_dir(fullname))
            {
                if (zip_dir_add(zipper, fullname, ZIP_FL_ENC_UTF_8) < 0)
                {
                    return -1;
                }
                walk_directory(start_dir, fullname, zipper);
            }
            else
            {
                zip_source_t *source = zip_source_file(zipper, fullname, 0, 0);
                if (source == NULL)
                {
                    return -1;
                }
                if (zip_file_add(zipper, fullname, source, ZIP_FL_ENC_UTF_8) < 0)
                {

                    zip_source_free(source);
                    return -1;
                }
            }
        }
    }
    closedir(dp);
}

static int zip_directory(const char *input_dir, const char *output_dir)
{
    int errorp;
    zip_t *zipper = zip_open(output_dir, ZIP_CREATE | ZIP_EXCL, &errorp);
    if (zipper == NULL)
    {
        zip_error_t ziperror;
        zip_error_init_with_code(&ziperror, errorp);
        return -1;
    }

    int res = walk_directory(input_dir, input_dir, zipper);
    if (res == -1)
    {
        zip_close(zipper);
        return -1;
    }

    zip_close(zipper);
    return 0;
}

char *giveme_packages_path()
{
    static char blockchain_file_path[PATH_MAX];
    sprintf(blockchain_file_path, "%s/%s/%s", getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_DATA_BASE, GIVEME_PACKAGES_PATH);
    return blockchain_file_path;
}

const char* giveme_package_storage_directory()
{
    static char tmp_path[PATH_MAX];
    sprintf(tmp_path, "%s/%s", getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_PACKAGE_DIRECTORY);
    return tmp_path;
}

const char* giveme_package_path(const char* filehash)
{
    static char tmp_path[PATH_MAX];
    sprintf(tmp_path, "%s/%s.zip", giveme_package_storage_directory(), filehash);
    return tmp_path;
}

bool giveme_package_downloaded(const char* filehash)
{
    return file_exists(giveme_package_path(filehash));
}

int giveme_packages_mapping_build()
{
    int res = 0;
    bool packages_exists = giveme_packages_exists();
    packages.fd = open(giveme_packages_path(), O_RDWR | O_CREAT, (mode_t)0600);

    size_t total_bytes = sizeof(struct package) * PACKAGES_TOTAL_ENTITIES;
    if (!packages_exists)
    {
        // No file? then truncate it
        ftruncate(packages.fd, total_bytes);
    }

    struct stat s;
    fstat(packages.fd, &s);
    total_bytes = s.st_size;

    packages.packages = mmap(0, total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, packages.fd, 0);
    if (packages.packages == MAP_FAILED)
    {
        giveme_log("Failed to map blockchain into memory\n");
        res = -1;
        goto out;
    }

    packages.total_possible_packages = total_bytes / sizeof(struct package);
out:
    return res;
}
int giveme_packages_cache_clear()
{
    size_t size = giveme_packages_size();
    munmap(packages.packages, size);
    close(packages.fd);
    unlink(giveme_packages_path());
    if (giveme_packages_mapping_build() < 0)
    {
        giveme_log("%s failed to reset packages cache\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

bool giveme_packages_exists()
{
    return file_exists(giveme_packages_path());
}

int giveme_package_initialize_packages()
{
    int res = 0;
    res = pthread_mutex_init(&packages.mutex, NULL);
    if (res < 0)
    {
        return res;
    }

    res = giveme_packages_mapping_build();
    if (res < 0)
    {
        goto out;
    }

    giveme_packages_calculate_total();
out:
    return res;
}

int giveme_package_initialize()
{
    int res = 0;
    res = giveme_package_initialize_packages();
    if (res < 0)
    {
        giveme_log("%s failed to initialize downloaded packages\n", __FUNCTION__);
    }
}

void giveme_packages_lock()
{
    pthread_mutex_lock(&packages.mutex);
}

void giveme_packages_unlock()
{
    pthread_mutex_unlock(&packages.mutex);
}

int giveme_package_create(const char *path, const char *package_name)
{
    int res = 0;
    char dst_path[PATH_MAX];
    strncpy(dst_path, giveme_package_path(package_name), sizeof(dst_path));
    char sha_buf[SHA256_STRING_LENGTH];

    res = zip_directory(path, dst_path);
    if (res < 0)
    {
        return res;
    }

    res = sha256_file(dst_path, sha_buf);
    if (res < 0)
    {
        return res;
    }

    char dst_path_hashed[PATH_MAX];
    strncpy(dst_path_hashed, giveme_package_path(sha_buf), sizeof(dst_path_hashed));
    res = rename(dst_path, dst_path_hashed);
    if (res < 0)
    {
        return res;
    }

    struct giveme_tcp_packet packet = {};
    packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE;
    strncpy(packet.data.publish_package.data.name, package_name, sizeof(packet.data.publish_package.data.name));
    sha256_file(dst_path_hashed, packet.data.publish_package.data.filehash);

    char tmp_hash[SHA256_STRING_LENGTH];
    sha256_data(&packet.data.publish_package.data, tmp_hash, sizeof(packet.data.publish_package.data));
    // We must sign the data
    res = private_sign_key_sig_hash(&packet.data.publish_package.signature, tmp_hash);
    if (res < 0)
    {
        giveme_log("%s failed to sign the packet publish data with private key\n", __FUNCTION__);

        return res;
    }
    // We should sign the data.
    giveme_network_broadcast(&packet);

    return res;
}