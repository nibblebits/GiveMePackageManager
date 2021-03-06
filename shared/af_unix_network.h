#ifndef GIVEME_AF_UNIX_NETWORK_H
#define GIVEME_AF_UNIX_NETWORK_H
#include <linux/limits.h>
#include <stdbool.h>
#include "config.h"
#include "blockchain.h"
#include "package.h"
#include "network.h"
#define NETWORK_AF_UNIX_PACKET_IO_OKAY 0
#define NETWORK_AF_UNIX_PACKET_IO_ERROR -1
#define FRIENDLY_MESSAGE_MAX 512

enum
{
    NETWORK_AF_UNIX_PACKET_TYPE_BLANK,
    NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE,
    NETWORK_AF_UNIX_PACKET_TYPE_GET_PACKAGE,
    NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE_RESPONSE,
    NETWORK_AF_UNIX_PACKET_TYPE_MAKE_FAKE_BLOCKCHAIN,
    NETWORK_AF_UNIX_PACKET_TYPE_JUST_A_MESSAGE,
    NETWORK_AF_UNIX_PACKET_TYPE_SIGNUP,
    NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PUBLIC_KEY_RESPONSE,
    NETWORK_AF_UNIX_PACKET_TYPE_MY_INFO,
    NETWORK_AF_UNIX_PACKET_TYPE_INFO_RESPONSE,
    NETWORK_AF_UNIX_PACKET_TYPE_PACKAGES,
    NETWORK_AF_UNIX_PACKET_TYPE_PACKAGES_RESPONSE,
    NETWORK_AF_UNIX_PACKET_TYPE_PACKAGE_DOWNLOAD,
    NETWORK_AF_UNIX_PACKET_TYPE_PACKAGE_DOWNLOAD_RESPONSE,
    NETWORK_AF_UNIX_PACKET_TYPE_MY_AWAITING_TRANSACTIONS,
    NETWORK_AF_UNIX_PACKET_TYPE_MY_AWAITING_TRANSACTIONS_RESPONSE,
    NETWORK_AF_UNIX_PACKET_TYPE_NOT_FOUND,
    NETWORK_AF_UNIX_PACKET_TYPE_PROBLEM
};

enum
{
    NETWORK_AF_UNIX_PACKET_FLAG_HAS_FRIENDLY_MESSAGE = 0b00000001
};
struct network_awaiting_transaction;
struct network_af_unix_packet
{
    int type;
    int flags;
    union
    {
        struct network_af_unix_publish_packet
        {
            char filename[PATH_MAX];
            char package[GIVEME_PACKAGE_NAME_MAX];
        } publish;

        struct network_af_unix_publish_response_packet
        {
            char filename[PATH_MAX];
            char package[GIVEME_PACKAGE_NAME_MAX];
            bool published;
        } publish_res;

        struct network_af_unix_fake_blockchain
        {
            size_t total_blocks;
        } fake_blockchain;

        struct network_af_unix_signup
        {
            char name[GIVEME_KEY_NAME_MAX];
        } signup;

        struct network_af_unix_my_info
        {

        } info;

        struct network_af_unix_info_response
        {
            struct blockchain_individual individual;
        } info_response;

        struct network_af_unix_packages
        {
            int page;
        } packages;

        struct network_af_unix_packages_response
        {
            // The page number
            int page;

            struct network_af_unix_packages_response_packages
            {
                size_t total;
                struct package packages[PACKAGE_MAX_PER_PAGE];
            } packages;
        } packages_response;

        struct network_af_unix_package_download
        {
            char package_name[GIVEME_PACKAGE_NAME_MAX];
        } package_download;

        struct network_af_unix_package_download_response
        {
            // Numerical ID of this download can be used to check the status
            char package_name[GIVEME_PACKAGE_NAME_MAX];
            char filehash[SHA256_STRING_LENGTH];
            char path[PATH_MAX];
            size_t size;
        } package_download_response;

        struct network_af_unix_my_awaiting_transactions
        {

        } my_awaiting_transactions;

        struct network_af_unix_my_awaiting_transactions_response
        {
            size_t total;
            struct network_awaiting_transaction transactions[AWAITING_TRANSACTION_MAX_PER_PAGE];

        } my_awaiting_transactions_response;
    };

    char message[FRIENDLY_MESSAGE_MAX];
};
int giveme_af_unix_connect();
int giveme_af_unix_listen();
int giveme_download(int sfd, const char *package_name, struct network_af_unix_packet *packet_out);
int giveme_publish(int sfd, const char *path_name, const char *package_name);
int giveme_packages(int sfd, int page, struct network_af_unix_packages_response_packages *packages_res_out);

int giveme_signup(int sfd, const char *name);
int giveme_make_fake_blockchain(int sfd, size_t total_blocks);
struct blockchain_individual giveme_info(int sfd);
int giveme_my_awaiting_transactions(int sfd, struct network_af_unix_my_awaiting_transactions_response* packet_out);

#endif