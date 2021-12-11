#ifndef GIVEME_AF_UNIX_NETWORK_H
#define GIVEME_AF_UNIX_NETWORK_H
#include <linux/limits.h>
#include <stdbool.h>
#include "config.h"
#define NETWORK_AF_UNIX_PACKET_IO_OKAY 0
#define NETWORK_AF_UNIX_PACKET_IO_ERROR -1
#define FRIENDLY_MESSAGE_MAX 512

enum
{
    NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE,
    NETWORK_AF_UNIX_PACKET_TYPE_GET_PACKAGE,
    NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE_RESPONSE,
    NETWORK_AF_UNIX_PACKET_TYPE_MAKE_FAKE_BLOCKCHAIN,
    NETWORK_AF_UNIX_PACKET_TYPE_JUST_A_MESSAGE,
};

enum
{
    NETWORK_AF_UNIX_PACKET_FLAG_HAS_FRIENDLY_MESSAGE = 0b00000001
};

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
    };

    char message[FRIENDLY_MESSAGE_MAX];
    
};
int giveme_af_unix_connect();
int giveme_af_unix_listen();
int giveme_download(int sfd, const char* package_name);
int giveme_publish(int sfd, const char* path_name, const char* package_name);
int giveme_make_fake_blockchain(int sfd, size_t total_blocks);

#endif