#ifndef NETWORK_H
#define NETWORK_H
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
    NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE_RESPONSE
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
            char package[PACKAGE_NAME_MAX];
        } publish;

        struct network_af_unix_publish_response_packet
        {
            char filename[PATH_MAX];
            char package[PACKAGE_NAME_MAX];
            bool published;
        } publish_res;
    };

    char message[FRIENDLY_MESSAGE_MAX];
    
};
int giveme_connect();
int giveme_network_listen();
int giveme_download(int sfd, const char* package_name);
int giveme_publish(int sfd, const char* path_name, const char* package_name);
#endif