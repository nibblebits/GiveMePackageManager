#ifndef GIVEME_NETWORK_H
#define GIVEME_NETWORK_H

#include "config.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define GIVEME_RECV_PACKET_OKAY 0
#define GIVEME_RECV_PACKET_UNEXPECTED -1
#define GIVEME_RECV_PACKET_WRONG_CHAIN -2

struct network_connection_data
{
    int sock;
    struct sockaddr_in addr;

    // The timestamp of the last communication with this socket.
    time_t last_contact;
};

struct network_connection
{
    pthread_mutex_t lock;
    struct network_connection_data *data;
};

struct network
{
    // IP Addresses on the network vector of struct in_addr
    struct vector *ip_addresses;

    struct network_connection connections[GIVEME_TCP_SERVER_MAX_CONNECTIONS];
    size_t total_connected;

    // Locked when preforming TCP actions that must not conflict such as modiying
    // the connection array
    pthread_mutex_t tcp_lock;

    struct sockaddr_in listen_address;
    int listen_socket;
};

enum
{
    GIVEME_NETWORK_TCP_PACKET_TYPE_PING,
    GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE
};

struct giveme_tcp_packet
{
    int type;

    struct giveme_tcp_packet_publish_package
    {
        char name[PACKAGE_NAME_MAX];

    } publish_package;
};

void giveme_network_initialize();
int giveme_network_listen();
int giveme_network_connection_thread_start();
int giveme_network_process_thread_start();
void giveme_network_broadcast(struct giveme_tcp_packet *packet);


#endif