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

struct network_connection
{
    int sock;
    struct sockaddr_in addr;
    pthread_mutex_t lock;

    // The timestamp of the last communication with this socket.
    time_t last_contact;
};

struct network
{
    // IP Addresses on the network vector of struct in_addr
    struct vector *ip_addresses;

    struct network_connection *connections[GIVEME_TCP_SERVER_MAX_CONNECTIONS];
    size_t total_connected;

    // Locked when preforming TCP actions that must not conflict such as modiying
    // the connection array
    pthread_mutex_t tcp_lock;

    struct sockaddr_in listen_address;
    int listen_socket;
};

struct giveme_tcp_packet
{
};


void giveme_network_initialize();
int giveme_network_listen();
int giveme_network_connection_thread_start();
int giveme_network_process_thread_start();




#endif