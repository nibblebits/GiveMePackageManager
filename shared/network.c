#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include "network.h"
#include "log.h"
#include "tpool.h"
#include "vector.h"
#include "misc.h"
#include "blockchain.h"

struct network network;
int giveme_network_accept_thread(struct queued_work *work);
int giveme_network_connection_thread(struct queued_work *work);
int giveme_network_process_thread(struct queued_work *work);

int giveme_tcp_network_listen(struct sockaddr_in *server_sock_out, bool has_timeout)
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        giveme_log("socket creation failed...\n");
        exit(0);
    }

    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(GIVEME_TCP_PORT);

    int _true = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &_true, sizeof(int)) < 0)
    {
        giveme_log("Failed to set socket reusable option\n");
        return -1;
    }

    // Binding newly created socket to given IP
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0)
    {
        giveme_log("server socket bind failed...\n");
        exit(0);
    }

    if ((listen(sockfd, GIVEME_TCP_SERVER_MAX_CONNECTIONS)) != 0)
    {
        giveme_log("TCP Server Listen failed...\n");
        return -1;
    }

    *server_sock_out = servaddr;
    return sockfd;
}

bool giveme_network_connection_connected(struct network_connection *connection)
{
    return connection->data != NULL;
}

int giveme_network_accept_thread_start()
{
    giveme_queue_work(giveme_network_accept_thread, NULL);
    return 0;
}

int giveme_network_connection_thread_start()
{
    giveme_queue_work(giveme_network_connection_thread, NULL);
    return 0;
}

int giveme_network_process_thread_start()
{
    giveme_queue_work(giveme_network_process_thread, NULL);
    return 0;
}

int giveme_network_listen()
{
    int err = 0;
    network.listen_socket = giveme_tcp_network_listen(&network.listen_address, false);
    if (network.listen_socket < 0)
    {
        giveme_log("Problem listening on port %i\n", GIVEME_TCP_PORT);
        err = -1;
        goto out;
    }

    //  Start the accept thread
    err = giveme_network_accept_thread_start();
    if (err < 0)
    {
        goto out;
    }

out:
    return err;
}

int giveme_tcp_network_accept(int sock, struct sockaddr_in *client_out)
{
    struct sockaddr_in client;
    int client_len = sizeof(client);
    int connfd = accept(sock, (struct sockaddr *)&client, &client_len);
    if (connfd < 0)
    {
        giveme_log("Nobody connected with us :(\n");
        return -1;
    }

    giveme_log("Received connection from %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

    int interval = 1;
    if (setsockopt(connfd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int)) < 0)
    {
        giveme_log("%s issue setting TCP_KEEPINTVL\n", __FUNCTION__);
        return -1;
    }

    int maxpkt = 10;
    if (setsockopt(connfd, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int)) < 0)
    {
        giveme_log("%s issue setting TCP_KEEPCNT\n", __FUNCTION__);
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = GIVEME_NETWORK_TCP_IO_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        giveme_log("Failed to set socket timeout\n");
        return -1;
    }

    *client_out = client;
    return connfd;
}

int giveme_tcp_send_bytes(int client, void *ptr, size_t amount)
{
    int res = 0;
    size_t amount_left = amount;
    while (amount_left != 0)
    {
        res = write(client, ptr, amount);
        if (res < 0)
        {
            return res;
        }
        amount_left -= res;
    }
    return res;
}

int giveme_tcp_recv_bytes(int client, void *ptr, size_t amount)
{
    int res = 0;
    size_t amount_left = amount;
    while (amount_left != 0)
    {
        res = recv(client, ptr, amount, 0);
        if (res < 0)
        {
            return res;
        }
        amount_left -= res;
    }
    return res;
}

int giveme_tcp_send_packet(struct network_connection *connection, struct giveme_tcp_packet *packet)
{
    if (!giveme_network_connection_connected(connection))
    {
        return -1;
    }

    int client = connection->data->sock;
    int res = giveme_tcp_send_bytes(client, packet, sizeof(struct giveme_tcp_packet)) > 0 ? 0 : -1;
    if (res == 0)
    {
        connection->data->last_contact = time(NULL);
    }
}

int giveme_tcp_recv_packet(struct network_connection *connection, struct giveme_tcp_packet *packet)
{
    if (!giveme_network_connection_connected(connection))
    {
        return -1;
    }

    int client = connection->data->sock;
    int res = giveme_tcp_recv_bytes(client, packet, sizeof(struct giveme_tcp_packet)) > 0 ? 0 : -1;
    if (res == 0)
    {
        connection->data->last_contact = time(NULL);
    }
}

bool giveme_network_ip_connected(struct in_addr *addr)
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        pthread_mutex_lock(&network.connections[i].lock);
        if (network.connections[i].data &&
            memcmp(&network.connections[i].data->addr.sin_addr, addr, sizeof(network.connections[i].data->addr.sin_addr)) == 0)
        {
            // The IP is connected
            pthread_mutex_unlock(&network.connections[i].lock);
            return true;
        }
        pthread_mutex_unlock(&network.connections[i].lock);
    }

    return false;
}

bool giveme_network_ip_address_exists(struct in_addr *addr)
{
    vector_set_peek_pointer(network.ip_addresses, 0);
    struct in_addr *vec_addr = vector_peek(network.ip_addresses);
    while (vec_addr)
    {
        if (memcmp(vec_addr, addr, sizeof(struct in_addr)) == 0)
            return true;

        vec_addr = vector_peek(network.ip_addresses);
    }

    return false;
}

void giveme_network_ip_address_add(struct in_addr addr)
{
    if (!giveme_network_ip_address_exists(&addr))
    {
        vector_push(network.ip_addresses, &addr);
    }
}

void giveme_network_load_ips()
{
    struct in_addr addr = {};
    if (inet_aton("127.0.0.1", &addr) == 0)
    {
        giveme_log("inet_aton() failed\n");
    }

    giveme_network_ip_address_add(addr);

    if (inet_aton("67.205.184.222", &addr) == 0)
    {
        giveme_log("inet_aton() failed\n");
    }
    giveme_network_ip_address_add(addr);

    if (inet_aton("198.199.83.208", &addr) == 0)
    {
        giveme_log("inet_aton() failed\n");
    }
    giveme_network_ip_address_add(addr);
}

struct network_connection *giveme_network_connection_find_slot(pthread_mutex_t **lock_to_unlock)
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        pthread_mutex_lock(&network.connections[i].lock);
        if (network.connections[i].data == NULL)
        {
            // Since we found a free slot we expect the caller to unlock the mutex
            // we tell the caller what the lock is so they know they have to unlock it.
            *lock_to_unlock = &network.connections[i].lock;
            return &network.connections[i];
        }
        pthread_mutex_unlock(&network.connections[i].lock);
    }

    return NULL;
}

int giveme_network_connection_add(struct network_connection_data *data)
{
    pthread_mutex_t *lock_to_unlock;
    struct network_connection *conn_slot = giveme_network_connection_find_slot(&lock_to_unlock);
    if (!conn_slot)
    {
        return -1;
    }

    conn_slot->data = data;
    network.total_connected++;

    // We must now unlock the lock that was locked for finding this connection
    pthread_mutex_unlock(lock_to_unlock);
    return 0;
}

struct network_connection_data *giveme_network_connection_data_new()
{
    int res = 0;
    struct network_connection_data *data = calloc(1, sizeof(struct network_connection_data));

out:
    if (res < 0)
        return NULL;

    return data;
}
int giveme_network_connection_data_free(struct network_connection_data *data)
{
    if (data->sock)
    {
        close(data->sock);
    }
    free(data);
    return 0;
}

int giveme_tcp_network_connect(struct in_addr addr)
{
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    // socket create and varification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        giveme_log("socket creation failed...\n");
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr = addr;
    servaddr.sin_port = htons(GIVEME_TCP_PORT);

    struct timeval timeout;
    timeout.tv_sec = GIVEME_NETWORK_TCP_CONNECT_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        // giveme_log("Failed to set socket timeout\n");
        return -1;
    }

    int optval = 1;
    size_t optlen = sizeof(optval);
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0)
    {
        giveme_log("%s failed to set keep alive on socket\n", __FUNCTION__);
        return -1;
    }

    int interval = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int)) < 0)
    {
        giveme_log("%s issue setting TCP_KEEPINTVL\n", __FUNCTION__);
        return -1;
    }

    int maxpkt = 10;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(int)) < 0)
    {
        giveme_log("%s issue setting TCP_KEEPCNT\n", __FUNCTION__);
        return -1;
    }

    // connect the client socket to server socket
    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        //  giveme_log("connection with the server failed...\n");
        return -1;
    }

    // Set the IO timeout now that we have connected.
    timeout.tv_sec = GIVEME_NETWORK_TCP_IO_TIMEOUT_SECONDS;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        giveme_log("Failed to set socket timeout\n");
        return -1;
    }

    struct network_connection_data *data = giveme_network_connection_data_new();
    data->sock = sockfd;
    data->addr = servaddr;
    data->last_contact = time(NULL);
    if (giveme_network_connection_add(data) < 0)
    {
        giveme_network_connection_data_free(data);
    }
    return sockfd;
}

int giveme_network_connect_to_ip(struct in_addr ip)
{
    // We are already connected to this client.
    if (giveme_network_ip_connected(&ip))
    {
        return 1;
    }

    return giveme_tcp_network_connect(ip) < 0 ? -1 : 0;
}
int giveme_network_connect()
{
    int res = 0;

    // We have to at several occasions in this function lock the mutex
    // and store the vector value on the stack
    // this is because we can't risk it changing during this operation and we also
    // do not want to lock the entire function during this time consuming process of
    // connecting to 100s of IP addresses.
    pthread_mutex_lock(&network.tcp_lock);
    vector_set_peek_pointer(network.ip_addresses, 0);
    struct in_addr *ip_address = vector_peek(network.ip_addresses);
    struct in_addr ip_address_stack;
    if (ip_address)
    {
        ip_address_stack = *ip_address;
    }
    pthread_mutex_unlock(&network.tcp_lock);

    while (ip_address)
    {
        int err;
        err = giveme_network_connect_to_ip(ip_address_stack);
        if (err == 0)
        {
            giveme_log("%s connected to %s\n", __FUNCTION__, inet_ntoa(ip_address_stack));
        }
        pthread_mutex_lock(&network.tcp_lock);
        ip_address = vector_peek(network.ip_addresses);
        if (ip_address)
        {
            ip_address_stack = *ip_address;
        }
        pthread_mutex_unlock(&network.tcp_lock);
    }

    return res;
}

int giveme_network_connection_thread(struct queued_work *work)
{
    while (1)
    {
        giveme_network_connect();
        sleep(5);
    }
    return 0;
}

void giveme_network_disconnect(struct network_connection *connection)
{
    giveme_network_connection_data_free(connection->data);
    connection->data = NULL;
}

void giveme_network_broadcast(struct giveme_tcp_packet *packet)
{

    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        if (!network.connections[i].data)
            continue;

        if (pthread_mutex_trylock(&network.connections[i].lock) < 0)
        {
            continue;
        }

        if (giveme_tcp_send_packet(&network.connections[i], packet) < 0)
        {
            // Problem sending packet? Then we should remove this socket from the connections
            giveme_log("%s problem sending packet to %s\n", __FUNCTION__, inet_ntoa(network.connections[i].data->addr.sin_addr));
            giveme_network_disconnect(&network.connections[i]);
        }

        pthread_mutex_unlock(&network.connections[i].lock);
    }
}

void giveme_network_ping()
{
    struct giveme_tcp_packet packet;
    packet.type = GIVEME_NETWORK_TCP_PACKET_TYPE_PING;
    giveme_network_broadcast(&packet);
}

int giveme_network_connection_socket(struct network_connection* connection)
{
    return connection->data ? connection->data->sock : -1;
}

void giveme_network_packet_handle_publish_package(struct giveme_tcp_packet* packet)
{
    giveme_log("%s Publish package request for packet %s\n", __FUNCTION__, packet->publish_package.name);
}
void giveme_network_packet_process(struct giveme_tcp_packet *packet)
{
    switch(packet->type)
    {
        case GIVEME_NETWORK_TCP_PACKET_TYPE_PING:
        // We ignore pings, they are used to check peer is still here..
        break;

        case GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE:
            giveme_network_packet_handle_publish_package(packet);
        break;

    }
}
void giveme_network_packets_process()
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        struct network_connection* connection = &network.connections[i];
        if (pthread_mutex_trylock(&connection->lock) < 0)
        {
            continue;
        }
        if (!giveme_network_connection_connected(connection))
        {
            pthread_mutex_unlock(&connection->lock);
            continue;
        }

        int sock = giveme_network_connection_socket(connection);
        int count = 0;
        do
        {
            if (ioctl(sock, FIONREAD, &count) < 0)
            {
                giveme_log("%s failed to poll the connection with index %i for bytes\n", __FUNCTION__, count);
                goto loop_end;
            }
            if (count > 0)
            {
                struct giveme_tcp_packet packet = {};
                if (giveme_tcp_recv_packet(connection, &packet) < 0)
                {
                    giveme_log("%s failed to read packet even though data was supposed to be available\n", __FUNCTION__);
                }
                giveme_network_packet_process(&packet);
            }
        } while (count > 0);

    loop_end:
        pthread_mutex_unlock(&network.connections[i].lock);
    }
}

int giveme_network_process_thread(struct queued_work *work)
{
    while (1)
    {
        giveme_network_ping();
        giveme_network_packets_process();
        sleep(1);
    }
    return 0;
}

int giveme_network_accept_thread(struct queued_work *work)
{
    while (1)
    {
        struct network_connection_data *data = giveme_network_connection_data_new();
        data->sock = giveme_tcp_network_accept(network.listen_socket, &data->addr);
        if (data->sock < 0)
        {
            giveme_log("%s Failed to accept a new client\n", __FUNCTION__);
            giveme_network_connection_data_free(data);
            continue;
        }

        // Have they already connected to us ? If so then we need to drop them
        // one connection per node..
        if (giveme_network_ip_connected(&data->addr.sin_addr))
        {
            giveme_log("%s dropping accepted client who is already connected %s\n", __FUNCTION__, inet_ntoa(data->addr.sin_addr));
            giveme_network_connection_data_free(data);
            continue;
        }

        data->last_contact = time(NULL);
        if (giveme_network_connection_add(data) < 0)
        {
            giveme_network_connection_data_free(data);
        }
        sleep(1);
    }
    return 0;
}

void giveme_network_initialize_connections()
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        if (pthread_mutex_init(&network.connections[i].lock, NULL) != 0)
        {
            giveme_log("%s failed to initialize network connection lock index %i\n", __FUNCTION__, i);
        }
    }
}
void giveme_network_initialize()
{
    int res = 0;
    memset(&network, 0, sizeof(struct network));
    network.ip_addresses = vector_create(sizeof(struct in_addr));
    if (pthread_mutex_init(&network.tcp_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize tcp_lock mutex\n");
        res = -1;
        goto out;
    }

    pthread_mutex_lock(&network.tcp_lock);
    giveme_network_load_ips();
    pthread_mutex_unlock(&network.tcp_lock);

    giveme_network_initialize_connections();

out:
    if (res < 0)
    {
        giveme_log("Network initialization failed\n");
    }
}
