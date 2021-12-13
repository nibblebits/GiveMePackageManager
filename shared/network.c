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
bool giveme_network_connection_connected(struct network_connection *connection);
int giveme_tcp_dataexchange_send_packet(int client, struct giveme_dataexchange_tcp_packet *packet);
int giveme_network_upload_chain(struct network_connection_data *conn, struct block *from_block, struct block *end_block, size_t total_blocks);
int giveme_tcp_dataexchange_recv_packet(int client, struct giveme_dataexchange_tcp_packet *packet);
struct network_connection_data *giveme_network_connection_data_new();
int giveme_tcp_network_accept(int sock, struct sockaddr_in *client_out);

struct network_transaction **giveme_network_find_network_transaction_slot()
{
    for (int i = 0; i < GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK; i++)
    {
        if (!network.transactions.awaiting[i])
        {
            return &network.transactions.awaiting[i];
        }
    }

    return NULL;
}

struct network_transaction *giveme_network_new_transaction()
{
    return calloc(1, sizeof(struct network_transaction));
}

int giveme_network_create_transaction_for_packet(struct giveme_tcp_packet *packet)
{
    int res = 0;
    pthread_mutex_lock(&network.transactions.lock);
    struct network_transaction **slot = giveme_network_find_network_transaction_slot();
    if (!slot)
    {
        giveme_log("%s out of transaction slots cannot create transaction\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    struct network_transaction *transaction = giveme_network_new_transaction();
    memcpy(&transaction->packet, packet, sizeof(struct giveme_tcp_packet));
    *slot = transaction;
    network.transactions.total++;
out:
    pthread_mutex_unlock(&network.transactions.lock);
    return res;
}

const char *giveme_connection_ip(struct network_connection *connection)
{
    if (!giveme_network_connection_connected(connection))
        return NULL;

    return inet_ntoa(connection->data->addr.sin_addr);
}

int giveme_tcp_network_listen(struct sockaddr_in *server_sock_out, int timeout_seconds, int port, int max_connections)
{
    int sockfd, len;
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
    servaddr.sin_port = htons(port);

    int _true = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &_true, sizeof(int)) < 0)
    {
        giveme_log("Failed to set socket reusable option\n");
        return -1;
    }

    if (timeout_seconds)
    {
        struct timeval timeout;
        timeout.tv_sec = timeout_seconds;
        timeout.tv_usec = 0;

        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof timeout) < 0)
        {
            giveme_log("Failed to set socket timeout\n");
            return -1;
        }
    }

    // Binding newly created socket to given IP
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0)
    {
        giveme_log("server socket bind failed...\n");
        return -1;
    }

    if ((listen(sockfd, max_connections)) != 0)
    {
        giveme_log("TCP Server Listen failed...\n");
        return -1;
    }

    *server_sock_out = servaddr;
    return sockfd;
}

bool giveme_network_connection_connected(struct network_connection *connection)
{
    return connection && connection->data != NULL;
}

int giveme_network_dataexchange_send_unable_to_help(struct network_connection_data *conn)
{
    struct giveme_dataexchange_tcp_packet res_packet = {};
    res_packet.type = GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_UNABLE_TO_HELP;
    return giveme_tcp_dataexchange_send_packet(conn->sock, &res_packet);
}

int giveme_network_dataexchange_handle_chain_request(struct giveme_dataexchange_tcp_packet *packet, struct network_connection_data *conn)
{
    int res = 0;
    giveme_lock_chain();

    const char *hash = packet->chain_request.hash;
    size_t blocks_left_to_end = 0;
    struct block *block = giveme_blockchain_block(hash, &blocks_left_to_end);
    if (!block)
    {
        // We couldn't find the block they asked us for sadly.
        res = giveme_network_dataexchange_send_unable_to_help(conn);
        if (res < 0)
        {
            giveme_log("%s unable to send unable to help packet\n");
        }
        res = -1;
        goto out;
    }

    struct block *end_block = giveme_blockchain_back();
    // We have the block we will send it to them.
    res = giveme_network_upload_chain(conn, block, end_block, blocks_left_to_end);
    if (res < 0)
    {
        giveme_log("%s unable to upload chain\n");
        goto out;
    }

out:
    giveme_unlock_chain();
    return 0;
}
int giveme_network_dataexchange_connection(struct queued_work *work)
{
    int res = 0;
    struct network_connection_data *conn = work->private;

    // Let's find out what this person wants from us
    struct giveme_dataexchange_tcp_packet packet;
    giveme_tcp_dataexchange_recv_packet(conn->sock, &packet);
    switch (packet.type)
    {
    case GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_CHAIN_REQUEST:
        res = giveme_network_dataexchange_handle_chain_request(&packet, conn);
        break;

    default:
        giveme_log("%s unrecognized request for dataexchange, nothing we can do\n", __FUNCTION__);
    }

    close(conn->sock);
    free(conn);

    return res;
}
int giveme_network_dataexchange_accept_thread(struct queued_work *work)
{
    while (1)
    {
        struct network_connection_data *conn = giveme_network_connection_data_new();
        conn->sock = giveme_tcp_network_accept(network.dataexchange_listen_socket, &conn->addr);
        if (conn->sock < 0)
        {
            giveme_log("%s Failed to accept a new client on data exchange accept thread\n", __FUNCTION__);
            free(conn);
            continue;
        }

        // Pass the connection as work
        giveme_queue_work(giveme_network_dataexchange_connection, conn);
    }
    return 0;
}

int giveme_network_dataexchange_accept_thread_start()
{
    giveme_queue_work(giveme_network_dataexchange_accept_thread, NULL);
    return 0;
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
    network.listen_socket = giveme_tcp_network_listen(&network.listen_address, false, GIVEME_TCP_PORT, GIVEME_TCP_SERVER_MAX_CONNECTIONS);
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

    network.dataexchange_listen_socket = giveme_tcp_network_listen(&network.dataexchange_listen_address, false, GIVEME_TCP_DATA_EXCHANGE_PORT, GIVEME_TCP_SERVER_MAX_CONNECTIONS);
    if (network.dataexchange_listen_socket < 0)
    {
        giveme_log("Problem listening on port %i\n", GIVEME_TCP_DATA_EXCHANGE_PORT);
        err = -1;
        goto out;
    }

    //  Start the accept thread
    err = giveme_network_dataexchange_accept_thread_start();
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
            printf("%s issue sending bytes err=%i\n", __FUNCTION__, errno);
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

int giveme_tcp_dataexchange_send_packet(int client, struct giveme_dataexchange_tcp_packet *packet)
{
    int res = giveme_tcp_send_bytes(client, packet, sizeof(struct giveme_dataexchange_tcp_packet)) > 0 ? 0 : -1;
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

    return res;
}

int giveme_tcp_dataexchange_recv_packet(int client, struct giveme_dataexchange_tcp_packet *packet)
{
    int res = giveme_tcp_recv_bytes(client, packet, sizeof(struct giveme_dataexchange_tcp_packet)) > 0 ? 0 : -1;
    return res;
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
    return res;
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

int giveme_tcp_network_connect(struct in_addr addr, int port, int flags)
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
    servaddr.sin_port = htons(port);

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

    if (flags & GIVEME_CONNECT_FLAG_ADD_TO_CONNECTIONS)
    {
        struct network_connection_data *data = giveme_network_connection_data_new();
        data->sock = sockfd;
        data->addr = servaddr;
        data->last_contact = time(NULL);
        if (giveme_network_connection_add(data) < 0)
        {
            giveme_network_connection_data_free(data);
        }
    }
    return sockfd;
}

int giveme_network_connect_to_ip(struct in_addr ip)
{
    giveme_log("%s connecting to IP address\n", __FUNCTION__);
    // We are already connected to this client.
    if (giveme_network_ip_connected(&ip))
    {
        return 1;
    }
    giveme_log("%s test\n", __FUNCTION__);
    return giveme_tcp_network_connect(ip, GIVEME_TCP_PORT, GIVEME_CONNECT_FLAG_ADD_TO_CONNECTIONS) < 0 ? -1 : 0;
}
int giveme_network_connect()
{
    int res = 0;

    // We have to at several occasions in this function lock the mutex
    // and store the vector value on the stack
    // this is because we can't risk it changing during this operation and we also
    // do not want to lock the entire function during this time consuming process of
    // connecting to 100s of IP addresses.
    pthread_mutex_lock(&network.ip_address_lock);
    vector_set_peek_pointer(network.ip_addresses, 0);
    struct in_addr *ip_address = vector_peek(network.ip_addresses);
    struct in_addr ip_address_stack;
    if (ip_address)
    {
        ip_address_stack = *ip_address;
    }
    pthread_mutex_unlock(&network.ip_address_lock);

    while (ip_address)
    {
        int err;
        err = giveme_network_connect_to_ip(ip_address_stack);
        if (err == 0)
        {
            giveme_log("%s connected to %s\n", __FUNCTION__, inet_ntoa(ip_address_stack));
        }
        pthread_mutex_lock(&network.ip_address_lock);
        ip_address = vector_peek(network.ip_addresses);
        if (ip_address)
        {
            ip_address_stack = *ip_address;
        }
        pthread_mutex_unlock(&network.ip_address_lock);
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
    network.total_connected--;
    connection->data = NULL;
}

void giveme_network_broadcast(struct giveme_tcp_packet *packet)
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        if (pthread_mutex_trylock(&network.connections[i].lock) == EBUSY)
        {
            continue;
        }

        if (!network.connections[i].data)
        {
            pthread_mutex_unlock(&network.connections[i].lock);
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

int giveme_network_connection_socket(struct network_connection *connection)
{
    return connection->data ? connection->data->sock : -1;
}

void giveme_network_packet_handle_publish_package(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    giveme_log("%s Publish package request for packet %s by %s\n", __FUNCTION__, packet->publish_package.name, giveme_connection_ip(connection));
    int res = giveme_network_create_transaction_for_packet(packet);
    if (res < 0)
    {
        giveme_log("%s failed to create a transaction for the packet provided for IP %s\n", __FUNCTION__, giveme_connection_ip(connection));
    }
}

void giveme_network_packet_handle_publish_key(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    // We have a request to publish a public key, lets add it to the transactions
    giveme_log("%s Publish public key request for packet %s by %s\n", __FUNCTION__, packet->publish_public_key.name, giveme_connection_ip(connection));
    int res = giveme_network_create_transaction_for_packet(packet);
    if (res < 0)
    {
        giveme_log("%s failed to create a transaction for the packet provided for IP %s\n", __FUNCTION__, giveme_connection_ip(connection));
    }
}

void giveme_network_packet_handle_verified_block(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    giveme_log("%s new verified block discovered, attempting to add to chain\n", __FUNCTION__);
    giveme_blockchain_add_block(&packet->verified_block.block);
}

int giveme_network_upload_chain(struct network_connection_data *conn, struct block *from_block, struct block *end_block, size_t total_blocks)
{
    int res = 0;
    if (!from_block || !end_block)
    {
        return -1;
    }

    struct giveme_dataexchange_tcp_packet packet;
    packet.type = GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_SENDING_CHAIN;
    strncpy(packet.sending_chain.start_hash, from_block->hash, sizeof(packet.sending_chain.start_hash));
    strncpy(packet.sending_chain.last_hash, end_block->hash, sizeof(packet.sending_chain.last_hash));
    packet.sending_chain.blocks_left_to_end = total_blocks;
    res = giveme_tcp_dataexchange_send_packet(conn->sock, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to send sending chain packet\n", __FUNCTION__);
        goto out;
    }

    giveme_blockchain_begin_crawl(from_block->hash, NULL);

    struct block *block = giveme_blockchain_crawl_next(0);
    size_t count = 0;
    while (block && count <= total_blocks)
    {
        int res = giveme_tcp_send_bytes(conn->sock, block, sizeof(struct block));
        if (res < 0)
        {
            giveme_log("%s failed to send block during upload\n", __FUNCTION__);
        }
        count++;
        block = giveme_blockchain_crawl_next(0);
    }

out:
    return res;
}

void giveme_network_packet_handle_update_chain(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    giveme_log("%s update chain request\n", __FUNCTION__);

    giveme_lock_chain();
    size_t blocks_left_to_end = 0;
    struct block *block = giveme_blockchain_block(packet->update_chain.last_hash, &blocks_left_to_end);
    struct block *last_block = giveme_blockchain_back();
    giveme_unlock_chain();

    if (block && blocks_left_to_end > 0)
    {
        struct giveme_tcp_packet res_packet = {};
        res_packet.type = GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN_RESPONSE;
        res_packet.update_chain_response.blocks_left_to_end = blocks_left_to_end;
        res_packet.update_chain_response.data_port = GIVEME_TCP_DATA_EXCHANGE_PORT;
        memcpy(res_packet.update_chain_response.last_hash, last_block->hash, sizeof(res_packet.update_chain_response.last_hash));
        memcpy(res_packet.update_chain_response.start_hash, block->hash, sizeof(res_packet.update_chain_response.start_hash));
        int res = giveme_tcp_send_packet(connection, &res_packet);
        if (res < 0)
        {
            giveme_log("%s failed to send update chain response packet\n", __FUNCTION__);
            goto out;
        }
    }

out:
    return;
}

int giveme_network_download_chain(struct in_addr addr, int port, const char *start_hash)
{
    giveme_lock_chain();
    int res = 0;
    giveme_log("%s download blockchain from peer\n", __FUNCTION__);
    int sock = giveme_tcp_network_connect(addr, port, 0);
    if (sock < 0)
    {
        giveme_log("%s Failed to connect to peer to download chain\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // First thing we do is send a request for a chain
    struct giveme_dataexchange_tcp_packet packet = {};
    packet.type = GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_CHAIN_REQUEST;
    strncpy(packet.chain_request.hash, start_hash, sizeof(packet.chain_request.hash));
    res = giveme_tcp_dataexchange_send_packet(sock, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to send dataexchange chain request packet\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    res = giveme_tcp_dataexchange_recv_packet(sock, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to read dataexchange chain response packet\n", __FUNCTION__);
        goto out;
    }

    if (packet.type == GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_UNABLE_TO_HELP)
    {
        giveme_log("%s the peer is not able to help us with this chain request\n");
        res = -1;
        goto out;
    }
    if (packet.type != GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_SENDING_CHAIN)
    {
        giveme_log("%s we received an unexpected packet type from the peer type=%i\n", __FUNCTION__, packet.type);
        res = -1;
        goto out;
    }

    if (strncmp(packet.sending_chain.start_hash, start_hash, sizeof(packet.sending_chain.start_hash) != 0))
    {
        giveme_log("%s start hash we requested and hash they have returned do not match\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    const char *end_hash = packet.sending_chain.last_hash;
    size_t total_blocks = packet.sending_chain.blocks_left_to_end;

    // We have a mathematically limited amount of blocks, lets ensure the blockchain can support
    // the amount the peer wants to send
    if (!giveme_blockchain_can_add_blocks(total_blocks))
    {
        giveme_log("%s the peer is trying to send more blocks than is mathematically allowed, its possible hes an attacker. We will not download his chain\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    for (size_t i = 0; i < total_blocks; i++)
    {
        struct block block;
        if (giveme_tcp_recv_bytes(sock, &block, sizeof(struct block)) < 0)
        {
            giveme_log("%s failed to read a block from the chain\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        if (i == 0)
        {
            // We wish to ignore the first block as we know about it already
            continue;
        }

        // Now we have a block lets add it to our blockchain
        int res = giveme_blockchain_add_block(&block);
        if (res < 0)
        {
            giveme_log("%s failed to add a new block to our blockchain\n", __FUNCTION__);
            res = -1;
            goto out;
        }
    }
out:
    giveme_unlock_chain();

    return res;
}

void giveme_network_packet_handle_update_chain_response(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    giveme_log("%s received packet for update chain will download new chain\n", __FUNCTION__);
    size_t blocks_to_end = packet->update_chain_response.blocks_left_to_end;
    int port = packet->update_chain_response.data_port;
    const char *start_hash = packet->update_chain_response.start_hash;
    int res = giveme_network_download_chain(connection->data->addr.sin_addr, port, start_hash);
    if (res < 0)
    {
        giveme_log("%s failed to download blockchain\n", __FUNCTION__);
    }
}
void giveme_network_packet_process(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    switch (packet->type)
    {
    case GIVEME_NETWORK_TCP_PACKET_TYPE_PING:
        // We ignore pings, they are used to check peer is still here..
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE:
        giveme_network_packet_handle_publish_package(packet, connection);
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PUBLIC_KEY:
        giveme_network_packet_handle_publish_key(packet, connection);
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_VERIFIED_BLOCK:
        giveme_network_packet_handle_verified_block(packet, connection);
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN:
        giveme_network_packet_handle_update_chain(packet, connection);
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN_RESPONSE:
        giveme_network_packet_handle_update_chain_response(packet, connection);
        break;
    }
}
void giveme_network_packets_process()
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        if (pthread_mutex_trylock(&network.connections[i].lock) == EBUSY)
        {
            continue;
        }
        struct network_connection *connection = &network.connections[i];

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
                giveme_network_packet_process(&packet, connection);
            }
        } while (count > 0);

    loop_end:
        pthread_mutex_unlock(&network.connections[i].lock);
    }
}

int giveme_network_create_block_transaction_for_network_transaction(struct network_transaction *transaction, struct block_transaction *transaction_out)
{
    int res = 0;

    // No transaction provided? then just return zero.

    switch (transaction->packet.type)
    {
    case GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE:
        transaction_out->type = BLOCK_TRANSACTION_TYPE_NEW_PACKAGE;
        strncpy(transaction_out->publish_package.name, transaction->packet.publish_package.name, sizeof(transaction_out->publish_package.name));
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PUBLIC_KEY:
        transaction_out->type = BLOCK_TRANSACTION_TYPE_NEW_KEY;
        strncpy(transaction_out->publish_public_key.name, transaction->packet.publish_public_key.name, sizeof(transaction_out->publish_public_key.name));
        memcpy(&transaction_out->publish_public_key.pub_key, &transaction->packet.publish_public_key.pub_key, sizeof(transaction_out->publish_public_key.pub_key));
        break;

    default:
        res = -1;
    }

    return res;
}
int giveme_network_make_block_for_transactions(struct network_transactions *transactions, struct block *block_out)
{
    int res = 0;
    memset(block_out, 0, sizeof(struct block));
    block_out->data.transactions.total = transactions->total;
    for (int i = 0; i < transactions->total; i++)
    {
        int res = giveme_network_create_block_transaction_for_network_transaction(transactions->awaiting[i], &block_out->data.transactions.transactions[i]);
        if (res < 0)
        {
            giveme_log("%s failed to create a new block transaction from a given network transaction\n");
            goto out;
        }
    }

    block_out->data.validator_key = *giveme_public_key();
out:
    return res;
}

void giveme_network_broadcast_block(struct block *block)
{
    struct giveme_tcp_packet packet = {};
    packet.type = GIVEME_NETWORK_TCP_PACKET_TYPE_VERIFIED_BLOCK;
    memcpy(&packet.verified_block.block, block, sizeof(packet.verified_block.block));
    giveme_network_broadcast(&packet);
}

void giveme_network_update_chain()
{
    giveme_log("%s asking the network for the most up to date chain\n", __FUNCTION__);
    giveme_lock_chain();
    struct giveme_tcp_packet update_chain_packet;
    update_chain_packet.type = GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN;
    memcpy(update_chain_packet.update_chain.last_hash, giveme_blockchain_back()->hash, sizeof(update_chain_packet.update_chain.last_hash));
    giveme_unlock_chain();
    giveme_network_broadcast(&update_chain_packet);
}

int giveme_network_make_block_if_possible()
{
    // Have we already made a block in the last five minutes
    if (time(NULL) - network.last_block_send < GIVEME_SECONDS_TO_MAKE_BLOCK)
    {
        // We already have made the block for this cycle
        return 0;
    }

    // Every 5 minutes we want to make a new block, lets see if its time.
    // We will only make the block if we are the next elected.
    size_t current_time_since_last_tick = time(NULL) % GIVEME_SECONDS_TO_MAKE_BLOCK;
    // We give a leighway of five seconds in regards to the five minutes
    // as sometimes theres delays right.
    if (current_time_since_last_tick >= 0 && current_time_since_last_tick <= 5)
    {
        giveme_log("%s time to make a new block\n", __FUNCTION__);
        struct key *key = giveme_blockchain_get_verifier_key();
        if (!key)
        {
            giveme_log("%s uh what the hell NULL verifier key\n", __FUNCTION__);
            goto out;
        }

        // Are we the one who should be verifying the block?
        if (key_cmp(key, giveme_public_key()))
        {
            struct block block;
            int res = giveme_network_make_block_for_transactions(&network.transactions, &block);
            if (res < 0)
            {
                giveme_log("%s failed to make a block for the transaction list\n", __FUNCTION__);
                goto out;
            }

            res = giveme_mine(&block);
            if (res < 0)
            {
                giveme_log("%s failed to mine the new block we verified\n", __FUNCTION__);
                goto out;
            }

            // Now we mined the block we are ready to send it
            giveme_network_broadcast_block(&block);
            network.last_block_send = time(NULL);
        }
    }

out:
    return 0;
}

int giveme_network_process_thread(struct queued_work *work)
{
    while (1)
    {
        giveme_network_ping();
        if (network.total_connected > 0 && (time(NULL) - network.last_chain_update_request) > GIVEME_NETWORK_UPDATE_CHANGE_REQUEST_SECONDS)
        {
            // Let's update our chain to the latest one
            giveme_network_update_chain();
            network.last_chain_update_request = time(NULL);
        }
        giveme_network_packets_process();
        giveme_network_make_block_if_possible();
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
    if (pthread_mutex_init(&network.ip_address_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize ip_address_lock mutex\n");
        res = -1;
        goto out;
    }

    if (pthread_mutex_init(&network.transactions.lock, NULL) != 0)
    {
        giveme_log("Failed to initialize network transaction mutex\n");
        res = -1;
        goto out;
    }

    pthread_mutex_lock(&network.ip_address_lock);
    giveme_network_load_ips();
    pthread_mutex_unlock(&network.ip_address_lock);

    giveme_network_initialize_connections();

    // To give some time for the IP's to be added before we get the most up to date blockchain
    // We will set the last request time so that it will trigger in 30 seconds
    network.last_chain_update_request = time(NULL) - GIVEME_NETWORK_UPDATE_CHANGE_REQUEST_SECONDS + 30;
out:
    if (res < 0)
    {
        giveme_log("Network initialization failed\n");
    }
}
