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
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include "network.h"
#include "log.h"
#include "tpool.h"
#include "vector.h"
#include "misc.h"
#include "package.h"
#include "blockchain.h"
#include "upnp.h"

//  GIVEME_NETWORK_TCP_PACKET_TYPE_PING,
//     GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE,
//     GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PUBLIC_KEY,
//     GIVEME_NETWORK_TCP_PACKET_TYPE_VERIFIED_BLOCK,
//     GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN,
//     GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN_RESPONSE,
//     GIVEME_NETWORK_TCP_PACKET_TYPE_DOWNLOADED_PACKAGE,
//     GIVEME_NETWORK_TCP_PACKET_TYPE_DOWNLOAD_PACKAGE_AS_HOST,
static size_t packet_payload_sizes[] = {
    sizeof(struct giveme_tcp_packet_ping),
    sizeof(struct giveme_tcp_packet_publish_package),
    sizeof(struct giveme_tcp_packet_publish_key),
    sizeof(struct giveme_tcp_packet_verified_block),
    sizeof(struct giveme_tcp_packet_update_chain),
    sizeof(struct giveme_tcp_packet_update_chain_response),
    sizeof(struct giveme_tcp_packet_package_downloaded),
    sizeof(struct giveme_tcp_packet_download_as_host_request)};

struct network network;

bool giveme_network_connection_connected(struct network_connection *connection);
int giveme_tcp_dataexchange_send_packet(int client, struct giveme_dataexchange_tcp_packet *packet);
int giveme_network_upload_chain(struct network_connection_data *conn, struct block *from_block, struct block *end_block, size_t total_blocks);
int giveme_tcp_dataexchange_recv_packet(int client, struct giveme_dataexchange_tcp_packet *packet);
struct network_connection_data *giveme_network_connection_data_new();
int giveme_tcp_network_accept(int sock, struct sockaddr_in *client_out);
int giveme_network_clear_transactions(struct network_transactions *transactions);
int giveme_tcp_send_bytes(int client, void *ptr, size_t amount);
struct network_package_download *giveme_network_downloads_find(const char *filehash);
int giveme_network_download_process_package_chunk(int sock, struct network_package_download *download, struct giveme_dataexchange_tcp_packet *packet, CHUNK_MAP_ENTRY *chunk_entry_out);
bool giveme_network_download_is_complete(struct network_package_download *download);
int giveme_finalize_download(struct network_package_download *download);
void giveme_network_download_remove_and_free(struct network_package_download *download);
void giveme_network_packet_process(struct giveme_tcp_packet *packet, struct network_connection *connection);
void giveme_network_disconnect(struct network_connection *connection);
int giveme_network_connection_socket(struct network_connection *connection);

void giveme_network_action_schedule_for_queue(struct action_queue *action_queue, NETWORK_ACTION_FUNCTION func, void *data, size_t size)
{
    struct network_action action;
    bzero(&action, sizeof(action));

    if (data)
    {
        action.data = data;
        action.size = size;
    }
    action.func = func;

    pthread_mutex_lock(&action_queue->lock);
    vector_push_at(action_queue->action_vector, 0, &action);

    pthread_mutex_unlock(&action_queue->lock);
}

/**
 * @brief If you use this function you may not schedule to the action queue directly for connections
 * You must always use this function because the underlying locking mechnism for the action queue is not used
 * the connection lock is used instead.
 *
 * @param connection
 * @param func
 * @param data
 * @param size
 */
void giveme_network_action_schedule_for_connection(struct network_connection *connection, NETWORK_ACTION_FUNCTION func, void *data, size_t size)
{
    if (pthread_mutex_lock(&connection->lock) < 0)
    {
        giveme_log("%s failed to lock the lock\n", __FUNCTION__);
    }

    if (!connection->data)
    {
        pthread_mutex_unlock(&connection->lock);
        return;
    }

    // No need to lock the action queue lock because we dont want nested locks
    // we have already locked the connection one.
    struct action_queue *action_queue = &connection->data->action_queue;
    struct network_action action;
    bzero(&action, sizeof(action));

    if (data)
    {
        action.data = data;
        action.size = size;
    }
    action.func = func;

    vector_push_at(action_queue->action_vector, 0, &action);
    pthread_mutex_unlock(&connection->lock);
}

void giveme_network_action_schedule(NETWORK_ACTION_FUNCTION func, void *data, size_t size)
{
    giveme_network_action_schedule_for_queue(&network.action_queue, func, data, size);
}

void giveme_network_action_execute(struct network_action *action)
{
    action->func(action->data, action->size);
}

/**
 * @brief All network actions must be done on this thread to avoid concurrency problems
 * Push your network commands to this vector.
 *
 */
int giveme_network_action_execute_first(struct action_queue *action_queue)
{

    // We use a stack action because we dont want to hold a lock for an entire
    // execution of the action where memory could easily be spilled and shifted.
    struct network_action saction;
    struct network_action *action = NULL;
    pthread_mutex_lock(&action_queue->lock);
    action = vector_back_or_null(action_queue->action_vector);
    if (action)
    {
        memcpy(&saction, action, sizeof(saction));
        vector_pop(action_queue->action_vector);
    }
    pthread_mutex_unlock(&action_queue->lock);
    if (action)
    {
        giveme_network_action_execute(&saction);
    }
    return 0;
}

int giveme_network_action_execute_first_no_locks(struct action_queue *action_queue)
{
    // We use a stack action because we dont want to hold a lock for an entire
    // execution of the action where memory could easily be spilled and shifted.
    struct network_action saction;
    struct network_action *action = NULL;
    action = vector_back_or_null(action_queue->action_vector);
    if (action)
    {
        memcpy(&saction, action, sizeof(saction));
        vector_pop(action_queue->action_vector);
    }
    if (action)
    {
        giveme_network_action_execute(&saction);
    }
    return 0;
}

int giveme_network_action_queue_initialize(struct action_queue *action_queue)
{
    int res = 0;
    if (pthread_mutex_init(&action_queue->lock, NULL) != 0)
    {
        giveme_log("Failed to initialize network action queue mutex\n");
        res = -1;
        goto out;
    }

    action_queue->action_vector = vector_create(sizeof(struct network_action));
out:
    return res;
}

void giveme_network_action_queue_destruct(struct action_queue *action_queue)
{
    pthread_mutex_destroy(&action_queue->lock);
    vector_free(action_queue->action_vector);
}

int giveme_network_action_thread(struct queued_work *work)
{
    while (1)
    {
        giveme_network_action_execute_first(&network.action_queue);
        usleep(10);
    }
    return 0;
}

/**
 * @brief Returns the packet payload size for the given packet.
 *
 * @param packet
 * @return size_t
 */
size_t giveme_tcp_packet_payload_size(struct giveme_tcp_packet *packet)
{
    size_t total_elements = sizeof(packet_payload_sizes) / sizeof(size_t);
    if (packet->data.type >= total_elements)
        return -1;

    return packet_payload_sizes[packet->data.type];
}

size_t giveme_tcp_header_size()
{
    sizeof(struct shared_signed_data);
    off_t shared_signed_data_offset = offsetof(struct giveme_tcp_packet, data.shared_signed_data);
    return shared_signed_data_offset + sizeof(struct shared_signed_data);
}

off_t giveme_tcp_payload_offset()
{
    return giveme_tcp_header_size();
}

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

struct network_transaction *giveme_network_network_transaction_get_by_id(int transaction_packet_id)
{
    for (int i = 0; i < GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK; i++)
    {
        if (network.transactions.awaiting[i] && giveme_tcp_packet_id(&network.transactions.awaiting[i]->packet) == transaction_packet_id)
        {
            return network.transactions.awaiting[i];
        }
    }

    return NULL;
}
int giveme_network_create_transaction_for_packet(struct giveme_tcp_packet *packet)
{
    int res = 0;
    pthread_mutex_lock(&network.transactions.lock);
    if (giveme_network_network_transaction_get_by_id(giveme_tcp_packet_id(packet)))
    {
        // We already are dealing with this packet.. we wont allow it again
        res = -1;
        goto out;
    }

    struct network_transaction **slot = giveme_network_find_network_transaction_slot();
    if (!slot)
    {
        giveme_log("%s out of transaction slots cannot create transaction\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    struct network_transaction *transaction = giveme_network_new_transaction();
    memcpy(&transaction->packet, packet, sizeof(struct giveme_tcp_packet));

    transaction->created = time(NULL);

    *slot = transaction;
    network.transactions.total++;

out:
    pthread_mutex_unlock(&network.transactions.lock);
    return res;
}

void giveme_network_delete_transaction(struct network_transaction *transaction)
{
    free(transaction);
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

int giveme_network_dataexchange_handle_request_block(struct giveme_dataexchange_tcp_packet *packet, struct network_connection_data *conn)
{
    giveme_log("%s block request, block_index=%i\n", __FUNCTION__, packet->request_block.block_index);
    struct block *block = giveme_blockchain_get_block_with_index(packet->request_block.block_index);
    if (!block)
    {
        giveme_log("%s block with index %i not found", __FUNCTION__, packet->request_block.block_index);
        // We couldn't find the block they asked us for sadly.
        int res = giveme_network_dataexchange_send_unable_to_help(conn);
        if (res < 0)
        {
            giveme_log("%s unable to send unable to help packet\n", __FUNCTION__);
        }
        return -1;
    }

    struct giveme_dataexchange_tcp_packet sending_block_packet = {};
    sending_block_packet.type = GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_SENDING_BLOCK;
    sending_block_packet.sending_block.block_index = packet->request_block.block_index;
    int res = giveme_tcp_dataexchange_send_packet(conn->sock, &sending_block_packet);
    if (res < 0)
    {
        giveme_log("%s failed to send GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_SENDING_BLOCK packet\n", __FUNCTION__);
        goto out;
    }

    // Now lets send the actual block
    res = giveme_tcp_send_bytes(conn->sock, block, sizeof(struct block));
    if (res < 0)
    {
        giveme_log("%s failed to send block\n", __FUNCTION__);
        goto out;
    }
out:
    return res;
}

int giveme_network_dataexchange_handle_package_request_chunk(struct giveme_dataexchange_tcp_packet *packet, struct network_connection_data *conn)
{
    struct package *package = giveme_package_get_by_filehash(packet->package_request_chunk.package.data_hash);
    off_t requested_chunk = packet->package_request_chunk.index;
    if (!package || !giveme_package_has_chunk(package, requested_chunk))
    {
        // We couldn't find the package or the chunk they asked for
        int res = giveme_network_dataexchange_send_unable_to_help(conn);
        if (res < 0)
        {
            giveme_log("%s unable to send unable to help packet\n", __FUNCTION__);
        }
        return -1;
    }
    int res = 0;

    size_t chunk_size_read = 0;
    const char *chunk_data = giveme_package_get_chunk(package, requested_chunk, &chunk_size_read);
    if (!chunk_data)
    {
        giveme_network_dataexchange_send_unable_to_help(conn);
        giveme_log("%s unable to load chunk %i\n", __FUNCTION__, (int)requested_chunk);
        res = -1;
        goto out;
    }

    struct giveme_dataexchange_tcp_packet send_chunk_packet = {};
    send_chunk_packet.type = GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_SEND_CHUNK;
    send_chunk_packet.package_send_chunk.index = packet->package_request_chunk.index;
    send_chunk_packet.package_send_chunk.chunk_size = chunk_size_read;
    strncpy(send_chunk_packet.package_send_chunk.package.data_hash, packet->package_request_chunk.package.data_hash, sizeof(send_chunk_packet.package_send_chunk.package.data_hash));

    res = giveme_tcp_dataexchange_send_packet(conn->sock, &send_chunk_packet);
    if (res < 0)
    {
        giveme_log("%s failed to send GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_SEND_CHUNK packet\n", __FUNCTION__);
        goto out;
    }

    // Now lets send the actual block
    res = giveme_tcp_send_bytes(conn->sock, (void *)chunk_data, chunk_size_read);
    if (res < 0)
    {
        giveme_log("%s failed to send block\n", __FUNCTION__);
        goto out;
    }

out:
    if (chunk_data)
    {
        free((void *)chunk_data);
    }
    return res;
}

bool giveme_network_dataexchange_close_on_request(int type)
{
    return type != GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_REQUEST_CHUNK;
}

void giveme_network_dataexchange_connection_close(struct network_connection_data *conn)
{
    close(conn->sock);
    free(conn);
}

/**
 * @brief Usually the send chunk packet is read with blocking as soon asa REQUEST_CHUNK has been sent.
 * However sometimes people are behind routers so would rather upload to us.
 *
 * @param packet
 * @param data
 * @return int
 */
int giveme_network_dataexchange_handle_package_send_chunk(struct giveme_dataexchange_tcp_packet *packet, struct network_connection_data *data)
{
    int res = 0;
    const char *package_hash = packet->package_send_chunk.package.data_hash;
    struct network_package_download *download = giveme_network_downloads_find(package_hash);
    if (!download)
    {
        giveme_log("%s somebody tried to send us a chunk for a package we are not downloading. It of course has been ignored\n", __FUNCTION__);
        return -1;
    }

    struct package *package = download->info.package;

    CHUNK_MAP_ENTRY chunk_entry = 0;
    res = giveme_network_download_process_package_chunk(data->sock, download, packet, &chunk_entry);
    if (res < 0)
    {
        giveme_log("%s we failed to process the package chunk for our download\n", __FUNCTION__);
        goto out;
    }

    if (giveme_network_download_is_complete(download))
    {
        giveme_log("%s the file was downloaded successfully into temporary file %s\n", __FUNCTION__, download->info.download.tmp_filename);
        giveme_log("%s moving to package directory\n", __FUNCTION__);
        res = giveme_finalize_download(download);
        giveme_network_download_remove_and_free(download);
    }

out:
    return 0;
}

int giveme_network_dataexchange_connection(struct queued_work *work)
{
    int res = 0;
    struct network_connection_data *conn = work->private;

    // Let's find out what this person wants from us
    struct giveme_dataexchange_tcp_packet packet;
    res = giveme_tcp_dataexchange_recv_packet(conn->sock, &packet);
    while (res >= 0)
    {
        switch (packet.type)
        {
        case GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_CHAIN_REQUEST:
            res = giveme_network_dataexchange_handle_chain_request(&packet, conn);
            break;

        case GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_REQUEST_BLOCK:
            res = giveme_network_dataexchange_handle_request_block(&packet, conn);
            break;

        case GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_REQUEST_CHUNK:
            res = giveme_network_dataexchange_handle_package_request_chunk(&packet, conn);
            break;

        case GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_SEND_CHUNK:
            res = giveme_network_dataexchange_handle_package_send_chunk(&packet, conn);
            break;

        default:
            giveme_log("%s unrecognized request for dataexchange, nothing we can do\n", __FUNCTION__);
        }

        // This was an ask and receive terminate type of connection.. so break!
        if (res < 0 || giveme_network_dataexchange_close_on_request(packet.type))
        {
            break;
        }

        res = giveme_tcp_dataexchange_recv_packet(conn->sock, &packet);
    }

    giveme_network_dataexchange_connection_close(conn);

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

int giveme_network_action_queue_thread_start()
{
    giveme_queue_work(giveme_network_action_thread, NULL);
    return 0;
}

int giveme_network_listen()
{
    int err = 0;
    network.listen_socket = giveme_tcp_network_listen(&network.listen_address, 0, GIVEME_TCP_PORT, GIVEME_TCP_SERVER_MAX_CONNECTIONS);
    if (network.listen_socket < 0)
    {
        giveme_log("Problem listening on port %i\n", GIVEME_TCP_PORT);
        err = -1;
        goto out;
    }

    // Start the accept thread.
    giveme_network_accept_thread_start();

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

    fcntl(connfd, F_SETFL, O_NONBLOCK);

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

int giveme_tcp_send_bytes_no_timeout(int client, void *ptr, size_t amount)
{
    int res = 0;
    size_t amount_left = amount;
    size_t amount_written = 0;
    size_t count = 0;
    while (amount_left > 0)
    {
        res = write(client, ptr + amount_written, amount_left);
        if (res < 0)
        {
            giveme_log("%s issue sending bytes err=%i\n", __FUNCTION__, errno);
            return res;
        }

        if (count > 1000)
        {
            giveme_log("%s stuck in loop\n", __FUNCTION__);
        }
        amount_written += res;
        amount_left -= res;
        count++;
    }
    return res;
}
int giveme_tcp_send_bytes(int client, void *ptr, size_t amount)
{
    // int res = 0;
    // fd_set fds;
    // FD_ZERO(&fds);
    // FD_SET(client, &fds);
    // struct timeval tv = {3, 0};
    // int st = select(client + 1, NULL, &fds, NULL, &tv);
    // if (st < 0)
    // {
    //     giveme_log("%s issue with select\n", __FUNCTION__);
    //     res = -1;
    // }
    // else if (FD_ISSET(client, &fds))
    // {
    int res = giveme_tcp_send_bytes_no_timeout(client, ptr, amount);
    // }
    // else
    // {
    //     giveme_log("%s client unresponsive for three seconds\n", __FUNCTION__);
    //     res = -1;
    // }

    return res;
}

int giveme_tcp_client_enable_blocking(int client)
{
    if (fcntl(client, F_SETFL, fcntl(client, F_GETFL) & ~O_NONBLOCK) < 0)
    {
        giveme_log("%s failed to put the socket in enable blocking mode\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

int giveme_tcp_client_disable_blocking(int client)
{
    if (fcntl(client, F_SETFL, fcntl(client, F_GETFL) | O_NONBLOCK) < 0)
    {
        giveme_log("%s failed to put the socket in non-blocking mode\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

/**
 * @brief [DEPRECATED]
 * 
 * @param client 
 * @param ptr 
 * @param amount 
 * @return int 
 */
int giveme_tcp_recv_bytes_no_block(int client, void *ptr, size_t amount)
{
    int res = 0;
    size_t amount_left = amount;

    struct timeval timeout;
    timeout.tv_sec = GIVEME_NETWORK_TCP_IO_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        giveme_log("Failed to set socket timeout\n");
        return -1;
    }

    giveme_tcp_client_disable_blocking(client);
    // Read the first byte non blocking so we can test if theirs any data on the stream
    res = recv(client, ptr, 1, 0);
    if (res <= 0)
    {
        giveme_tcp_client_enable_blocking(client);
        return -1;
    }

    amount_left--;
    giveme_tcp_client_enable_blocking(client);

    while (amount_left > 0)
    {
        res = recv(client, ptr + 1, amount_left, MSG_WAITALL);
        if (res <= 0)
        {
            res = -1;
            return res;
        }
        amount_left -= res;
    }
    return res;
}

int giveme_tcp_recv_bytes_no_timeout(int client, void *ptr, size_t amount)
{
    int res = 0;
    size_t amount_left = amount;
    size_t amount_read = 0;
    while (amount_left > 0)
    {
        res = recv(client, ptr + amount_read, amount_left, 0);
        if (res <= 0)
        {
            res = -1;
            return res;
        }
        amount_read += res;
        amount_left -= res;
    }
    return res;
}
int giveme_tcp_recv_bytes(int client, void *ptr, size_t amount, size_t timeout_seconds)
{
    int res = 0;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(client, &fds);
    struct timeval tv = {timeout_seconds, 0};
    int st = select(client + 1, NULL, &fds, NULL, &tv);
    if (st < 0)
    {
        giveme_log("%s issue with select\n", __FUNCTION__);
        res = -1;
    }
    else if (FD_ISSET(client, &fds))
    {
        res = giveme_tcp_recv_bytes_no_timeout(client, ptr, amount);
    }
    else
    {
        giveme_log("%s client unresponsive for three seconds\n", __FUNCTION__);
        res = -1;
    }

    return res;
}

int giveme_tcp_dataexchange_send_packet(int client, struct giveme_dataexchange_tcp_packet *packet)
{
    int res = giveme_tcp_send_bytes(client, packet, sizeof(struct giveme_dataexchange_tcp_packet)) > 0 ? 0 : -1;
    return res;
}

int giveme_tcp_packet_null_garbage(struct giveme_tcp_packet *packet)
{
    // We must NULL all unused bytes.
    // So that we get rid of garbage and it does not damage
    // the hashing process.
    char *payload_start = (char *)packet + giveme_tcp_payload_offset();
    char *payload_end = payload_start + giveme_tcp_packet_payload_size(packet);
    char *packet_end = (char *)packet + sizeof(struct giveme_tcp_packet);

    size_t total_unused_payload_bytes = 0;
    total_unused_payload_bytes = packet_end - payload_end;
    bzero(payload_end, total_unused_payload_bytes);

    return 0;
}

int giveme_tcp_send_packet(struct network_connection *connection, struct giveme_tcp_packet *packet)
{
    if (!giveme_network_connection_connected(connection))
    {
        return -1;
    }

    if (key_loaded(&connection->data->key) &&
        key_cmp(giveme_public_key(), &connection->data->key))
    {
        // The key of the connection we are sending a packet too is us...
        // We shouldn't send packets to ourself.. drop it..
        return -1;
    }

    // We must NULL all unused bytes.
    // So that we get rid of garbage and it does not damage
    // the hashing process.
    giveme_tcp_packet_null_garbage(packet);

    // Packet must be signed before being sent
    memcpy(&packet->pub_key, giveme_public_key(), sizeof(struct key));
    sha256_data(&packet->data, packet->data_hash, sizeof(packet->data));
    if (private_sign(packet->data_hash, strlen(packet->data_hash), &packet->sig) < 0)
    {
        giveme_log("%s failed to sign packet with my private key\n", __FUNCTION__);
        return -1;
    }

    int client = connection->data->sock;
    // We must send the initial header of the packet. Data following is the payload
    // the amount of bytes to be sent depends on the packet type

    int res = giveme_tcp_send_bytes(client, packet, giveme_tcp_header_size()) > 0 ? 0 : -1;
    if (res < 0)
    {
        return res;
    }

    // Send the payload of the packet
    res = giveme_tcp_send_bytes(client, (void *)packet + giveme_tcp_payload_offset(), giveme_tcp_packet_payload_size(packet));
    if (res == 0)
    {
        connection->data->last_contact = time(NULL);
    }

    return res;
}

int giveme_tcp_dataexchange_recv_packet(int client, struct giveme_dataexchange_tcp_packet *packet)
{
    // We must start by reading the packet header.
    int res = giveme_tcp_recv_bytes(client, packet, sizeof(struct giveme_dataexchange_tcp_packet), GIVEME_NETWORK_TCP_DATA_EXCHANGE_IO_TIMEOUT_SECONDS) > 0 ? 0 : -1;
    return res;
}

int giveme_verify_packet(struct giveme_tcp_packet *packet)
{
    int res = 0;
    // We must ensure the packet was signed by the sender
    // First rehash the data and compare it with the hash provided
    char recalculated_hash[SHA256_STRING_LENGTH] = {};
    sha256_data(&packet->data, recalculated_hash, sizeof(packet->data));
    if (strncmp(recalculated_hash, packet->data_hash, sizeof(recalculated_hash)) != 0)
    {
        giveme_log("%s provided hash does not match the hash we calculated\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Okay the hash matches, lets ensure the signature agrees. If it agrees then this
    // data was signed by the public key provided to us. Therefore proving that the given
    // public key in this packet wrote it.
    res = public_verify(&packet->pub_key, packet->data_hash, strlen(packet->data_hash), &packet->sig);
    if (res < 0)
    {
        giveme_log("%s public key verification failed, this packet was not signed correctly\n", __FUNCTION__);
        goto out;
    }
out:
    return res;
}

int giveme_tcp_recv_packet(struct network_connection *connection, struct giveme_tcp_packet *packet)
{
    if (!giveme_network_connection_connected(connection))
    {
        return -1;
    }

    if (key_cmp(giveme_public_key(), &packet->pub_key))
    {
        // This packet sent is from ourselves... we dont want to process packets from ourself..
        // drop it.
        return -1;
    }

    // Entire packet must start as NULL so that hashing process
    // is not damaged
    bzero(packet, sizeof(struct giveme_tcp_packet));

    int client = connection->data->sock;
    int res = giveme_tcp_recv_bytes(client, packet, giveme_tcp_header_size(), 3) > 0 ? 0 : -1;
    if (res < 0)
    {
        goto out;
    }

    res = giveme_tcp_recv_bytes(client, (void *)packet + giveme_tcp_payload_offset(), giveme_tcp_packet_payload_size(packet), GIVEME_NETWORK_TCP_IO_TIMEOUT_SECONDS);
    if (res < 0)
    {
        goto out;
    }

    connection->data->last_contact = time(NULL);
    res = giveme_verify_packet(packet);

out:
    if (res < 0)
    {
        // Repsonse below zero? Then NULL the packet we don't want to have any accidental processing of it..
        bzero(packet, sizeof(struct giveme_tcp_packet));
    }
    return res;
}

struct network_connection *giveme_network_get_connection(struct in_addr *addr)
{
    struct network_connection *connection = NULL;
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        pthread_mutex_lock(&network.connections[i].lock);
        if (network.connections[i].data &&
            memcmp(&network.connections[i].data->addr.sin_addr, addr, sizeof(network.connections[i].data->addr.sin_addr)) == 0)
        {
            // The IP is connected
            connection = &network.connections[i];
            pthread_mutex_unlock(&network.connections[i].lock);
            break;
        }
        pthread_mutex_unlock(&network.connections[i].lock);
    }

    return connection;
}

bool giveme_network_ip_connected(struct in_addr *addr)
{
    return giveme_network_get_connection(addr) != NULL;
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
    // if (inet_aton("127.0.0.1", &addr) == 0)
    // {
    //     giveme_log("inet_aton() failed\n");
    // }

    // giveme_network_ip_address_add(addr);

    if (inet_aton("137.184.101.59", &addr) == 0)
    {
        giveme_log("inet_aton() failed\n");
    }
    giveme_network_ip_address_add(addr);

    if (inet_aton("159.223.114.44", &addr) == 0)
    {
        giveme_log("inet_aton() failed\n");
    }
    giveme_network_ip_address_add(addr);
}

struct network_connection *giveme_network_connection_find_slot(pthread_mutex_t **lock_to_unlock)
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        if (pthread_mutex_trylock(&network.connections[i].lock) == EBUSY)
            continue;

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

struct network_connection *giveme_network_connection_add(struct network_connection_data *data)
{
    pthread_mutex_t *lock_to_unlock;
    struct network_connection *conn_slot = giveme_network_connection_find_slot(&lock_to_unlock);
    if (!conn_slot)
    {
        return NULL;
    }

    conn_slot->data = data;
    pthread_mutex_unlock(lock_to_unlock);

    network.total_connected++;

    return conn_slot;
}

int giveme_network_packets_process(struct network_connection *connection)
{
    int res = 0;
    int sock = giveme_network_connection_socket(connection);

    struct giveme_tcp_packet packet = {};
    if(giveme_tcp_recv_packet(connection, &packet) < 0)
    {
        goto out;
    }

    // We have a packet then process it.
    giveme_network_packet_process(&packet, connection);

out:
    return res;
}

int giveme_network_ping(struct network_connection *connection)
{
    struct giveme_tcp_packet packet = {};
    packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_PING;

    struct block *last_block = giveme_blockchain_back();
    assert(last_block);
    memcpy(packet.data.ping.last_hash, giveme_blockchain_block_hash(last_block), sizeof(packet.data.ping.last_hash));

    // We will only ping once a second.
    if (!connection->data || (time(NULL) - connection->data->last_contact) < 1)
    {
        return 0;
    }

    if (giveme_tcp_send_packet(connection, &packet) < 0)
    {
        // Problem sending packet? Then we should remove this socket from the connections
        giveme_log("%s problem sending packet to %s\n", __FUNCTION__, inet_ntoa(connection->data->addr.sin_addr));
        return -1;
    }

    return 0;
}

/**
 * @brief Each connection has its own thread for preformance reasons.
 *
 * @param work
 * @return int
 */
int giveme_network_connection_thread(struct queued_work *work)
{
    int res = 0;
    struct network_connection *connection = work->private;
    while (1)
    {
        if (pthread_mutex_lock(&connection->lock) < 0)
        {
            giveme_log("%s failed to lock connecton\n", __FUNCTION__);
            res = -1;
            break;
        }
        if (giveme_network_ping(connection) < 0)
        {
            giveme_network_disconnect(connection);
            pthread_mutex_unlock(&connection->lock);
            break;
        }

        if (giveme_network_packets_process(connection) < 0)
        {
            /*
             * Issue processing packets, disconnect the client. It is probably
             * already a dead socket anyway. Even if its not, we dont want to deal with this error
             * let them reconnect. It could be a spammer DDOS attack.. Better to disconnect
             * when their is unknown problems.
             *
             */
            giveme_network_disconnect(connection);
            pthread_mutex_unlock(&connection->lock);
            res = -1;
            break;
        }
        // Next step is to run the action queue and execute the last element on the stack.
        giveme_network_action_execute_first_no_locks(&connection->data->action_queue);

        pthread_mutex_unlock(&connection->lock);

        // Let's give some time for others to use the lock.
        usleep(100);
    }
    return res;
}
int giveme_network_connection_start(struct network_connection_data *data)
{
    struct network_connection *connection = giveme_network_connection_add(data);
    if (connection == NULL)
    {
        giveme_log("%s issue creating connection\n", __FUNCTION__);
        return -1;
    }

    giveme_queue_work(giveme_network_connection_thread, connection);
    return 0;
}

struct network_connection_data *giveme_network_connection_data_new()
{
    int res = 0;
    struct network_connection_data *data = calloc(1, sizeof(struct network_connection_data));
    giveme_network_action_queue_initialize(&data->action_queue);
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

    giveme_network_action_queue_destruct(&data->action_queue);
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

    int synRetries = 2; // Send a total of 3 SYN packets => Timeout ~7s
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof(synRetries)) < 0)
    {
        giveme_log("%s issue setting the maximum SYN packets\n", __FUNCTION__);
        return -1;
    }

    // connect the client socket to server socket
    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        giveme_log("%s connection with the server failed...\n", __FUNCTION__);
        return -1;
    }

    // Set the IO timeout now that we have connected.
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    if (flags & GIVEME_CONNECT_FLAG_ADD_TO_CONNECTIONS)
    {
        struct network_connection_data *data = giveme_network_connection_data_new();
        data->sock = sockfd;
        data->addr = servaddr;
        data->last_contact = time(NULL);
        if (giveme_network_connection_start(data) < 0)
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
    int res = giveme_tcp_network_connect(ip, GIVEME_TCP_PORT, GIVEME_CONNECT_FLAG_ADD_TO_CONNECTIONS) < 0 ? -1 : 0;
    if (res < 0)
    {
        giveme_log("%s failed to connect to ip\n", __FUNCTION__);
    }
    return res;
}
int giveme_network_connect()
{
    // If not much time has passed we will wait..
    if (time(NULL) - network.last_attempt_for_new_connections < 5)
    {
        return 0;
    }

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

    network.last_attempt_for_new_connections = time(NULL);
    return res;
}

void giveme_network_connection_connect_all_action_command_queue();
void giveme_network_connection_connect_all_action(void *data, size_t d_size)
{

    giveme_network_connect();
    // We must requeue ourselves
    giveme_network_connection_connect_all_action_command_queue();
}

/**
 * @brief Queues the connection command so that it will be added to the action queue.
 * Note this command will readd its self to the queue after exectuting, this results
 * in an infinite operation.
 *
 */
void giveme_network_connection_connect_all_action_command_queue()
{
    giveme_network_action_schedule(giveme_network_connection_connect_all_action, NULL, 0);
}

void giveme_network_disconnect(struct network_connection *connection)
{
    giveme_network_connection_data_free(connection->data);
    connection->data = NULL;
    network.total_connected--;
}

void giveme_network_relayed_packet_push(struct giveme_tcp_packet *packet)
{
    // Note that this does not push the pointer, the memory is copied to an element
    // in the vector.
    vector_push(network.relayed_packets, packet);
}

bool giveme_network_did_relay_packet(struct giveme_tcp_packet *packet)
{
    vector_set_peek_pointer(network.relayed_packets, 0);
    for (int i = 0; i < GIVEME_MAX_RELAYED_PACKET_ELEMENTS; i++)
    {
        struct giveme_tcp_packet *rpacket = vector_at(network.relayed_packets, i);
        if (rpacket && memcmp(rpacket, packet, sizeof(struct giveme_tcp_packet) == 0))
        {
            // We have a relayed packet that is equal to the one sent to us..
            // THis packet was already relayed!!!
            return true;
        }
    }

    return false;
}

void giveme_network_relay(struct giveme_tcp_packet *packet)
{
    if (giveme_network_did_relay_packet(packet))
    {
        // This packet has already been relayed. We must return to avoid an infinite loop
        // of people passing packets back and fourth forever.
        return;
    }

    // Let us broadcast this packet we received to all other peers
    giveme_network_broadcast(packet);

    // We must add the packet to our relayed packets vector so we know
    // not to send it again, resulting in an infinate loop
    giveme_network_relayed_packet_push(packet);
}

struct network_broadcast_private *giveme_network_new_broadcast_private(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    struct network_broadcast_private *private = calloc(1, sizeof(struct network_broadcast_private));
    struct giveme_tcp_packet *packet_copy = calloc(1, sizeof(struct giveme_tcp_packet));
    memcpy(packet_copy, packet, sizeof(struct giveme_tcp_packet));
    private->packet = packet_copy;
    private->connection = connection;
}

void giveme_network_broadcast_private_free(struct network_broadcast_private *private)
{
    free(private->packet);
    free(private);
}

void giveme_network_broadcast_action(void *data, size_t d_size)
{
    struct network_broadcast_private *private = data;
    struct giveme_tcp_packet *packet = private->packet;
    struct network_connection *connection = private->connection;
    if (giveme_tcp_send_packet(connection, packet) < 0)
    {
        // Problem sending packet? Then we should remove this socket from the connections
        giveme_log("%s problem sending packet to %s\n", __FUNCTION__, inet_ntoa(connection->data->addr.sin_addr));
    }

    // Done? great free the private.
    giveme_network_broadcast_private_free(private);
}

void giveme_network_broadcast(struct giveme_tcp_packet *packet)
{
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        struct network_broadcast_private *private = giveme_network_new_broadcast_private(packet, &network.connections[i]);
        giveme_network_action_schedule_for_connection(&network.connections[i], giveme_network_broadcast_action, private, sizeof(struct network_broadcast_private));
    }
}

struct network_last_hash *giveme_network_get_known_last_hash(const char *hash)
{
    vector_set_peek_pointer(network.hashes.hashes, 0);
    struct network_last_hash *last_hash = vector_peek_ptr(network.hashes.hashes);
    while (last_hash)
    {

        if (strncmp(last_hash->hash, hash, sizeof(last_hash->hash)) == 0)
        {
            return last_hash;
        }
        last_hash = vector_peek_ptr(network.hashes.hashes);
    }

    return NULL;
}

struct network_last_hash *giveme_network_create_known_last_hash(const char *hash)
{
    struct network_last_hash *last_hash = calloc(1, sizeof(struct network_last_hash));
    strncpy(last_hash->hash, hash, sizeof(last_hash->hash));

    vector_push(network.hashes.hashes, &last_hash);
    return last_hash;
}

void giveme_network_known_hashes_lock()
{
    pthread_mutex_lock(&network.hashes.lock);
}

void giveme_network_known_hashes_unlock()
{
    pthread_mutex_unlock(&network.hashes.lock);
}

void giveme_network_known_hashes_finalize_result()
{
    vector_set_peek_pointer(network.hashes.hashes, 0);
    struct network_last_hash *last_hash = vector_peek_ptr(network.hashes.hashes);
    struct network_last_hash *famous_hash = last_hash;
    while (last_hash)
    {
        if (last_hash->total == 0)
        {
            vector_pop_last_peek(network.hashes.hashes);
        }

        if (memcmp(last_hash->hash, famous_hash->hash, sizeof(last_hash->hash)) != 0 && last_hash->total >= famous_hash->total)
        {
            famous_hash = last_hash;
        }

        last_hash = vector_peek_ptr(network.hashes.hashes);
    }

    if (famous_hash)
    {
        strncpy(network.hashes.famous_hash, famous_hash->hash, sizeof(network.hashes.famous_hash));
    }
}

void giveme_network_reset_known_hash_counts()
{
    vector_set_peek_pointer(network.hashes.hashes, 0);
    struct network_last_hash *last_hash = vector_peek_ptr(network.hashes.hashes);
    while (last_hash)
    {
        last_hash->total = 0;
        last_hash = vector_peek_ptr(network.hashes.hashes);
    }
}

void giveme_network_update_known_hashes()
{
    giveme_log("%s updating known hashes\n", __FUNCTION__);
    giveme_network_reset_known_hash_counts();
    for (int i = 0; i < GIVEME_TCP_SERVER_MAX_CONNECTIONS; i++)
    {
        if (pthread_mutex_trylock(&network.connections[i].lock) == EBUSY)
        {
            continue;
        }

        if (!giveme_network_connection_connected(&network.connections[i]))
        {
            pthread_mutex_unlock(&network.connections[i].lock);
            continue;
        }

        char *peer_hash = network.connections[i].data->block_hash;
        char blank_hash[SHA256_STRING_LENGTH] = {};
        if (memcmp(peer_hash, blank_hash, sizeof(network.connections[i].data->block_hash)) == 0)
        {
            // This connection has not received a hash of the last block yet..
            // lets ignore him
            pthread_mutex_unlock(&network.connections[i].lock);
            continue;
        }

        struct network_last_hash *last_hash = giveme_network_get_known_last_hash(peer_hash);
        if (!last_hash)
        {
            // Does not exist yet? Okay we need to create it
            last_hash = giveme_network_create_known_last_hash(peer_hash);
        }

        last_hash->total++;
        pthread_mutex_unlock(&network.connections[i].lock);
    }
    giveme_network_known_hashes_finalize_result();
}

int giveme_network_connection_socket(struct network_connection *connection)
{
    return connection->data ? connection->data->sock : -1;
}

void giveme_network_packet_handle_publish_package(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    char tmp_hash[SHA256_STRING_LENGTH];
    sha256_data(&packet->data.publish_package.data, tmp_hash, sizeof(packet->data.publish_package.data));
    if (public_verify_key_sig_hash(&packet->data.publish_package.signature, tmp_hash) < 0)
    {
        giveme_log("%s the package to be published was incorrectly signed\n", __FUNCTION__);
        return;
    }

    // We got a blank IP? Then this is not from a relay
    // we should set the IP to the IP address who connected to us.
    // This will be the IP address of the peer who holds the package data that can
    // be downloaded a later date.. All downlaoders will also become peers  or seeds
    // of the file data.
    if (!packet->data.publish_package.ip_address[0])
    {
        // No IP address was provided therefore we must set it.
        strncpy(packet->data.publish_package.ip_address, giveme_connection_ip(connection), sizeof(packet->data.publish_package.ip_address));
    }
    int res = giveme_network_create_transaction_for_packet(packet);
    if (res < 0)
    {
        giveme_log("%s problem creating transaction for the package creation request\n", __FUNCTION__);
        return;
    }

    giveme_log("%s Publish package request for packet %s by %s\n", __FUNCTION__, packet->data.publish_package.data.name, giveme_connection_ip(connection));

    // Package publish packets should be relayed
    giveme_network_relay(packet);
}

void giveme_network_packet_handle_publish_key(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    // We have a request to publish a public key, lets add it to the transactions
    giveme_log("%s Publish public key request for packet %s by %s\n", __FUNCTION__, packet->data.publish_public_key.name, giveme_connection_ip(connection));
    int res = giveme_network_create_transaction_for_packet(packet);
    if (res < 0)
    {
        giveme_log("%s failed to create a transaction for the packet provided for IP %s\n", __FUNCTION__, giveme_connection_ip(connection));
    }
}

void giveme_network_clear_network_transactions_of_block(struct block *block)
{
    // Clear all transactions.. in future we should loop through block transactions
    // and only delete those that are in the block as theirs a small chance
    // we could lose transactions that arent in a block if we clear them all.
    giveme_network_clear_transactions(&network.transactions);
}

void giveme_network_my_awaiting_transactions_remove_succeeded()
{
    for (int i = 0; i < network.my_awaiting_transactions.mem_total; i++)
    {
        // We don't care about packets that are not awaiting transactions
        // these are free slots... get rid of them.
        struct network_awaiting_transaction blank_transaction = {};
        if (memcmp(&blank_transaction, &network.my_awaiting_transactions.data[i], sizeof(blank_transaction)) == 0)
        {
            continue;
        }

        struct network_awaiting_transaction *transaction = &network.my_awaiting_transactions.data[i];
        if (transaction->state == GIVEME_NETWORK_AWAITING_TRANSACTION_STATE_SUCCESS)
        {
            memcpy(transaction, &blank_transaction, sizeof(struct network_awaiting_transaction));
            network.my_awaiting_transactions.total--;
        }
    }
}

const char *giveme_network_awaiting_transaction_state_string(struct network_awaiting_transaction *transaction)
{
    const char *ret = "Unknown";
    if (transaction->state == GIVEME_NETWORK_AWAITING_TRANSACTION_STATE_FAILED)
    {
        ret = "failed";
    }
    else if (transaction->state == GIVEME_NETWORK_AWAITING_TRANSACTION_STATE_SUCCESS)
    {
        ret = "success";
    }
    else if (transaction->state == GIVEME_NETWORK_AWAITING_TRANSACTION_STATE_PENDING)
    {
        ret = "pending";
    }
    return ret;
}
struct network_awaiting_transaction *giveme_network_my_awaiting_transactions_get_by_index(int index)
{
    if (index >= network.my_awaiting_transactions.total)
    {
        return NULL;
    }

    return &network.my_awaiting_transactions.data[index];
}

struct network_awaiting_transaction *giveme_network_my_awaiting_transactions_get_by_packet_id(int id)
{
    for (int i = 0; i < network.my_awaiting_transactions.mem_total; i++)
    {
        // We don't care about packets that are not awaiting transactions
        // these are free slots... get rid of them.
        struct network_awaiting_transaction blank_transaction = {};
        if (memcmp(&blank_transaction, &network.my_awaiting_transactions.data[i], sizeof(blank_transaction)) == 0)
        {
            continue;
        }

        struct network_awaiting_transaction *transaction = &network.my_awaiting_transactions.data[i];
        if (giveme_tcp_packet_id(&transaction->packet) == id)
        {
            return transaction;
        }
    }

    return NULL;
}

int giveme_network_handle_added_block(struct block *block)
{
    for (int i = 0; i < GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK; i++)
    {
        // Ignore all empty transactions.
        struct block_transaction empty_transaction = {};
        if (memcmp(&empty_transaction, &block->data.transactions.transactions[i], sizeof(empty_transaction)) == 0)
        {
            continue;
        }

        struct block_transaction *target_transaction = &block->data.transactions.transactions[i];
        giveme_network_my_awaiting_transactions_lock();
        // Let's grab the ID of this target transaction and remove it from our awaiting transactions
        // since we have now processed it.
        struct network_awaiting_transaction *awaiting_transaction =
            giveme_network_my_awaiting_transactions_get_by_packet_id(target_transaction->data.shared_signed_data.data.id);
        if (awaiting_transaction)
        {
            // We had an awaiting transaction for the block transaction.
            // Now we can confirm we have a block for this transaction
            // lets update the state
            awaiting_transaction->state = GIVEME_NETWORK_AWAITING_TRANSACTION_STATE_SUCCESS;
            giveme_log("%s resolved awaiting transaction with ID %i, block %s has resolved it\n", __FUNCTION__, target_transaction->data.shared_signed_data.data.id, giveme_blockchain_block_hash(block));
        }

        giveme_network_my_awaiting_transactions_unlock();
    }
}

void giveme_network_rebroadcast_my_pending_transactions()
{
    giveme_network_my_awaiting_transactions_lock();

    for (int i = 0; i < network.my_awaiting_transactions.mem_total; i++)
    {
        struct network_awaiting_transaction blank_transaction = {};
        struct network_awaiting_transaction *transaction = &network.my_awaiting_transactions.data[i];
        if (memcmp(transaction, &blank_transaction, sizeof(blank_transaction)) == 0)
        {
            continue;
        }

        // We only want to rebroadcast pending transactions.
        if (transaction->state != GIVEME_NETWORK_AWAITING_TRANSACTION_STATE_PENDING)
        {
            continue;
        }

        giveme_network_broadcast(&transaction->packet);
    }
    giveme_network_my_awaiting_transactions_unlock();
}

int giveme_network_packet_handle_verified_block(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    if (time(NULL) - network.blockchain.last_block_receive < GIVEME_SECONDS_TO_MAKE_BLOCK)
    {
        // We already have made the block for this cycle
        giveme_log("%s verified block has been resent to us, we will ignore it as we already registered a block this cycle\n", __FUNCTION__);
        return -1;
    }
    giveme_log("%s new verified block discovered, attempting to add to chain\n", __FUNCTION__);
    // We must ensure that this is the verifiers public key who signed this
    if (!key_cmp(giveme_blockchain_get_verifier_key(), &packet->pub_key))
    {
        giveme_log("%s someone other than the verifier published a block, we will ignore it\n", __FUNCTION__);
        return -1;
    }

    int res = giveme_blockchain_add_block(&packet->data.verified_block.block);
    if (res < 0)
    {
        giveme_log("%s there was a problem adding the block to the chain, it may contain malformed or illegal transactions\n", __FUNCTION__);
        return -1;
    }

    giveme_network_handle_added_block(&packet->data.verified_block.block);
    giveme_network_clear_transactions(&network.transactions);

    // Now we need to rebroadcast pending transactions that are still not completed.
    giveme_network_rebroadcast_my_pending_transactions();
    network.blockchain.last_block_receive = time(NULL);
    network.blockchain.last_block_processed = time(NULL);

    return 0;
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
    strncpy(packet.sending_chain.start_hash, giveme_blockchain_block_hash(from_block), sizeof(packet.sending_chain.start_hash));
    strncpy(packet.sending_chain.last_hash, giveme_blockchain_block_hash(end_block), sizeof(packet.sending_chain.last_hash));
    packet.sending_chain.blocks_left_to_end = total_blocks;
    res = giveme_tcp_dataexchange_send_packet(conn->sock, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to send sending chain packet\n", __FUNCTION__);
        goto out;
    }

    giveme_blockchain_begin_crawl(giveme_blockchain_block_hash(from_block), NULL);

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

    size_t blocks_left_to_end = 0;
    struct block *block = giveme_blockchain_block(packet->data.update_chain.last_hash, &blocks_left_to_end);
    struct block *last_block = giveme_blockchain_back();

    // Seems they JAM when they ask eachother for their chains.
    if (block && blocks_left_to_end > 0)
    {
        struct giveme_tcp_packet res_packet = {};
        res_packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN_RESPONSE;
        res_packet.data.update_chain_response.blocks_left_to_end = blocks_left_to_end;
        res_packet.data.update_chain_response.data_port = GIVEME_TCP_DATA_EXCHANGE_PORT;
        memcpy(res_packet.data.update_chain_response.last_hash, giveme_blockchain_block_hash(last_block), sizeof(res_packet.data.update_chain_response.last_hash));
        memcpy(res_packet.data.update_chain_response.start_hash, giveme_blockchain_block_hash(block), sizeof(res_packet.data.update_chain_response.start_hash));
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
    int res = 0;
    giveme_log("%s download blockchain from peer\n", __FUNCTION__);
    int sock = giveme_tcp_network_connect(addr, port, 0);
    if (sock < 0)
    {
        giveme_log("%s Failed to connect to peer to download chain\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    giveme_log("%s connected, downloading chain\n", __FUNCTION__);
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

    for (size_t i = 0; i <= total_blocks; i++)
    {
        struct block block;
        giveme_log("%s downloading block %i\n", __FUNCTION__, i);
        if (giveme_tcp_recv_bytes(sock, &block, sizeof(struct block), GIVEME_NETWORK_TCP_DATA_EXCHANGE_IO_TIMEOUT_SECONDS) < 0)
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

    giveme_log("%s downloaded entire blockchain\n", __FUNCTION__);

out:
    close(sock);
    return res;
}

void giveme_network_packet_handle_update_chain_response(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    giveme_log("%s received packet for update chain will add to peers to download chain from\n", __FUNCTION__);

    // Let us add this peer to the chain
    vector_push(network.blockchain.peers_with_blocks, connection->data);
}

bool giveme_network_needs_chain_update()
{
    struct block *last_block = giveme_blockchain_back();
    if (!last_block)
    {
        return false;
    }

    // Let's first check if our current last block is equal to the famous hash.
    // If it is we are done and the chain does not need an update.
    if (S_EQ(giveme_blockchain_block_hash(last_block), network.hashes.famous_hash))
    {
        return false;
    }

    // We should go back several blocks to see if we do have the famous hash
    // if so then we are the most up to date chain or an illegal fork
    int res = giveme_blockchain_begin_crawl(giveme_blockchain_block_hash(last_block), NULL);
    if (res < 0)
    {
        giveme_log("%s problem initiating crawl procedure\n", __FUNCTION__);
        return false;
    }

    int count = 0;
    struct block *crawled_block = giveme_blockchain_crawl_next(BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN);
    while (crawled_block && count < 10)
    {
        if (S_EQ(giveme_blockchain_block_hash(crawled_block), network.hashes.famous_hash))
        {
            return false;
        }

        count++;
    }
    return true;
}

bool giveme_network_needs_chain_update_do_lock()
{
    bool needs_update = false;
    // Nested locks... yikes..
    giveme_network_known_hashes_lock();
    needs_update = !S_EQ(network.hashes.famous_hash, giveme_blockchain_block_hash(giveme_blockchain_back()));
    giveme_network_known_hashes_unlock();

    return needs_update;
}
void giveme_network_packet_handle_ping(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    memcpy(connection->data->block_hash, packet->data.ping.last_hash, sizeof(connection->data->block_hash));
}

/**
 * @brief This is called when someone wants us to upload a package to them.
 *
 * @param packet
 * @param connectiom
 */
int giveme_network_packet_handle_download_package_as_host(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    int res = 0;
    char *package_filehash = packet->data.download_package_as_host.filehash;
    struct package *package = giveme_package_get_by_filehash(package_filehash);
    if (!package)
    {
        // Package is non-existant on the blockchain.
        return -1;
    }

    if (!package->downloaded.yes)
    {
        // We don't have the package?? Then we cannot upload anything, lets ignore this packet.
        return -1;
    }

    // Lets craft a response.
    struct giveme_tcp_packet res_packet;
    bzero(&res_packet, sizeof(res_packet));

out:
    return res;
}

void giveme_network_packet_handle_downloaded_package(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    // Someone has signified they have downlaoded a package and wants
    // to become apart of the peer pool in exchange for money tips..
    // Let's ensure this is added to the chain and known by all peers.

    // If the IP address provided is NULL then we can assume
    // the current peer is the one who downloaded the package
    // set the IP address and relay to all peers.
    if (!packet->data.downloaded_package.ip_address[0])
    {
        // No IP address was provided therefore we must set it.
        strncpy(packet->data.downloaded_package.ip_address, giveme_connection_ip(connection), sizeof(packet->data.downloaded_package.ip_address));
    }
    int res = giveme_network_create_transaction_for_packet(packet);
    if (res < 0)
    {
        giveme_log("%s problem creating transaction for the downloaded package request\n", __FUNCTION__);
        return;
    }

    // Lets relay the packet to all known peers.
    giveme_network_relay(packet);
}

void giveme_network_packet_process(struct giveme_tcp_packet *packet, struct network_connection *connection)
{
    // Is the packet signed? If so we need to verify its signed correctly
    if (giveme_tcp_packet_signed(packet))
    {
        // We have a signed packet?? Let's ensure its signed correctly with the signature
        // given to us.
        int res = giveme_tcp_packet_signature_verify(packet);
        if (res < 0)
        {
            // We do not deal with packets not signed correctly... that is a security concern
            // we ignore all packets not signed properly.
            return;
        }
    }

    switch (packet->data.type)
    {
    case GIVEME_NETWORK_TCP_PACKET_TYPE_PING:
        giveme_network_packet_handle_ping(packet, connection);
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

    case GIVEME_NETWORK_TCP_PACKET_TYPE_DOWNLOADED_PACKAGE:
        giveme_network_packet_handle_downloaded_package(packet, connection);
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_DOWNLOAD_PACKAGE_AS_HOST:
        giveme_network_packet_handle_download_package_as_host(packet, connection);
        break;
    }
}

int giveme_network_create_block_transaction_for_network_transaction_new_package(struct network_transaction *transaction, struct block_transaction *transaction_out)
{
    char tmp_hash[SHA256_STRING_LENGTH];
    transaction_out->data.type = BLOCK_TRANSACTION_TYPE_NEW_PACKAGE;
    memcpy(&transaction_out->data.publish_package.data, &transaction->packet.data.publish_package.data, sizeof(transaction_out->data.publish_package.data));
    memcpy(&transaction_out->data.publish_package.ip_address, &transaction->packet.data.publish_package.ip_address, sizeof(transaction_out->data.publish_package.ip_address));
    transaction_out->data.publish_package.signature = transaction->packet.data.publish_package.signature;

    sha256_data(&transaction_out->data.publish_package.data, tmp_hash, sizeof(transaction_out->data.publish_package.data));
    if (public_verify_key_sig_hash(&transaction_out->data.publish_package.signature, tmp_hash) < 0)
    {
        giveme_log("%s received new package transaction but the package data was signed incorrectly\n", __FUNCTION__);
        bzero(transaction_out, sizeof(struct block_transaction));
        return -1;
    }
    return 0;
}

int giveme_network_create_block_transaction_for_network_transaction_downloaded_package(struct network_transaction *transaction, struct block_transaction *transaction_out)
{
    transaction_out->data.type = BLOCK_TRANSACTION_TYPE_DOWNLOADED_PACKAGE;
    strncpy(transaction_out->data.downloaded_package.ip_address, transaction->packet.data.downloaded_package.ip_address, sizeof(transaction_out->data.downloaded_package.ip_address));
    return 0;
}

int giveme_network_create_block_transaction_for_network_transaction(struct network_transaction *transaction, struct block_transaction *transaction_out)
{
    int res = 0;

    // No transaction provided? then just return zero.

    switch (transaction->packet.data.type)
    {
    case GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PACKAGE:
        res = giveme_network_create_block_transaction_for_network_transaction_new_package(transaction, transaction_out);
        break;

    case GIVEME_NETWORK_TCP_PACKET_TYPE_DOWNLOADED_PACKAGE:
        giveme_log("Downloaded package blcok transaction created\n");
        res = giveme_network_create_block_transaction_for_network_transaction_downloaded_package(transaction, transaction_out);
        break;
    case GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PUBLIC_KEY:
        transaction_out->data.type = BLOCK_TRANSACTION_TYPE_NEW_KEY;
        strncpy(transaction_out->data.publish_public_key.name, transaction->packet.data.publish_public_key.name, sizeof(transaction_out->data.publish_public_key.name));
        memcpy(&transaction_out->data.publish_public_key.pub_key, &transaction->packet.data.publish_public_key.pub_key, sizeof(transaction_out->data.publish_public_key.pub_key));
        break;

    default:
        res = -1;
    }

    transaction_out->data.timestamp = transaction->created;
    // We must copy the signed data from the network transaction to the block transaction
    // this will allow us to preserve important data signed by the creator
    // of the packet that made the network transaction
    memcpy(&transaction_out->data.shared_signed_data, &transaction->packet.data.shared_signed_data, sizeof(transaction_out->data.shared_signed_data));
    sha256_data(&transaction_out->data, transaction_out->hash, sizeof(transaction_out->data));
    return res;
}

int giveme_network_clear_transactions(struct network_transactions *transactions)
{
    for (int i = 0; i < GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK; i++)
    {
        giveme_network_delete_transaction(transactions->awaiting[i]);
    }
    memset(transactions->awaiting, 0, sizeof(transactions->awaiting));
    transactions->total = 0;
    return 0;
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

    block_out->data.timestamp = time(NULL);
out:
    return res;
}

void giveme_network_broadcast_block(struct block *block)
{
    struct giveme_tcp_packet packet;
    bzero(&packet, sizeof(packet));

    packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_VERIFIED_BLOCK;
    memcpy(&packet.data.verified_block.block, block, sizeof(packet.data.verified_block.block));
    giveme_network_broadcast(&packet);
}

void giveme_network_update_chain()
{
    giveme_log("%s asking the network for the most up to date chain\n", __FUNCTION__);
    struct giveme_tcp_packet update_chain_packet;
    bzero(&update_chain_packet, sizeof(update_chain_packet));
    update_chain_packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_UPDATE_CHAIN;
    memcpy(update_chain_packet.data.update_chain.last_hash, giveme_blockchain_block_hash(giveme_blockchain_back()), sizeof(update_chain_packet.data.update_chain.last_hash));
    giveme_network_broadcast(&update_chain_packet);
}

struct network_package_download *giveme_network_new_package_download(struct package *package)
{
    struct network_package_download *res = NULL;
    int tmp_filename_fp = 0;
    struct network_package_download *download = calloc(1, sizeof(struct network_package_download));
    download->info.connections.peers = vector_create(sizeof(struct network_package_download_uploading_peer));

    if (pthread_mutex_init(&download->info.connections.mutex, NULL) != 0)
    {
        giveme_log("%s failed to initialize the connections mutex\n", __FUNCTION__);
        goto out_err;
    }

    if (pthread_mutex_init(&download->info.download.mutex, NULL) != 0)
    {
        giveme_log("%s failed to initialize the download mutex\n", __FUNCTION__);
        goto out_err;
    }

    download->info.package = package;
    download->info.download.chunks.total = giveme_package_total_chunks(package);

    tmpnam(download->info.download.tmp_filename);
    tmp_filename_fp = open(download->info.download.tmp_filename, O_RDWR | O_CREAT, (mode_t)0600);
    if (!tmp_filename_fp)
    {
        giveme_log("%s failed to create temporary file\n", __FUNCTION__);
        goto out_err;
    }

    // Truncate the temporary file so we have enough room for all the chunks we will download
    if (ftruncate(tmp_filename_fp, package->details.size) < 0)
    {
        giveme_log("%s failed to resize temporary file\n", __FUNCTION__);
        goto out_err;
    }

    // We must memory map create a file for this package we are downloading.
    download->info.download.data = mmap(0, package->details.size, PROT_READ | PROT_WRITE, MAP_SHARED, tmp_filename_fp, 0);
    if (download->info.download.data == MAP_FAILED)
    {
        giveme_log("Failed to memory map package temporary file into memory\n", __FUNCTION__);
        goto out_err;
    }

    // Setup a chunk map which lets all threads know which parts of the file
    // have been downloaded already.
    download->info.download.chunks.chunk_map = calloc(download->info.download.chunks.total, sizeof(CHUNK_MAP_ENTRY));
    download->info.download.tmp_fp = tmp_filename_fp;

    res = download;

out_err:
    if (!res)
    {
        if (download)
        {
            free(download);
            vector_free(download->info.connections.peers);
        }

        if (tmp_filename_fp)
        {
            close(tmp_filename_fp);
        }
    }
    return res;
}

void giveme_network_download_package_free_peer(struct network_package_download_uploading_peer *peer)
{
    free(peer);
}

size_t giveme_network_download_package_peer_count(struct network_package_download *download)
{
    return vector_count(download->info.connections.peers);
}

void giveme_network_free_package_download(struct network_package_download *download)
{
    close(download->info.download.tmp_fp);
    munmap(download->info.download.data, download->info.package->details.size);
    free(download->info.download.chunks.chunk_map);

    struct network_package_download_uploading_peer *peer = vector_back_ptr_or_null(download->info.connections.peers);
    while (peer)
    {
        giveme_network_download_package_free_peer(peer);
        peer = vector_back_ptr_or_null(download->info.connections.peers);
    }
    vector_free(download->info.connections.peers);
    free(download);
}

char *giveme_network_download_file_data_ptr(struct network_package_download *download)
{
    return download->info.download.data;
}

struct network_package_download_uploading_peer *giveme_network_download_package_new_peer(const char *ip_address, struct network_package_download *download)
{
    struct network_package_download_uploading_peer *uploading_peer = calloc(1, sizeof(struct network_package_download_uploading_peer));
    strncpy(uploading_peer->ip_address, ip_address, sizeof(uploading_peer->ip_address));
    uploading_peer->download = download;
    return uploading_peer;
}

bool giveme_network_download_is_complete(struct network_package_download *download)
{
    return (download->info.download.chunks.downloaded == download->info.download.chunks.total);
}
/**
 * @brief Finds a chunk that needs to be downloaded from a peer.
 *
 * @param download
 * @param chunk_out
 * @return int
 */
int giveme_network_download_package_get_required_chunk(struct network_package_download *download, int *chunk_out)
{
    for (int i = 0; i < download->info.download.chunks.total; i++)
    {
        CHUNK_MAP_ENTRY entry = download->info.download.chunks.chunk_map[i];

        if (entry == GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_NOT_DOWNLOADED)
        {
            // We have a chunk available that needs downloading
            *chunk_out = i;
            return GIVEME_NETWORK_PACKAGE_DOWNLOAD_INCOMPLETE;
        }
    }

    bool is_downloaded = giveme_network_download_is_complete(download);
    if (is_downloaded)
    {
        return GIVEME_NETWORK_PACKAGE_DOWNLOAD_COMPLETED;
    }

    return GIVEME_NETWORK_PACKAGE_DOWNLOAD_NO_CHUNKS_AVAILABLE;
}

void giveme_network_download_package_set_chunk_status(struct network_package_download *download, int chunk, CHUNK_MAP_ENTRY entry)
{
    download->info.download.chunks.chunk_map[chunk] = entry;
}

int giveme_network_download_process_package_chunk(int sock, struct network_package_download *download, struct giveme_dataexchange_tcp_packet *packet, CHUNK_MAP_ENTRY *chunk_entry_out)
{
    CHUNK_MAP_ENTRY new_entry_status = 0;
    struct package *package = download->info.package;
    int res = 0;
    if (strncmp(packet->package_send_chunk.package.data_hash, package->details.filehash, sizeof(packet->package_send_chunk.package.data_hash)) != 0)
    {
        giveme_log("%s peer responded with a chunk from a package we are not asking for\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    off_t chunk_index = packet->package_send_chunk.index;
    // We are in agreement of the chunk to be sent, lets download the data directly into
    // the package in question.
    off_t offset = giveme_package_file_offset_for_chunk(package, chunk_index);
    size_t total_bytes = packet->package_send_chunk.chunk_size;
    char *data = giveme_network_download_file_data_ptr(download) + offset;

    // Will we be in bounds?
    if (package->details.size < offset + total_bytes)
    {
        // We aren't in bounds, this could be an attacker.
        giveme_log("%s peer attempted an out of bounds attack which was caught\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Okay it is safe for us to read the data into the buffer lets do it.
    res = giveme_tcp_recv_bytes(sock, data, total_bytes, GIVEME_NETWORK_TCP_DATA_EXCHANGE_IO_TIMEOUT_SECONDS);
    if (res < 0)
    {
        giveme_log("%s failed to read the chunk bytes from the peer\n", __FUNCTION__);
        res = -1;
        goto out;
    }
out:
    new_entry_status = GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_DOWNLOADED;
    if (res < 0)
    {
        // We failed?? Then the new status must be a not downloaded status
        // so another thread can pick up the slack.
        new_entry_status = GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_NOT_DOWNLOADED;
    }
    pthread_mutex_lock(&download->info.download.mutex);
    giveme_network_download_package_set_chunk_status(download, chunk_index, new_entry_status);
    if (new_entry_status == GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_DOWNLOADED)
    {
        download->info.download.chunks.downloaded++;
    }
    pthread_mutex_unlock(&download->info.download.mutex);

    *chunk_entry_out = new_entry_status;
    return res;
}

int giveme_network_download_request_chunk(struct network_package_download *download, int required_chunk, int sock, struct network_package_download_uploading_peer *peer)
{
    int res = 0;
    struct package *package = download->info.package;
    CHUNK_MAP_ENTRY new_entry_status = 0;

    // We have a required chunk that needs downloading, lets ask for it.
    struct giveme_dataexchange_tcp_packet packet = {};
    packet.type = GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_REQUEST_CHUNK;
    packet.package_request_chunk.index = required_chunk;
    strncpy(packet.package_request_chunk.package.data_hash, package->details.filehash, sizeof(packet.package_request_chunk.package.data_hash));
    res = giveme_tcp_dataexchange_send_packet(sock, &packet);
    if (res < 0)
    {
        giveme_log("%s we failed to send the request chunk packet to the peer.\n", __FUNCTION__);
        goto out;
    }

    res = giveme_tcp_dataexchange_recv_packet(sock, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to receive response packet from peer\n", __FUNCTION__);
        goto out;
    }

    // Can the peer help us?
    if (packet.type == GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_UNABLE_TO_HELP)
    {
        giveme_log("%s the peer is unable to help us with this chunk for some reason..\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    if (packet.type != GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_PACKAGE_SEND_CHUNK)
    {
        giveme_log("%s the peer responded in an unexpected way, they sent a packet of type %i\n", __FUNCTION__, packet.type);
        res = -1;
        goto out;
    }

    // We have a chunk packet response.
    if (packet.package_send_chunk.index != required_chunk)
    {
        giveme_log("%s peer responded with a chunk we did not ask for\n", __FUNCTION__);
        res = -1;
        goto out;
    }
out:
    res = giveme_network_download_process_package_chunk(sock, download, &packet, &new_entry_status);
    if (res >= 0)
    {
        // Has the peer successfully uploaded a chunk to us. Then let us mark him one chunk up
        // Best uploaders get higher rewards.
        if (new_entry_status == GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_DOWNLOADED)
        {
            if (peer)
            {
                pthread_mutex_lock(&download->info.connections.mutex);
                peer->chunks_uploaded++;
                pthread_mutex_unlock(&download->info.connections.mutex);
            }
        }
    }
    return res;
}
int giveme_network_download_package_peer_session_download_chunk(struct network_package_download_uploading_peer *peer, int sock)
{
    int res = GIVEME_NETWORK_PACKAGE_DOWNLOAD_COMPLETED;
    struct network_package_download *download = peer->download;
    struct package *package = download->info.package;
    // What chunks are not downloaded yet? Let's find one
    int required_chunk = 0;

    pthread_mutex_lock(&download->info.download.mutex);
    res = giveme_network_download_package_get_required_chunk(download, &required_chunk);
    if (res == GIVEME_NETWORK_PACKAGE_DOWNLOAD_INCOMPLETE)
    {
        giveme_network_download_package_set_chunk_status(download, required_chunk, GIVEME_NETWORK_PACKAGE_DOWNLOAD_CHUNK_MAP_CHUNK_DOWNLOAD_IN_PROGRESS);
    }
    pthread_mutex_unlock(&download->info.download.mutex);

    if (res < 0)
    {
        giveme_log("%s an error occured..\n", __FUNCTION__);
        res = -1;
        goto out;
    }
    else if (res == GIVEME_NETWORK_PACKAGE_DOWNLOAD_COMPLETED)
    {
        giveme_log("%s the download has completed, we have no more chunks to ask for all threads succeeded in downloading the package from severla peers\n", __FUNCTION__);
        goto out;
    }
    else if (res == GIVEME_NETWORK_PACKAGE_DOWNLOAD_NO_CHUNKS_AVAILABLE)
    {
        giveme_log("%s there are no chunks available for download as all threads are downloading the last chunks we know of\n", __FUNCTION__);
        goto out;
    }

    res = giveme_network_download_request_chunk(download, required_chunk, sock, peer);
out:
    return res;
}
int giveme_network_download_package_peer_session_download_chunks(struct network_package_download_uploading_peer *peer, int sock)
{
    int res = 1;
    // Keep downloading until the file is done.
    while (res > 0 && res != GIVEME_NETWORK_PACKAGE_DOWNLOAD_COMPLETED)
    {
        res = giveme_network_download_package_peer_session_download_chunk(peer, sock);
    }
    return res;
}

int giveme_network_download_package_peer_session(struct queued_work *work)
{
    int res = 0;
    struct network_package_download_uploading_peer *peer = work->private;

    struct in_addr peer_addr;
    if (inet_aton(peer->ip_address, &peer_addr) == 0)
    {
        giveme_log("%s failed to convert string IP address into numerical\n", __FUNCTION__);
        goto out;
    }

    /**
     * @brief We will try up to five times to connect to the peer and download the blocks
     * after five tries we will give up.
     *
     */
    int tries = 0;
    do
    {
        // We need to connect to the peer and hopefully we are successful.
        int sock = giveme_tcp_network_connect(peer_addr, GIVEME_TCP_DATA_EXCHANGE_PORT, 0);
        if (sock < 0)
        {
            giveme_log("%s Failed to connect to peer who holds the package we want. Hopefully another peer will be available\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        // We are connected to this peer.. Alright lets ask for the chunks of the file.
        // several threads will ask several peers until the file is downloaded entirely.

        res = giveme_network_download_package_peer_session_download_chunks(peer, sock);
        close(sock);
        tries++;
    } while (res < 0 && tries <= 2);
out:
    return res;
}

struct network_package_download *giveme_network_downloads_find(const char *filehash)
{
    vector_set_peek_pointer(network.downloads, 0);
    struct network_package_download *current_download = vector_peek_ptr(network.downloads);
    while (current_download)
    {
        if (strncmp(current_download->info.package->details.filehash, filehash,
                    sizeof(current_download->info.package->details.filehash)) == 0)
        {
            // We have the download we are looking for
            return current_download;
        }
        current_download = vector_peek_ptr(network.downloads);
    }

    return NULL;
}

void giveme_network_downloads_push(struct network_package_download *download)
{
    vector_push(network.downloads, &download);
}

void giveme_network_downloads_remove(struct network_package_download *download)
{
    vector_pop_value(network.downloads, download);
}
struct network_package_summary_download_info giveme_network_download_info(struct network_package_download *download)
{
    struct network_package_summary_download_info info = {};
    strncpy(info.datahash, download->info.package->details.filehash, sizeof(info.datahash));
    info.downloaded_chunks = download->info.download.chunks.downloaded;
    info.total_chunks = download->info.download.chunks.total;
    info.percentage = 100 * info.downloaded_chunks / info.total_chunks;
    return info;
}

void giveme_network_download_add_peer(struct network_package_download *download, struct network_package_download_uploading_peer *peer)
{
    vector_push(download->info.connections.peers, &peer);
}

int giveme_network_package_downloaded(const char *filehash)
{
    int res = 0;
    struct giveme_tcp_packet packet = {};
    packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_DOWNLOADED_PACKAGE;
    struct block_transaction_downloaded_package_data *downloaded_package_data =
        &packet.data.shared_signed_data.data.downloaded_package.data;
    strncpy(downloaded_package_data->filehash, filehash, sizeof(downloaded_package_data->filehash));

    // Apply money tips here... TODO..

    res = giveme_tcp_packet_sign(&packet);
    if (res < 0)
    {
        giveme_log("%s failed to sign our package_downloaded TCP packet...\n", __FUNCTION__);
        goto out;
    }

    // Let's broadcast this downloaded package packet.
    giveme_network_broadcast(&packet);

out:
    return res;
}

/**
 * @brief This is a failsafe command in the event we cannot download a package due to the other node
 * being behind a highly restricted router that does not support UPNP. With this command we will become the host
 * and the user will upload to us instead of us downloading directly from them as the host.
 *
 * @param package_filehash
 * @param filename_out
 * @param filename_size
 * @return int
 */
int giveme_network_download_package_as_host(const char *package_filehash, char *filename_out, size_t filename_size)
{
    int res = 0;
    struct package *package = giveme_package_get_by_filehash(package_filehash);
    if (!package)
    {
        // Package is non-existant on the blockchain.
        return -1;
    }

    if (package->downloaded.yes)
    {
        // We already have downlaoded this package, it is in cache.
        strncpy(filename_out, package->downloaded.filepath, filename_size);
        return 0;
    }

    struct network_package_download *download = giveme_network_new_package_download(package);
    if (!download)
    {
        giveme_log("%s issue creating a new download, nothing we can do right now\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    pthread_mutex_lock(&network.downloads_lock);
    giveme_network_downloads_push(download);
    pthread_mutex_unlock(&network.downloads_lock);

    struct giveme_tcp_packet packet;
    bzero(&packet, sizeof(packet));
    packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_DOWNLOAD_PACKAGE_AS_HOST;
    strncpy(packet.data.download_package_as_host.filehash, package_filehash, sizeof(packet.data.download_package_as_host.filehash));
    // Alright lets broadcast this package and wait for people to come
    giveme_network_broadcast(&packet);

out:
    return res;
}

void giveme_network_download_remove_and_free(struct network_package_download *download)
{
    pthread_mutex_lock(&network.downloads_lock);
    giveme_network_downloads_remove(download);
    pthread_mutex_unlock(&network.downloads_lock);
    giveme_network_free_package_download(download);
}

int giveme_finalize_download(struct network_package_download *download)
{
    int res = 0;
    struct package *package = download->info.package;
    // Chunks match downloaded? Let's ensure the integrity of the data sent to us.
    char tmp_hash[SHA256_STRING_LENGTH];
    sha256_file(download->info.download.tmp_filename, tmp_hash);
    if (strncmp(tmp_hash, package->details.filehash, sizeof(tmp_hash)) != 0)
    {
        giveme_log("%s the hash of the file we downloaded does not match the package hash, a peer lied to us when sending us a chunk\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    char package_path[PATH_MAX];
    strncpy(package_path, giveme_package_path(package->details.filehash), sizeof(package_path));
    rename(download->info.download.tmp_filename, package_path);
    strncpy(package->downloaded.filepath, package_path, sizeof(package->downloaded.filepath));
    package->downloaded.yes = true;

out:
    return res;
}
int giveme_network_download_package(const char *package_filehash, char *filename_out, size_t filename_size)
{
    struct network_package_download *download = NULL;
    // We must download the different chunks from several peers for efficiency.
    struct package *package = giveme_package_get_by_filehash(package_filehash);
    if (!package)
    {
        // Theres no mention of the package on the chain cache..
        // Package does not exist or is unknown to us
        return -1;
    }
    if (package->downloaded.yes)
    {
        // We already have the package? Then what do we need to download it for..
        strncpy(filename_out, package->downloaded.filepath, filename_size);
        return 0;
    }

    // Let's go through all the peers to download chunks from
    char addresses[PACKAGE_MAX_KNOWN_IP_ADDRESSES][GIVEME_IP_STRING_SIZE];
    int res = giveme_package_get_ips(package, addresses);
    if (res <= 0)
    {
        giveme_log("%s no available IP addresses found for the package or their was an error\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    int total_ips = res;

    // We have all the peers who have this package, now we need to create a new download
    download = giveme_network_new_package_download(package);
    if (!download)
    {
        giveme_log("%s issue creating a new download, nothing we can do right now\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    pthread_mutex_lock(&network.downloads_lock);
    giveme_network_downloads_push(download);
    pthread_mutex_unlock(&network.downloads_lock);

    struct thread_pool *pool = giveme_thread_pool_create(GIVEME_PACKAGE_DOWNLOAD_TOTAL_THREADS, GIVEME_THREAD_POOL_FLAG_END_THREADS_WHEN_NO_JOBS);
    if (!pool)
    {
        giveme_log("%s failed to create a thread pool for the package download\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // We now need to start several threads which will connect to every peer here
    // and download the required chunks.
    for (int i = 0; i < total_ips; i++)
    {
        struct network_package_download_uploading_peer *peer = giveme_network_download_package_new_peer(addresses[i], download);
        giveme_queue_work_for_pool(pool, giveme_network_download_package_peer_session, peer);
        giveme_log("%s queued connection for peer %s will attempt to connect and download chunks of package\n", __FUNCTION__, addresses[i]);
    }

    giveme_log("%s starting pool jobs to download the package\n", __FUNCTION__);
    giveme_thread_pool_start_for_pool(pool);
    giveme_log("%s waiting for download to finish\n", __FUNCTION__);
    giveme_thread_pool_join_and_free(pool);
    giveme_log("%s all threads completed, download done.\n", __FUNCTION__);

    // Let's now see if we was successful in downloading the file.
    if (!giveme_network_download_is_complete(download))
    {
        giveme_log("%s not all chunks were sent to us.. data error download unexpectedly failed\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    giveme_log("%s the file was downloaded successfully into temporary file %s\n", __FUNCTION__, download->info.download.tmp_filename);
    giveme_log("%s moving to package directory\n", __FUNCTION__);

    res = giveme_finalize_download(download);
    if (res < 0)
    {
        giveme_log("%s issue finalizing the download\n", __FUNCTION__);
        goto out;
    }
    int r = giveme_network_package_downloaded(package->details.filehash);
    if (r < 0)
    {
        giveme_log("%s package was downloaded successfully but we failed to transmit a downloaded packet, so that other peers can download this package from us in the future\n", __FUNCTION__);
    }

out:
    if (download)
    {
        giveme_network_download_remove_and_free(download);
    }
    return res;
}

int giveme_network_update_chain_for_block_from_peer(struct network_connection_data *peer, int block_index)
{
    int res = 0;
    giveme_log("%s connecting to peer to download block %i\n", __FUNCTION__, block_index);
    int sock = giveme_tcp_network_connect(peer->addr.sin_addr, GIVEME_TCP_DATA_EXCHANGE_PORT, 0);
    if (sock < 0)
    {
        giveme_log("%s Failed to connect to peer to download block\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    giveme_log("%s connected, downloading block\n", __FUNCTION__);
    // First thing we do is send a request for a chain
    struct giveme_dataexchange_tcp_packet packet = {};
    packet.type = GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_REQUEST_BLOCK;
    packet.request_block.block_index = block_index;
    res = giveme_tcp_dataexchange_send_packet(sock, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to send data exchange packet\n", __FUNCTION__);
        goto out;
    }

    // Now we expect a resposne
    res = giveme_tcp_dataexchange_recv_packet(sock, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to receive resposne from data exchange server\n", __FUNCTION__);
        goto out;
    }

    if (packet.type != GIVEME_DATAEXCHANGE_NETWORK_PACKET_TYPE_SENDING_BLOCK)
    {
        giveme_log("%s unexpected packet type provided for data exchange type=%i\n", __FUNCTION__, packet.type);
        res = -1;
        goto out;
    }

    if (packet.sending_block.block_index != block_index)
    {
        giveme_log("%s peer is sending us a block we did not ask for, we want block %i but block %i was provided\n", __FUNCTION__, block_index, packet.sending_block.block_index);
        res = -1;
        goto out;
    }

    // Let's now read the block
    struct block block = {};
    res = giveme_tcp_recv_bytes(sock, &block, sizeof(struct block), GIVEME_NETWORK_TCP_DATA_EXCHANGE_IO_TIMEOUT_SECONDS);
    if (res < 0)
    {
        giveme_log("%s peer did not send us a block\n", __FUNCTION__);
        goto out;
    }

    // We have the block the peer sent now attempting to add it to the chain
    res = giveme_blockchain_add_block(&block);
out:

    close(sock);
    return res;
}

void giveme_network_update_chain_from_found_peers()
{
    giveme_blockchain_changes_prepare();
    int tail_next_index = giveme_blockchain_index() + 1;
    int current_index = tail_next_index;
    size_t current_chunk_count = 0;
    while (giveme_network_needs_chain_update() && vector_count(network.blockchain.peers_with_blocks) > 0)
    {
        vector_set_peek_pointer(network.blockchain.peers_with_blocks, 0);
        struct network_connection_data *peer = vector_peek(network.blockchain.peers_with_blocks);
        struct network_connection_data *last_peer = NULL;

        int attempts = 0;
        while (peer && attempts < 10)
        {
            // We got to keep pinging as this process can take a long time
            // we want people to still know we exist.
            //   giveme_network_ping();

            int res = giveme_network_update_chain_for_block_from_peer(peer, current_index);
            if (res < 0)
            {
                giveme_log("%s we was sent an unsuitable block.. We will try all over again\n", __FUNCTION__);
                giveme_blockchain_changes_discard();
                giveme_blockchain_changes_prepare();
                current_index = giveme_blockchain_index() + 1;
                current_chunk_count = 0;
                // We will not ask the last peer or this peer for a block again, as one of them
                // lied to us..
                vector_pop_at_data_address(network.blockchain.peers_with_blocks, peer);
                if (last_peer)

                {
                    vector_pop_at_data_address(network.blockchain.peers_with_blocks, last_peer);
                }
                last_peer = NULL;
                peer = vector_peek(network.blockchain.peers_with_blocks);
                attempts++;
                continue;
            }

            current_chunk_count++;
            current_index++;
            if (current_chunk_count > 100)
            {
                giveme_blockchain_changes_apply();
                giveme_blockchain_changes_prepare();
                current_chunk_count = 0;
            }
            last_peer = peer;
            peer = vector_peek(network.blockchain.peers_with_blocks);
        }
    }
    giveme_blockchain_changes_apply();
    giveme_blockchain_give_ready_signal();
}
int giveme_network_make_block_if_possible()
{
    int res = 0;
    // Have we already made a block in the last five minutes
    if (time(NULL) - network.blockchain.last_block_processed < GIVEME_SECONDS_TO_MAKE_BLOCK)
    {
        // We already have made the block for this cycle
        return 0;
    }

    // Every 5 minutes we want to make a new block, lets see if its time.
    // We will only make the block if we are the next elected.
    size_t current_time_since_last_tick = time(NULL) % GIVEME_SECONDS_TO_MAKE_BLOCK;
    // We give a leighway of five seconds in regards to the five minutes
    // as sometimes theres delays right.
    if (current_time_since_last_tick >= 0 && current_time_since_last_tick <= 15)
    {
        giveme_log("%s time to make a new block\n", __FUNCTION__);
        struct key *key = giveme_blockchain_get_verifier_key();
        if (!key)
        {
            giveme_log("%s uh what the hell NULL verifier key\n", __FUNCTION__);
            goto out;
        }

        giveme_log("%s validator expected key=%s\n", __FUNCTION__, key->key);
        // Are we the one who should be verifying the block?
        if (key_cmp(key, giveme_public_key()))
        {
            if (giveme_network_needs_chain_update())
            {
                giveme_log("%s we may be the verifier but our chain isnt up to date, therefore we cant make this block\n", __FUNCTION__);
                goto out;
            }

            struct block block;
            res = giveme_network_make_block_for_transactions(&network.transactions, &block);
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

            // Clear our transactions
            giveme_network_clear_transactions(&network.transactions);
            network.blockchain.last_block_processed = time(NULL);
        }
    }

    if (current_time_since_last_tick >= 16 && current_time_since_last_tick <= 17)
    {
        // Fifteen seconds without even receving the block we was supposed too...
        // The verifier let us down
        giveme_log("%s verifier was a no show\n", __FUNCTION__);
        //  network.last_block_processed = time(NULL);
    }

out:
    return 0;
}

bool giveme_network_time_to_forward_ports()
{
    // Every hour we forward the ports again
    return (time(NULL) - network.last_upnp_forward) > 3600;
}
void giveme_network_process_action_queue();
void giveme_network_process_action(void *data, size_t d_size)
{
    if (giveme_network_time_to_forward_ports())
    {
        giveme_network_upnp_port_forward();
    }

    // Kept getting issues with lock order. We will lock in the actual loop
    // this may result in slower operations than expected.
    giveme_lock_chain();
    if (network.blockchain.chain_requesting_update && (time(NULL) - network.blockchain.last_chain_update_request) > 30)
    {
        // We have given 30 seconds for people to tell us they are able to update our chain...
        // Now its time to preform the update.
        giveme_network_update_chain_from_found_peers();
        network.blockchain.chain_requesting_update = false;
    }
    else if (giveme_network_needs_chain_update_do_lock() &&
             network.total_connected > 0 &&
             (time(NULL) - network.blockchain.last_chain_update_request) > GIVEME_NETWORK_UPDATE_CHAIN_REQUEST_SECONDS)
    {
        // Let's update our chain to the latest one
        giveme_network_update_chain();
        network.blockchain.last_chain_update_request = time(NULL);
        network.blockchain.chain_requesting_update = true;
    }
    else if (time(NULL) - network.blockchain.last_chain_update_request > 120)
    {
        // Nobody updated the chain and its been 120 seconds?
        // Then we are probably up to date... lets give the blockchain ready signal..
        giveme_blockchain_give_ready_signal();
        network.blockchain.chain_requesting_update = false;
    }
    else if (time(NULL) - network.blockchain.last_known_hashes_update > 5)
    {
        giveme_network_known_hashes_lock();
        giveme_network_update_known_hashes();
        giveme_network_known_hashes_unlock();
        network.blockchain.last_known_hashes_update = time(NULL);
    }

    giveme_network_make_block_if_possible();
    giveme_unlock_chain();
    usleep(10);

    // We must requeue this action so that it will be processed infinetly
    giveme_network_process_action_queue();
}
void giveme_network_process_action_queue()
{
    giveme_network_action_schedule(giveme_network_process_action, NULL, 0);
}

void giveme_network_accepted_action(void *data_in, size_t d_size)
{

    struct network_connection_data *data = data_in;
    // Have they already connected to us ? If so then we need to drop them
    // one connection per node..
    if (giveme_network_ip_connected(&data->addr.sin_addr))
    {
        giveme_log("%s dropping accepted client who is already connected %s\n", __FUNCTION__, inet_ntoa(data->addr.sin_addr));
        giveme_network_connection_data_free(data);
        return;
    }

    data->last_contact = time(NULL);
    if (giveme_network_connection_start(data) < 0)
    {
        giveme_network_connection_data_free(data);
    }
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
            goto out;
        }

        // The actual work should be handled by the action thread.. Hopefully its processed fast enough!
        giveme_network_action_schedule(giveme_network_accepted_action, data, sizeof(struct network_connection_data));
    out:
        usleep(10);
    }
    return 0;
}
void giveme_network_accept_thread_start()
{
    giveme_queue_work(giveme_network_accept_thread, NULL);
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

/**
 * @brief Returns the file size for the awaiting for transactions file if their was total_blocks provided
 *
 * @param total_blocks
 * @return size_t
 */
size_t giveme_network_my_awaiting_transactions_file_size(size_t total_blocks)
{
    return total_blocks * sizeof(struct network_awaiting_transaction);
}

size_t giveme_network_my_awaiting_transactions_count_for_size(size_t filesize)
{
    return filesize / sizeof(struct network_awaiting_transaction);
}

char *giveme_my_awaiting_transactions_path()
{
    static char awaiting_for_block_path[PATH_MAX];
    sprintf(awaiting_for_block_path, "%s/%s/%s", getenv(GIVEME_DATA_BASE_DIRECTORY_ENV), GIVEME_DATA_BASE, GIVEME_MY_AWAITING_TRANSACTIONS_PATH);
    return awaiting_for_block_path;
}

struct network_awaiting_transaction *giveme_network_my_awaiting_transaction_find_free_slot()
{
    for (int i = 0; i < network.my_awaiting_transactions.mem_total; i++)
    {
        struct network_awaiting_transaction blank_packet = {};
        if (memcmp(&blank_packet, &network.my_awaiting_transactions.data[i], sizeof(blank_packet)) == 0)
        {
            return &network.my_awaiting_transactions.data[i];
        }
    }

    return NULL;
}

int giveme_network_my_awaiting_transactions_resize()
{
    size_t new_block_count = network.my_awaiting_transactions.mem_total + GIVEME_AWAITING_FOR_BLOCK_MINIMUM_BLOCK_SIZE;
    size_t new_file_size = giveme_network_my_awaiting_transactions_file_size(new_block_count);
    munmap(network.my_awaiting_transactions.data, giveme_network_my_awaiting_transactions_file_size(network.my_awaiting_transactions.mem_total));
    ftruncate(network.my_awaiting_transactions.fp, new_file_size);
    network.my_awaiting_transactions.data = mmap(0, new_file_size, PROT_READ | PROT_WRITE, MAP_SHARED, network.my_awaiting_transactions.fp, 0);
    if (network.my_awaiting_transactions.data == MAP_FAILED)
    {
        giveme_log("%s Failed to map our awaiting transactions file into memory\n", __FUNCTION__);
        return -1;
    }

    network.my_awaiting_transactions.mem_total = new_block_count;
    return 0;
}

void giveme_network_my_awaiting_transactions_lock()
{
    pthread_mutex_lock(&network.my_awaiting_transactions.lock);
}

void giveme_network_my_awaiting_transactions_unlock()
{
    pthread_mutex_unlock(&network.my_awaiting_transactions.lock);
}

int giveme_network_my_awaiting_transaction_add(struct network_awaiting_transaction *transaction)
{
    int res = 0;
    transaction->state = GIVEME_NETWORK_AWAITING_TRANSACTION_STATE_PENDING;
    struct network_awaiting_transaction *available_slot = giveme_network_my_awaiting_transaction_find_free_slot();
    if (!available_slot)
    {
        res = giveme_network_my_awaiting_transactions_resize();
        if (res < 0)
        {
            goto out;
        }

        available_slot = giveme_network_my_awaiting_transaction_find_free_slot();
        if (!available_slot)
        {
            res = -1;
            goto out;
        }
    }

    // We have an available slot, copy the packet data in.
    memcpy(available_slot, transaction, sizeof(struct network_awaiting_transaction));

    // Let's increment the total avaialble
    network.my_awaiting_transactions.total++;
out:
    // Okay we added the awaiting transaction but we are not done
    // broadcast the packet for first time discovery
    giveme_network_broadcast(&transaction->packet);
    return res;
}

size_t giveme_network_count_my_awaiting_transactions()
{
    size_t count = 0;
    for (int i = 0; i < network.my_awaiting_transactions.mem_total; i++)
    {
        struct network_awaiting_transaction blank_transaction = {};
        if (memcmp(&blank_transaction, &network.my_awaiting_transactions.data[i], sizeof(struct network_awaiting_transaction)) != 0)
        {
            count++;
        }
    }
    return count;
}

int giveme_network_initialize_my_awaiting_transactions()
{
    if (pthread_mutex_init(&network.my_awaiting_transactions.lock, NULL) != 0)
    {
        giveme_log("Failed to initialize my_awaiting_transactions mutex\n");
        return -1;
    }

    bool exists = file_exists(giveme_my_awaiting_transactions_path());

    network.my_awaiting_transactions.fp = open(giveme_my_awaiting_transactions_path(), O_RDWR | O_CREAT, (mode_t)0600);
    size_t total_bytes = 0;
    if (exists)
    {
        struct stat s;
        fstat(network.my_awaiting_transactions.fp, &s);
        total_bytes = s.st_size;
    }
    if (!exists)
    {
        total_bytes = giveme_network_my_awaiting_transactions_file_size(GIVEME_AWAITING_FOR_BLOCK_MINIMUM_BLOCK_SIZE);
        ftruncate(network.my_awaiting_transactions.fp, total_bytes);
    }
    network.my_awaiting_transactions.data = mmap(0, total_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, network.my_awaiting_transactions.fp, 0);

    if (network.my_awaiting_transactions.data == MAP_FAILED)
    {
        giveme_log("%s Failed to map our awaiting transactions file into memory\n", __FUNCTION__);
        return -1;
    }
    network.my_awaiting_transactions.mem_total = giveme_network_my_awaiting_transactions_count_for_size(total_bytes);
    network.my_awaiting_transactions.total = giveme_network_count_my_awaiting_transactions();

    return 0;
}

void giveme_network_initialize()
{
    int res = 0;
    memset(&network, 0, sizeof(struct network));
    network.ip_addresses = vector_create(sizeof(struct in_addr));
    network.blockchain.peers_with_blocks = vector_create(sizeof(struct network_connection_data));
    if (pthread_mutex_init(&network.ip_address_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize ip_address_lock mutex\n");
        res = -1;
        goto out;
    }

    giveme_network_action_queue_initialize(&network.action_queue);

    if (pthread_mutex_init(&network.hashes.lock, NULL) != 0)
    {
        giveme_log("Failed to initialize network hashes mutex\n");
        res = -1;
        goto out;
    }

    if (pthread_mutex_init(&network.downloads_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize downloads mutex\n");
        res = -1;
        goto out;
    }

    res = giveme_network_initialize_my_awaiting_transactions();
    if (res < 0)
    {
        goto out;
    }

    network.hashes.hashes = vector_create(sizeof(struct network_last_hash *));
    network.downloads = vector_create(sizeof(struct network_package_download *));

    if (pthread_mutex_init(&network.transactions.lock, NULL) != 0)
    {
        giveme_log("Failed to initialize network transaction mutex\n");
        res = -1;
        goto out;
    }

    pthread_mutex_lock(&network.ip_address_lock);
    giveme_network_load_ips();
    pthread_mutex_unlock(&network.ip_address_lock);

    network.relayed_packets = vector_create_extra(sizeof(struct giveme_tcp_packet), GIVEME_MAX_RELAYED_PACKET_ELEMENTS, 0);
    giveme_network_initialize_connections();

    // To give some time for the IP's to be added before we get the most up to date blockchain
    // We will set the last request time so that it will trigger in 5 seconds
    network.blockchain.chain_requesting_update = false;
    network.blockchain.last_chain_update_request = time(NULL) - GIVEME_NETWORK_UPDATE_CHAIN_REQUEST_SECONDS + 5;
out:
    if (res < 0)
    {
        giveme_log("Network initialization failed\n");
    }
}

struct shared_signed_data *giveme_tcp_packet_shared_signed_data(struct giveme_tcp_packet *packet)
{
    return &packet->data.shared_signed_data;
}

/**
 * Generates a random transaction ID and then signs this packet
 * @param packet
 */
int giveme_tcp_packet_sign(struct giveme_tcp_packet *packet)
{
    int res = 0;
    packet->data.shared_signed_data.data.id = rand() % 999999999;
    char tmp_hash[SHA256_STRING_LENGTH];
    sha256_data(&packet->data.shared_signed_data.data, tmp_hash, sizeof(packet->data.shared_signed_data.data));
    res = private_sign_key_sig_hash(&packet->data.shared_signed_data.signature, tmp_hash);
    if (res < 0)
    {
        giveme_log("%s failed to sign the packet with our private key\n", __FUNCTION__);
        goto out;
    }

    packet->data.shared_signed_data.is_signed = true;
out:
    return res;
}

int giveme_tcp_packet_id(struct giveme_tcp_packet *packet)
{
    if (!packet->data.shared_signed_data.is_signed)
    {
        return -1;
    }

    return packet->data.shared_signed_data.data.id;
}

bool giveme_tcp_packet_signed(struct giveme_tcp_packet *packet)
{
    return packet->data.shared_signed_data.is_signed;
}

int giveme_tcp_packet_signature_verify(struct giveme_tcp_packet *packet)
{
    if (!giveme_tcp_packet_signed(packet))
    {
        // The packet is not signed so we will just say it was verified correctly
        return 0;
    }

    int res = 0;
    res = giveme_verify_signed_data(&packet->data.shared_signed_data);
    if (res < 0)
    {
        giveme_log("%s the packet was incorrectly signed.\n", __FUNCTION__);
        res = -1;
        goto out;
    }
out:
    return res;
}

void giveme_network_upnp_port_forward()
{
    // Let's open ourselves up to the world
    upnp_redirect(GIVEME_TCP_PORT, GIVEME_TCP_PORT);
    upnp_redirect(GIVEME_TCP_DATA_EXCHANGE_PORT, GIVEME_TCP_DATA_EXCHANGE_PORT);
    network.last_upnp_forward = time(NULL);
}