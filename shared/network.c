#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "network.h"
#include "log.h"
#include "tpool.h"
#include "vector.h"
#include "misc.h"
#include "blockchain.h"

struct network network;

int giveme_tcp_network_upload_chain(int sockfd, const char *hash);
int giveme_tcp_network_download_chain(struct blockchain *chain, int sockfd, struct block *last_known_block, int flags);
void giveme_udp_broadcast_no_localhost(struct giveme_udp_packet *packet);
int giveme_udp_network_handle_packet(struct giveme_udp_packet *packet, struct in_addr *from_address);

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

bool giveme_network_ip_address_exists_on_ignore_broadcast_list(struct in_addr *addr)
{
    vector_set_peek_pointer(network.ignore_broadcast_ips, 0);
    struct in_addr *vec_addr = vector_peek(network.ignore_broadcast_ips);
    while (vec_addr)
    {
        if (memcmp(vec_addr, addr, sizeof(struct in_addr)) == 0)
            return true;

        vec_addr = vector_peek(network.ignore_broadcast_ips);
    }

    return false;
}

bool giveme_network_clear_ignore_broadcast_list()
{
    vector_clear(network.ignore_broadcast_ips);
    return true;
}

void giveme_network_ip_address_add(struct in_addr addr)
{
    if (!giveme_network_ip_address_exists(&addr))
    {
        vector_push(network.ip_addresses, &addr);
    }
}

void giveme_network_ip_address_ignore(struct in_addr addr)
{
    vector_push(network.ignore_broadcast_ips, &addr);
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
    timeout.tv_sec = GIVEME_NETWORK_TCP_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        giveme_log("Failed to set socket timeout\n");
        return -1;
    }

    // connect the client socket to server socket
    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
    {
        giveme_log("connection with the server failed...\n");
        return -1;
    }

    return sockfd;
}

int giveme_tcp_network_listen(struct sockaddr_in *server_sock_out)
{
    struct sockaddr_in si_me;

    int s, i;

    //create a UDP socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        giveme_log("Problem creating TCP socket\n");
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = GIVEME_NETWORK_TCP_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
    {
        giveme_log("Failed to set socket timeout\n");
        return -1;
    }

    int _true = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &_true, sizeof(int)) < 0)
    {
        giveme_log("Failed to set socket reusable option\n");
        return -1;
    }

    // zero out the structure
    memset((char *)&si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(GIVEME_TCP_PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    if ((bind(s, (struct sockaddr *)&si_me, sizeof(si_me))) != 0)
    {
        giveme_log("socket bind failed...\n");
        return -1;
    }

    if ((listen(s, GIVEME_TCP_SERVER_MAX_CONNECTIONS)) != 0)
    {
        giveme_log("TCP Server Listen failed...\n");
        return -1;
    }

    *server_sock_out = si_me;
    return s;
}

int giveme_tcp_network_accept(int sock, struct sockaddr_in *client_out)
{
    struct sockaddr_in client;
    int client_len = sizeof(client);
    int connfd = accept(sock, (struct sockaddr *)&client, &client_len);
    if (connfd < 0)
    {
        giveme_log("Nobody connected with us to say hello :(\n");
        return -1;
    }

    giveme_log("Received connection from %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

    *client_out = client;
    return connfd;
}

int giveme_tcp_send_bytes(int client, void *ptr, size_t amount)
{
    int res = 0;
    size_t amount_left = amount;
    while (amount_left != 0)
    {
        res = send(client, ptr, amount, 0);
        if (res <= 0)
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
        if (res <= 0)
        {
            return res;
        }
        amount_left -= res;
    }
    return res;
}

int giveme_tcp_send_packet(int client, struct giveme_tcp_packet *packet)
{
    return giveme_tcp_send_bytes(client, packet, sizeof(struct giveme_tcp_packet)) > 0 ? 0 : -1;
}

int giveme_tcp_recv_packet(int client, struct giveme_tcp_packet *packet)
{
    return giveme_tcp_recv_bytes(client, packet, sizeof(struct giveme_tcp_packet)) > 0 ? 0 : -1;
}

int giveme_tcp_network_send_unknown_entity(int sockfd)
{
    struct giveme_tcp_packet packet = {};
    packet.type = GIVEME_TCP_PACKET_TYPE_UNKNOWN_ENTITY;
    return giveme_tcp_send_packet(sockfd, &packet);
}

int giveme_tcp_network_block_count_exchange_upload(int sockfd)
{
    int res = 0;
    // We should send our total block count to this guy
    struct giveme_tcp_packet packet = {};
    packet.type = GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE;
    packet.block_count_exchange.count = giveme_blockchain_block_count();
    res = giveme_tcp_send_packet(sockfd, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to send GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE packet\n", __FUNCTION__);
        goto out;
    }

    while (1)
    {
        res = giveme_tcp_recv_packet(sockfd, &packet);
        if (res < 0)
        {
            giveme_log("%s failed to receive packet\n", __FUNCTION__);
            goto out;
        }
        if (packet.type != GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREEABLE_BLOCK)
        {
            giveme_log("%s expecting a GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREEABLE_BLOCK packet, something else was provided\n", __FUNCTION__);
            goto out;
        }

        // The client has given us a hash we might know of, lets see if we know it.
        size_t blocks_to_end = 0;
        struct block *block = giveme_blockchain_block(packet.agreeable_block.hash, &blocks_to_end);
        if (block && S_EQ(block->data.prev_hash, packet.agreeable_block.prev_hash))
        {
            // We know this block that they have asked about. We are in agreement
            packet.type = GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREED_ON_BLOCK;
            strncpy(packet.agreed_block.hash, block->hash, sizeof(packet.agreed_block.hash));
            packet.agreed_block.total_blocks_to_end = blocks_to_end;
            res = giveme_tcp_send_packet(sockfd, &packet);
            if (res < 0)
            {
                giveme_log("%s failed to send agreed block\n", __FUNCTION__);
                goto out;
            }
            // Upload the blockchain
            res = giveme_tcp_network_upload_chain(sockfd, block->hash);
            if (res < 0)
            {
                giveme_log("%s failed to upload blockchain to recipient node\n", __FUNCTION__);
                goto out;
            }

            giveme_log("%s sent longest blockchain successfully\n", __FUNCTION__);
        }
        else
        {
            res = giveme_tcp_network_send_unknown_entity(sockfd);
            if (res < 0)
            {
                giveme_log("%s failed to send unknown entity packet\n", __FUNCTION__);
                goto out;
            }
        }
    }
out:
    return res;
}

int giveme_tcp_network_block_count_exchange_download(int sockfd)
{
    int res = 0;
    // We should send our total block count to this guy
    struct giveme_tcp_packet packet = {};
    res = giveme_tcp_recv_packet(sockfd, &packet);
    if (res < 0)
    {
        giveme_log("%s failed to receive packet\n", __FUNCTION__);
        goto out;
    }
    if (packet.type != GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE)
    {
        giveme_log("%s expecting a type of GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE but a different packet type was provided\n", __FUNCTION__);
        res = -1;
        goto out;
    }
    size_t total_blocks = packet.block_count_exchange.count;
    if (total_blocks <= giveme_blockchain_block_count())
    {
        // We are bigger than this guy.
        giveme_log("%s our chain is bigger or equal in size to the node, so we refuse to update our chain to theirs\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    // Okay we must now send the client our hashes to try to find a hash we both agree on
    giveme_blockchain_begin_crawl(NULL, NULL);
    struct block *block = giveme_blockchain_crawl_next(BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN);
    while (block)
    {
        struct giveme_tcp_packet packet_out;
        packet_out.type = GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREEABLE_BLOCK;
        strncpy(packet_out.agreeable_block.hash, block->hash, sizeof(packet_out.agreeable_block.hash));
        strncpy(packet_out.agreeable_block.prev_hash, block->data.prev_hash, sizeof(packet_out.agreeable_block.hash));
        res = giveme_tcp_send_packet(sockfd, &packet_out);
        if (res < 0)
        {
            giveme_log("%s failed to send GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREEABLE_BLOCK packet\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        res = giveme_tcp_recv_packet(sockfd, &packet);
        if (res < 0)
        {
            giveme_log("%s failed to receive return packet\n", __FUNCTION__);
            res = -1;
            goto out;
        }

        if (packet.type == GIVEME_TCP_PACKET_TYPE_BLOCK_COUNT_EXCHANGE_AGREED_ON_BLOCK)
        {
            if (!S_EQ(packet.agreed_block.hash, block->hash))
            {
                giveme_log("%s client agreed on the block but sent back an unexpected hash: %s\n", packet.agreed_block.hash);
                res = -1;
                goto out;
            }

            if (packet.agreed_block.total_blocks_to_end <= 0)
            {
                giveme_log("%s client sent that the total blocks to the end are zero. In which case the blockchains should already be equal. Or an invalid total blocks was provided\n", __FUNCTION__);
                res = -1;
                goto out;
            }

            giveme_log("%s client agrees on the block %s with us. Downloading chain from this point\n", __FUNCTION__, block->hash);
            // We +1 because we will also be receving our current block that we both agreed on

            struct blockchain *tmp_chain = giveme_blockchain_create(packet.agreed_block.total_blocks_to_end + 1);
            res = giveme_tcp_network_download_chain(tmp_chain, sockfd, block, 0);
            if (res < 0)
            {
                giveme_log("%s failed to download blockchain\n", __FUNCTION__);
                giveme_blockchain_free(tmp_chain);
                goto out;
            }

            giveme_blockchain_free(tmp_chain);
        }
        else if (packet.type == GIVEME_TCP_PACKET_TYPE_UNKNOWN_ENTITY)
        {
            giveme_log("%s client is not aware of our hash %s we will try the previous block\n", __FUNCTION__, block->hash);
        }
        block = giveme_blockchain_crawl_next(BLOCKCHAIN_CRAWLER_FLAG_CRAWL_DOWN);
    }
out:
    return res;
}

void giveme_udp_network_send_my_block_count()
{
    giveme_lock_chain();
    giveme_log("%s sending my block count to the network\n", __FUNCTION__);
    pthread_mutex_lock(&network.tcp_lock);
    struct sockaddr_in tcp_sock;
    // We want someone to connect to us so we can send our blockchain if needed
    int sock = giveme_tcp_network_listen(&tcp_sock);
    if (sock < 0)
    {
        giveme_log("%s Sending block count failed, could not start TCP server\n", __FUNCTION__);
        goto out;
    }

    struct giveme_udp_packet packet;
    packet.type = GIVEME_UDP_PACKET_TYPE_CHAIN_BLOCK_COUNT;
    packet.block_count.total = giveme_blockchain_block_count();
    giveme_udp_broadcast(&packet);

    struct sockaddr_in client;
    int client_s = giveme_tcp_network_accept(sock, &client);
    if (client_s < 0)
    {
        giveme_log("%s Nobody wants our blockchain right now\n", __FUNCTION__);
        goto out;
    }
    if (giveme_tcp_network_block_count_exchange_upload(client_s) < 0)
    {
        giveme_log("%s Issue uploading block count and exchanging blockchains\n", __FUNCTION__);
    }
out:
    close(client_s);
    close(sock);
    pthread_mutex_unlock(&network.tcp_lock);
    giveme_unlock_chain();
}
void giveme_udp_network_announce()
{
    int res = 0;
    pthread_mutex_lock(&network.tcp_lock);
    struct sockaddr_in tcp_sock;
    // We want someone to connect to us now once we send that packet
    int sock = giveme_tcp_network_listen(&tcp_sock);
    if (sock < 0)
    {
        giveme_log("Announcment failed, could not start TCP server\n");
        res = -1;
        goto out;
    }

    struct giveme_udp_packet packet;
    packet.type = GIVEME_UDP_PACKET_TYPE_HELLO;
    giveme_udp_broadcast(&packet);

    struct sockaddr_in client;
    int client_s = giveme_tcp_network_accept(sock, &client);

    // Let's say hello to this dude.
    struct giveme_tcp_packet tcp_packet = {};
    packet.type = GIVEME_TCP_PACKET_TYPE_HELLO;
    res = giveme_tcp_send_packet(client_s, &tcp_packet);
    if (res < 0)
    {
        giveme_log("Failed to send hello packet via TCP stream\n");
        goto out;
    }
    // Lets receive the response from him
    res = giveme_tcp_recv_packet(client_s, &tcp_packet);
    if (res < 0 || tcp_packet.type != GIVEME_TCP_PACKET_TYPE_HELLO)
    {
        giveme_log("Client failed to provide us a HELLO packet via TCP stream\n");
        goto out;
    }

    giveme_log("Client responded with HELLO packet\n");

out:
    close(client_s);
    close(sock);
    pthread_mutex_unlock(&network.tcp_lock);

}

int giveme_udp_network_process_queued_packets()
{
    pthread_mutex_lock(&network.queued_udp_packets_lock);
    vector_set_peek_pointer_end(network.queued_udp_packets);
    vector_set_flag(network.queued_udp_packets, VECTOR_FLAG_PEEK_DECREMENT);

    struct giveme_queued_udp_packet *packet = vector_peek(network.queued_udp_packets);
    while (packet)
    {
        if (time(NULL) - packet->created >= GIVEME_UDP_PACKET_QUEUE_PACKET_EXPIRE_SECONDS)
        {
            // The queued packet has expired...
            packet = vector_peek(network.queued_udp_packets);
            continue;
        }

        giveme_udp_network_handle_packet(&packet->packet, &packet->addr);
        packet = vector_peek(network.queued_udp_packets);
    }

    vector_clear(network.queued_udp_packets);
    pthread_mutex_unlock(&network.queued_udp_packets_lock);
    return 0;
}

int giveme_network_mine_block(struct queued_work *work)
{
    struct block *block = work->private;
    int mine_res = giveme_mine(block);
    if (mine_res >= 0)
    {
        // Mined successfully then transfer it to the network.
        giveme_network_block_send(block);
    }
}

void giveme_network_block_send(struct block *block)
{
    giveme_log("Sending mined %s block to network\n", block->hash);
    struct giveme_udp_packet packet = {};
    packet.type = GIVEME_UDP_PACKET_TYPE_BLOCK;
    memcpy(&packet.block.block, block, sizeof(packet.block.block));
    giveme_udp_broadcast(&packet);
}

int giveme_tcp_network_upload_chain(int sockfd, const char *hash)
{
    int res = 0;
    struct block *last_block = giveme_blockchain_back();
    if (!last_block)
    {
        giveme_log("%s we have no blocks on our chain to upload\n", __FUNCTION__);
        return GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND;
    }

    if (S_EQ(last_block->hash, hash))
    {
        // Theres nothing to upload
        return GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND;
    }

    res = giveme_blockchain_begin_crawl(hash, NULL);
    if (res < 0)
    {
        giveme_log("%s Failed to begin crawling\n", __FUNCTION__);
        goto out;
    }

    struct giveme_tcp_packet tcp_packet = {};
    tcp_packet.type = GIVEME_TCP_PACKET_TYPE_BLOCK_TRANSFER;
    strncpy(tcp_packet.block_transfer.hash, hash, sizeof(tcp_packet.block_transfer.hash));
    strncpy(tcp_packet.block_transfer.end_hash, last_block->hash, sizeof(tcp_packet.block_transfer.end_hash));
    res = giveme_tcp_send_packet(sockfd, &tcp_packet);
    if (res < 0)
    {
        giveme_log("%s failed to send block transfer packet\n", __FUNCTION__);
        goto out;
    }

    // Clear the tcp packet as we will reuse it
    bzero(&tcp_packet, sizeof(tcp_packet));
    struct block *current_block = giveme_blockchain_crawl_next(0);
    while (current_block)
    {
        tcp_packet.type = GIVEME_TCP_PACKET_TYPE_BLOCK;
        tcp_packet.block.block = *current_block;
        res = giveme_tcp_send_packet(sockfd, &tcp_packet);
        if (res < 0)
        {
            giveme_log("%s failed to send block to peer\n", __FUNCTION__);
            break;
        }
        current_block = giveme_blockchain_crawl_next(0);
    }
out:
    return res;
}

int giveme_tcp_network_download_chain(struct blockchain *chain, int sockfd, struct block *last_known_block, int flags)
{
    int res = 0;
    struct giveme_tcp_packet tcp_packet;
    res = giveme_tcp_recv_packet(sockfd, &tcp_packet);
    if (res < 0)
    {
        goto out;
    }

    if (tcp_packet.type != GIVEME_TCP_PACKET_TYPE_BLOCK_TRANSFER)
    {
        // What is this guy sending us...
        res = GIVEME_RECV_PACKET_UNEXPECTED;
        goto out;
    }

    if (last_known_block && !S_EQ(last_known_block->hash, tcp_packet.block_transfer.hash))
    {
        // Sender of chain is sending from a different state than we need.
        res = GIVEME_RECV_PACKET_WRONG_CHAIN;
        goto out;
    }
    if (S_EQ(tcp_packet.block_transfer.hash, tcp_packet.block_transfer.end_hash))
    {
        // This client is trying to send us no blocks
        res = GIVEME_RECV_PACKET_UNEXPECTED;
        goto out;
    }

    // Okay great we are on the same page, we can now expect a series of blocks up to end hash
    char end_hash[SHA256_STRING_LENGTH];
    strncpy(end_hash, tcp_packet.block_transfer.end_hash, sizeof(end_hash));

    if (flags & GIVEME_DOWNLOAD_CHAIN_FLAG_IGNORE_FIRST_BLOCK && last_known_block)
    {
        // First block should be our last block and can be ignored
        res = giveme_tcp_recv_packet(sockfd, &tcp_packet);
        if (res < 0)
        {
            giveme_log("%s Issue receving TCP packet\n", __FUNCTION__);
            goto out;
        }

        if (tcp_packet.type != GIVEME_TCP_PACKET_TYPE_BLOCK)
        {
            giveme_log("%s expecting a type of GIVEME_TCP_PACKET_TYPE_BLOCK\n", __FUNCTION__);
            res = -GIVEME_RECV_PACKET_UNEXPECTED;
            goto out;
        }

        char blank_hash[SHA256_STRING_LENGTH] = {};

        // If we don't know about any blocks yet then obviously its not going to match up when we check
        // the first block hash.
        if (!S_EQ(tcp_packet.block.block.hash, last_known_block->hash))
        {
            giveme_log("%s expecting first block in transfer to be the block we said we was at but %s was provided\n", __FUNCTION__, tcp_packet.block.block.hash);
            res = GIVEME_RECV_PACKET_UNEXPECTED;
            goto out;
        }
    }
    // Now we get the blocks
    do
    {
        res = giveme_tcp_recv_packet(sockfd, &tcp_packet);
        if (res < 0)
        {
            giveme_log("%s Issue receving TCP packet", __FUNCTION__);
            continue;
        }

        if (tcp_packet.type != GIVEME_TCP_PACKET_TYPE_BLOCK)
        {
            giveme_log("%s peer issued the wrong packet to us, we expected a block packet\n", __FUNCTION__);
            res = -1;
            break;
        }

        // Let's add the block to our chain
        res = giveme_blockchain_add_block_for_chain(chain, &tcp_packet.block.block);
        if (res < 0)
        {
            giveme_log("%s failed to add block to blockchain\n", __FUNCTION__);
            break;
        }

        if (S_EQ(tcp_packet.block.block.hash, end_hash))
        {
            // We are at the end of the transfer? Chao chao
            break;
        }

    } while (res >= 0);

out:
    return res;
}

int giveme_network_request_blockchain()
{
    int res = 0;
    pthread_mutex_lock(&network.tcp_lock);

    struct sockaddr_in tcp_sock;
    // We want someone to connect to us now once we send that packet
    int sock = giveme_tcp_network_listen(&tcp_sock);
    if (sock < 0)
    {
        giveme_log("%s failed to listen on TCP server when trying to get blockchain\n", __FUNCTION__);
        res = -1;
        goto out;
    }
    giveme_log("%s started TCP server to await blockchain\n", __FUNCTION__);
    struct block *top_block = NULL;
    giveme_lock_chain();
    top_block = giveme_blockchain_back();
    giveme_unlock_chain();
    struct giveme_udp_packet packet = {};
    packet.type = GIVEME_UDP_PACKET_TYPE_REQUEST_CHAIN;
    if (top_block)
    {
        // We need to tell the clients our last hash
        strncpy(packet.request_chain.hash, packet.request_chain.hash, sizeof(packet.request_chain.hash));
    }

    // Broadcast our request to random clients we will also need to open a TCP port
    // for them to connect to us.
    giveme_udp_broadcast_no_localhost(&packet);

    struct sockaddr_in client;
    int sock_cli = giveme_tcp_network_accept(sock, &client);
    if (sock_cli < 0)
    {
        giveme_log("%s failed to accept client\n", __FUNCTION__);
        res = sock_cli;
        goto out;
    }

    printf("%s accepted client, downloading blockchain\n", __FUNCTION__);
    giveme_lock_chain();
    res = giveme_tcp_network_download_chain(giveme_blockchain_master(), sock_cli, top_block, GIVEME_DOWNLOAD_CHAIN_FLAG_IGNORE_FIRST_BLOCK);
    if (res < 0)
    {
        giveme_log("%s failed to download blockchain\n", __FUNCTION__);
        // We should ban this client for now since we don't want to poll him again when we are
        // having transfer problems
        giveme_network_ip_address_ignore(client.sin_addr);
        goto out_unlock_chain;
    }

    giveme_log("%s Downloaded updated blockchain successfully\n", __FUNCTION__);

out_unlock_chain:
    giveme_unlock_chain();

out:
    pthread_mutex_unlock(&network.tcp_lock);

    close(sock);
    close(sock_cli);
    return res;
}

int giveme_network_request_blockchain_try(size_t tries)
{
    int res = 0;
    // We will request the blockchain for the number of tries, once max tries are reached we will give up
    for (size_t i = 0; i < tries; i++)
    {
        res = giveme_network_request_blockchain();
        if (res == 0)
            break;
    }
    // Some ip addresses may have been ignored during the request process, we can now safely ignore them
    // from the ignore list.
    giveme_network_clear_ignore_broadcast_list();
    return res;
}

void giveme_udp_network_handle_packet_publish_package(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    giveme_log("Packet publish request for package %s\n", packet->package.name);
    struct block *block = calloc(1, sizeof(struct block));
    strncpy(block->data.package.name, packet->package.name, sizeof(block->data.package.name));
    giveme_queue_work(giveme_network_mine_block, block);
}

int giveme_udp_network_handle_packet_hello(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    int res = 0;
    // We should connect to this person on TCP and we can tell eachother who we are.
    int client = giveme_tcp_network_connect(*from_address);
    if (client < 0)
    {
        return -1;
    }

    // We are connected, they will say hello to us first so lets read it then we will respond
    struct giveme_tcp_packet tcp_packet;
    res = giveme_tcp_recv_packet(client, &tcp_packet);
    if (res < 0)
    {
        giveme_log("Failed to receive a packet via TCP connection\n");
        goto out;
    }

    // Let's check we are on agreement here and this is a hello
    if (tcp_packet.type != GIVEME_TCP_PACKET_TYPE_HELLO)
    {
        giveme_log("%s expecting to handle a HELLO packet but they sent us a packet of type %i on a TCP connection\n", __FUNCTION__, tcp_packet.type);
        goto out;
    }

    // Now its our job to send a hello packet back
    giveme_log("%s Received a HELLO packet via TCP connection\n", __FUNCTION__);
    res = giveme_tcp_send_packet(client, &tcp_packet);
    if (res < 0)
    {
        giveme_log("%s Failed to send HELLO packet to client\n", __FUNCTION__);
    }

    giveme_log("%s Sent a TCP packet back\n", __FUNCTION__);
out:
    close(client);
}

int giveme_udp_network_handle_block(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    giveme_lock_chain();
    giveme_log("%s Received a new network block will try to add it to the chain\n", __FUNCTION__);
    int res = giveme_blockchain_add_block(&packet->block.block);
    if (res == GIVEME_BLOCKCHAIN_BLOCK_VALID)
    {
        giveme_log("%s The block was valid and added to our chain, broadcasting to others\n", __FUNCTION__);
        giveme_udp_broadcast(packet);
    }
    else if (res == GIVEME_BLOCKCHAIN_BAD_PREVIOUS_HASH)
    {
        giveme_log("%s Bad previous hash detected for new block\n", __FUNCTION__);
    }
    else if (res == GIVEME_BLOCKCHAIN_ALREADY_ON_TAIL)
    {
        giveme_log("%s The block is already on the tail\n", __FUNCTION__);
    }
    giveme_unlock_chain();
    return 0;
}

int giveme_udp_network_handle_chain_block_count(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    int res = 0;
    size_t total_blocks = packet->block_count.total;
    // We don't care about a block count equal or less than ours.
    if (total_blocks <= giveme_blockchain_block_count())
    {
        giveme_log("%s peer has shared his block count of %i ours is %i we are bigger\n", total_blocks, giveme_blockchain_block_count());
        return 0;
    }
    giveme_log("%s peer has greater block count than us we will exchange our chain for theirs\n", __FUNCTION__);
    int sockfd = giveme_tcp_network_connect(*from_address);
    if (sockfd < 0)
    {
        giveme_log("%s failed to connect to peer\n", __FUNCTION__);
        res = -1;
        goto out;
    }
    // They have more blocks than us? Its possible that we are working on the wrong chain.
    res = giveme_tcp_network_block_count_exchange_download(sockfd);
    if (res < 0)
    {
        giveme_log("%s failed to do a block exchange\n", __FUNCTION__);
        goto out;
    }

out:
    close(sockfd);
    return 0;
}
int giveme_udp_network_handle_request_chain(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    return 0;
    int res = 0;
    giveme_lock_chain();
    // Let's see if we are able to handle this request
    res = giveme_blockchain_index_for_block(packet->request_chain.hash);
    if (res < 0)
    {
        // Nope we don't have the hash that the user is asking for.
        // This could mean our chain is lagging behind.
        goto out;
    }

    // Do we have any further blocks ahead?
    size_t total_blocks_to_send = giveme_blockchain_total_blocks_left(res);
    if (total_blocks_to_send <= 0)
    {
        // We can't handle this as our chains are equal
        goto out;
    }
    int sockfd = giveme_tcp_network_connect(*from_address);
    if (sockfd < 0)
    {
        // We failed to connect
        giveme_log("%s failed to connect to client who requested a chain\n", __FUNCTION__);
        res = -1;
        goto out;
    }

    res = giveme_tcp_network_upload_chain(sockfd, packet->request_chain.hash);
    if (res < 0)
    {
        giveme_log("%s failed to upload chain to peer\n", __FUNCTION__);
        goto out;
    }

out:
    close(sockfd);

    giveme_unlock_chain();
    return res;
}


// No longer used for now.
int giveme_udp_network_queue_packet(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    int res = 0;
    struct giveme_queued_udp_packet queued_packet = {};
    queued_packet.packet = *packet;
    queued_packet.addr = *from_address;
    pthread_mutex_lock(&network.queued_udp_packets_lock);
    if (vector_count(network.queued_udp_packets) >= GIVEME_UDP_PACKET_QUEUE_MAXIMUM_PACKETS)
    {
        giveme_log("%s rejected attempt to queue packet as the packet queue is full\n", __FUNCTION__);
        res = -1;
        goto out;
    }
    vector_push(network.queued_udp_packets, &queued_packet);
out:
    pthread_mutex_unlock(&network.queued_udp_packets_lock);
    return 0;
}

int giveme_udp_network_handle_packet(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    switch (packet->type)
    {

    case GIVEME_UDP_PACKET_TYPE_HELLO:
        giveme_udp_network_handle_packet_hello(packet, from_address);
        break;
    case GIVEME_UDP_PACKET_TYPE_PUBLISH_PACKAGE:
        giveme_udp_network_handle_packet_publish_package(packet, from_address);
        break;
    case GIVEME_UDP_PACKET_TYPE_BLOCK:
        giveme_udp_network_handle_block(packet, from_address);
        break;

    case GIVEME_UDP_PACKET_TYPE_REQUEST_CHAIN:
        giveme_udp_network_handle_request_chain(packet, from_address);
        break;

    case GIVEME_UDP_PACKET_TYPE_CHAIN_BLOCK_COUNT:
        giveme_udp_network_handle_chain_block_count(packet, from_address);
        break;
    }
    return 0;
}
int giveme_udp_network_listen_thread(struct queued_work *work)
{

    int s = work->private_i;
    struct sockaddr_in si_other;

    int slen = sizeof(si_other);
    int recv_len = 0;
    time_t last_sync_time = time(NULL);
    while (1)
    {
        struct giveme_udp_packet packet;
        giveme_log("Waiting for next UDP packet\n");

        if ((recv_len = recvfrom(s, &packet, sizeof(packet), 0, (struct sockaddr *)&si_other, &slen)) == -1)
        {
            giveme_log("Failed to receive packet\n");
        }

        //print details of the client/peer and the data received
        giveme_log("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        // Let's add this IP address who knows about us to our IP list
        giveme_network_ip_address_add(si_other.sin_addr);
        giveme_udp_network_handle_packet(&packet, &si_other.sin_addr);
        if (time(NULL) - last_sync_time > 30)
        {
            giveme_udp_network_send_my_block_count();
            last_sync_time = time(NULL);
        }
    }
    close(s);
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

void giveme_network_initialize()
{
    memset(&network, 0, sizeof(struct network));
    network.ip_addresses = vector_create(sizeof(struct in_addr));
    network.ignore_broadcast_ips = vector_create(sizeof(struct in_addr));
    network.queued_udp_packets = vector_create(sizeof(struct giveme_queued_udp_packet));
    if (pthread_mutex_init(&network.queued_udp_packets_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize queued_udp_packets_lock mutex\n");
    }

    if (pthread_mutex_init(&network.tcp_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize tcp_lock mutex\n");
    }

    giveme_network_load_ips();
}

int giveme_process_thread_start()
{
    // Not implemented.
   // giveme_queue_work(giveme_process_thread, NULL);
    return 0;
}

int giveme_udp_network_listen()
{
    struct sockaddr_in si_me;

    int s, i;

    //create a UDP socket
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        giveme_log("Problem creating UDP socket\n");
        return -1;
    }

    // zero out the structure
    memset((char *)&si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(GIVEME_UDP_PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    //bind socket to port
    if (bind(s, (struct sockaddr *)&si_me, sizeof(si_me)) == -1)
    {
        giveme_log("Failed to bind UDP socket server\n");
        return -1;
    }

    giveme_queue_work(giveme_udp_network_listen_thread, (void *)(long)s);
    return 0;
}

void giveme_udp_broadcast_random(struct giveme_udp_packet *packet, int max_packets_sent)
{
    size_t total = vector_count(network.ip_addresses);
    for (int i = 0; i < max_packets_sent; i++)
    {
        int random_index = rand() % total;
        struct in_addr *addr = vector_at(network.ip_addresses, random_index);
        giveme_udp_network_send(*addr, packet);
    }
}

void giveme_udp_broadcast_random_no_localhost(struct giveme_udp_packet *packet, int max_packets_sent)
{
    size_t total = vector_count(network.ip_addresses);
    for (int i = 0; i < max_packets_sent; i++)
    {
        int random_index = rand() % total;
        struct in_addr *addr = vector_at(network.ip_addresses, random_index);
        giveme_udp_network_send(*addr, packet);
    }
}

void giveme_udp_broadcast_no_localhost(struct giveme_udp_packet *packet)
{
    vector_set_peek_pointer(network.ip_addresses, 0);
    struct in_addr *addr = vector_peek(network.ip_addresses);
    while (addr)
    {
        if (S_EQ(inet_ntoa(*addr), "127.0.0.1") || giveme_network_ip_address_exists_on_ignore_broadcast_list(addr))
        {
          //  addr = vector_peek(network.ip_addresses);
           // continue;
        }
        giveme_udp_network_send(*addr, packet);
        addr = vector_peek(network.ip_addresses);
    }
}

void giveme_udp_broadcast(struct giveme_udp_packet *packet)
{
    vector_set_peek_pointer(network.ip_addresses, 0);
    struct in_addr *addr = vector_peek(network.ip_addresses);
    while (addr)
    {
        if (giveme_network_ip_address_exists_on_ignore_broadcast_list(addr))
        {
            // We should ignore this one for this cycle
       //     addr = vector_peek(network.ip_addresses);
         //   continue;
        }
        giveme_udp_network_send(*addr, packet);
        addr = vector_peek(network.ip_addresses);
    }
}

int giveme_udp_network_send(struct in_addr addr, struct giveme_udp_packet *packet)
{
    struct sockaddr_in si_other = {};
    int s, i, slen = sizeof(si_other);

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        giveme_log("Problem creating socket\n");
        return -1;
    }
    si_other.sin_addr = addr;
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(GIVEME_UDP_PORT);

    if (sendto(s, packet, sizeof(struct giveme_udp_packet), 0, (struct sockaddr *)&si_other, slen) == -1)
    {
        giveme_log("Issue sending UDP packet\n");
        return -1;
    }

    close(s);

    return 0;
}
