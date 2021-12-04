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
    size_t amount_left = amount;
    while (amount_left != 0)
    {
        int res = send(client, ptr, amount, 0);
        if (res <= 0)
        {
            return res;
        }
        amount_left -= res;
    }
    return 0;
}

int giveme_tcp_recv_bytes(int client, void *ptr, size_t amount)
{
    size_t amount_left = amount;
    while (amount_left != 0)
    {
        int res = recv(client, ptr, amount, 0);
        if (res <= 0)
        {
            return res;
        }
        amount_left -= res;
    }
    return 0;
}

int giveme_tcp_send_packet(int client, struct giveme_tcp_packet *packet)
{
    return giveme_tcp_send_bytes(client, packet, sizeof(struct giveme_tcp_packet));
}

int giveme_tcp_recv_packet(int client, struct giveme_tcp_packet *packet)
{
    return giveme_tcp_recv_bytes(client, packet, sizeof(struct giveme_tcp_packet));
}

void giveme_udp_network_announce()
{
    int res = 0;
    struct sockaddr_in tcp_sock;
    // We want someone to connect to us now once we send that packet
    int sock = giveme_tcp_network_listen(&tcp_sock);
    if (sock < 0)
    {
        giveme_log("Announcment failed, could not start TCP server\n");
        return;
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
    struct block *last_block = giveme_blockchain_back_nosafety();
    if (!last_block)
    {
        giveme_log("%s we have no blocks on our chain to upload\n", __FUNCTION__);
        return -GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND;
    }

    if (S_EQ(last_block->hash, hash))
    {
        // Theres nothing to upload
        return -GIVEME_BLOCKCHAIN_BLOCK_NOT_FOUND;
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

int giveme_tcp_network_download_chain(int sockfd, struct block *last_known_block)
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

    // First block should be our last block and can be ignored
    res = giveme_tcp_recv_packet(sockfd, &tcp_packet);
    if (res < 0)
    {
        giveme_log("%s Issue receving TCP packet", __FUNCTION__);
        goto out;
    }

    if (tcp_packet.type != GIVEME_TCP_PACKET_TYPE_BLOCK)
    {
        giveme_log("%s expecting a type of GIVEME_TCP_PACKET_TYPE_BLOCK\n", __FUNCTION__);
        res = -GIVEME_RECV_PACKET_UNEXPECTED;
        goto out;
    }

    if(!S_EQ(tcp_packet.block.block.hash, last_known_block->hash))
    {
        giveme_log("%s expecting first block in transfer to be the block we said we was at but %s was provided\n", __FUNCTION__, tcp_packet.block.block.hash);
        res = -GIVEME_RECV_PACKET_UNEXPECTED;
        goto out;
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
        res = giveme_blockchain_add_block_nosafety(&tcp_packet.block.block);
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

void giveme_network_request_blockchain()
{
    giveme_lock_chain();

    struct sockaddr_in tcp_sock;
    // We want someone to connect to us now once we send that packet
    int sock = giveme_tcp_network_listen(&tcp_sock);
    if (sock < 0)
    {
        giveme_log("%s failed to listen on TCP server when trying to get blockchain\n", __FUNCTION__);
        goto out;
    }
    giveme_log("%s started TCP server to await blockchain\n", __FUNCTION__);
    struct block *top_block = giveme_blockchain_back_nosafety();
    struct giveme_udp_packet packet = {};
    packet.type = GIVEME_UDP_PACKET_TYPE_REQUEST_CHAIN;
    if (top_block)
    {
        // We need to tell the clients our last hash
        strncpy(packet.request_chain.hash, packet.request_chain.hash, sizeof(packet.request_chain.hash));
    }

    // Broadcast our request to random clients we will also need to open a TCP port
    // for them to connect to us.
    giveme_udp_broadcast(&packet);

    struct sockaddr_in client;
    int sock_cli = giveme_tcp_network_accept(sock, &client);
    if (sock_cli < 0)
    {
        giveme_log("%s failed to accept client\n", __FUNCTION__);
        goto out;
    }

    printf("%s accepted client, downloading blockchain\n", __FUNCTION__);
    int res = giveme_tcp_network_download_chain(sock_cli, top_block);
    if (res < 0)
    {
        giveme_log("%s failed to download blockchain\n", __FUNCTION__);
        goto out;
    }

    giveme_log("%s Downloaded updated blockchain successfully\n", __FUNCTION__);

out:
    giveme_unlock_chain();

    close(sock);
    close(sock_cli);
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
    int res = giveme_blockchain_add_block_nosafety(&packet->block.block);
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

int giveme_udp_network_handle_request_chain(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
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
    }
    return 0;
}
int giveme_udp_network_listen_thread(struct queued_work *work)
{

    int s = work->private_i;
    struct sockaddr_in si_other;

    int slen = sizeof(si_other);
    int recv_len = 0;

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

    //giveme_network_ip_address_add(addr);

    if (inet_aton("67.205.184.222", &addr) == 0)
    {
        giveme_log("inet_aton() failed\n");
    }
    giveme_network_ip_address_add(addr);
}

void giveme_network_initialize()
{
    memset(&network, 0, sizeof(struct network));
    network.ip_addresses = vector_create(sizeof(struct sockaddr_in));
    giveme_network_load_ips();
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
void giveme_udp_broadcast(struct giveme_udp_packet *packet)
{
    vector_set_peek_pointer(network.ip_addresses, 0);
    struct in_addr *addr = vector_peek(network.ip_addresses);
    while (addr)
    {
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
