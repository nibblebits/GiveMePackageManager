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

int giveme_tcp_send_bytes(int client, void* ptr, size_t amount)
{
    size_t amount_left = amount;
    while(amount_left != 0)
    {
        int res = send(client, ptr, amount, 0);
        if (res < 0)
        {
            return res;
        }
        amount_left -= res;
    }
    return 0;

}

int giveme_tcp_recv_bytes(int client, void* ptr, size_t amount)
{
    size_t amount_left = amount;
    while(amount_left != 0)
    {
        int res = recv(client, ptr, amount, 0);
        if (res < 0)
        {
            return res;
        }
        amount_left -= res;
    }
    return 0;

}

int giveme_tcp_send_packet(int client, struct giveme_tcp_packet* packet)
{
   return giveme_tcp_send_bytes(client, packet, sizeof(struct giveme_tcp_packet));
}

int giveme_tcp_recv_packet(int client, struct giveme_tcp_packet* packet)
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
    giveme_udp_broadcast_random(&packet, GIVEME_UDP_MAX_BROADCASTS_FOR_ANNOUNCMENT);

    struct sockaddr_in client;
    int client_s = giveme_tcp_network_accept(sock, &client);

    // Let's say hello to this dude.
    struct giveme_tcp_packet tcp_packet = {};
    packet.type = GIVEME_TCP_PACKET_TYPE_HELLO;
    inet_ntop(AF_INET, &client, tcp_packet.hello.dst_ip, sizeof(struct sockaddr_in));

    res = giveme_tcp_send_packet(client_s, &tcp_packet);
    if(res < 0)
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

    

    giveme_log("Client responded with HELLO packet my address is %s\n", tcp_packet.hello.dst_ip);

out:
    close(client_s);
    close(sock);
}

int giveme_network_mine_block(struct queued_work *work)
{
    struct block *block = work->private;
    return giveme_mine(block);
}

void giveme_udp_network_handle_packet_publish_package(struct giveme_udp_packet *packet, struct in_addr *from_address)
{
    giveme_log("Packet publish request for package %s\n", packet->package.name);
    struct block *block = calloc(1, sizeof(struct block));
    strncpy(block->data.package.name, packet->package.name, sizeof(block->data.package.name));
    giveme_queue_work(giveme_network_mine_block, block);
}

void giveme_network_set_my_ip(const char *ip)
{
    // In the future we will need a mechnism of ensuring people aren't telling us fake IP addresses.
    strncpy(network.my_ip, ip, sizeof(network.my_ip));
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
    // We should tell them who they are and send them the packet back
    inet_ntop(AF_INET, from_address, tcp_packet.hello.dst_ip, sizeof(struct in_addr));
    res = giveme_tcp_send_packet(client, &tcp_packet);
    if (res < 0)
    {
        giveme_log("%s Failed to send HELLO packet to client\n", __FUNCTION__);
    }
    
    giveme_log("%s Sent a TCP packet back and I am %s\n", __FUNCTION__, tcp_packet.hello.dst_ip);
out:
    close(client);
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


    giveme_network_ip_address_add(addr);
}

void giveme_network_initialize()
{
    memset(&network, 0, sizeof(struct network));
    network.ip_addresses = vector_create(sizeof(struct sockaddr_in));
    // We don't know our public ip address yet so its our local one for now
    // someone on the network will tell us soon enough
    strncpy(network.my_ip, "127.0.0.1", sizeof(network.my_ip));
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
