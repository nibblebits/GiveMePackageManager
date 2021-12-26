#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <unistd.h>
#include <assert.h>
#include <zip.h>

#include "config.h"
#include "misc.h"
#include "af_unix_network.h"
#include "blockchain.h"
#include "network.h"
#include "log.h"
#include "package.h"
#define LISTEN_BACKLOG 50

#define handle_error(msg)   \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

int giveme_af_unix_connect()
{
    int sfd, cfd;
    struct sockaddr_un serv_addr, peer_addr;
    socklen_t peer_addr_size;

    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1)
        handle_error("Issue creating socket");

    memset(&serv_addr, 0, sizeof(struct sockaddr_un));
    /* Clear structure */
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, GIVEME_CLIENT_SERVER_PATH,
            sizeof(serv_addr.sun_path) - 1);

    if (connect(sfd, (struct sockaddr *)&serv_addr,
                strlen(serv_addr.sun_path) + sizeof(serv_addr.sun_family)) == -1)
        handle_error("Issue connecting to socket");

    return sfd;
}

int giveme_af_unix_write(int sfd, struct network_af_unix_packet *packet)
{
    int res = 0;
    size_t amount_to_write = sizeof(struct network_af_unix_packet);
    while (amount_to_write > 0)
    {
        res = write(sfd, packet, amount_to_write);
        if (res == -1)
            break;
        amount_to_write -= res;
    }

    if (res > 0)
    {
        res = NETWORK_AF_UNIX_PACKET_IO_OKAY;
    }
    return res;
}

int giveme_af_unix_read(int sfd, struct network_af_unix_packet *packet_out)
{
    int res = 0;
    size_t amount_to_read = sizeof(struct network_af_unix_packet);
    while (amount_to_read > 0)
    {
        res = read(sfd, packet_out, amount_to_read);
        if (res == -1)
            break;
        amount_to_read -= res;
    }

    if (res > 0)
    {
        res = NETWORK_AF_UNIX_PACKET_IO_OKAY;
    }

    if (res == NETWORK_AF_UNIX_PACKET_IO_OKAY)
    {
        // Do we have a friendly message to output?
        if (packet_out->flags & NETWORK_AF_UNIX_PACKET_FLAG_HAS_FRIENDLY_MESSAGE)
        {
            printf("%s\n", packet_out->message);
        }
    }

    return res;
}

int giveme_send_message(int sfd, const char *message)
{
    struct network_af_unix_packet packet = {};
    packet.type = NETWORK_AF_UNIX_PACKET_TYPE_JUST_A_MESSAGE;
    packet.flags |= NETWORK_AF_UNIX_PACKET_FLAG_HAS_FRIENDLY_MESSAGE;
    sprintf(packet.message, "%s", message);
    if (giveme_af_unix_write(sfd, &packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        return -1;

    return 0;
}

struct blockchain_individual giveme_info(int sfd)
{
    struct blockchain_individual blank_data = {};
    struct network_af_unix_packet packet = {};
    packet.type = NETWORK_AF_UNIX_PACKET_TYPE_MY_INFO;
    // Send the packet
    if (giveme_af_unix_write(sfd, &packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
    {
        printf("Failed to send packet to server\n");
        return blank_data;
    }

    // Let's read back the publish response
    struct network_af_unix_packet res_packet;
    if (giveme_af_unix_read(sfd, &res_packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
    {
        printf("Failed to receive response packet from server\n");
        return blank_data;
    }

    assert(res_packet.type == NETWORK_AF_UNIX_PACKET_TYPE_INFO_RESPONSE);


    return res_packet.info_response.individual;
}

int giveme_download(int sfd, const char *package_name)
{
}

int giveme_make_fake_blockchain(int sfd, size_t total_blocks)
{
    struct network_af_unix_packet packet = {};
    packet.type = NETWORK_AF_UNIX_PACKET_TYPE_MAKE_FAKE_BLOCKCHAIN;
    packet.fake_blockchain.total_blocks = total_blocks;
    // Send the packet
    if (giveme_af_unix_write(sfd, &packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        return -1;

    // Let's read back the publish response
    struct network_af_unix_packet res_packet;
    if (giveme_af_unix_read(sfd, &res_packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        return -1;

    return 0;
}

int giveme_signup(int sfd, const char *name)
{
    struct network_af_unix_packet packet = {};
    packet.type = NETWORK_AF_UNIX_PACKET_TYPE_SIGNUP;
    strncpy(packet.signup.name, name, sizeof(packet.signup.name));
    // Send the packet
    if (giveme_af_unix_write(sfd, &packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        return -1;

    // Let's read back the publish response
    struct network_af_unix_packet res_packet;
    if (giveme_af_unix_read(sfd, &res_packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        return -1;

    return 0;
}
int giveme_publish(int sfd, const char *filename, const char *package_name)
{
    struct network_af_unix_packet packet = {};
    packet.type = NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE;
    strncpy(packet.publish.filename, realpath(filename, NULL), sizeof(packet.publish.filename));
    strncpy(packet.publish.package, package_name, sizeof(packet.publish.package));

    // Send the packet
    if (giveme_af_unix_write(sfd, &packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        return -1;

    // Let's read back the publish response
    struct network_af_unix_packet res_packet;
    if (giveme_af_unix_read(sfd, &res_packet) != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        return -1;

    // res_packet has our response, lets see if publish was a success
    assert(res_packet.type == NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE_RESPONSE);
    if (!res_packet.publish_res.published)
    {
        return -1;
    }

    return 0;
}

int giveme_network_af_unix_handle_packet_publish(int sock, struct network_af_unix_packet *packet)
{
    int res = 0;

    giveme_log("Package publish request %s located at %s\n", packet->publish.package, packet->publish.filename);

    // Let's make an archive
    giveme_package_create(packet->publish.filename, packet->publish.package);

    // We have a request from the client to publish a packet to the network
    // Issue a published response as a test
    struct network_af_unix_packet res_packet = {};
    res_packet.type = NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE_RESPONSE;
    res_packet.flags |= NETWORK_AF_UNIX_PACKET_FLAG_HAS_FRIENDLY_MESSAGE;
    sprintf(res_packet.message, "Your package %s has been published successfully", packet->publish.package);
    strncpy(res_packet.publish_res.filename, packet->publish.filename, sizeof(res_packet.publish_res.filename));
    strncpy(res_packet.publish_res.package, packet->publish.package, sizeof(res_packet.publish_res.package));

    giveme_af_unix_write(sock, &res_packet);
    return res;
}

int giveme_network_af_unix_handle_packet_make_fake_blockchain(int sock, struct network_af_unix_packet *packet)
{
    giveme_send_message(sock, "Mining useless blocks, we can't confirm when its done\n");
    for (int i = 0; i < packet->fake_blockchain.total_blocks; i++)
    {
        struct block b = {};
        giveme_mine(&b);
    }
    return 0;
}

int giveme_network_af_unix_handle_packet_signup(int sock, struct network_af_unix_packet *packet)
{
    struct giveme_tcp_packet tcp_packet = {};
    tcp_packet.data.type = GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PUBLIC_KEY;
    strncpy(tcp_packet.data.publish_public_key.name, packet->signup.name, sizeof(tcp_packet.data.publish_public_key.name));
    memcpy(&tcp_packet.data.publish_public_key.pub_key, giveme_public_key(), sizeof(tcp_packet.data.publish_public_key.pub_key));
    giveme_network_broadcast(&tcp_packet);

    struct network_af_unix_packet res_packet = {};
    res_packet.type = NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PUBLIC_KEY_RESPONSE;
    res_packet.flags |= NETWORK_AF_UNIX_PACKET_FLAG_HAS_FRIENDLY_MESSAGE;
    sprintf(res_packet.message, "You have successfully signed up to the network as %s it can take 5-20 minutes before your able to be recognized and access your own account data with \"giveme info\" \n", packet->signup.name);
    giveme_af_unix_write(sock, &res_packet);
}

int giveme_network_af_unix_handle_packet_my_info(int sock, struct network_af_unix_packet *packet)
{
    struct network_af_unix_packet res_packet = {};
    res_packet.type = NETWORK_AF_UNIX_PACKET_TYPE_INFO_RESPONSE;
    res_packet.flags |= NETWORK_AF_UNIX_PACKET_FLAG_HAS_FRIENDLY_MESSAGE;
    giveme_lock_chain();
    res_packet.info_response.individual = *giveme_blockchain_me();
    giveme_unlock_chain();
    giveme_af_unix_write(sock, &res_packet);
    return 0;
}

int giveme_network_af_unix_handle_packet(int sock, struct network_af_unix_packet *packet)
{
    int res = 0;
    switch (packet->type)
    {
    case NETWORK_AF_UNIX_PACKET_TYPE_PUBLISH_PACKAGE:
        res = giveme_network_af_unix_handle_packet_publish(sock, packet);
        break;

    case NETWORK_AF_UNIX_PACKET_TYPE_MAKE_FAKE_BLOCKCHAIN:
        res = giveme_network_af_unix_handle_packet_make_fake_blockchain(sock, packet);
        break;

    case NETWORK_AF_UNIX_PACKET_TYPE_SIGNUP:
        res = giveme_network_af_unix_handle_packet_signup(sock, packet);
        break;

    case NETWORK_AF_UNIX_PACKET_TYPE_MY_INFO:
        res = giveme_network_af_unix_handle_packet_my_info(sock, packet);
        break;
    }
    return res;
}
int giveme_network_server_af_unix_read(int sock)
{
    int res = 0;
    struct network_af_unix_packet packet;
    res = giveme_af_unix_read(sock, &packet);
    if (res < 0)
        return res;

    giveme_blockchain_wait_until_ready();

    // We now have a packet lets handle it
    return giveme_network_af_unix_handle_packet(sock, &packet);
}
int giveme_af_unix_listen()
{
    unlink(GIVEME_CLIENT_SERVER_PATH);
    int sfd, cfd;
    struct sockaddr_un my_addr, peer_addr;
    socklen_t peer_addr_size;

    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1)
        handle_error("Issue creating socket");

    memset(&my_addr, 0, sizeof(struct sockaddr_un));
    /* Clear structure */
    my_addr.sun_family = AF_UNIX;
    strncpy(my_addr.sun_path, GIVEME_CLIENT_SERVER_PATH,
            sizeof(my_addr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr *)&my_addr,
             sizeof(struct sockaddr_un)) == -1)
        handle_error("Issue binding to socket");

    if (listen(sfd, LISTEN_BACKLOG) == -1)
        handle_error("Issue listening on socket");

    /* Now we can accept incoming connections one
       at a time using accept(2) */

    peer_addr_size = sizeof(struct sockaddr_un);
    while (1)
    {
        cfd = accept(sfd, (struct sockaddr *)&peer_addr,
                     &peer_addr_size);
        if (cfd == -1)
            handle_error("Issue accepting socket");

        int res = giveme_network_server_af_unix_read(cfd);
        if (res != NETWORK_AF_UNIX_PACKET_IO_OKAY)
        {
            close(cfd);
        }
    }
}
