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
int giveme_udp_network_listen_thread(struct queued_work* work)
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

        // //now reply the client with the same data
        // if (sendto(s, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) == -1)
        // {
        // 	die("sendto()");
        // }
    }
    close(s);
}
int giveme_udp_network_listen()
{
    struct sockaddr_in si_me, si_other;

    int s, i, slen = sizeof(si_other), recv_len;

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

    giveme_queue_work(giveme_udp_network_listen_thread, (void*)(long)s);
    return 0;
}

