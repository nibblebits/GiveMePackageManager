#ifndef GIVEME_NETWORK_H
#define GIVEME_NETWORK_H

#define GIVEME_UDP_PORT 9987

enum
{
    GIVEME_UDP_PACKET_TYPE_HELLO
};
struct giveme_udp_packet
{
    int type;
    union 
    {
        struct giveme_udp_packet_hello
        {

        } hello;
    };
    
};

int giveme_udp_network_listen();

#endif