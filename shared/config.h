#ifndef CONFIG_H
#define CONFIG_H
#define GIVEME_MINIMUM_ARGC 2
#define GIVEME_REQUIRED_PUBLISH_ARGC 4
#define GIVEME_REQUIRED_FAKE_MINING_ARGC 3

#define GIVEME_CLIENT_SERVER_PATH "/tmp/givemebinds"
#define GIVEME_DATA_BASE ".giveme"
#define GIVEME_PACKAGE_DIRECTORY GIVEME_DATA_BASE "/packages"
#define GIVEME_DATA_BASE_DIRECTORY_ENV "HOME"
#define GIVEME_BLOCKCHAIN_FILEPATH "/blockchain.bin"
#define GIVEME_TOTAL_THREADS 4
#define PACKAGE_NAME_MAX 256
#define GIVEME_TOTAL_ZEROS_FOR_MINED_BLOCK 5
#define GIVEME_IP_STRING_SIZE 17
#define GIVEME_UDP_MAX_BROADCASTS_FOR_ANNOUNCMENT 10
#define GIVEME_UDP_MAX_BROADCASTS_FOR_CHAIN_REQUEST 30

// We only ever turn on TCP when we are expecting someone, therefore we wont allow any queuing of any kind
// first to chat with us gets priority
#define GIVEME_TCP_SERVER_MAX_CONNECTIONS 1
// If we have no client accepted or message within 10 seconds we will drop the TCP connection
#define GIVEME_NETWORK_TCP_TIMEOUT_SECONDS 10

// Blockchain will resize its self after 1024 blocks, and it will resize to +1024 blocks each time
#define BLOCKCHAIN_RESIZE_TOTAL_BLOCKS 1024

#endif