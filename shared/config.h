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
#define GIVEME_PUBLIC_KEY_FILEPATH "/key.pub"
#define GIVEME_PRIVATE_KEY_FILEPATH "/key.pri"

#define GIVEME_TOTAL_THREADS 6
#define GIVEME_MAX_BLOCKCHAIN_REQUESTS_IF_FAILED 1
#define GIVEME_PACKAGE_NAME_MAX 256
#define GIVEME_KEY_NAME_MAX 128
#define GIVEME_TOTAL_ZEROS_FOR_MINED_BLOCK 1
#define GIVEME_IP_STRING_SIZE 17

#define GIVEME_SECONDS_TO_MAKE_BLOCK 60

#define GIVEME_MINIMUM_TCP_PACKET_SIZE 1024
#define GIVEME_MAX_KEY_LENGTH 4096

// We allow a maximum of 1024 transactions per block
#define GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK 16

#define GIVEME_VALIDATION_MINING_REWARD 0.05

// Genesis key will be added as a first block when ever anyone first downloads the software
// A new public key block will automatically be created upon starting the software for
// the first time, with this gensis key being that block.
#define GIVEME_BLOCKCHAIN_GENESIS_KEY "-----BEGIN RSA PUBLIC KEY----- \
MIIBCgKCAQEAnvZrnzUVpxhJbCJZ/lY0/+2qqBS/mrJH+HFu5kDavqihF46Mm2FB  \
T21QCp95h6m7D6ovEJZodXEd8QP5pBEvAoWUnw0t1xMlySLY6tDD1HN1u5kFptgA \
HEOqAPZA/rsmeRysu0291WSn56lkaVEs4+PAbOV+a7N3ECCaKuJaSwFsGLskiOKi \
AIIrZBLAkzK6r0qX+I3KbMbcb0FFMAKpIuLAAivrljmYEBdsxkTxXJ2DVujEc7oJ \
n0EKJ4j377zzuXv4XwWxbJ1sYFhUrRx1lFdrx3T8KiVJ8Yv6F3YHwWXZEW4E5++Y \
Wiqbf7ZAeToe7zD78/4lBlB1Y0rGzXPTHQIDAQAB \
-----END RSA PUBLIC KEY-----"

#define GIVEME_BLOCKCHAIN_GENESIS_HASH "0ee976a68948529107f4496fabf220b3d192e8e79340f5b025796f5741261d9d"
#define GIVEME_BLOCKCHAIN_GENESIS_NOUNCE "5375715"

#define GIVEME_TCP_PORT 10287

// We only ever turn on TCP when we are expecting someone, therefore we wont allow any queuing of any kind
// first to chat with us gets priority
#define GIVEME_TCP_SERVER_MAX_CONNECTIONS 100
// If we have no client accepted or message within 2 seconds we will drop the TCP connection
#define GIVEME_NETWORK_TCP_CONNECT_TIMEOUT_SECONDS 2
// 30 seconds waiting on a recv or send and we will timeout.
#define GIVEME_NETWORK_TCP_IO_TIMEOUT_SECONDS 7

// Blockchain will resize its self after 1024 blocks, and it will resize to +1024 blocks each time
#define BLOCKCHAIN_RESIZE_TOTAL_BLOCKS 1024

#endif