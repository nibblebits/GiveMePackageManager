#ifndef CONFIG_H
#define CONFIG_H
#define GIVEME_MINIMUM_ARGC 2
#define GIVEME_REQUIRED_PUBLISH_ARGC 4
#define GIVEME_REQUIRED_SIGNUP_ARGC 3
#define GIVEME_REQUIRED_FAKE_MINING_ARGC 3
#define GIVEME_REQUIRED_GET_INFO_ARGC 2

#define GIVEME_CLIENT_SERVER_PATH "/tmp/givemebinds"
#define GIVEME_DATA_BASE ".giveme"
#define GIVEME_PACKAGE_DIRECTORY GIVEME_DATA_BASE "/packages"
#define GIVEME_DATA_BASE_DIRECTORY_ENV "HOME"
#define GIVEME_BLOCKCHAIN_FILEPATH "/blockchain.bin"
#define GIVEME_PUBLIC_KEY_FILEPATH "/key.pub"
#define GIVEME_PRIVATE_KEY_FILEPATH "/key.pri"

#define GIVEME_TOTAL_THREADS 7
#define GIVEME_MAX_BLOCKCHAIN_REQUESTS_IF_FAILED 1
#define GIVEME_PACKAGE_NAME_MAX 256
#define GIVEME_KEY_NAME_MAX 128
#define GIVEME_TOTAL_ZEROS_FOR_MINED_BLOCK 1
#define GIVEME_IP_STRING_SIZE 17

// Must have the last number as 1
#define GIVEME_SECONDS_TO_MAKE_BLOCK 61

#define GIVEME_MINIMUM_TCP_PACKET_SIZE 1024
// 64 bytes for hashed key then +1 for null terminator
#define GIVEME_MAX_KEY_LENGTH 140

#define GIVEME_MAX_SIGNATURE_PART_LENGTH 65

// We allow a maximum of 1024 transactions per block
#define GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK 16

#define GIVEME_VALIDATION_MINING_REWARD 0.05

// Genesis key will be added as a first block when ever anyone first downloads the software
// A new public key block will automatically be created upon starting the software for
// the first time, with this gensis key being that block.
#define GIVEME_BLOCKCHAIN_GENESIS_KEY "04B008DE6617103CA76D235E10980C0AE5812D3538AF0732800F387DEAE9D6BCC6A4F42E786ABA216B0C3F508F8C0AE35516984B0FFEDAB80894E5EEFF9FCEF3D9"
#define GIVEME_BLOCKCHAIN_GENESIS_HASH "055a43a6aa5868390991cc79fb416e6cf07d8c748f3999c586101ee4a998afc2"
#define GIVEME_BLOCKCHAIN_GENESIS_NOUNCE "3352266"

// Unix timestamp from when blocks are allowed to be added to the chain
// We can use this timestamp to know how long the blockchain should be.
// If an attacker sent a longer chain than mathematically allowed then we know its fraud.
#define GIVEME_BLOCK_BEGIN_TIMESTAMP 1639333570

#define GIVEME_TCP_PORT 10287
#define GIVEME_TCP_DATA_EXCHANGE_PORT 10288

// We only ever turn on TCP when we are expecting someone, therefore we wont allow any queuing of any kind
// first to chat with us gets priority
#define GIVEME_TCP_SERVER_MAX_CONNECTIONS 100
// If we have no client accepted or message within 2 seconds we will drop the TCP connection
#define GIVEME_NETWORK_TCP_CONNECT_TIMEOUT_SECONDS 2
// 30 seconds waiting on a recv or send and we will timeout.
#define GIVEME_NETWORK_TCP_IO_TIMEOUT_SECONDS 30

#define GIVEME_NETWORK_TCP_DATA_EXCHANGE_LISTEN_TIMEOUT 10

// Once every 30 minutes we will ask for the most up to date blockchain incase we lagged behind.
#define GIVEME_NETWORK_UPDATE_CHAIN_REQUEST_SECONDS 1800

// Blockchain will resize its self after 1024 blocks, and it will resize to +1024 blocks each time
#define BLOCKCHAIN_RESIZE_TOTAL_BLOCKS 1024


#endif