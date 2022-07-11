#ifndef CONFIG_H
#define CONFIG_H
#define GIVEME_MINIMUM_ARGC 2
#define GIVEME_REQUIRED_PUBLISH_ARGC 4
#define GIVEME_REQUIRED_SIGNUP_ARGC 3
#define GIVEME_REQUIRED_FAKE_MINING_ARGC 3
#define GIVEME_REQUIRED_GET_INFO_ARGC 2
#define GIVEME_REQUIRED_PACKAGES_ARGC 2
#define GIVEME_REQUIRED_DOWNLOAD_ARGC 4

#define GIVEME_CLIENT_SERVER_PATH "/tmp/givemebinds"
#define GIVEME_DATA_BASE ".giveme"
#define GIVEME_PACKAGE_DIRECTORY GIVEME_DATA_BASE "/packages"
#define GIVEME_DATA_BASE_DIRECTORY_ENV "HOME"
#define GIVEME_BLOCKCHAIN_FILEPATH "/blockchain.bin"
#define GIVEME_PACKAGES_PATH "/dpackages.bin"
#define GIVEME_MY_AWAITING_TRANSACTIONS_PATH "/awaiting-transactions.bin"

#define GIVEME_PUBLIC_KEY_FILEPATH "/key.pub"
#define GIVEME_PRIVATE_KEY_FILEPATH "/key.pri"

#define GIVEME_TOTAL_THREADS 8
#define GIVEME_MAX_BLOCKCHAIN_REQUESTS_IF_FAILED 1
#define GIVEME_PACKAGE_NAME_MAX 128
#define GIVEME_PACKAGE_DESCRIPTION_MAX 512
#define GIVEME_KEY_NAME_MAX 128
#define GIVEME_TOTAL_ZEROS_FOR_MINED_BLOCK 1
#define GIVEME_IP_STRING_SIZE 17

// Must have the last number as 1
#define GIVEME_SECONDS_TO_MAKE_BLOCK 321

#define GIVEME_MINIMUM_TCP_PACKET_SIZE 1024
// 64 bytes for hashed key then +1 for null terminator
#define GIVEME_MAX_KEY_LENGTH 140

#define GIVEME_MAX_SIGNATURE_PART_LENGTH 65

// We allow a maximum of 16 transactions per block
#define GIVEME_MAXIMUM_TRANSACTIONS_IN_A_BLOCK 16

#define GIVEME_VALIDATION_MINING_REWARD 0.05

// Genesis key will be added as a first block when ever anyone first downloads the software
// A new public key block will automatically be created upon starting the software for
// the first time, with this gensis key being that block.
#define GIVEME_BLOCKCHAIN_GENESIS_HASH "ee38b3a044378efdfd15a8ff908b2968fff654ea8226d3b6a76dd055166726bd"
#define GIVEME_BLOCKCHAIN_GENESIS_NOUNCE "16664369"
#define GIVEME_BLOCKCHAIN_GENESIS_PUBLIC_KEY "04A3B8CB0EE06C17FF179E6BDB803F5AEC06CADBA6ADE808616F2BAADB79A3F5571744DD06CDBF7585AE97755290B961CAE974063530B6421E7E930D778D820F91"
#define GIVEME_BLOCKCHAIN_GENESIS_PUBLIC_KEY_SIZE 129
// Unix timestamp from when blocks are allowed to be added to the chain
// We can use this timestamp to know how long the blockchain should be.
// If an attacker sent a longer chain than mathematically allowed then we know its fraud.
#define GIVEME_BLOCK_BEGIN_TIMESTAMP 1639333570

#define GIVEME_TCP_PORT 10287
#define GIVEME_TCP_DATA_EXCHANGE_PORT 10288
// Used for transmission between socket client and server.
#define GIVEME_LOCAL_EXCHANGE_PORT 10289

// We only ever turn on TCP when we are expecting someone, therefore we wont allow any queuing of any kind
// first to chat with us gets priority
#define GIVEME_TCP_SERVER_MAX_CONNECTIONS 100
// If we have no client accepted or message within 2 seconds we will drop the TCP connection
#define GIVEME_NETWORK_TCP_CONNECT_TIMEOUT_SECONDS 2
// 1 seconds waiting on a recv or send and we will timeout.
#define GIVEME_NETWORK_TCP_IO_TIMEOUT_SECONDS 10
// Longer timeout for data exchange protocol
#define GIVEME_NETWORK_TCP_DATA_EXCHANGE_IO_TIMEOUT_SECONDS 10

#define GIVEME_NETWORK_TCP_DATA_EXCHANGE_LISTEN_TIMEOUT 10

// Once every minute after block verify we will ask for the most up to date blockchain incase we lagged behind.
#define GIVEME_NETWORK_UPDATE_CHAIN_REQUEST_SECONDS GIVEME_SECONDS_TO_MAKE_BLOCK + 10

// Blockchain will resize its self after 1024 blocks, and it will resize to +1024 blocks each time
#define BLOCKCHAIN_RESIZE_TOTAL_BLOCKS 1024

// The total packages that can exist before a resize is needed
#define PACKAGES_TOTAL_ENTITIES 2056

// The maximum known ip addresses in a package cache..
#define PACKAGE_MAX_KNOWN_IP_ADDRESSES 32

#define PACKAGE_MAX_PER_PAGE 1

#define AWAITING_TRANSACTION_MAX_PER_PAGE 5

#define GIVEME_PACKAGE_CHUNK_SIZE 8192

#define GIVEME_PACKAGE_DOWNLOAD_TOTAL_THREADS 1

#define GIVEME_MAX_RELAYED_PACKET_ELEMENTS 100

#define GIVEME_AWAITING_FOR_BLOCK_MINIMUM_BLOCK_SIZE 24

// We can tip a maximum of four people who assisted in us downloading a file from.
#define GIVEME_MAX_TIPS_PER_DOWNLOAD 4
#endif