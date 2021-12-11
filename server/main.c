#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include "config.h"
#include "af_unix_network.h"
#include "network.h"
#include "tpool.h"
#include "blockchain.h"
#include "log.h"
#include "key.h"

void initialize()
{
	// We should setup the seeder for when we use random.
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	/* using nano-seconds instead of seconds */
	srand((time_t)ts.tv_nsec);

	char data_directory[PATH_MAX];
	sprintf(data_directory, "%s/%s", getenv("HOME"), ".giveme");
	DIR *dir = opendir(data_directory);
	if (!dir)
	{
		// First time setup
		mkdir(data_directory, 0775);
		sprintf(data_directory, "%s/%s/packages", getenv("HOME"), ".giveme");
		mkdir(data_directory, 0775);
	}

	sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
	giveme_thread_pool_init(GIVEME_TOTAL_THREADS);
	giveme_blockchain_initialize();
	giveme_network_initialize();
	giveme_load_keypair();
}

void check_my_key()
{
	giveme_lock_chain();
	// Do we have our public key in the blockchain yet?
	struct blockchain_individual individual;
	int res = giveme_blockchain_get_individual(giveme_public_key(), &individual);
	if (res < 0)
	{
		giveme_log("%s could not find our public key data in the blockchain\n", __FUNCTION__);
		giveme_log("%s will publish our identity and key to the network\n", __FUNCTION__);
		struct giveme_tcp_packet packet = {};
		packet.type = GIVEME_NETWORK_TCP_PACKET_TYPE_PUBLISH_PUBLIC_KEY;
		strncpy(packet.publish_public_key.name, getenv("USER"), sizeof(packet.publish_package.name));
		memcpy(&packet.publish_public_key.pub_key, giveme_public_key(), sizeof(packet.publish_public_key.pub_key));
		giveme_network_broadcast(&packet);
	}
	giveme_unlock_chain();
}

int main(int argc, char *argv[])
{
	initialize();
	giveme_thread_pool_start();

	giveme_network_listen();
	giveme_network_connection_thread_start();
	giveme_network_process_thread_start();
	check_my_key();

	giveme_af_unix_listen();

	return 0;
}
