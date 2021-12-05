#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include "config.h"
#include "af_unix_network.h"
#include "network.h"
#include "tpool.h"
#include "blockchain.h"

void initialize()
{
	// We should setup the seeder for when we use random.
	struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* using nano-seconds instead of seconds */
    srand((time_t)ts.tv_nsec);

	char data_directory[PATH_MAX];
	sprintf(data_directory, "%s/%s", getenv("HOME"), ".giveme");
	DIR* dir = opendir(data_directory);
	if(!dir)
	{
		// First time setup
		mkdir(data_directory, 0775);
		sprintf(data_directory, "%s/%s/packages", getenv("HOME"), ".giveme");
		mkdir(data_directory, 0775);
	}

	giveme_blockchain_initialize();
	giveme_network_initialize();
}

int main(int argc, char *argv[])
{
	initialize();
	giveme_thread_pool_init(GIVEME_TOTAL_THREADS);
	giveme_thread_pool_start();
	
	giveme_udp_network_announce();
	giveme_network_request_blockchain_try(GIVEME_MAX_BLOCKCHAIN_REQUESTS_IF_FAILED);
	giveme_process_thread_start();
	giveme_udp_network_listen();

	giveme_af_unix_listen();

	return 0;
}
