#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include "config.h"
#include "af_unix_network.h"
#include "network.h"
#include "tpool.h"
#include "blockchain.h"
#include "package.h"
#include "vector.h"
#include "log.h"
#include "key.h"

void initialize(bool mine_genesis)
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
	giveme_log_initialize();
	giveme_package_initialize();
	giveme_load_keypair();
	

	giveme_thread_pool_init(GIVEME_TOTAL_THREADS);
	giveme_blockchain_initialize(mine_genesis);
	giveme_network_initialize();
}

int main(int argc, char *argv[])
{
	sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
	bool mine_genesis = (argc > 1 && S_EQ(argv[1], "genesis"));
	initialize(mine_genesis);
	giveme_thread_pool_start();
	giveme_network_listen();
	giveme_network_upnp_port_forward();
	giveme_network_connection_thread_start();
	giveme_network_process_thread_start();
	giveme_af_unix_listen();

	return 0;
}
