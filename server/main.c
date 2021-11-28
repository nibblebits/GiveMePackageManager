#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "af_unix_network.h"
#include "network.h"
#include "tpool.h"

void initialize()
{
	char data_directory[PATH_MAX];
	sprintf(data_directory, "%s/%s/packages", getenv("HOME"), ".giveme");
	DIR* dir = opendir(data_directory);
	if(!dir)
	{
		// First time setup
		mkdir(data_directory, 0775);
	}
}
int main(int argc, char *argv[])
{
	initialize();
	giveme_thread_pool_init(GIVEME_TOTAL_THREADS);
	giveme_thread_pool_start();

	giveme_udp_network_listen();
	giveme_af_unix_listen();

	return 0;
}
