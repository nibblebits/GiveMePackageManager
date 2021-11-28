#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "network.h"

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
	giveme_network_listen();

	return 0;
}
