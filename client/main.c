#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "af_unix_network.h"
#include "network.h"
#include "misc.h"
int publish_package(int argc, char*argv[])
{
	if (argc < GIVEME_REQUIRED_PUBLISH_ARGC)
	{
		printf("Expecting giveme publish filename package_name\n");
		return -1;
	}

	int sock = giveme_af_unix_connect();
	giveme_publish(sock, argv[2], argv[3]);
	
	return 0;
}

int mine_useless_blocks(int argc, char*argv[])
{
	if (argc < GIVEME_REQUIRED_FAKE_MINING_ARGC)
	{
		printf("Expecting total fake blocks to mine\n");
		return -1;
	}
	int sock = giveme_af_unix_connect();
	giveme_make_fake_blockchain(sock, atoi(argv[2]));
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < GIVEME_MINIMUM_ARGC)
	{
		printf("You must provide a package name to download\n E.g giveme laravel-framework\n\nTo publish do\ngiveme publish DIRECTORY_PATH\n");
		return -1;
	}
	
	if (S_EQ(argv[1], "publish"))
	{
		return publish_package(argc, argv);
	}
	else if(S_EQ(argv[1], "mine"))
	{
		return mine_useless_blocks(argc, argv);
	}

	return 0;
}
