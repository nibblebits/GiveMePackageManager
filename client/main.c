#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "package.h"
#include "af_unix_network.h"
#include "network.h"
#include "misc.h"
int publish_package(int argc, char *argv[])
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

void packages_print(struct package* packages, size_t total)
{
	printf("Total known packages on network %i\n", (int)total);
	for (int i = 0; i < total; i++)
	{
		printf("%s : %s : %s\n", packages[i].details.name, packages[i].details.description, packages[i].details.filehash);
	}
}
int packages(int argc, char* argv[])
{
	if (argc < GIVEME_REQUIRED_PACKAGES_ARGC)
	{
		printf("Not enough arguments to display packages\n");
		return -1;
	}

	int sock = giveme_af_unix_connect();
	struct network_af_unix_packages_response_packages packages;
	int res = giveme_packages(sock, 0, &packages);
	if (res < 0)
	{
		printf("Problem getting packages\n");
		return -1;
	}

	packages_print(packages.packages, packages.total);
}

int signup(int argc, char *argv[])
{
	if (argc < GIVEME_REQUIRED_SIGNUP_ARGC)
	{
		printf("Expecting a name that you want to identify on the network with\n");
		return -1;
	}

	int sock = giveme_af_unix_connect();
	giveme_signup(sock, argv[2]);
}

int mine_useless_blocks(int argc, char *argv[])
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

int get_my_info(int argc, char *argv[])
{
	if (argc < GIVEME_REQUIRED_GET_INFO_ARGC)
	{
		printf("Expecting additional arguments to get your information\n");
		return -1;
	}
	int sock = giveme_af_unix_connect();
	struct blockchain_individual my_info = giveme_info(sock);
	if (!(my_info.flags & GIVEME_BLOCKCHAIN_INDIVIDUAL_FLAG_HAS_KEY_ON_CHAIN))
	{
		printf("Your not known to the blockchain, do \"giveme signup YourNameHere\"\n");
		return -1;
	}

	printf("Your account details\n");

	printf("Name: %s\n", my_info.key_data.name);
	printf("Balance %f\n", my_info.key_data.balance);
	printf("Public key / Payment Key %s\n", my_info.key_data.key.key);
	printf("Total blocks verified: %zd\n", my_info.key_data.verified_blocks.total);
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
	else if (S_EQ(argv[1], "mine"))
	{
		return mine_useless_blocks(argc, argv);
	}
	else if (S_EQ(argv[1], "signup"))
	{
		return signup(argc, argv);
	}
	else if (S_EQ(argv[1], "info"))
	{
		return get_my_info(argc, argv);
	}
	else if(S_EQ(argv[1], "packages"))
	{
		return packages(argc, argv);
	}

	return 0;
}
