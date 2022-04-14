#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "package.h"
#include "af_unix_network.h"
#include "network.h"
#include "misc.h"
#include "givemezip.h"
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

void packages_print(struct package *packages, size_t total)
{
	for (int i = 0; i < total; i++)
	{
		printf("%s : %s : %s : Size=%lld\n", packages[i].details.name, packages[i].details.description, packages[i].details.filehash, (long long int)packages[i].details.size);
	}
}

int download_package(int argc, char* argv[])
{
	if (argc < GIVEME_REQUIRED_DOWNLOAD_ARGC)
	{
		printf("Expecting giveme download package_name\n");
		return -1;
	}

	int sock = giveme_af_unix_connect();
	struct network_af_unix_packet packet;
	if (giveme_download(sock, argv[2], &packet) < 0)
	{
		printf("Issue communicating with socket to preform a download\n");
		return -1;
	}

	if (packet.type == NETWORK_AF_UNIX_PACKET_TYPE_NOT_FOUND)
	{
		printf("The package with the given name %s could not be located\n", argv[1]);
		return -1;
	}
	else if (packet.type == NETWORK_AF_UNIX_PACKET_TYPE_PROBLEM)
	{
		printf("Theres an issue downloading the package, its possible no active peers with this file data could be found.\n");
		return -1;
	}

	printf("The package %s has been downloaded\n", argv[1]);

	char dst_path[PATH_MAX];
	strncpy(dst_path, realpath(argv[3], NULL), sizeof(dst_path));
	// Extracting our file to the given path.
	printf("Extracting to %s\n", dst_path);
	giveme_unzip_directory(packet.package_download_response.path, dst_path);

	return 0;
}

int packages(int argc, char *argv[])
{
	if (argc < GIVEME_REQUIRED_PACKAGES_ARGC)
	{
		printf("Not enough arguments to display packages\n");
		return -1;
	}

	int page = 0;
	while (1)
	{
		for (int i = 0; i < 5; i++)
		{
			int sock = giveme_af_unix_connect();
			struct network_af_unix_packages_response_packages packages;
			int res = giveme_packages(sock, (page * 5) + i, &packages);
			if (res < 0)
			{
				printf("Problem getting packages\n");
				return -1;
			}

			close(sock);

			if (packages.total == 0)
			{
				printf("You have reached the end of the available packages. To create your own use giveme publish command\n");
				return 0;
			}
			packages_print(packages.packages, packages.total);
		}
		page++;

		printf("Press any to load more\n");
		getchar();
	}
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

int awaiting_transactions(int argc, char* argv[])
{
	int res = -1;
	int sock = giveme_af_unix_connect();
	struct network_af_unix_my_awaiting_transactions_response packet_out;
	res = giveme_my_awaiting_transactions(sock, &packet_out);
	if (res < 0)
	{
		printf("There was an issue getting your awaiting transactions\n");
		goto out;
	}

	printf("You have %i awaiting transactions\n", (int)packet_out.total);
	for (int i = 0; i < packet_out.total; i++)
	{
		printf("Transaction %s - %s\n", packet_out.transactions[i].packet.data_hash, giveme_network_awaiting_transaction_state_string(&packet_out.transactions[i]));
	}
out:
	return res;

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
	else if (S_EQ(argv[1], "packages"))
	{
		return packages(argc, argv);
	}
	else if(S_EQ(argv[1], "download"))
	{
		return download_package(argc, argv);
	}
	else if(S_EQ(argv[1], "awaiting"))
	{
		return awaiting_transactions(argc, argv);
	}

	return 0;
}
