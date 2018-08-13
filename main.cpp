/* Copyright © 2018 James Sung. All rights reserved. */

#include "functions.h"

// ./send_arp <interface> <sender ip> <target ip>
int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		PRINT_USAGE();
		puts("[*] Exiting program with -1");
		return -1;
	}
	
	puts("[+] Running program...\n");

	int res = SEND_ARP(argv[1], argv[2], argv[3]);

	if (res == -1)
	{
		return -1;
	}

	puts("[*] Exiting program with 0");

	return 0;
}

