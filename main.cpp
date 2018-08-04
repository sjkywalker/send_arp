/*----------------------------------------------------------------------*/
/* Program Description */
/* 
 * Fake sender(=victim)'s ARP table by sending arp packets
 * sender ip == victim ip
 * target ip usually set as gateway ip
 * 
 * Send user defined buffer as packet, using pcap_sendpacket()
 * Find attacker(=you)'s MAC information (@google)
 * 
 * Copyright © 2018 James Sung. All rights reserved.
 */
/*----------------------------------------------------------------------*/


#include "functions.h"


int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		usage();
		return -1;
	}
	
	printf("Running Program...\n\n");

	return 0;
}

