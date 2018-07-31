/*----------------------------------------------------------------------*/
/* Program Description */
/* 
 * Fake sender(=victim)'s ARP table by sending arp packets
 * sender ip == victim ip
 * target ip usually set as gateway ip
 * 
 * Send user defined buffer as packet, using pcap_sendpacket()
 * Find attacker(=you)'s MAC information (@google)
 */
/*----------------------------------------------------------------------*/


#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>


void usage(void);

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

void usage(void)
{
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
	
	return;
}

