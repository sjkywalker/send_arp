#include "functions.h"


void usage(void)
{
	printf("[-] Wrong usage!\n");
	printf("[-] syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("[-] sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");

	return;
}




