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
	
	printf("[+] Running Program...\n\n");
	
	uint8_t attacker_MAC[6];
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
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
	
	char           attacker_IP_char[16];
	struct in_addr *attacker_IP_struct = (struct in_addr *)calloc(1, sizeof(in_addr));
	uint32_t       attacker_IP_int;

	strcpy(attacker_IP_char, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	//display result
	printf("[My IP  Address] %s\n", attacker_IP_char);
	
	inet_aton(attacker_IP_char, attacker_IP_struct);
	attacker_IP_int = ntohl(attacker_IP_struct->s_addr);
	printf("%08x\n", attacker_IP_int);

/* get attacker mac address */
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, dev);
	if (!ioctl(fd, SIOCGIFHWADDR, &s))
	{
		printf("[My MAC Address] ");
		for (int i = 0; i < 6; i++)
		{
			//printf(" %02x", (unsigned char) s.ifr_addr.sa_data[i]);
			attacker_MAC[i] = s.ifr_addr.sa_data[i];
			if(i) { printf(":"); }
			printf("%02x", (unsigned char) attacker_MAC[i]);
		}
		puts("");
	}

/* send arp request broadcast */
	my_etharp_pckt *arp_request = (my_etharp_pckt *)calloc(1, sizeof(my_etharp_pckt));
	//my_arp_hdr *arp_request = (my_arp_hdr *)calloc(1, sizeof(my_arp_hdr));

	struct in_addr *victim_IP_struct = (struct in_addr *)calloc(1, sizeof(struct in_addr));
	uint32_t       victim_IP_int;

	inet_aton(argv[3], victim_IP_struct);
	
	victim_IP_int = ntohl(victim_IP_struct->s_addr);

	for (int i = 0; i < 6; i++) { arp_request->DMAC[i] = 0xFF; }
	for (int i = 0; i < 6; i++) { arp_request->SMAC[i] = attacker_MAC[i]; }
	arp_request->ETHTYPE = ETHERTYPE_ARP;
/*
	(arp_request->ARPHDR).HTYPE = ARP_HTYPE_ETH;
	(arp_request->ARPHDR).PTYPE = ARP_PTYPE_IP;
	(arp_request->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_request->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_request->ARPHDR).OPER  = ARP_OPER_RQ;
*/
	(arp_request->ARPHDR).HTYPE = ARPHRD_ETHER;
	(arp_request->ARPHDR).PTYPE = ETHERTYPE_IP;
	(arp_request->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_request->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_request->ARPHDR).OPER  = ARPOP_REQUEST;
	for (int i = 0; i < 6; i++) { (arp_request->ARPHDR).SHA[i] = attacker_MAC[i]; }
	(arp_request->ARPHDR).SPA   = attacker_IP_int;
	for (int i = 0; i < 6; i++) { (arp_request->ARPHDR).THA[i] = 0x00; }
	(arp_request->ARPHDR).TPA   = victim_IP_int;
	
	

	


	

/* from pcap_send */
/*
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	printf("Receiving packets...\n\n");

	while (true)
	{
		struct pcap_pkthdr *header;
		const uint8_t *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
	}
*/
	
	
	return 0;
}





