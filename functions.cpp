#include "functions.h"


void PRINT_USAGE(void)
{
	printf("[-] Wrong usage!\n");
	printf("[-] syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("[-] sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
	return;
}

void PRINT_IP(char *IP_char)
{
	printf("%s", IP_char);
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


