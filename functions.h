#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <pcap/pcap.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>



/* ARP protocol opcodes in net/if_arp.h */


#define ARP_HTYPE_ETH 1
#define ARP_PTYPE_IP  0x0800
#define ARP_HLEN_ETH  6
#define ARP_PLEN_IP   4
#define ARP_OPER_RQ   1
#define ARP_OPER_RP   2


void usage(void);


typedef struct _my_arp_hdr
{
	uint16_t HTYPE;		// hardware type
	uint16_t PTYPE;		// protocol type
	uint8_t  HLEN;		// hardware address length
	uint8_t  PLEN;		// protocol address length
	uint16_t OPER;		// operation
	uint8_t  SHA[6];	// sender hardware address; actually uint48_t
	uint32_t SPA;		// sender protocol address
	uint8_t  THA[6];	// target hardware address; actually uint48_t
	uint32_t TPA;		// target protocol address
} my_arp_hdr;

typedef struct _my_etharp_pckt
{
	uint8_t    DMAC[6];
	uint8_t    SMAC[6];
	uint16_t   ETHTYPE;
	my_arp_hdr ARPHDR;
} my_etharp_pckt;

