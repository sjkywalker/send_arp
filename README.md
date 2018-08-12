# Send ARP

This program poisons sender's ARP table, and redirects outgoing packets from sender to attacker.

## Getting started

### Overview

* Fake sender(=victim)'s ARP table by sending arp packets
* sender ip == victim ip
* target ip usually set as gateway ip
* Send user defined buffer as packet, using pcap_sendpacket()
* Find attacker(=you)'s MAC information (@google)
* Three entities
    * attacker
    * sender (victim)
    * target (gateway, *usually*)

### Program Flow

```txt
1. Find attacker IP address
2. Find attacker MAC address
3. Send ARP request and receive ARP reply to identify sender MAC address
4. Send fake ARP reply to sender and poison its ARP table
```

### Development Environment

```bash
user@ubuntu:~/send_arp$ uname -a
Linux ubuntu 4.15.0-30-generic #32~16.04.1-Ubuntu SMP Thu Jul 26 20:25:39 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

user@ubuntu:~/send_arp$ g++ --version
g++ (Ubuntu 5.4.0-6ubuntu1~16.04.10) 5.4.0 20160609
```

### Prerequisites

This program includes the following headers. Make sure you have the right packages.
```c
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
```

## Running the program

### Build

Simply hit 'make' to create object files and executable.
```bash
make
```

### Run

Format
```bash
./send_arp <interface> <sender ip> <target ip>
```

Example
```bash
./send_arp ens33 192.168.120.119 192.168.120.2
```

You might need root priviledges to capture, send, and monitor network packets.

## Acknowledgements

* [Get my IP address](https://www.sanfoundry.com/c-program-get-ip-address/)
* [Get my MAC address](https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program)

## Authors

* **James Sung** - *Initial work* - [sjkywalker](https://github.com/sjkywalker)
* Copyright © 2018 James Sung. All rights reserved.
