# Copyright © 2018 James Sung. All rights reserved.

all: send_arp

send_arp: main.o functions.o
	g++ -g -o send_arp main.o functions.o -lpcap

main.o: functions.h main.cpp
	g++ -c -g -o main.o main.cpp

functions.o: functions.h functions.cpp
	g++ -c -g -o functions.o functions.cpp

clean:
	rm -f *.o
	rm -f send_arp

