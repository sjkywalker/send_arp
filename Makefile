all: send_arp

functions.o: functions.h functions.cpp
	g++ -c -g -o functions.o functions.cpp

main.o: functions.h main.cpp
	g++ -c -g -o main.o main.cpp

send_arp: main.o functions.o
	g++ -g -o send_arp main.o functions.o

clean:
	rm -f *.o
	rm -f send_arp

