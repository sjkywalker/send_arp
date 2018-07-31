all: send_arp

main.o: main.cpp
	gcc -c -g -o main.o main.cpp

send_arp: main.o
	gcc -g -o send_arp main.o

clean:
	rm -f *.o
	rm -f send_arp

