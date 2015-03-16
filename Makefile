CC=gcc
CFLAGS=-c -Wall -Wextra -g
CFULES=


all: bgp_listener

bgp_listener: main.o bgp.o
	$(CC) main.o bgp.o -o bgp_listener

main.o: main.c 
	$(CC) $(CFLAGS) main.c

bgp.o: bgp.c 
	$(CC) $(CFLAGS) bgp.c

clean:  	
	rm -rf *.o bgp_listener
