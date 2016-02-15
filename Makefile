CC=c99
CFLAGS=-c -Wall -Wextra -g

all: bgp_listener

bgp_listener: main.o bgp.o cli.o debug.o
	$(CC) -pthread main.o bgp.o cli.o debug.o -o bgp_listener -lm

main.o: main.c 
	$(CC) $(CFLAGS) main.c

bgp.o: bgp.c bgp.h
	$(CC) $(CFLAGS) bgp.c

cli.o: cli.c cli.h
	$(CC) $(CFLAGS) cli.c

debug.o: debug.c debug.h
	$(CC) $(CFLAGS) debug.c
clean:  	
	rm -rf *.o bgp_listener
