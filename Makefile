CC   := gcc 
src = $(wildcard *.c)
obj = $(src:.c=.o)
CFLAGS += -Wall -Wextra -g -std=gnu99 -fdiagnostics-color=always -Wno-unused-parameter -Wno-unused-variable
LDFLAGS = -pthread

bgp_listener: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) myprog


