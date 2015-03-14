#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TCP_BGP_PORT 179


struct bgp_peer *bgp_create_peer(const char *, const int, const char*);
int bgp_destroy_peer(struct bgp_peer *);
void bgp_print_info(const struct bgp_peer *);
int bgp_connect(struct bgp_peer *);
void bgp_print_err(char *);

enum bgp_messsage_type {
    OPEN,
    UPDATE,
    NOTIFICATION,
    KEEPALIVE
};

struct bgp_socket {
    int fd;
    struct sockaddr_in sock_addr;
};

struct bgp_peer {
    char *name;
    unsigned int asn;
    char *ip;
    int hold_time;
    int identifier;
    struct bgp_socket socket;
};

