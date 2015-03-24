#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <math.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TCP_BGP_PORT 179

#define BGP_HEADER_LEN 19
#define BGP_HEADER_MARKER_LEN 16
//First byte after BGP header, same as length of header.
#define BGP_MAX_LEN 4096

typedef enum {
    OPEN = 1,
    UPDATE,
    NOTIFICATION,
    KEEPALIVE
} bgp_msg_type;

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

struct bgp_local {
    unsigned int asn;
    int hold_time;
    int identifier;
};

struct bgp_msg {
    uint16_t length;
    bgp_msg_type type;
    uint8_t body[BGP_MAX_LEN - BGP_HEADER_LEN];
};

struct bgp_ipv4_route {
    uint8_t network[4];
    uint8_t prefix;
};

struct bgp_route_chain {
    struct bgp_ipv4_route route;
    struct bgp_route_chain *next;
};



struct bgp_peer *bgp_create_peer(const char *, const int, const char*);
int bgp_destroy_peer(struct bgp_peer *);

void bgp_create_header(const short, bgp_msg_type, unsigned char*);
struct bgp_msg bgp_validate_header(const uint8_t *);

int bgp_connect(struct bgp_peer *);
int bgp_open(struct bgp_peer *, const struct bgp_local);
int bgp_keepalive(struct bgp_peer *);

int bgp_readloop(struct bgp_peer *);
void parse_update(struct bgp_msg);
struct bgp_route_chain *extract_routes(int, uint8_t *);

void bgp_print_err(char *);


