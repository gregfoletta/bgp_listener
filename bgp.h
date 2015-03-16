#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TCP_BGP_PORT 179

#define BGP_HEADER_LEN 19

typedef enum {
    OPEN = 1,
    UPDATE,
    NOTIFICATION,
    KEEPALIVE
} bgp_msg_type;

struct bgp_header_struct {
    uint8_t marker[16];    
    uint16_t length;
    bgp_msg_type msg_type;
};

union bgp_header {
    struct bgp_header_struct params;
    uint8_t data[19];
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

struct bgp_peer *bgp_create_peer(const char *, const int, const char*);
int bgp_destroy_peer(struct bgp_peer *);
void bgp_print_info(const struct bgp_peer *);

void bgp_create_header(const short, bgp_msg_type, unsigned char*);

int bgp_connect(struct bgp_peer *);
void bgp_send_message(const struct bgp_peer *peer);

void bgp_print_err(char *);


