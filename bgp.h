#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 

#define MAX_BGP_PEERS 16

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

struct bgp_peer_group {
    int total_peers;
    struct bgp_peer *peer_list[MAX_BGP_PEERS];
};


struct bgp_local {
    unsigned int asn;
    int hold_time;
    int identifier;
};


struct bgp_peer *bgp_create_peer(const char *, const int, const char*, struct bgp_peer_group *);
int bgp_destroy_peer(struct bgp_peer *);

int bgp_connect(struct bgp_peer *);
int bgp_open(struct bgp_peer *, const struct bgp_local);
int bgp_loop(struct bgp_peer *);

void bgp_print_err(char *);


