#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 

enum bgp_fsm_states { 
    BGP_IDLE, 
    BGP_ACTIVE, 
    BGP_OPENSENT, 
    BGP_OPENCONFIRM, 
    BGP_ESTABLISHED 
};

struct bgp_socket {
    int fd;
    struct sockaddr_in sock_addr;
};

struct bgp_peer {
    char *name;
    uint8_t version;
    uint16_t local_asn;
    uint16_t remote_asn;
    uint32_t identifier;
    char *ip;
    uint16_t recv_hold_time;
    uint16_t curr_hold_time;
    enum bgp_fsm_states fsm_state;
    struct bgp_tlv_list *open_parameters;
    struct bgp_socket socket;
};

struct bgp_local {
    unsigned int asn;
    int hold_time;
    int identifier;
};


struct bgp_peer *bgp_create_peer(const char *, const uint16_t, const char*);
int bgp_destroy_peer(struct bgp_peer *);

int bgp_connect(struct bgp_peer *);
int bgp_open(struct bgp_peer *, const struct bgp_local);
int bgp_loop(struct bgp_peer *);
void print_bgp_peer_info(const struct bgp_peer *);

void bgp_print_err(char *);


