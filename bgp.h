#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <pthread.h>

struct bgp_peer;

struct bgp_local;

struct bgp_peer *bgp_create_peering(const char *, const uint16_t , const uint16_t , uint32_t , uint16_t ,const char *);
int bgp_destroy_peer(struct bgp_peer *);

int bgp_activate(struct bgp_peer *);

int bgp_connect(struct bgp_peer *);
int bgp_open(struct bgp_peer *);
int print_bgp_peer_info(void *);
int print_bgp_pending_withdrawn(void *);

void bgp_print_err(char *);


