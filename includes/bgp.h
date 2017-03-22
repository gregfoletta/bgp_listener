#include <stdint.h>

struct bgp;

struct bgp *create_bgp_process(uint32_t, uint32_t);
int destroy_bgp_process(struct bgp *);
int add_bgp_peer(struct bgp *, const char *, uint32_t);
int delete_bgp_peer(struct bgp *, int);

int get_bgp_process_uptime(struct bgp *);




