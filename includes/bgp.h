#include <stdint.h>

struct bgp;

struct bgp *create_bgp_process(uint32_t, uint32_t);

int get_bgp_process_uptime(struct bgp *);




