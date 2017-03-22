#include <unistd.h>
#include <stdio.h>
#include "includes/bgp.h"

int main(int argc, char **argv) {
    struct bgp *proc;

    proc = create_bgp_process(0x01010101, 0x01);

    printf("Added peer %d\n", add_bgp_peer(proc, "1.1.1.1", 65000));
    printf("Added peer %d\n", add_bgp_peer(proc, "1.1.1.1", 65000));
    printf("Added peer %d\n", add_bgp_peer(proc, "1.1.1.1", 65000));
    delete_bgp_peer(proc, 0);
    delete_bgp_peer(proc, 1);
    delete_bgp_peer(proc, 2);

    //destroy_bgp_process(proc);

    return 0;
}




