#include <stdio.h>
#include <stdlib.h>


#include "bgp.h"


int main(int argc, char **argv) {
    struct bgp_peer *peer_1;

    peer_1 = bgp_create_peer(argv[1], atoi(argv[2]), "Test Peer");

    bgp_connect(peer_1);

    bgp_destroy_peer(peer_1);

    return 0;
}
