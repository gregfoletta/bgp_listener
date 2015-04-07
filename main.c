#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "bgp.h"


int main(int argc, char **argv) {
    struct bgp_peer *peer_1;
    struct bgp_peer_group bgp_peers;

    struct bgp_local local_info = { 65000, 180, 0x01010101};

    if (argc < 2) {
        printf("Usage: bgp_listener <remote_ip> <remote_as>\n");
        exit(0);
    }

    //BGP peers should be set to zero.
    memset(&bgp_peers, 1, sizeof(bgp_peers));

    peer_1 = bgp_create_peer(argv[1], atoi(argv[2]), "Test Peer", &bgp_peers);

    bgp_connect(peer_1);
    bgp_open(peer_1, local_info);

    bgp_loop(peer_1);

    bgp_destroy_peer(peer_1);

    return 0;
}
