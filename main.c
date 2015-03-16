#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "bgp.h"


int main(int argc, char **argv) {
    struct bgp_peer *peer_1;
    struct bgp_local local_info;

    if (argc < 2) {
        printf("Usage: bgp_listener <remote_ip> <remote_as>\n");
        exit(0);
    }

    //Our local information
    local_info.asn = 65000;
    local_info.hold_time = 180;
    local_info.identifier = 0x01010101;

    peer_1 = bgp_create_peer(argv[1], atoi(argv[2]), "Test Peer");

    bgp_connect(peer_1);
    bgp_open(peer_1, local_info);

    bgp_readloop(peer_1);

    bgp_destroy_peer(peer_1);

    return 0;
}
