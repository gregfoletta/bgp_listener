#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "bgp.h"


int main(int argc, char **argv) {
    unsigned char bgp_header[BGP_HEADER_LEN];

    if (argc < 2) {
        printf("Usage: bgp_listener <remote_ip> <remote_as>\n");
        exit(0);
    }

    struct bgp_peer *peer_1;

    peer_1 = bgp_create_peer(argv[1], atoi(argv[2]), "Test Peer");

    bgp_connect(peer_1);

    bgp_create_header(255, OPEN, bgp_header);

    send(peer_1->socket.fd, bgp_header, BGP_HEADER_LEN, 0);

    sleep(10);

    bgp_destroy_peer(peer_1);

    return 0;
}
