#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "bgp.h"
#include "cli.h"


int test_func(void *);

int main(int argc, char **argv) {
    struct bgp_peer *peer_1;
    struct cli_command_list *list = NULL;

    
    cli_commandlist_add(&list, "show peer", print_bgp_peer_info);
    cli_commandlist_add(&list, "show withdrawn", print_bgp_pending_withdrawn);

    struct bgp_local local_info = { 65000, 180, 0x01010101};

    if (argc < 2) {
        printf("Usage: bgp_listener <remote_ip> <remote_as>\n");
        exit(0);
    }

    peer_1 = bgp_create_peer(argv[1], atoi(argv[2]), "Test Peer");

    bgp_connect(peer_1);
    bgp_open(peer_1, local_info);

    if (pthread_create(&(peer_1->thread), NULL, bgp_loop, peer_1) != 0) {
        bgp_print_err("pthread_create() failed");
        return 0;
    }

    cli_read_loop(list, peer_1);

    bgp_destroy_peer(peer_1);

    return 0;
}

