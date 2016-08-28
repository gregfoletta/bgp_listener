#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "bgp.h"
#include "cli.h"
#include "debug.h"


int quit_func(int, char **, void *);
int change_debug_level(int, char **, void *);

int main(int argc, char **argv) {
    struct bgp_peer *peer_1;
    struct cli_command_list *list = NULL;

    if (argc < 2) {
        printf("Usage: bgp_listener <remote_ip> <remote_as>\n");
        exit(0);
    }

    debug_enable();
   
    DEBUG_PRINT("Adding functioins to the CLI list\n");
    cli_commandlist_add(&list, "quit", quit_func);
    cli_commandlist_add(&list, "debug", change_debug_level);
    cli_commandlist_add(&list, "stats", print_bgp_statistics);

    peer_1 = bgp_create_peering(argv[1], atoi(argv[2]), 65000, 0x01010101, 120, "Remote_Peer");
    bgp_activate(peer_1);
    cli_read_loop(list, peer_1);
    cli_free(list);
    bgp_destroy_peer(peer_1);

    return 0;
}


int quit_func(int argc, char **argv, void *data) { return -1; }

int change_debug_level(int argc, char **argv, void *data) { 
    if (argc < 2) {
        printf("%s requires an argument\n", argv[0]);
        return 0; 
    }

    switch (atoi(argv[1])) {
    case 0:
        printf("Disabling Debug\n");
        debug_disable();
        break;
    case 1:
        printf("Enabling Debug\n");
        debug_enable();
        break;
    default:
        printf("Unkown Argument\n");
    }
    return 0;
}





