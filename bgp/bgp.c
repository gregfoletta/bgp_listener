#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <unistd.h>    
#include <sys/select.h>
#include <string.h>

#include <inttypes.h> //only needed temporarily for 64bit printf


#include <stdio.h>

#include "../includes/list.h"
#include "../includes/tcp_client.h"


#define MAX_BGP_PEERS   16
#define MAX_FD          MAX_BGP_PEERS + 1  //1 more FD for the timerfd
#define TIMER_FD        0 //0 is always the timerfd for the process


struct bgp {
    uint32_t router_id;
    uint32_t asn;
    int is_active;

    pthread_t worker_thread;


    struct list_head ingress_msg_queue;
    struct list_head egress_msg_queue;

    int uptime; //Specified in 10ths of a second
    int num_peers;

    struct bgp_peer *peers[MAX_BGP_PEERS];

    int file_desc[MAX_FD]; 
    int max_fd; //Required for pselect();
    fd_set file_desc_set;
};


struct bgp_peer {
    uint32_t router_id;
    uint32_t asn;
    int sock_fd;
    int id;
};


void *bgp_worker_thread(void *);
int init_bgp_timer(void);
int max_peer_fd(struct bgp *);



struct bgp *create_bgp_process(uint32_t router_id, uint32_t asn) {
    struct bgp *bgp_process;
    int x;

    bgp_process = malloc(sizeof *bgp_process);
    if (bgp_process == NULL) {
        goto out_error;
    }

    bgp_process->router_id = router_id;
    bgp_process->asn = asn;
    bgp_process->uptime = 0;
    bgp_process->num_peers = 0;
    bgp_process->is_active = 1;

    //Set all the peer pointers to NULL
    for (x = 0; x < MAX_BGP_PEERS; x++) {
        bgp_process->peers[x] = NULL;
    }

    //Create the 1 second timer and set up the FD set
    bgp_process->file_desc[TIMER_FD] = init_bgp_timer();
    bgp_process->max_fd = bgp_process->file_desc[TIMER_FD];
    FD_ZERO(&bgp_process->file_desc_set);
    FD_SET(bgp_process->file_desc[TIMER_FD] + 1, &bgp_process->file_desc_set);


    if  (pthread_create(&bgp_process->worker_thread, NULL, bgp_worker_thread, bgp_process) != 0) {
        goto out_error;
    }

    return bgp_process;

out_error:
    free(bgp_process);
    return NULL;
}


void *bgp_worker_thread(void *arg) {
    struct bgp *bgp_process = arg;
    int ret, x;
    ssize_t read_bytes;
    uint64_t timer_iterations;

    while (bgp_process->is_active)
    {
        ret = pselect(bgp_process->max_fd, &bgp_process->file_desc_set, NULL, NULL, NULL, NULL);
        printf("Here\n");

        for (x = 0; x < MAX_FD; x++) {
            if (FD_ISSET(bgp_process->file_desc[x], &bgp_process->file_desc_set)) {
                read_bytes = read(bgp_process->file_desc[x], &timer_iterations, sizeof(uint64_t));
                bgp_process->uptime += timer_iterations;
            }
        }
    }

    return NULL;
}

void destroy_bgp_process(struct bgp *bgp_process) {
    printf("Destroying");
    bgp_process->is_active = 0;

    //Join the worker thread - throw away thbe return value
    pthread_join(bgp_process->worker_thread, NULL);
    free(bgp_process);
}


int init_bgp_timer(void) {
    int second_timer_fd;

    struct itimerspec second_counter = {
        .it_interval = { 0, 100000000 },
        .it_value = { 0, 100000000 }
    };

    second_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(second_timer_fd, 0, &second_counter, NULL);

    return second_timer_fd;
}


int add_bgp_peer(struct bgp *bgp_process, const char *host, uint32_t asn) {
    struct bgp_peer *new_peer;
    int peer_id;
    
    new_peer = malloc(sizeof(*new_peer));
    if (!new_peer) {
        goto error;
    }

    //Find an unused peer slot
    for (peer_id = 0; peer_id < MAX_BGP_PEERS; peer_id++) {
        if (bgp_process->peers[peer_id]) {
            continue;
        }

        bgp_process->peers[peer_id] = new_peer;
        bgp_process->num_peers++;
        
        new_peer->asn = asn;
        new_peer->id = peer_id;

        //Allocate the socket and add it to the FD_SET
        if ((new_peer->sock_fd = tcp_socket(host, "179")) < 0) {
            goto error_free;
        }
        FD_SET(new_peer->sock_fd, &bgp_process->file_desc_set);
        bgp_process->max_fd = max_peer_fd(bgp_process);

        return peer_id;
    }

error_free:
    free(new_peer);
error:
    return -1;
}


int delete_bgp_peer(struct bgp *bgp_process, int peer_id) {
    printf("Deleting peer");
    if (peer_id < 0 || peer_id > MAX_BGP_PEERS - 1 || !bgp_process->peers[peer_id]) {
        return -1;
    }

    FD_CLR(bgp_process->peers[peer_id]->sock_fd, &bgp_process->file_desc_set);
    close(bgp_process->peers[peer_id]->sock_fd);

    free(bgp_process->peers[peer_id]);
    bgp_process->peers[peer_id] = NULL;
    bgp_process->num_peers--;

    return 0;
}


int max_peer_fd(struct bgp *bgp_process) {
    int max = 0, x = 0;

    for (x = 0; x < MAX_BGP_PEERS - 1; x++) {
        if (!bgp_process->peers[x]) {
            continue;
        }

        max = (max > bgp_process->peers[x]->sock_fd) ? max : bgp_process->peers[x]->sock_fd;
    }

    return max;
}



int get_bgp_process_uptime(struct bgp *bgp_process) {
    if (!bgp_process)
        return -1;

    return bgp_process->uptime;
}
    


