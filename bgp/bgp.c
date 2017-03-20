#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <unistd.h>    
#include <sys/select.h>

#include <inttypes.h> //only needed temporarily for 64bit printf


#include <stdio.h>

#include "../includes/list.h"


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

    int uptime;
    int num_peers;

    int file_desc[MAX_FD]; 
    int max_fd; //Required for pselect();
    fd_set file_desc_set;
};


void *bgp_worker_thread(void *);
int init_bgp_timer(void);



struct bgp *create_bgp_process(uint32_t router_id, uint32_t asn) {
    struct bgp *bgp_process;

    bgp_process = malloc(sizeof *bgp_process);
    if (bgp_process == NULL) {
        goto out_error;
    }

    bgp_process->router_id = router_id;
    bgp_process->asn = asn;
    bgp_process->uptime = 0;
    bgp_process->num_peers = 0;
    bgp_process->is_active = 1;

    //Create the 1 second timer and set up the FD set
    bgp_process->file_desc[TIMER_FD] = init_bgp_timer();
    bgp_process->max_fd = bgp_process->file_desc[TIMER_FD] + 1;
    FD_ZERO(&bgp_process->file_desc_set);
    FD_SET(bgp_process->file_desc[TIMER_FD], &bgp_process->file_desc_set);


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
    free(bgp_process);
}


int init_bgp_timer(void) {
    int second_timer_fd;

    struct itimerspec second_counter = {
        .it_interval = { 1, 0 },
        .it_value = { 1, 0 }
    };

    second_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(second_timer_fd, 0, &second_counter, NULL);

    return second_timer_fd;
}


    



int get_bgp_process_uptime(struct bgp *bgp_process) {
    if (!bgp_process)
        return -1;

    return bgp_process->uptime;
}
    


