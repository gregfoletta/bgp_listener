#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/timerfd.h>

#include "../includes/list.h"

struct bgp {
    uint32_t router_id;
    uint32_t asn;
    pthread_t worker_thread;

    struct list_head ingress_msg_queue;
    struct list_head egress_msg_queue;
};


void *bgp_worker_thread(void *);



struct bgp *create_bgp_process(uint32_t router_id, uint32_t asn) {
    struct bgp *bgp_process;

    bgp_process = malloc(sizeof *bgp_process);
    if (bgp_process == NULL) {
        goto out_error;
    }

    bgp_process->router_id = router_id;
    bgp_process->asn = asn;

    if  (pthread_create(&bgp_process->worker_thread, NULL, bgp_worker_thread, bgp_process) != 0) {
        goto out_error;
    }

    return bgp_process;

out_error:
    free(bgp_process);
    return NULL;
}


void *bgp_worker_thread(void *arg) {
    struct bgp *bgp_proc = arg;

    struct timespec sec_timer_spec = { 1, 0 };
    int sec_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);

    return NULL;
}



void destroy_bgp_process(struct bgp *bgp_process) {
    free(bgp_process);
}
    


