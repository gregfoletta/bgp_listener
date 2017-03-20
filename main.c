#include <unistd.h>
#include <stdio.h>
#include "includes/bgp.h"

int main(int argc, char **argv) {
    struct bgp *proc;

    proc = create_bgp_process(0x01010101, 0x01);

    for (int x = 0; x < 20; x++) {
        printf("BGP uptime: %d\n", get_bgp_process_uptime(proc));
        sleep(2);
    }

    return 0;
}




