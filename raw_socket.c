#include "raw_socket.h"


int raw_sock_create(void) {
    int fd;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_OSPF);

    if (fd < 0) {
        DEBUG_PRINT("Unable to create RAW socket\n");
        return -1;
    }
    
    return fd;
}

int raw_sock_connect(const char *host) {
    int fd, ret;

    struct addrinfo *result;

    fd = raw_sock_create();
    if (fd < 0) {
        return -1;
    }

    if ((ret = getaddrinfo(host, NULL, NULL, &result)) < 0) {
        DEBUG_PRINT("Could not getaddrinfo() for raw socket\n");
        return -1;
    }

    if (connect(fd, result->ai_addr, result->ai_addrlen) < 0) {
        DEBUG_PRINT("Unable to connect to raw socket on %s\n", host);
        freeaddrinfo(result);
        return -1;
    }

    return fd;
}




