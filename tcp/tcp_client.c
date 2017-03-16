#include "tcp_client.h"



int tcp_connect(const char *host, const char *port) {
    int sock_fd, ret;
    struct addrinfo hints, *result, *result_head;

    bzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    if ((ret = getaddrinfo(host, port, &hints, &result)) < 0) {
        DEBUG_PRINT("getaddrinfo() returns %d (%s)\n", ret, gai_strerror(ret));
        return -1;
    }

    result_head = result;

    //Iterate through the items returned by getaddrinfo()
    do {
        if ((sock_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) < 0) {
            continue;
        }

        if (connect(sock_fd, result->ai_addr, result->ai_addrlen) == 0) {
            break;
        }
        close(sock_fd);
    } while ((result = result->ai_next) != NULL);

    freeaddrinfo(result_head);

    if (result == NULL) {
        DEBUG_PRINT("Unable to connect to %s\n", host);
        return -1;
    }

    return sock_fd;
}
