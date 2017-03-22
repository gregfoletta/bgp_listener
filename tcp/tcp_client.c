#include "../includes/tcp_client.h"
#include <stdio.h>

int tcp_socket(const char *host, const char *port) {
    int sock_fd, ret;
    struct addrinfo hints, *result, *result_head;

    bzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    if ((ret = getaddrinfo(host, port, &hints, &result)) != 0) {
        return -ret;
    }

    result_head = result;

    //Iterate through the items returned by getaddrinfo()
    do {
        if ((sock_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) < 0) {
            continue;
        }
    } while ((result = result->ai_next) != NULL);

    freeaddrinfo(result_head);

    return sock_fd;
}
