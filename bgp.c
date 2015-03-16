#include "bgp.h"


struct bgp_peer *bgp_create_peer(const char *ip, const int asn, const char *name) {

    struct bgp_peer *bgp_peer;
    bgp_peer = malloc(sizeof(*bgp_peer));

    bgp_peer->ip = malloc((strlen(ip) + 1) * sizeof(*ip));
    strncpy(bgp_peer->ip, ip, strlen(ip) + 1);

    bgp_peer->asn = asn;

    bgp_peer->name = malloc((strlen(name) + 1) * sizeof(*name));
    strncpy(bgp_peer->name, name, strlen(name) + 1);

    return bgp_peer;
}


int bgp_destroy_peer(struct bgp_peer *bgp_peer) {
    close(bgp_peer->socket.fd);
    free(bgp_peer->name);
    free(bgp_peer->ip);
    free(bgp_peer);

    return 0;
}

void bgp_print_info(const struct bgp_peer *peer) {
    printf("[*] Name: %s, IP: %s, Autonomous System: %d\n", peer->name, peer->ip, peer->asn);
}


int bgp_connect(struct bgp_peer *peer) {
    peer->socket.fd = socket(AF_INET, SOCK_STREAM, 0);

    if (peer->socket.fd < 0) 
        bgp_print_err("socket()");

    memset(&(peer->socket.sock_addr), '0', sizeof(peer->socket.sock_addr));
    peer->socket.sock_addr.sin_family = AF_INET;
    peer->socket.sock_addr.sin_port = htons(TCP_BGP_PORT); 


    if (inet_pton(AF_INET, peer->ip, &peer->socket.sock_addr.sin_addr) <= 0)
        bgp_print_err("inet_pton()");

    if (connect(peer->socket.fd, (struct sockaddr *) &peer->socket.sock_addr, sizeof(peer->socket.sock_addr)) < 0)
        bgp_print_err("connect()");

    return 1;
}

void bgp_create_header(const short length, bgp_msg_type type, unsigned char *buffer) {
    uint8_t header_marker[16] = {   0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff  };

    //Copy the 16 octets of header marker
    memcpy(buffer, header_marker, 16);

    //Copy the length
    buffer[16] = length >> 8;
    buffer[17] = length & 0xff;

    //Copy message type
    buffer[18] = type;
}


void bgp_send_message(const struct bgp_peer *peer) {
    peer = peer;    
}



void bgp_print_err(char *err_message) {
    int error = errno;
    fprintf(stderr, "[-] Err: %s, errno: %d\n", err_message, error);
    exit(1);
}






