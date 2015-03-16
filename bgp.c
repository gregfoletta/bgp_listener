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


int bgp_open(struct bgp_peer *peer, struct bgp_local local_info) {
    uint8_t open_buffer[BGP_MAX_LEN];
    int open_buffer_pos = BGP_HEADER_LEN;

    //BGP Version, starting after header
    open_buffer[open_buffer_pos++] = 0x4;
    
    //Our ASN
    open_buffer[open_buffer_pos++] = local_info.asn >> 8;
    open_buffer[open_buffer_pos++] = local_info.asn & 0xff;

    //Holdtime
    open_buffer[open_buffer_pos++] = local_info.hold_time >> 8;
    open_buffer[open_buffer_pos++] = local_info.hold_time & 0xff;

    //BGP Identifier
    open_buffer[open_buffer_pos++] = local_info.identifier >> 24;
    open_buffer[open_buffer_pos++] = local_info.identifier >> 16; 
    open_buffer[open_buffer_pos++] = local_info.identifier >> 8;
    open_buffer[open_buffer_pos++] = local_info.identifier & 0xff;

    //Param length
    open_buffer[open_buffer_pos++] = 0x0;

    bgp_create_header(open_buffer_pos, OPEN, open_buffer);

    send(peer->socket.fd, open_buffer, open_buffer_pos, 0);

    return 1;
}

int bgp_keepalive(struct bgp_peer *peer) {
    uint8_t ka_buffer[BGP_HEADER_LEN];

    bgp_create_header(BGP_HEADER_LEN, KEEPALIVE, ka_buffer); 

    send(peer->socket.fd, ka_buffer, BGP_HEADER_LEN, 0);

    return 1;
}


int bgp_readloop(struct bgp_peer *peer) {
    uint8_t buffer[BGP_MAX_LEN];
    uint8_t *buffer_pos;

    struct bgp_header msg_header;

    int bytes_read;
    int byte_interval;
    buffer_pos = buffer;

    while (1) {
        bytes_read = 0;
        buffer_pos = buffer;
        //We first read enough to get the header of the message
        while (bytes_read < BGP_HEADER_LEN) {
            byte_interval = recv(peer->socket.fd, buffer_pos, BGP_HEADER_LEN - bytes_read, 0);

            if (byte_interval == -1) { 
                return 0;
            }

            buffer_pos += byte_interval;
            bytes_read += byte_interval;
        }

        msg_header = bgp_validate_header(buffer);
        
        bytes_read = 0;

        while (bytes_read < msg_header.length - BGP_HEADER_LEN) {
            byte_interval = recv(peer->socket.fd, buffer_pos, (msg_header.length - BGP_HEADER_LEN) - bytes_read, 0);
            if (byte_interval == -1) {
                return 0;
            }
            buffer_pos += byte_interval;
            bytes_read += byte_interval;
        }

        switch (msg_header.type) {
            case OPEN:
                printf("OPEN\n");
                bgp_keepalive(peer);
                break;
            case UPDATE:
                printf("UPDATE\n");
                break;
            case NOTIFICATION:
                printf("NOTIFICATION\n");
                break;
            case KEEPALIVE:
                printf("KEEPALIVE\n");
                break;
            default:
                bgp_print_err("Unknown BGP message type");
        }
    }
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


struct bgp_header bgp_validate_header(const uint8_t *header_buffer) {
    struct bgp_header header;

    //Check to see that the first 8 octets are 0xff
    for (int x = 0; x < BGP_HEADER_MARKER_LEN; x++) {
        if (header_buffer[x] != 0xff) {
            bgp_print_err("Header received has invalid marker");
        }
    }

    header.length = (header_buffer[16] << 8) | header_buffer[17];
    header.type = header_buffer[18];

    return header;
}





void bgp_print_err(char *err_message) {
    int error = errno;
    fprintf(stderr, "[-] Err: %s, errno: %d\n", err_message, error);
    exit(1);
}






