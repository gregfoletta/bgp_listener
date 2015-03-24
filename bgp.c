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

    struct bgp_msg message;

    int bytes_read;
    int byte_interval;

    while (1) {
        bytes_read = 0;
        buffer_pos = buffer;
        //We first read enough to get the header of the message
        while (bytes_read < BGP_HEADER_LEN) {
            byte_interval = recv(peer->socket.fd, buffer_pos, BGP_HEADER_LEN - bytes_read, 0);

            if (byte_interval <= 0) { 
                return 0;
            }

            buffer_pos += byte_interval;
            bytes_read += byte_interval;
        }

        message = bgp_validate_header(buffer);
       
        //Reset the read and buffer position - we use the same buffer as we used in the header. 
        bytes_read = 0;
        buffer_pos = buffer;

        while (bytes_read < message.length - BGP_HEADER_LEN) {
            byte_interval = recv(peer->socket.fd, buffer_pos, (message.length - BGP_HEADER_LEN) - bytes_read, 0);
            if (byte_interval <= 0) {
                return 0;
            }
            buffer_pos += byte_interval;
            bytes_read += byte_interval;
        }

        //Copy the body to the message
        memcpy(&message.body, buffer, message.length);


        switch (message.type) {
            case OPEN:
                printf("OPEN\n");
                bgp_keepalive(peer);
                break;
            case UPDATE:
                parse_update(message);
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



void parse_update(struct bgp_msg message) {
    int withdrawn_len;

    //Withdrawn length is the number of octets contained 
    withdrawn_len = (*message.body << 8) | *(message.body + 1);

    printf("UPDATE\n");
    printf("Widthdrawn len: %d\n", withdrawn_len);

    extract_routes(withdrawn_len, message.body + 2);
}

/*
extract_route()

Given a start point in a buffer and a length, it recusively extracts routes from
an update of the form [prefix_length (1 byte), prefix (var)].
It returns a bgp_route_chain object, which is a linked list of 
all of the routes in the update
*/
struct bgp_route_chain *extract_routes(int length, uint8_t *routes) {
    struct bgp_route_chain *node = NULL;
    int net_len;

    if (length == 0) {
        return NULL;
    }

   
    //Allocate the node, set the prefix length and increment the pointer.
    node = malloc(sizeof(*node));
    node->route.prefix = *routes++;


    if (node->route.prefix > 32) {
        bgp_print_err("bgp_route_chain(): prefix length > 32");
    }

    net_len = ceil((float) node->route.prefix / 8);

    memcpy(node->route.network, routes , net_len); 

    printf("Length: %d, net_len: %d\n", length, net_len);
    printf("%x.%x.%x.%x/%x\n", node->route.network[0], node->route.network[1], node->route.network[2], node->route.network[3], node->route.prefix);
    
    //Decrease the length of routes (1 byte for the prefix len + length of the network)

    node->next = extract_routes(length - (1 + net_len), routes + net_len);

    return node->next;
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


struct bgp_msg bgp_validate_header(const uint8_t *header_buffer) {
    struct bgp_msg header;

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






