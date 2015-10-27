#include <string.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <stdint.h> 
#include <unistd.h> 
#include <errno.h> 
#include <math.h>

#include <sys/time.h>
 
#define TCP_BGP_PORT 179 
 
#define BGP_HEADER_LEN 19 
#define BGP_HEADER_MARKER_LEN 16 
//First byte after BGP header, same as length of header. 
#define BGP_MAX_LEN 4096 

#include "bgp.h"

//Index matches the BGP message code
char *bgp_msg_code[] = {
    "<Reserved>",
    "OPEN",
    "UPDATE", 
    "NOTIFICATION",
    "KEEPALIVE",
    "ROUTE-REFRESH"
};

//Index matches the path attribute code
char *pa_type_code[] = {
    "<Reserved>",
    "ORIGIN",
    "AS_PATH",
    "NEXT_HOP",
    "MULTI_EXIT_DISC",
    "LOCAL_PREF",
    "ATOMIC_AGGREGATE",
    "AGGREGATOR"
};

typedef enum {
    OPEN = 1,
    UPDATE,
    NOTIFICATION,
    KEEPALIVE
} bgp_msg_type;

struct bgp_msg {
    uint16_t length;
    bgp_msg_type type;
    uint8_t body[BGP_MAX_LEN - BGP_HEADER_LEN];
};

struct bgp_ipv4_route {
    uint8_t network[4];
    uint8_t prefix;
};

struct bgp_route_chain {
    struct bgp_ipv4_route route;
    struct bgp_route_chain *next;
};

struct bgp_tlv {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
};

struct bgp_tlv_chain {
    struct bgp_tlv_chain *next;
    struct bgp_tlv tlv;
};

struct bgp_pa {
    uint8_t flags;
    uint8_t type;
    uint16_t length;
    uint8_t *value;
};

struct bgp_pa_chain {
    struct bgp_pa_chain *next;
    struct bgp_pa pa;
};


//Non-public functions:
static int parse_update(struct bgp_msg);
static int parse_open(struct bgp_msg, struct bgp_peer *);

struct bgp_route_chain *extract_routes(int, uint8_t *);
struct bgp_tlv_chain *extract_tlv(uint8_t, uint8_t *);
struct bgp_pa_chain *extract_path_attributes(uint8_t, uint8_t *);

void bgp_create_header(const short, bgp_msg_type, unsigned char*);
struct bgp_msg bgp_validate_header(const uint8_t *);

int bgp_keepalive(struct bgp_peer *);



struct bgp_peer *bgp_create_peer(const char *ip, const uint16_t asn, const char *name) {
    struct bgp_peer *bgp_peer;

    bgp_peer = malloc(sizeof(*bgp_peer));

    bgp_peer->ip = malloc((strlen(ip) + 1) * sizeof(*ip));
    strncpy(bgp_peer->ip, ip, strlen(ip) + 1);

    bgp_peer->local_asn = asn;

    bgp_peer->name = malloc((strlen(name) + 1) * sizeof(*name));
    strncpy(bgp_peer->name, name, strlen(name) + 1);

    return bgp_peer;
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


int bgp_loop(struct bgp_peer *peer) {
    uint8_t buffer[BGP_MAX_LEN];
    uint8_t *buffer_pos;

    struct bgp_msg message;

    int bytes_read;
    int byte_interval;
    int fd_ready;

    struct timeval select_wait;

    
    fd_set select_set;
    
    //Set up the select() set
    FD_ZERO(&select_set);

    while (1) {
        bytes_read = 0;
        buffer_pos = buffer;
        select_wait = (struct timeval){ 1, 0 };


        FD_SET(peer->socket.fd, &select_set);   

        //Wait for an active socket
        fd_ready = select(peer->socket.fd + 1, &select_set, NULL, NULL, &select_wait);

        if (fd_ready < 0) {
            bgp_print_err("select() error");
        } else if (fd_ready == 0) {
            //Select timeout
            printf("select() timeout\n");
            continue;
        }

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

        printf("{ %s }\n", bgp_msg_code[message.type]);

        switch (message.type) {
            case OPEN:
                parse_open(message, peer);
                bgp_keepalive(peer);
                break;
            case UPDATE:
                parse_update(message);
                break;
            case NOTIFICATION:
                break;
            case KEEPALIVE:
                bgp_keepalive(peer);
                break;
            default:
                break;
        }
    }
    return 1;
}


int bgp_destroy_peer(struct bgp_peer *bgp_peer) {
    close(bgp_peer->socket.fd);
    free(bgp_peer->name);
    free(bgp_peer->ip);
    free(bgp_peer);

    return 0;
}

static int parse_update(struct bgp_msg message) {
    int withdrawn_len, pa_len, nlri_len;

    //body_pos is the current position within the BGP message body
    uint8_t *body_pos = message.body;

    //Withdrawn length is the number of octets contained 
    withdrawn_len = *(body_pos++) << 8;
    withdrawn_len |= *(body_pos++);

    
    if (withdrawn_len > 0) {
        extract_routes(withdrawn_len, body_pos);
        body_pos += withdrawn_len;
    }

    pa_len = *(body_pos++) << 8;
    pa_len |= *(body_pos++);
    
    //The "4" is the withdrawn routes length field (2 bytes) and the PA Attribute length field (2 bytes)
    nlri_len = message.length - BGP_HEADER_LEN - 4 - withdrawn_len - pa_len;

    if (pa_len > 0) {
        extract_path_attributes(pa_len, body_pos);
        body_pos += pa_len;
    }

    extract_routes(nlri_len, body_pos);
    printf("\n");

    return 0;

}

static int parse_open(struct bgp_msg message, struct bgp_peer *peer) {
    uint8_t *body_pos = message.body;
    int opt_param_len;

    //Length must be at least 9 bytes
    if (message.length < 9) {
        return -1;
    }

    peer->version = *(body_pos++);

    peer->remote_asn = *(body_pos++) << 8;
    peer->remote_asn |= *(body_pos++);

    peer->recv_hold_time = *(body_pos++) << 8;
    peer->recv_hold_time |= *(body_pos++);

    peer->identifier = *(body_pos++) << 24;
    peer->identifier |= *(body_pos++) << 16;
    peer->identifier |= *(body_pos++) << 8;
    peer->identifier |= *(body_pos++);

    //No optional parameters, we return
    if (message.length == 9) {
        return 0;
    }

    opt_param_len = *(body_pos++);
    peer->open_parameters = extract_tlv(opt_param_len, body_pos);
    

    printf("Param Length: %d\n", opt_param_len);

    printf("Version: %d, Remote ASN: %d, Hold Time: %d, Identifier: %d\n", peer->version, peer->remote_asn, peer->recv_hold_time, peer->identifier);

    return 0;
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

    if (length <= 0) {
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

    printf("  { %d.%d.%d.%d/%d ", node->route.network[0], node->route.network[1], node->route.network[2], node->route.network[3], node->route.prefix);
    printf("(%x %x %x %x %x) }\n", node->route.network[0], node->route.network[1], node->route.network[2], node->route.network[3], node->route.prefix);
    
    //Decrease the length of routes (1 byte for the prefix len + length of the network)

    node->next = extract_routes(length - (1 + net_len), routes + net_len);

    return node->next;
}


struct bgp_tlv_chain *extract_tlv(uint8_t length, uint8_t *attributes) {
    struct bgp_tlv_chain *node = NULL;

    printf("TLV Length: %d\n", length);

    if (length <= 0) {
        return NULL;
    }

    node = malloc(sizeof(*node));
    
    node->tlv.type = *attributes++;
    node->tlv.length = *attributes++;

    //Copy the attribute
    node->tlv.value = malloc(sizeof(*node->tlv.value) * node->tlv.length);
    memcpy(node->tlv.value, attributes, node->tlv.length);
    attributes += node->tlv.length;

    printf(" { T: %x L: %x V: %x }\n", node->tlv.type, node->tlv.length, *node->tlv.value);

    node->next = extract_tlv(length - (node->tlv.length +2), attributes);

    return node;
}

struct bgp_pa_chain *extract_path_attributes(uint8_t length, uint8_t *attributes) {
    struct bgp_pa_chain *node = NULL;

    if (length <= 0) {
        return NULL;
    }

    node = malloc(sizeof(*node));
    
    node->pa.flags = *attributes++;
    node->pa.type = *attributes++;
    node->pa.length = *attributes++;

    //Copy the attribute
    node->pa.value = malloc(sizeof(node->pa.value) * node->pa.length);
    memcpy(node->pa.value, attributes, node->pa.length);
    attributes += node->pa.length;

    printf(" { F: %x T: %s L: %x }\n", node->pa.flags, pa_type_code[node->pa.type], node->pa.length);

    node->next = extract_path_attributes(length - node->pa.length - 3, attributes);

    return node;
}


void bgp_create_header(const short length, bgp_msg_type type, unsigned char *buffer) {
    uint8_t header_marker[BGP_HEADER_MARKER_LEN] = {   0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff  };

    //Copy the 16 octets of header marker
    memcpy(buffer, header_marker, BGP_HEADER_MARKER_LEN);

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






