#include <string.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <stdint.h> 
#include <unistd.h> 
#include <errno.h> 
#include <math.h>

#include <pthread.h>

#include <sys/time.h>
#include <time.h>
 
#define TCP_BGP_PORT 179 
 
#define BGP_HEADER_LEN 19 
#define BGP_HEADER_MARKER_LEN 16 
#define BGP_OPEN_HEADER_LEN 10 
//First byte after BGP header, same as length of header. 
#define BGP_MAX_LEN 4096 

#include "bgp.h"
#include "debug.h"
#include "list.h"
#include "tcp_client.h"
#include "byte_conv.h"

enum bgp_fsm_states { 
    BGP_IDLE, 
    BGP_CONNECT, 
    BGP_ACTIVE, 
    BGP_OPENSENT, 
    BGP_OPENCONFIRM, 
    BGP_ESTABLISHED 
};

struct bgp_socket {
    int fd;
    struct sockaddr_in sock_addr;
};

/*
 * Each statistic is a 2 element array.
 * * First element: messages sent
 * * Second element: messages received
 */
#define STAT_SENT 0
#define STAT_RECV 1

struct bgp_stats {
    int open[2];
    int update[2];
    int notification[2];
    int keepalive[2];
    int route_refresh[2];
};

struct bgp_peer {
    char *name;
    uint8_t version;
    uint16_t local_asn;
    uint16_t peer_asn;
    uint32_t local_rid;
    uint32_t peer_rid;
    char *peer_ip;
    uint16_t recv_hold_time;
    uint16_t curr_hold_time;
    uint16_t conf_hold_time;
    enum bgp_fsm_states fsm_state;
    struct bgp_tlv_list *open_parameters;
    struct bgp_socket socket;
    struct bgp_route_chain *pending_withdrawn;
    pthread_t rw_thread;
    pthread_t util_thread;
    struct list_head ingress_msg_queue;
    struct list_head egress_msg_queue;

    struct bgp_stats stats;
};

enum bgp_msg_type {
    OPEN = 1,
    UPDATE,
    NOTIFICATION,
    KEEPALIVE,
    ROUTE_REFRESH,
    NUMBER_OF_MSG_TYPES //This will evaluate to the number msg types. Used during validation.
};

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


struct bgp_msg {
    unsigned char *raw;               //Pointer to the start of the message
    unsigned char *header;            //Pointer to the start of the header (after the 16 bytes of 0xff)
    unsigned char *data;              //Pointer to the beginning of the message (after the BGP header)

    struct list_head list;
};

#define MSG_LENGTH(x) (uchar_be_to_uint16(x->raw + BGP_HEADER_MARKER_LEN)) //Length is the first two bytes after the marker
#define MSG_TYPE(x) (uchar_to_uint8(x->raw + BGP_HEADER_MARKER_LEN + 2)) //Type is the next byte after the length


struct bgp_route_chain {
    uint8_t *route;                 //Of the form prefix_len(1), prefix(var)
    struct bgp_route_chain *next;
};

struct bgp_tlv {
    uint8_t type;
    uint8_t length;
    uint8_t *value;
};

struct bgp_tlv_list {
    struct bgp_tlv_list *next;
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

struct bgp_capability_code {
    uint8_t value;
    char *description;
};

//Non-public functions:
static void parse_message(struct bgp_peer *, struct bgp_msg *);
static void parse_open(struct bgp_peer *, struct bgp_msg *);
static void parse_update(struct bgp_peer *, struct bgp_msg *);
static void withdraw_routes(struct bgp_peer *, uint16_t, unsigned char *);
static void parse_notification(struct bgp_peer *, struct bgp_msg *);
static void parse_keepalive(struct bgp_peer *, struct bgp_msg *);

void update_stats(struct bgp_peer *, enum bgp_msg_type, int send_or_recv);

struct bgp_msg *alloc_bgp_msg(const uint16_t length, enum bgp_msg_type type);
struct bgp_msg *create_bgp_open(struct bgp_peer *peer);
void queue_bgp_open(struct bgp_peer *);
struct bgp_msg *create_bgp_keepalive(struct bgp_peer *);


void *bgp_rw_thread(void *);
int bgp_read_msg(struct bgp_peer *);
int bgp_send_msg(struct bgp_peer *);
void *bgp_util_thread(void *);

struct bgp_tlv_list *extract_tlv(uint8_t, uint8_t *);
struct bgp_pa_chain *extract_path_attributes(uint8_t, uint8_t *);

int validate_header(const unsigned char *); 



struct bgp_peer *bgp_create_peering(const char *peer_ip, const uint16_t peer_asn, const uint16_t local_asn, const uint32_t local_rid, const uint16_t hold_time, const char *peer_name) {
    struct bgp_peer *bgp_peer;

    bgp_peer = malloc(sizeof(*bgp_peer));

    INIT_LIST_HEAD(&bgp_peer->ingress_msg_queue);
    INIT_LIST_HEAD(&bgp_peer->egress_msg_queue);

    bgp_peer->fsm_state = BGP_IDLE;
    //Copy the attributes into our structure
    bgp_peer->peer_ip = malloc((strlen(peer_ip) + 1) * sizeof(*peer_ip));
    bgp_peer->name = malloc((strlen(peer_name) + 1) * sizeof(*peer_name));
    strncpy(bgp_peer->peer_ip, peer_ip, strlen(peer_ip) + 1);
    strncpy(bgp_peer->name, peer_name, strlen(peer_name) + 1);

    bgp_peer->version = 0x04;
    bgp_peer->local_asn = local_asn;
    bgp_peer->peer_asn = peer_asn;
    bgp_peer->local_rid = local_rid;
    bgp_peer->conf_hold_time = hold_time;

    return bgp_peer;
}


int bgp_activate(struct bgp_peer *peer) {
    DEBUG_PRINT("Activating peer %s (%s)\n", peer->name, peer->peer_ip);

    if (pthread_create(&peer->rw_thread, NULL, bgp_rw_thread, peer) != 0) {
        bgp_print_err("Unable to create RW thread");
    }

    if (pthread_create(&peer->util_thread, NULL, bgp_util_thread, peer) != 0) {
        bgp_print_err("Unable to create util thread");
    }

    return 1;
}


void *bgp_rw_thread(void *param) {
    DEBUG_PRINT("RW Thread Active\n");
    struct bgp_peer *peer = param;

    while (1) {
        if (peer->fsm_state == BGP_IDLE) {
            DEBUG_PRINT("Peer is BGP_IDLE, attempting to connect\n");
            if ((peer->socket.fd = tcp_connect(peer->peer_ip, "bgp")) > 0) {
                DEBUG_PRINT("Peer is connected on fd %d\n", peer->socket.fd);
                peer->fsm_state = BGP_CONNECT;
                queue_bgp_open(peer);
                continue;
            }

            DEBUG_PRINT("Connection to %s timed out... waiting 10 seconds then retrying\n", peer->peer_ip);
            sleep(10);
            continue;
        }
        if (bgp_read_msg(peer) < 0) {
            DEBUG_PRINT("bgp_read_msg returned an error\n");
            return NULL;
        }
        if (bgp_send_msg(peer) < 0) {
            DEBUG_PRINT("bgp_send_msg returned an error\n");
            return NULL;
        }
    }

    return param;
}

void *bgp_util_thread(void *param) {
    DEBUG_PRINT("UTIL Thread Active\n");
    struct bgp_peer *peer = param;
    struct bgp_msg *message;
    struct timespec time_start, time_end;

    while (1) {
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &time_start) != 0) {
            bgp_print_err("clock_gettime() error");
        }

        if (!list_empty(&peer->ingress_msg_queue)) {
            struct list_head *i;
            list_for_each(i, &peer->ingress_msg_queue) {
                message = list_entry(i, struct bgp_msg, list);
                parse_message(peer, message);
                if (MSG_TYPE(message) == 3) {
                    return NULL;
                }
                list_del(i);
                free(message);
            }
        }

        sleep(1);

        if (clock_gettime(CLOCK_MONOTONIC_RAW, &time_end) != 0) {
            bgp_print_err("clock_gettime() error");
        }}

    return NULL;
}


static void parse_message(struct bgp_peer *peer, struct bgp_msg *message) {
    switch (MSG_TYPE(message)) {
        case 1:
            parse_open(peer, message);
            break;
        case 2:
            parse_update(peer, message);
            break;
        case 3:
            parse_notification(peer, message);
            break;
        case 4:
            parse_keepalive(peer, message);
            break;
        default:
            DEBUG_PRINT("Error: unknown message type %d\n", MSG_TYPE(message));
            exit(1);
    }
}



int bgp_connect(struct bgp_peer *peer) {
    peer->socket.fd = socket(AF_INET, SOCK_STREAM, 0);

    if (peer->socket.fd < 0) 
        bgp_print_err("socket()");

    memset(&(peer->socket.sock_addr), '0', sizeof(peer->socket.sock_addr));
    peer->socket.sock_addr.sin_family = AF_INET;
    peer->socket.sock_addr.sin_port = htons(TCP_BGP_PORT); 


    if (inet_pton(AF_INET, peer->peer_ip, &peer->socket.sock_addr.sin_addr) <= 0)
        bgp_print_err("inet_pton()");


    if (connect(peer->socket.fd, (struct sockaddr *) &peer->socket.sock_addr, sizeof(peer->socket.sock_addr)) < 0) {
        peer->fsm_state = BGP_IDLE;
        return -1;
    }
    
    DEBUG_PRINT("%s is connected\n", peer->peer_ip);
    peer->fsm_state = BGP_OPENSENT;
    return 0;
}

struct bgp_msg *create_bgp_open(struct bgp_peer *peer) {
    struct bgp_msg *message;
    const int open_msg_data_len = 10; //Length with no parameters is 10;
    unsigned char *pos;

    message = alloc_bgp_msg(open_msg_data_len, OPEN);
    pos = message->data;

    uint8_to_uchar_inc(&pos, peer->version);
    uint16_to_uchar_be_inc(&pos, peer->local_asn);
    uint16_to_uchar_be_inc(&pos, peer->conf_hold_time); 
    uint32_to_uchar_be_inc(&pos, peer->local_rid);
     
    //Param length
    uint8_to_uchar_inc(&pos, 0x00);

    return message;
}

void queue_bgp_open(struct bgp_peer *peer) {
    struct bgp_msg *open;

    DEBUG_PRINT("Queueing OPEN\n");
    
    open = create_bgp_open(peer);
    list_add(&open->list, &peer->egress_msg_queue);
    update_stats(peer, OPEN, STAT_SENT);
}

struct bgp_msg *create_bgp_keepalive(struct bgp_peer *peer) {
    struct bgp_msg *keepalive;

    keepalive = alloc_bgp_msg(0, KEEPALIVE); //Keepalve has no data

    return keepalive;
}

void queue_bgp_keepalive(struct bgp_peer *peer) {
    struct bgp_msg *keepalive;

    DEBUG_PRINT("Queueing KEEPALIVE\n");

    keepalive = create_bgp_keepalive(peer);
    list_add(&keepalive->list, &peer->egress_msg_queue);
    update_stats(peer, KEEPALIVE, STAT_SENT);
}


int bgp_read_msg(struct bgp_peer *peer) {
    struct bgp_msg *message;
    unsigned char header[BGP_HEADER_LEN];
    uint16_t length;
    enum bgp_msg_type type;

    unsigned char *pos;
    int ret, fd_ready;

    struct timeval select_wait = { 1, 0 };

    //Set up the select() set  
    fd_set select_set;
    FD_ZERO(&select_set);
    FD_SET(peer->socket.fd, &select_set);   

    //Wait for an active socket
    fd_ready = select(peer->socket.fd + 1, &select_set, NULL, NULL, &select_wait);

    if (fd_ready < 0) {
        bgp_print_err("select() error");
    } else if (fd_ready == 0) {
        //select has timed out without any data
        return 0;
    }

    //We first read enough to get the header of the message
    ret = recv(peer->socket.fd, header, BGP_HEADER_LEN, MSG_WAITALL);
    if (ret == 0) { //EOF - switch to BGP_IDLE, and (eventually) cleanup
        peer->fsm_state = BGP_IDLE;
        return 0;
    }

    if (ret < 0) { 
        return -1;
    }

    if (validate_header(header) < 0) {
        return -1;
    }

    //Pull out the length and the type
    pos = header + BGP_HEADER_MARKER_LEN;
    length = uchar_be_to_uint16_inc(&pos);
    type = uchar_to_uint8(pos); 

    message = alloc_bgp_msg(length, type);
    memcpy(message->raw, header, BGP_HEADER_LEN);

    //Keepalives have no body
    if (MSG_LENGTH(message) - BGP_HEADER_LEN > 0) {
        ret = recv(peer->socket.fd, message->data, MSG_LENGTH(message) - BGP_HEADER_LEN, MSG_WAITALL);
        if (ret == 0) { //EOF
            peer->fsm_state = BGP_IDLE;
            return 0;
        }
        if (ret < 0) {
              return -1;
        }
    }

    //Add the message to the ingress queue
    list_add(&message->list, &peer->ingress_msg_queue);

    return 0;
}

int bgp_send_msg(struct bgp_peer *peer) {
    struct list_head *i;
    struct bgp_msg *message;

    if (!list_empty(&peer->egress_msg_queue)) {
        list_for_each(i, &peer->egress_msg_queue) {
            message = list_entry(i, struct bgp_msg, list);
            send(peer->socket.fd, message->raw, MSG_LENGTH(message), 0);
            list_del(i);
            free(message);
        }
    }

    return 0;
}



int bgp_destroy_peer(struct bgp_peer *bgp_peer) {
    close(bgp_peer->socket.fd);
    free(bgp_peer->name);
    free(bgp_peer->peer_ip);
    free(bgp_peer);

    return 0;
}

static void parse_open(struct bgp_peer *peer, struct bgp_msg *message) {
    unsigned char *pos = message->data;
    int opt_param_len;

    DEBUG_PRINT("Received OPEN\n");
    update_stats(peer, OPEN, STAT_RECV) ;

    //Length must be at least 9 bytes
    if (MSG_LENGTH(message) < 9) {
        return;
    }


    peer->version = uchar_to_uint8_inc(&pos);
    peer->peer_asn = uchar_be_to_uint16_inc(&pos);
    peer->recv_hold_time = uchar_be_to_uint16_inc(&pos);
    peer->curr_hold_time = peer->recv_hold_time;
    peer->peer_rid = uchar_be_to_uint32_inc(&pos);

    DEBUG_PRINT("(V: %d, ASN: %d, HT: %d, RID: %d)\n", peer->version, peer->peer_asn, peer->recv_hold_time, peer->peer_rid);
    
    //TODO: Temp hack. We've already sent an open, let's send a keepalive to confirm the session
    queue_bgp_keepalive(peer);

    //No optional parameters, we return
    if (MSG_LENGTH(message) == 9) {
        return;
    }

    opt_param_len = uchar_to_uint8(pos);
    peer->open_parameters = extract_tlv(opt_param_len, pos);


    return;
}


static void parse_update(struct bgp_peer *peer, struct bgp_msg *message) {
    uint16_t withdrawn_len, pa_len, nlri_len;
    unsigned char *pos;
    
    DEBUG_PRINT("Received UPDATE\n");
    update_stats(peer, UPDATE, STAT_RECV);

    pos = message->data;
    withdrawn_len = uchar_be_to_uint16_inc(&pos);
    if (withdrawn_len > (MSG_LENGTH(message) + BGP_HEADER_LEN + 2 + 2)) { //
        bgp_print_err("parse_update() - received withdrawn length too large");
    }

    withdraw_routes(peer, withdrawn_len, pos);
    pa_len = uchar_be_to_uint16(pos + withdrawn_len);
    //The "4" is the withdrawn routes length field (2 bytes) and the PA Attribute length field (2 bytes)
    nlri_len = MSG_LENGTH(message) - (BGP_HEADER_LEN + 4 + withdrawn_len + pa_len);
}


static void withdraw_routes(struct bgp_peer *peer, uint16_t length, unsigned char *routes) {
    uint8_t prefix_len, net_len;
    unsigned char route[4]; //4 is worst case (prefix_len 32)

    if (length <= 0) {
        return;
    }

    while (length > 0) {

        prefix_len = uchar_to_uint8(routes);
        if (prefix_len > 32) { //unsigned, so don't need to check for < 32
            bgp_print_err("withdraw_routes(): invalid prefix length");
        }

        net_len = ((prefix_len + 8) - 1) / 8; //This is a ceil()

        DEBUG_PRINT("prefix_len: %d, net_len: %d\n", prefix_len, net_len);
        
        length -= (1 + net_len);
        routes += (1 + net_len);
    }
}

static void parse_notification(struct bgp_peer *peer, struct bgp_msg *message) {
    const char *error_codes[] = { 
        "Message Header Error",
        "OPEN Message Error",
        "UPDATE Message Error",
        "Hold Timer Expired",
        "Finite State Machine Error",
        "Cease"
    };

    const char *msg_header_subcode[] = {
        "Connection Not Synchronized",
        "Bad Message Length",
        "Bad Message Type"
    };

    const char *open_subcode[] = {
        "Unsupported Version Number",
        "Bad Peer AS",
        "Bad BGP Identifier",
        "Unsupported Optional Parameter",
        "[Deprecated] (5)",
        "Unacceptable Hold Time",
    };

    const char *update_subcode[] = {
        "Malformed Attribute List",
        "Unrecognized Well-known Attribute",
        "Missing Well-known Attribute",
        "Attribute Flags Error",
        "Attribute Length Error",
        "Invalid ORIGIN Attribute",
        "[Deprecated] (7)",
        "Invalid NEXT_HOP Attribute",
        "Optional Attribute Error",
        "Invalid Network Field",
        "Malformed AS_PATH"
    };

    update_stats(peer, NOTIFICATION, STAT_RECV);

}

static void parse_keepalive(struct bgp_peer *peer, struct bgp_msg *message) {
    struct bgp_msg *keepalive;

    DEBUG_PRINT("Received KEEPALIVE\n");

    queue_bgp_keepalive(peer);
    update_stats(peer, KEEPALIVE, STAT_RECV);
}


void update_stats(struct bgp_peer *peer, enum bgp_msg_type type, int send_or_recv) {
    if (send_or_recv != STAT_SENT && send_or_recv != STAT_RECV) {
        bgp_print_err("update_stats() - 'send_or_recv' value error");
    }

    switch (type) {
        case OPEN:
            (peer->stats.open[send_or_recv])++;
            break;
        case UPDATE:
            (peer->stats.update[send_or_recv])++;
            break;
        case NOTIFICATION:
            (peer->stats.notification[send_or_recv])++;
            break;
        case KEEPALIVE:
            (peer->stats.keepalive[send_or_recv])++;
            break;
        case ROUTE_REFRESH:
            (peer->stats.route_refresh[send_or_recv])++;
            break;
        default:
            bgp_print_err("update_stats() - unknown message type");
    }
}

        

struct bgp_tlv_list *extract_tlv(uint8_t length, uint8_t *attributes) {
    struct bgp_tlv_list *node = NULL;

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

    node->next = extract_path_attributes(length - node->pa.length - 3, attributes);

    return node;
}


struct bgp_msg *alloc_bgp_msg(const uint16_t data_len, enum bgp_msg_type type) {
    uint8_t header_marker[] = { 0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff  };

    struct bgp_msg *message;
    uint8_t *pos;

    message = malloc(sizeof(*message));
    message->raw = malloc((BGP_HEADER_LEN + data_len) * sizeof(message->raw));
    message->header = message->raw + BGP_HEADER_MARKER_LEN;
    message->data = message->raw + BGP_HEADER_LEN;

    //Copy the 16 bytes of marker
    memcpy(message->raw, header_marker, BGP_HEADER_MARKER_LEN);

    //Copy the length and the type
    pos = message->header;
    uint16_to_uchar_be_inc(&pos, BGP_HEADER_LEN + data_len);
    uint8_to_uchar(pos, type);

    return message;
}


int validate_header(const unsigned char *header) {
    const char marker[] = { 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF };
    int x;

    /* The last entry in the type enum is NUMBER_OF_MSG_TYPES. 
     * Any type equal to or greater than this entry is invalid. */
    enum bgp_msg_type high_msg_type = NUMBER_OF_MSG_TYPES;

    //Check that the marker is correct
    if(memcmp(header, marker, BGP_HEADER_MARKER_LEN)) {
        DEBUG_PRINT("Message has invalid marker\n");
        return -1;
    }

    return 0;
}


int print_bgp_peer_info(void *arg) {
    struct bgp_peer *peer = arg;
    struct bgp_tlv_list *open_parameter;

    struct bgp_capability_code code_lookup[] = {
        { 1, "Multiprotocol Extensions for BGP-4" },
        { 2, "Route Refresh Capability for BGP-4" },
        { 3, "Outbound Route Filtering Capability" },
        { 4, "Multiple routes to a destination capability" },
        { 5, "Extended Next Hop Encoding" },
        { 6, "BGP-Extended Message" },
        { 65, "Support for 4-octet AS number capability" },
        { 66, "Deprecated (2003-03-06)" },
        { 67, "Support for Dynamic Capability (capability specific)" },
        { 68, "Multisession BGP Capability" },
        { 69, "ADD-PATH Capability" },
        { 70, "Enhanced Route Refresh Capability" },
        { 71, "Long-Lived Graceful Restart (LLGR) Capability" },
        { 72, "CP-ORF Capability" },
        { 73, "FQDN Capability" },
        { 128, "Old Cisco Route Refresh" },
    };

    //Traverse the parameter list for the peer and print the matching capabilities
    for (open_parameter = peer->open_parameters; open_parameter != NULL; open_parameter = open_parameter->next) {
        for (unsigned int x = 0; x < sizeof(code_lookup) / sizeof(struct bgp_capability_code); x++) {
            if (open_parameter->tlv.value[0] == code_lookup[x].value) {
                printf(" *%s (%d)\n", code_lookup[x].description, code_lookup[x].value);
            }   
        }
    } 

    return 0;
}

int print_bgp_pending_withdrawn(void *arg) {
    struct bgp_peer *peer = arg;
    struct bgp_route_chain *iterate;

    printf("Pending withdrawn routes:\n");
    for (iterate = peer->pending_withdrawn; iterate != NULL; iterate = iterate->next) {
        printf("%d - %d %d\n", iterate->route[0],iterate->route[1],iterate->route[2]);\
}
    
    return 0;
}

int print_bgp_statistics(int argc, char **argv, void *arg) {
    struct bgp_peer *peer = arg;

    printf("BGP Message Statistics:\n");
    printf("\tOPEN sent: %d\t\tOPEN recv: %d\n", peer->stats.open[STAT_SENT], peer->stats.open[STAT_RECV]);
    printf("\tUPDATE sent: %d\t\tUPDATE recv: %d\n", peer->stats.update[STAT_SENT], peer->stats.update[STAT_RECV]);
    printf("\tNOTIFICATION sent: %d\tNOTIFICATION recv: %d\n", peer->stats.notification[STAT_SENT], peer->stats.notification[STAT_RECV]);
    printf("\tKEEPALIVE sent: %d\tKEEPALIVE recv: %d\n", peer->stats.keepalive[STAT_SENT], peer->stats.keepalive[STAT_RECV]);
    printf("\tROUTE-REFRESH sent: %d\tROUTE-REFRESH recv: %d\n", peer->stats.route_refresh[STAT_SENT], peer->stats.route_refresh[STAT_RECV]);

    return 0;
}


void bgp_print_err(char *err_message) {
    int error = errno;
    fprintf(stderr, "[-] Err: %s, errno: %d\n", err_message, error);
    exit(1);
}

