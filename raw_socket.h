#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include "debug.h"

#define IPPROTO_OSPF 89

int raw_sock_create(void);
int raw_sock_connect(const char *);
