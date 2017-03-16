#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <strings.h> 
#include <unistd.h>

#include "debug.h"

int tcp_connect(const char *, const char *);
