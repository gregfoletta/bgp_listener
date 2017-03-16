#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cli_command_list;

int cli_commandlist_add(struct cli_command_list **, char *, int (*)(int, char**, void *));
int cli_read_loop(struct cli_command_list *, void *);
int cli_free(struct cli_command_list *);



