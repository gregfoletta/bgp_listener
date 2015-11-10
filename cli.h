struct cli_command_list {
    char *command;
    int (*func)(void *arg);
    struct cli_command_list *next;
};

int cli_commandlist_add(struct cli_command_list **, char *, int (*)(void *));
int cli_read_loop(struct cli_command_list *, void *);



