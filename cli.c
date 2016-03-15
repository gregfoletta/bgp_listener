#include <stdio.h>
#include <termios.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"

#define STDIN_FD 0
#define EOT 0x4

#define LINE_BUFFER 510
#define MAX_ARGS 3 

#define CMDRETEXIT -1
#define CMDNOTENTERED -2
#define CMDNOTFOUND -3

struct cli_command_list {
    char *command;
    int (*func)(int, char **, void *); 
    struct cli_command_list *next;
};

int toggle_stdin_raw(void);
int print_commands(struct cli_command_list *);
int tokenise_and_execute(struct cli_command_list *, char *, void *);


int toggle_stdin_raw(void) {
    struct termios old_term, new_term;

    if (tcgetattr(STDIN_FD, &old_term) == -1) {
        return -1;
    }

    new_term = old_term;
    new_term.c_lflag &= ~(ICANON | ECHO | ISIG);

    tcsetattr(STDIN_FD, TCSANOW, &new_term);

    return 0;
}




int cli_commandlist_add(struct cli_command_list **head, char *command, int (*action)(int, char **, void *)) {
    struct cli_command_list *iterate, *new;

    //Create the new command struct and members
    new = malloc(sizeof(*new));
    new->command = malloc(sizeof(*(new->command) * (strlen(command) + 1)));
    memcpy(new->command, command, strlen(command) +1);
    new->func = action;
    new->next = NULL;


    /* Is the head allocated already? If not, add the new entry */
    if (*head == NULL) {
        *head = new;
    }
    else {
        for (iterate = *head; iterate->next != NULL; iterate = iterate->next) { ; }
        iterate->next = new;
    }

    return 0;
}





int print_commands(struct cli_command_list *list) {
    struct cli_command_list *iterate = list;
    printf("Available commands:\n");

    while (iterate != NULL) {
        printf("  %s\n", iterate->command);
        iterate = iterate->next;
    }

    return 0;
}







int cli_read_loop(struct cli_command_list *command_list, void *data) {
    int input;
    char *prefix = "cli> ";
    char buffer[LINE_BUFFER];
    int cursor_pos = 0;

    buffer[cursor_pos] = '\0';
    toggle_stdin_raw();

    fputs(prefix, stdout);

    while ((input = getchar()) != EOT) {
        switch (input) {
        case '?':
            print_commands(command_list);
            fputs(prefix, stdout);
            continue;
        case 0x7f: //Backspace
            if (cursor_pos == 0) {
                continue;
            }
            fputs("\b \b", stdout);
            cursor_pos--;
            continue;
        case 0xa: //Enter
            fputs("\n", stdout);
            switch (tokenise_and_execute(command_list, buffer, data)) {
            case CMDRETEXIT:
                return 0;
            case CMDNOTFOUND: //Note: we don't break out of this
                fputs("Command not found\n", stdout);
            default:
                cursor_pos = 0;
                buffer[cursor_pos]= '\0';
                fputs(prefix, stdout);
                continue;
            }
        default:
            if (cursor_pos >= LINE_BUFFER - 1 || (input < ' ' || input > '~')) {
                continue;
            }
            buffer[cursor_pos] = input;
            buffer[cursor_pos + 1] = '\0';
            putchar(input);
            cursor_pos++;
        }
    }
    return 0;
}

int cli_free(struct cli_command_list *cmd_list) {
    struct cli_command_list *curr, *prev;

    curr = cmd_list;
    while (curr != NULL) {
        prev = curr;
        free(curr->command);
        curr = curr->next;
        free(prev);
    }

    return 0;
}


int tokenise_and_execute(struct cli_command_list *command_list, char *buffer, void *data) {
    int argc = 0;
    char *argv[MAX_ARGS];
    struct cli_command_list *iterate;

    argv[0] = strtok(buffer, " ");
    if (argv[0] == NULL) {
        //No command
        return CMDNOTENTERED;
    }
    argc++;

    while ((argv[argc] = strtok(NULL, " ")) != NULL) {
        argc++;
        if (argc == MAX_ARGS) {
            break;
        }
    }

    iterate = command_list;
    while (iterate != NULL) {
        if (strcmp(argv[0], iterate->command) == 0) {
            return iterate->func(argc, argv, data);
        }
        iterate = iterate->next;
    }
    //Command not found
    return CMDNOTFOUND;
}






