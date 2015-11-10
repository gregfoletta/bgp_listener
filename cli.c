#include <stdio.h>
#include <termios.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"

#define STDIN_FD 0
#define EOT 0x4

#define LINE_BUFFER 510

int toggle_stdin_raw(void);
int cli_print_commands(struct cli_command_list *);



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




int cli_commandlist_add(struct cli_command_list **head, char *command, int (*action)(void *)) {
    struct cli_command_list *iterate, *new;


    //Create the new command struct and members
    new = malloc(sizeof(*new));
    new->command = malloc(sizeof(*(new->command) * (strlen(command) + 1)));
    memcpy(new->command, command, strlen(command) +1);
    new->func = action;
    new->next = NULL;


    /* Is the head allocated already? If not, add the new entry */
    if (*head == NULL) {
        printf("Headr not allocated..., allocating for %s\n", command);
        *head = new;
    }
    else {
        iterate = *head;
        printf("Current head command: %s\n", (*head)->command);

        while (iterate->next != NULL) {
            iterate = iterate->next;
        }
        iterate->next = new;
    }

    return 0;
}





int cli_print_commands(struct cli_command_list *list) {
    struct cli_command_list *iterate = list;
    printf("Available commands:\n");

    while (iterate != NULL) {
        printf("  %s\n", iterate->command);
        iterate = iterate->next;
    }

    return 0;
}




int cli_read_loop(struct cli_command_list *command_list) {
    int input;
    char *prefix = "\ncli> ";
    char buffer[LINE_BUFFER];
    int cursor_pos = 0;
    struct cli_command_list *iterate;

    buffer[cursor_pos] = '\0';
    toggle_stdin_raw();

    fputs(prefix, stdout);


    while ((input = getchar()) != EOT) {
        switch (input) {
        case '?':
            cli_print_commands(command_list);
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
            iterate = command_list;

            while (iterate != NULL) {
                if (strcmp(iterate->command, buffer) == 0) {
                    iterate->func("Matching command");
                }
                iterate = iterate->next; 
            }

            cursor_pos = 0;
            buffer[cursor_pos]= '\0';
            fputs(prefix, stdout);
            continue;
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




