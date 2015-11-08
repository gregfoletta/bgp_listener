#include <stdio.h>
#include <termios.h>

#define STDIN_FD 0
#define EOT 0x4

#define LINE_BUFFER 510

int toggle_stdin_raw(void);

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


int cli_read_loop(void) {
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
            fputs(buffer, stdout);
            fputs("\n", stdout);
            fputs(prefix, stdout);
            cursor_pos = 0;
            buffer[cursor_pos]= '\0';
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




