#include <stdio.h>

void debug_enable();
void debug_disable();
int is_debug();

#define DEBUG_PRINT(...) if (is_debug()) { fprintf(stderr, "[DEBUG] "); fprintf((stderr), __VA_ARGS__); }
