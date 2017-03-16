#include "debug.h"

int debugging;

void debug_enable() {
    debugging = 1;
}

void debug_disable() {
    debugging = 0;
}

int is_debug() {
    return debugging;
}


