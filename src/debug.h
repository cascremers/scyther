#ifndef DEBUG_H
#define DEBUG_H

#include "config.h"

void debugSet (int level);
int debugCond (int level);
void debug (int level, char *string);

#define DEBUGL(a) debugCond(a)

#endif
