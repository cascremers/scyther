#ifndef DEBUG_H
#define DEBUG_H

void debugSet (int level);
int debugCond (int level);
void debug (int level, char *string);

#define DEBUGL(a) debugCond(a)

#endif
