#ifndef OUTPUT
#define OUTPUT

#include "system.h"

void tracePrint (const System sys);
void attackDisplay (const System sys);
void graphInit (const System sys);
void graphDone (const System sys);
void graphNode (const System sys);
void graphNodePath (const System sys, const int length, const char *nodepar);
void graphEdgePath (const System sys, const int length, const char *edgepar);
void graphPath (const System sys, int length);
void graphScenario (const System sys, const int run, const Roledef rd);

#endif
