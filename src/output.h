#ifndef OUTPUT
#define OUTPUT

#include "runs.h"

void tracePrint(const System sys);
void attackDisplay(const System sys);
void graphInit (const System sys);
void graphDone (const System sys);
void graphNode (const System sys);
void graphPath (const System sys, const char* nodepar, const char*
		edgepar);

#endif
