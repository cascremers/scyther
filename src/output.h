#ifndef OUTPUT
#define OUTPUT

#include "runs.h"

void tracePrint(const System sys);
void attackDisplay(const System sys);
void graphInit (const System sys);
void graphDone (const System sys);
void graphNode (const System sys);
void graphNodePath (const System sys, const int length, const char*
		nodepar);
void graphEdgePath (const System sys, const int length, const char*
		edgepar);

#endif
