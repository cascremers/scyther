#ifndef MEMORY
#define MEMORY

#include "string.h"
#include "debug.h"
#include <malloc.h>

void memInit ();
void memDone ();
#define memAlloc(t) malloc(t)
#define memFree(p,t) free(p)
#define memRealloc(p,t) realloc(p,t);

#endif
