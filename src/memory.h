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

#define findLoserBegin(ign)	int mem_before; \
				int mem_diff; \
				static int mem_errorcount = 0; \
				struct mallinfo mi; \
				mi = mallinfo(); \
				mem_before = mi.uordblks - ign;
#define findLoserEnd(ign,t)	mi = mallinfo(); \
				mem_diff = mi.uordblks - ign - mem_before; \
				if (mem_diff != 0) \
				  { \
					warning ("Memory leak in [%s] of %i", t, mem_diff); \
					mem_errorcount++; \
					if (mem_errorcount >= 1) \
						error ("More than enough leaks."); \
				  }

#endif
