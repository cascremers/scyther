/**
 * Malloc on all platforms except Apple ones
 */

#ifndef MYMALLOC
#define MYMALLOC

#ifndef __APPLE__
#include <malloc.h>
#else
#include <stdlib.h>
#endif

#endif
