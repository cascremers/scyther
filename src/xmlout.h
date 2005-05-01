#ifndef XMLOUT
#define XMLOUT

#include "system.h"

void xmlOutInit (void);
void xmlOutDone (void);

void xmlOutSemitrace (const System sys);
void xmlOutTrace (const System sys);

#endif
