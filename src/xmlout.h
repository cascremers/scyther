#ifndef XMLOUT
#define XMLOUT

#include "system.h"
#include "claim.h"

void xmlOutInit (void);
void xmlOutDone (void);

void xmlOutSemitrace (const System sys);
void xmlOutTrace (const System sys);
void xmlOutClaim (const System sys, Claimlist cl);

#endif
