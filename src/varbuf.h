#ifndef VARBUF
#define VARBUF

#include "runs.h"

Varbuf varbufInit (System sys);
void varbufSet (System sys, Varbuf vb);
void varbufDone (Varbuf vb);

#endif
