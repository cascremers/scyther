#ifndef VARBUF
#define VARBUF

#include "runs.h"

Varbuf varbufInit (const System sys);
void varbufSet (const System sys, Varbuf vb);
void varbufDone (Varbuf vb);

#endif
