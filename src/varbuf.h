#ifndef VARBUF
#define VARBUF

#include "system.h"

Varbuf varbufInit (const System sys);
void varbufSet (const System sys, Varbuf vb);
void varbufDone (Varbuf vb);

#endif
