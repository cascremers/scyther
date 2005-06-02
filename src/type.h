#ifndef TYPE
#define TYPE

#include "term.h"
#include "system.h"

int checkTypeTerm (const int mgumode, const Term t);
int checkTypeTermlist (const int mgumode, Termlist tl);
int checkTypeLocals (const System sys);

#endif
