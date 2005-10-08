#ifndef TYPE
#define TYPE

#include "term.h"
#include "system.h"

int checkTypeTerm (const int mgumode, const Term t);
int checkTypeTermlist (const int mgumode, Termlist tl);
int checkTypeLocals (const System sys);
Termlist typelistConjunct (Termlist typelist1, Termlist Typelist2);
int checkAllSubstitutions (const System sys);
int isAgentType (Termlist typelist);

#endif
