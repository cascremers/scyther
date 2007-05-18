#ifndef TYPE
#define TYPE

#include "term.h"
#include "system.h"

int checkTypeTerm (const Term t);
int checkTypeTermlist (Termlist tl);
int checkTypeLocals (const System sys);
Termlist typelistConjunct (Termlist typelist1, Termlist Typelist2);
int checkAllSubstitutions (const System sys);
int isAgentType (Termlist typelist);
int goodAgentType (Term agent);

#endif
