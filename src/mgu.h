#ifndef MGU
#define MGU

#include "terms.h"
#include "termlists.h"
#include "substitutions.h"

#define MGUFAIL (Termlist) -1

Termlist termMguTerm (Term t1, Term t2);

#endif
