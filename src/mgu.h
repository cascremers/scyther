#ifndef MGU
#define MGU

#include "terms.h"
#include "termlists.h"
#include "substitutions.h"

//! A special constant do denote failure.
/**
 * \c NULL already denotes equality, so an extra signal is needed to
 * denote that a unification fails.
 * \todo Find a portable solution for this \c MGUFAIL constant:
 * maybe a pointer to some special constant.
 */
#define MGUFAIL (Termlist) -1

Termlist termMguTerm (Term t1, Term t2);

#endif
