#ifndef MGU
#define MGU

#include "term.h"
#include "termlist.h"
#include "substitution.h"

//! A special constant do denote failure.
/**
 * \c NULL already denotes equality, so an extra signal is needed to
 * denote that a unification fails.
 * \todo Find a portable solution for this \c MGUFAIL constant:
 * maybe a pointer to some special constant.
 */
#define MGUFAIL (Termlist) -1

void setMguMode (const int mgu);
Termlist termMguTerm (Term t1, Term t2);
int termMguInTerm (Term t1, Term t2, int (*iterator) (Termlist));
int termMguSubTerm (Term t1, Term t2, int (*iterator) (Termlist, Termlist),
		    Termlist inverses, Termlist keylist);
void termlistSubstReset (Termlist tl);

// The new iteration methods
int unify (Term t1, Term t2, Termlist tl, int (*callback) (Termlist));
int
subtermUnify (Term tbig, Term tsmall, Termlist tl, Termlist keylist,
	      int (*callback) (Termlist, Termlist));
#endif
