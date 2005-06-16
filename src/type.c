/*
 * type.c
 *
 * Code to check the consistency of types, in the presence of type flaw stuff etc.
 */

#include <stdlib.h>
#include <stdio.h>
#include "term.h"
#include "termlist.h"
#include "system.h"
#include "debug.h"
#include "switches.h"
#include "specialterm.h"

extern Protocol INTRUDER;

//! Report a bad substitution, if needed
void
reportBadSubst (const Term tvar, const Term tsubst)
{
#ifdef DEBUG
  if (DEBUGL (5))
    {
      Term tbuf;

      tbuf = tvar->subst;
      tvar->subst = NULL;

      eprintf ("Substitution fails on ");
      termPrint (tvar);
      eprintf (" -/-> ");
      termPrint (tsubst);
      eprintf (", maybe because type: \n");
      termlistPrint (tvar->stype);
      eprintf (" does not contain ");
      termlistPrint (tsubst->stype);
      eprintf ("\n");

      tvar->subst = tbuf;
    }
#endif
}

//! Check whether a single variable term is instantiated correctly.
/**
 * Check whether a single variable term is instantiated correctly in this
 * system. This takes the matching parameter into account, and is aware of the
 * 'ticket' type.
 *
 * Non-variables etc. imply true.
 */
int
checkTypeTerm (const int mgumode, const Term tvar)
{
  // Checks are only needed for mgumode < 2 etc.
  if (mgumode < 2 && tvar != NULL && realTermVariable (tvar))
    {
      // Non-instantiated terms are fine.
      if (tvar->subst != NULL)
	{
	  // NULL type is always fine
	  if (tvar->stype != NULL)
	    {
	      // Tickets are always fine too
	      if (!inTermlist (tvar->stype, TERM_Ticket))
		{
		  // So there is a specific (non-ticket) type, and the var is instantiated, match mode 0 or 1
		  // Is it really a leaf?
		  Term tsubst;

		  tsubst = deVar (tvar);
		  if (!realTermLeaf (tsubst))
		    {
		      // Then it's definitively false
		      reportBadSubst (tvar, tsubst);
		      return false;
		    }
		  else
		    {
		      // It is a leaf
		      if (mgumode == 0)
			{
			  /* Types must match exactly. Thus, one of the variable type should match a type of the constant.
			   */
			  Termlist tl;

			  tl = tvar->stype;
			  while (tl != NULL)
			    {
			      if (inTermlist (tsubst->stype, tl->term))
				{
				  // One type matches
				  return true;
				}
			      tl = tl->next;
			    }
			  // No type matches.
			  reportBadSubst (tvar, tsubst);
			  return false;
			}
		    }
		}
	    }
	}
    }
  return true;
}

//! Check types of a list
/**
 * Empty list implies true.
 */
int
checkTypeTermlist (const int mgumode, Termlist tl)
{
  while (tl != NULL)
    {
      if (!checkTypeTerm (mgumode, tl->term))
	return false;
      tl = tl->next;
    }
  return true;
}

//! Check whether all local variables are instantiated correctly.
int
checkTypeLocals (const System sys)
{
  int run;

  run = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].protocol != INTRUDER)
	{
	  if (!checkTypeTermlist (switches.match, sys->runs[run].locals))
	    return false;
	}
      run++;
    }
  return true;
}
