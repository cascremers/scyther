#include <stdlib.h>
#include <stdio.h>
#include "term.h"
#include "termlist.h"
#include "substitution.h"
#include "mgu.h"
#include "memory.h"

/*
   Most General Unifier

   Unification etc.

   New version yields a termlist with substituted variables, which can later be reset to NULL.
*/

//! Global constant. If true, typed checking
/**
 * Analoguous to sys->match
 * 0	typed
 * 1	basic typeflaws
 * 2	all typeflaws
 */
int mgu_match = 0;

extern Term TERM_Hidden;

void
showSubst (Term t)
{
#ifdef DEBUG
  if (!DEBUGL (5))
    return;

  indent ();
  printf ("Substituting ");
  termPrint (t);
  printf (", typed ");
  termlistPrint (t->stype);
  if (realTermLeaf (t->subst))
    {
      printf ("->");
      termlistPrint (t->subst->stype);
    }
  else
    {
      printf (", composite term");
    }
  if (t->type != VARIABLE)
    {
      printf (" (bound roleconstant)");
    }
  printf ("\n");
#endif
}

//! See if a substitution is valid
__inline__ int
goodsubst (Term tvar, Term tsubst)
{
  if (tvar->stype == NULL || (mgu_match == 2))
    {
      return 1;
    }
  else
    {
      /**
       * Check if each type of the substitution is allowed in the variable
       */
      if (!realTermLeaf (tsubst))
	{
	  // Typed var cannot match with non-leaf
	  return 0;
	}
      else
	{
	  // It's a leaf, but what type?
	  if (mgu_match == 1
	      || termlistContained (tvar->stype, tsubst->stype))
	    {
	      return 1;
	    }
	  else
	    {
#ifdef DEBUG
	      if (DEBUGL (5))
		{
		  eprintf ("Substitution fails on ");
		  termPrint (tvar);
		  eprintf (" -/-> ");
		  termPrint (tsubst);
		  eprintf (", because type: \n");
		  termlistPrint (tvar->stype);
		  eprintf (" does not contain ");
		  termlistPrint (tsubst->stype);
		  eprintf ("\n");
		}
#endif
	      return 0;
	    }
	}
    }
}

//! Undo all substitutions in a list of variables.
/**
 * The termlist should contain only variables.
 */
void
termlistSubstReset (Termlist tl)
{
  while (tl != NULL)
    {
      tl->term->subst = NULL;
      tl = tl->next;
    }
}

//! Most general unifier.
/**
 * Try to determine the most general unifier of two terms.
 * Resulting termlist must be termlistDelete'd.
 *
 *@return Returns a list of variables, that were previously open, but are now closed
 * in such a way that the two terms unify. Returns \ref MGUFAIL if it is impossible.
 */
Termlist
termMguTerm (Term t1, Term t2)
{
  /* added for speed */
  t1 = deVar (t1);
  t2 = deVar (t2);
  if (t1 == t2)
    return NULL;

  if (!(hasTermVariable (t1) || hasTermVariable (t2)))
    {
      if (isTermEqual (t1, t2))
	{
	  return NULL;
	}
      else
	{
	  return MGUFAIL;
	}
    }

  /* symmetrical tests for single variable */
  if (realTermVariable (t2))
    {
      if (termSubTerm (t1, t2) || !goodsubst (t2, t1))
	return MGUFAIL;
      else
	{
	  t2->subst = t1;
#ifdef DEBUG
	  showSubst (t2);
#endif
	  return termlistAdd (NULL, t2);
	}
    }
  if (realTermVariable (t1))
    {
      if (termSubTerm (t2, t1) || !goodsubst (t1, t2))
	return MGUFAIL;
      else
	{
	  t1->subst = t2;
#ifdef DEBUG
	  showSubst (t1);
#endif
	  return termlistAdd (NULL, t1);
	}
    }

  /* left & right are compounds with variables */
  if (t1->type != t2->type)
    return MGUFAIL;

  /* identical compounds */
  /* encryption first */
  if (realTermEncrypt (t1))
    {
      Termlist tl1, tl2;

      tl1 = termMguTerm (TermKey(t1), TermKey(t2));
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (TermOp(t1), TermOp(t2));
	  if (tl2 == MGUFAIL)
	    {
	      termlistSubstReset (tl1);
	      termlistDelete (tl1);
	      return MGUFAIL;
	    }
	  else
	    {
	      return termlistConcat (tl1, tl2);
	    }
	}
    }

  /* tupling second
     non-associative version ! TODO other version */
  if (isTermTuple (t1))
    {
      Termlist tl1, tl2;

      tl1 = termMguTerm (TermOp1(t1), TermOp1(t2));
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (TermOp2(t1), TermOp2(t2));
	  if (tl2 == MGUFAIL)
	    {
	      termlistSubstReset (tl1);
	      termlistDelete (tl1);
	      return MGUFAIL;
	    }
	  else
	    {
	      return termlistConcat (tl1, tl2);
	    }
	}
    }
  return MGUFAIL;
}

//! Most general interm unifiers of t1 interm t2
/**
 * Try to determine the most general interm unifiers of two terms.
 *@returns Nothing. Iteration gets termlist of substitutions.
 */
int
termMguInTerm (Term t1, Term t2, int (*iterator) (Termlist))
{
  Termlist tl;
  int flag;

  flag = 1;
  t2 = deVar (t2);
  if (t2 != NULL)
    {
      if (realTermTuple (t2))
	{
	  // t2 is a tuple, consider interm options as well.
	  flag = flag && termMguInTerm (t1, TermOp1(t2), iterator);
	  flag = flag && termMguInTerm (t1, TermOp2(t2), iterator);
	}
      // simple clause or combined
      tl = termMguTerm (t1, t2);
      if (tl != MGUFAIL)
	{
	  // Iterate
	  flag = flag && iterator (tl);
	  // Reset variables
	  termlistSubstReset (tl);
	  // Remove list
	  termlistDelete (tl);
	}
    }
  else
    {
      if (deVar (t1) != NULL)
	{
	  flag = 0;
	}
    }
  return flag;
}

//! Most general subterm unifiers of t1 subterm t2
/**
 * Try to determine the most general subterm unifiers of two terms.
 *@returns Nothing. Iteration gets termlist of subst, and list of keys needed to decrypt.
 */
int
termMguSubTerm (Term t1, Term t2, int (*iterator) (Termlist, Termlist),
		Termlist inverses, Termlist keylist)
{
  int flag;

  flag = 1;
  t1 = deVar (t1);
  t2 = deVar (t2);
  if (t2 != NULL)
    {
      Termlist tl;

      if (!realTermLeaf (t2))
	{
	  if (realTermTuple (t2))
	    {
	      // 'simple' tuple
	      flag =
		flag && termMguSubTerm (t1, TermOp1(t2), iterator, inverses,
					keylist);
	      flag =
		flag && termMguSubTerm (t1, TermOp2(t2), iterator, inverses,
					keylist);
	    }
	  else
	    {
	      // Must be encryption
	      // So, we need the key, and try to get the rest
	      Term newkey;

	      newkey = inverseKey (inverses, TermKey(t2));
	      // We can never produce the TERM_Hidden key, thus, this is not a valid iteration.
	      if (!isTermEqual (newkey, TERM_Hidden))
		{
	          Termlist keylist_new;

		  keylist_new = termlistShallow (keylist);
		  keylist_new = termlistAdd (keylist_new, newkey);

		  // Recurse
		  flag =
		    flag && termMguSubTerm (t1, TermOp(t2), iterator, inverses,
					    keylist_new);

		  termlistDelete (keylist_new);
		}
	      termDelete (newkey);
	    }
	}
      // simple clause or combined
      tl = termMguTerm (t1, t2);
      if (tl != MGUFAIL)
	{
	  // Iterate
	  flag = flag && iterator (tl, keylist);
	  // Reset variables
	  termlistSubstReset (tl);
	  // Remove list
	  termlistDelete (tl);
	}
    }
  else
    {
      if (t1 != NULL)
	{
	  flag = 0;
	}
    }
  return flag;
}
