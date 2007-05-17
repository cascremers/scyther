#include <stdlib.h>
#include <stdio.h>
#include "term.h"
#include "termlist.h"
#include "mgu.h"
#include "type.h"
#include "debug.h"
#include "specialterm.h"
#include "switches.h"

/*
   Most General Unifier

   Unification etc.

   New version yields a termlist with substituted variables, which can later be reset to NULL.
*/

//! Internal constant. If true, typed checking
/**
 * Analoguous to switches.match
 * 0	typed
 * 1	basic typeflaws
 * 2	all typeflaws
 */
static int mgu_match = 0;

//! Set mgu mode (basically switches.match)
void
setMguMode (const int match)
{
  mgu_match = match;
}

void
showSubst (Term t)
{
#ifdef DEBUG
  if (!DEBUGL (5))
    return;

  indent ();
  eprintf ("Substituting ");
  termPrint (t);
  eprintf (", typed ");
  termlistPrint (t->stype);
  if (realTermLeaf (t->subst))
    {
      eprintf ("->");
      termlistPrint (t->subst->stype);
    }
  else
    {
      eprintf (", composite term");
    }
  if (t->type != VARIABLE)
    {
      eprintf (" (bound roleconstant)");
    }
  eprintf ("\n");
#endif
}

//! See if this is preferred substitution
/**
 * By default, ta->tb will map. Returning 0 (false) will swap them.
 */
int
preferSubstitutionOrder (Term ta, Term tb)
{
  if (termlistLength (ta->stype) == 1 && inTermlist (ta->stype, TERM_Agent))
    {
      /**
       * If the first one is an agent type, we prefer swapping.
       */
      return 0;
    }

  // Per default, leave it as it is.
  return 1;
}

//! See if a substitution is valid
__inline__ int
goodsubst (Term tvar, Term tsubst)
{
  Term tbuf;
  int res;

  tbuf = tvar->subst;
  tvar->subst = tsubst;

  res = checkTypeTerm (mgu_match, tvar);

  tvar->subst = tbuf;
  return res;
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

//! Most general unifier iteration
/**
 * Try to determine the most general unifier of two terms, if so calls function.
 *
 * The callback receives a list of variables, that were previously open, but are now closed
 * in such a way that the two terms unify. 
 *
 * The callback must return true for the iteration to proceed: if it returns false, a single call would abort the scan.
 * The return value shows this: it is false if the scan was aborted, and true if not.
 */
int
unify (Term t1, Term t2, Termlist tl, int (*callback) (Termlist))
{
  int callsubst (Termlist tl, Term t, Term tsubst)
  {
    int proceed;

    t->subst = tsubst;
#ifdef DEBUG
    showSubst (t);
#endif
    tl = termlistAdd (tl, t);
    proceed = callback (tl);
    tl = termlistDelTerm (tl);
    t->subst = NULL;
    return proceed;
  }

  /* added for speed */
  t1 = deVar (t1);
  t2 = deVar (t2);
  if (t1 == t2)
    {
      return callback (tl);
    }

  if (!(hasTermVariable (t1) || hasTermVariable (t2)))
    {
      // None has a variable
      if (isTermEqual (t1, t2))
	{
	  // Equal!
	  return callback (tl);
	}
      else
	{
	  // Can never be fixed, no variables
	  return true;
	}
    }

  /*
   * Distinguish a special case where both are unbound variables that will be
   * connected, and I want to give one priority over the other for readability.
   *
   * Because t1 and t2 have been deVar'd means that if they are variables, they
   * are also unbound.
   */

  if (realTermVariable (t1) && realTermVariable (t2) && goodsubst (t1, t2))
    {
      /* Both are unbound variables. Decide.
       *
       * The plan: t1->subst will point to t2. But maybe we prefer the other
       * way around?
       */
      if (preferSubstitutionOrder (t2, t1))
	{
	  Term t3;

	  // Swappy.
	  t3 = t1;
	  t1 = t2;
	  t2 = t3;
	}
      return callsubst (tl, t1, t2);
    }

  /* symmetrical tests for single variable.
   */

  if (realTermVariable (t2))
    {
      if (termSubTerm (t1, t2) || !goodsubst (t2, t1))
	return true;
      else
	{
	  return callsubst (tl, t2, t1);
	}
    }
  if (realTermVariable (t1))
    {
      if (termSubTerm (t2, t1) || !goodsubst (t1, t2))
	return true;
      else
	{
	  return callsubst (tl, t1, t2);
	}
    }

  /* left & right are compounds with variables */
  if (t1->type != t2->type)
    return true;

  /* identical compound types */

  /* encryption first */
  if (realTermEncrypt (t1))
    {
      int unify_combined_enc (Termlist tl)
      {
	// now the keys are unified (subst in this tl)
	// and we try the inner terms
	return unify (TermOp (t1), TermOp (t2), tl, callback);
      }

      return unify (TermKey (t1), TermKey (t2), tl, unify_combined_enc);
    }

  /* tupling second
     non-associative version ! TODO other version */
  if (isTermTuple (t1))
    {
      int unify_combined_tup (Termlist tl)
      {
	// now the keys are unified (subst in this tl)
	// and we try the inner terms
	return unify (TermOp2 (t1), TermOp2 (t2), tl, callback);
      }
      return unify (TermOp1 (t1), TermOp1 (t2), tl, unify_combined_tup);
    }

  return true;
}


//! Subterm unification
/**
 * Try to unify (a subterm of) tbig with tsmall.
 *
 * Callback is called with a list of substitutions, and a list of terms that
 * need to be decrypted in order for this to work.
 *
 * E.g. subtermUnify ( {{m}k1}k2, m ) yields a list : {{m}k1}k2, {m}k1 (where
 * the {m}k1 is the last added node to the list)
 *
 * The callback should return true for the iteration to proceed, or false to abort.
 * The final result is this flag.
 */
int
subtermUnify (Term tbig, Term tsmall, Termlist tl, Termlist keylist,
	      int (*callback) (Termlist, Termlist))
{
  int proceed;

  int keycallback (Termlist tl)
  {
    return callback (tl, keylist);
  }

  proceed = true;

  // Devar
  tbig = deVar (tbig);
  tsmall = deVar (tsmall);

  // Three options:
  // 1. simple unification
  proceed = proceed && unify (tbig, tsmall, tl, keycallback);

  // [2/3]: complex
  if (switches.intruder)
    {
      // 2. interm unification
      // Only if there is an intruder
      if (realTermTuple (tbig))
	{
	  proceed = proceed
	    && subtermUnify (TermOp1 (tbig), tsmall, tl, keylist, callback);
	  proceed = proceed
	    && subtermUnify (TermOp2 (tbig), tsmall, tl, keylist, callback);
	}

      // 3. unification with encryption needed
      if (realTermEncrypt (tbig))
	{
	  // extend the keylist
	  keylist = termlistAdd (keylist, tbig);
	  proceed = proceed
	    && subtermUnify (TermOp (tbig), tsmall, tl, keylist, callback);
	  // remove last item again
	  keylist = termlistDelTerm (keylist);
	}
    }
  return proceed;
}


//! Most general unifier.
/**
 * Try to determine the most general unifier of two terms.
 * Resulting termlist must be termlistDelete'd.
 *
 *@return Returns a list of variables, that were previously open, but are now closed
 * in such a way that the two terms unify. Returns \ref MGUFAIL if it is impossible.
 * The termlist should be deleted.
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

  /*
   * Distinguish a special case where both are unbound variables that will be
   * connected, and I want to give one priority over the other for readability.
   *
   * Because t1 and t2 have been deVar'd means that if they are variables, they
   * are also unbound.
   */

  if (realTermVariable (t1) && realTermVariable (t2) && goodsubst (t1, t2))
    {
      /* Both are unbound variables. Decide.
       *
       * The plan: t1->subst will point to t2. But maybe we prefer the other
       * way around?
       */
      if (preferSubstitutionOrder (t2, t1))
	{
	  Term t3;

	  // Swappy.
	  t3 = t1;
	  t1 = t2;
	  t2 = t3;
	}
      t1->subst = t2;
#ifdef DEBUG
      showSubst (t1);
#endif
      return termlistAdd (NULL, t1);
    }

  /* symmetrical tests for single variable.
   */

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

      tl1 = termMguTerm (TermKey (t1), TermKey (t2));
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (TermOp (t1), TermOp (t2));
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

      tl1 = termMguTerm (TermOp1 (t1), TermOp1 (t2));
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (TermOp2 (t1), TermOp2 (t2));
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
	  flag = flag && termMguInTerm (t1, TermOp1 (t2), iterator);
	  flag = flag && termMguInTerm (t1, TermOp2 (t2), iterator);
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

//! Most general subterm unifiers of smallterm subterm bigterm
/**
 * Try to determine the most general subterm unifiers of two terms.
 *@returns Nothing. Iteration gets termlist of subst, and list of keys needed
 *  to decrypt. This termlist does not need to be deleted, because it is handled
 *  by the mguSubTerm itself.
 */
int
termMguSubTerm (Term smallterm, Term bigterm,
		int (*iterator) (Termlist, Termlist), Termlist inverses,
		Termlist cryptlist)
{
  int flag;

  flag = 1;
  smallterm = deVar (smallterm);
  bigterm = deVar (bigterm);
  if (bigterm != NULL)
    {
      Termlist tl;

      if (!realTermLeaf (bigterm))
	{
	  if (realTermTuple (bigterm))
	    {
	      // 'simple' tuple
	      flag =
		flag
		&& termMguSubTerm (smallterm, TermOp1 (bigterm), iterator,
				   inverses, cryptlist);
	      flag = flag
		&& termMguSubTerm (smallterm, TermOp2 (bigterm), iterator,
				   inverses, cryptlist);
	    }
	  else
	    {
	      // Must be encryption
	      Term keyneeded;

	      keyneeded = inverseKey (inverses, TermKey (bigterm));
	      // We can never produce the TERM_Hidden key, thus, this is not a valid iteration.
	      if (!isTermEqual (keyneeded, TERM_Hidden))
		{
		  cryptlist = termlistAdd (cryptlist, bigterm);	// Append, so the last encrypted term in the list is the most 'inner' one, and the first is the outer one.

		  // Recurse
		  flag =
		    flag
		    && termMguSubTerm (smallterm, TermOp (bigterm), iterator,
				       inverses, cryptlist);


		  cryptlist = termlistDelTerm (cryptlist);
		}
	      termDelete (keyneeded);
	    }
	}
      // simple clause or combined
      tl = termMguTerm (smallterm, bigterm);
      if (tl != MGUFAIL)
	{
	  // Iterate
	  flag = flag && iterator (tl, cryptlist);
	  // Reset variables
	  termlistSubstReset (tl);
	  // Remove list
	  termlistDelete (tl);
	}
    }
  else
    {
      if (smallterm != NULL)
	{
	  flag = 0;
	}
    }
  return flag;
}

//! Check if role terms might match in some way
/**
 * Interesting case: role names are variables here, so they always match. We catch that case by inspecting the variable list.
 */
int
checkRoletermMatch (const Term t1, const Term t2, const Termlist notmapped)
{
  Termlist tl;

  // simple clause or combined
  tl = termMguTerm (t1, t2);
  if (tl == MGUFAIL)
    {
      return false;
    }
  else
    {
      int result;
      Termlist vl;

      result = true;
      // Reset variables
      termlistSubstReset (tl);
      // Check variable list etc: should not contain mapped role names
      vl = tl;
      while (vl != NULL)
	{
	  // This term should not be in the notmapped list
	  if (inTermlist (notmapped, vl->term))
	    {
	      result = false;
	      break;
	    }
	  vl = vl->next;

	}
      // Remove list
      termlistDelete (tl);
      return result;
    }
}