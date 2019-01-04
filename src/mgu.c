/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2013 Cas Cremers
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "term.h"
#include "termlist.h"
#include "mgu.h"
#include "type.h"
#include "debug.h"
#include "specialterm.h"
#include "switches.h"
#include "arachne.h"

/*
   Most General Unifier

   Unification etc.

   New version yields a termlist with substituted variables, which can later be reset to NULL.
*/

/**
 * switches.match
 * 0	typed
 * 1	basic typeflaws
 * 2	all typeflaws
 */

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
int
goodsubst (Term tvar, Term tsubst)
{
  Term tbuf;
  int res;

  tbuf = tvar->subst;
  tvar->subst = tsubst;

  res = checkTypeTerm (tvar);

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

/**
 * Helper structure and function for unify
 *
 * These help to allow recursive calls within unify while still passing through the "outer" callback and state pointers.
 */

struct state_mgu_tmp
{
  void *oldstate;
  int (*oldcallback) ();
  Term unifyt1;
  Term unifyt2;
};

int
unify_callback_wrapper (Termlist tl, struct state_mgu_tmp *ptr_tmpstate)
{
  // now the keys are unified (subst in this tl)
  // and we try the inner terms
  assert (ptr_tmpstate != NULL);
  return unify (ptr_tmpstate->unifyt1, ptr_tmpstate->unifyt2, tl,
		ptr_tmpstate->oldcallback, ptr_tmpstate->oldstate);
}

int
callsubst (int (*callback) (), void *state, Termlist tl, Term t, Term tsubst)
{
  int proceed;

  t->subst = tsubst;
#ifdef DEBUG
  showSubst (t);
#endif
  tl = termlistAdd (tl, t);
  proceed = callback (tl, state);
  tl = termlistDelTerm (tl);
  t->subst = NULL;
  return proceed;
}

//! Most general unifier iteration
/**
 * Try to determine the most general unifier of two terms, if so calls function.
 *
 * int callback(Termlist, *state)
 *
 * The callback receives a list of variables, that were previously open, but are now closed
 * in such a way that the two terms unify. 
 *
 * The callback must return true for the iteration to proceed: if it returns false, a single call would abort the scan.
 * The return value shows this: it is false if the scan was aborted, and true if not.
 */
int
unify (Term t1, Term t2, Termlist tl, int (*callback) (), void *state)
{
  /* added for speed */
  t1 = deVar (t1);
  t2 = deVar (t2);
  if (t1 == t2)
    {
      return callback (tl, state);
    }

  if (!(hasTermVariable (t1) || hasTermVariable (t2)))
    {
      // None has a variable
      if (isTermEqual (t1, t2))
	{
	  // Equal!
	  return callback (tl, state);
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
      return callsubst (callback, state, tl, t1, t2);
    }

  /* symmetrical tests for single variable.
   */

  if (realTermVariable (t2))
    {
      if (termSubTerm (t1, t2) || !goodsubst (t2, t1))
	return true;
      else
	{
	  return callsubst (callback, state, tl, t2, t1);
	}
    }
  if (realTermVariable (t1))
    {
      if (termSubTerm (t2, t1) || !goodsubst (t1, t2))
	return true;
      else
	{
	  return callsubst (callback, state, tl, t1, t2);
	}
    }

  /* left & right are compounds with variables */
  if (t1->type != t2->type)
    return true;

  /* identical compound types */

  /* encryption first */
  if (realTermEncrypt (t1))
    {
      struct state_mgu_tmp tmpstate;

      tmpstate.oldstate = state;
      tmpstate.oldcallback = callback;
      tmpstate.unifyt1 = TermOp (t1);
      tmpstate.unifyt2 = TermOp (t2);

      return unify (TermKey (t1), TermKey (t2), tl, unify_callback_wrapper,
		    &tmpstate);
    }

  /* tupling second
     non-associative version ! TODO other version */
  if (isTermTuple (t1))
    {
      struct state_mgu_tmp tmpstate;

      tmpstate.oldstate = state;
      tmpstate.oldcallback = callback;
      tmpstate.unifyt1 = TermOp2 (t1);
      tmpstate.unifyt2 = TermOp2 (t2);

      return unify (TermOp1 (t1), TermOp1 (t2), tl, unify_callback_wrapper,
		    &tmpstate);
    }

  return true;
}


/**
 * State for subterm unification call into keycallback
 */
struct su_kcb_state
{
  void *oldstate;
  int (*callback) (Termlist, Termlist, void *);
  Termlist keylist;
};

int
keycallback (Termlist tl, struct su_kcb_state *ptr_kcb_state)
{
  assert (ptr_kcb_state != NULL);
  return ptr_kcb_state->callback (tl, ptr_kcb_state->keylist,
				  ptr_kcb_state->oldstate);
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
 *
 * This is the actual procedure used by the Arachne algorithm in archne.c
 */
int
subtermUnify (Term tbig, Term tsmall, Termlist tl, Termlist keylist,
	      int (*callback) (), void *state)
{
  int proceed;
  struct su_kcb_state kcb_state;

  kcb_state.oldstate = state;
  kcb_state.callback = callback;
  kcb_state.keylist = keylist;

  proceed = true;

  // Devar
  tbig = deVar (tbig);
  tsmall = deVar (tsmall);

  // Three options:
  // 1. simple unification
  proceed = proceed && unify (tbig, tsmall, tl, keycallback, &kcb_state);

  // [2/3]: complex
  if (switches.intruder)
    {
      // 2. interm unification
      // Only if there is an intruder
      if (realTermTuple (tbig))
	{
	  proceed = proceed
	    && subtermUnify (TermOp1 (tbig), tsmall, tl, keylist, callback,
			     state);
	  proceed = proceed
	    && subtermUnify (TermOp2 (tbig), tsmall, tl, keylist, callback,
			     state);
	}

      // 3. unification with encryption needed
      if (realTermEncrypt (tbig))
	{
	  // extend the keylist
	  keylist = termlistAdd (keylist, tbig);
	  proceed = proceed
	    && subtermUnify (TermOp (tbig), tsmall, tl, keylist, callback,
			     state);
	  // remove last item again
	  keylist = termlistDelTerm (keylist);
	}
    }

  // Athena problem case: open variable about to be unified.
	  /**
	   * In this case we really need to consider the problematic Athena case for untyped variables.
	   */
  if (isTermVariable (tbig))
    {
      // Check the type: can it contain tuples, encryptions?
      if (isOpenVariable (tbig))
	{
	  // This one needs to be pursued by further constraint adding
	  /**
	   * Currently, this is not implemented yet. TODO.
	   * This is actually the main Athena problem that we haven't solved yet.
	   */
	  // Mark that we don't have a full proof, and possibly remark in proof output.
	  markNoFullProof (tbig, tsmall);
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
 *
 * @TODO this code should be removed, as it duplicates 'unify' code, and is
 * ill-suited for adaption later on with multiple unifiers.
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
