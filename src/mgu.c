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

#ifdef DEBUG
  void showSubst (Term t)
  {
    if (!DEBUGL (5))
      return;

    indent ();
    printf ("Substituting ");
    termPrint (t);
    printf (", typed ");
    termlistPrint (t->stype);
    printf ("->");
    termlistPrint (t->subst->stype);
    printf ("\n");
  }
#endif

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
  if (realTermVariable (t1))
    {
      if (termOccurs (t2, t1))
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
  if (realTermVariable (t2))
    {
      if (termOccurs (t1, t2))
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

  /* left & right are compounds with variables */
  if (t1->type != t2->type)
    return MGUFAIL;

  /* identical compounds */
  /* encryption first */
  if (realTermEncrypt (t1))
    {
      Termlist tl1, tl2;

      tl1 = termMguTerm (t1->right.key, t2->right.key);
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (t1->left.op, t2->left.op);
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

      tl1 = termMguTerm (t1->left.op1, t2->left.op1);
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (t1->right.op2, t2->right.op2);
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
termMguInTerm (Term t1, Term t2, int (*iterator) ())
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
	  flag = flag && termMguInTerm (t1, t2->left.op1, iterator);
	  flag = flag && termMguInTerm (t1, t2->right.op2, iterator);
	}
      // simple clause or combined
      tl = termMguTerm (t1, t2);
      if (tl != MGUFAIL)
	{
	  // Iterate
	  flag = flag && iterator (tl);
	  // Reset variables
	  termlistSubstReset (tl);
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
termMguSubTerm (Term t1, Term t2, int (*iterator) (),
		Termlist inverses, Termlist keylist)
{
  int flag;
  Termlist tl;

  flag = 1;
  t2 = deVar (t2);
  if (t2 != NULL)
    {
      if (!realTermLeaf (t2))
	{
	  if (realTermTuple (t2))
	    {
	      // 'simple' tuple
	      flag =
		flag && termMguSubTerm (t1, t2->left.op1, iterator, inverses,
					keylist);
	      flag =
		flag && termMguSubTerm (t1, t2->right.op2, iterator, inverses,
					keylist);
	    }
	  else
	    {
	      // Must be encryption
	      // So, we need the key, and try to get the rest
	      Termlist keylist_new;
	      Term newkey;

	      keylist_new = termlistShallow (keylist);
	      newkey = inverseKey (inverses, t2->right.key);
	      keylist_new = termlistAdd (keylist_new, newkey);

	      // Recurse
	      flag =
		flag && termMguSubTerm (t1, t2->left.op, iterator, inverses,
					keylist_new);

	      termlistDelete (keylist_new);
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
	}
    }
  return flag;
}
