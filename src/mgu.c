#include <stdlib.h>
#include <stdio.h>
#include "terms.h"
#include "termlists.h"
#include "substitutions.h"
#include "mgu.h"
#include "memory.h"

/*
   Most General Unifier

   Unification etc.

   New version yields a termlist with substituted variables, which can later be reset to NULL.
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
  if (isTermVariable (t1))
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
  if (isTermVariable (t2))
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
  if (isTermEncrypt (t1))
    {
      Termlist tl1, tl2;

      tl1 = termMguTerm (t1->key, t2->key);
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (t1->op, t2->op);
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

      tl1 = termMguTerm (t1->op1, t2->op1);
      if (tl1 == MGUFAIL)
	{
	  return MGUFAIL;
	}
      else
	{
	  tl2 = termMguTerm (t1->op2, t2->op2);
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
