#include <stdlib.h>
#include <stdio.h>
#include "term.h"
#include "substitution.h"
#include "memory.h"

/* substitutions in terms */

Substitution
makeSubstitution (Term from, Term to)
{
  Substitution subs;

  subs = memAlloc (sizeof (struct substitution));
  subs->from = from;
  subs->to = to;
  return subs;
}

void
substitutionDelete (Substitution subs)
{
  if (subs == NULL)
    return;
  memFree (subs, sizeof (struct substitution));
}

void
substitutionDestroy (Substitution subs)
{
  if (subs == NULL)
    return;
  termDelete (subs->from);
  termDelete (subs->to);
  memFree (subs, sizeof (struct substitution));
}



/*
   termSubstitute

   Yields a new (deep copy) term of a term, according to the
   substitution.

   To remove the old term, use termDelete.
   Be sure to use termNormalize on it afterwards!!

*/


Term
termSubstitute (Term term, Substitution subs)
{
  if (term == NULL)
    return NULL;
  if (isTermEqual (term, subs->from))
    {
      return termDuplicate (subs->to);
    }
  else
    {
      if (!isTermLeaf (term))
	{
	  if (isTermEncrypt (term))
	    {
	      return makeTermEncrypt (termSubstitute (TermOp (term), subs),
				      termSubstitute (TermKey (term), subs));
	    }
	  else
	    {
	      return
		makeTermTuple (termSubstitute (TermOp1 (term), subs),
			       termSubstitute (TermOp2 (term), subs));
	    }
	}
      else
	{
	  return termDuplicate (term);
	}
    }
}

/*

   termlistSubstitute.

   Makes a new list, deep copies of the terms. 

   To remove the old termlist, use termlistDestroy

   TODO
*/

Termlist
termlistSubstitute (Termlist tl, Substitution subs)
{
  if (tl == NULL)
    return NULL;
  else
    {
      Termlist tls = termlistSubstitute (tl->next, subs);
      //return termlistAdd(termlistSubstitute(tl->next, subs),
      //                 termSubstitute(tl->term, subs));
      return tls;
    }
}


void
substitutionPrint (Term t, Substitution subs)
{
  printf ("Substituting ");
  termPrint (subs->from);
  printf (" by ");
  termPrint (subs->to);
  printf (" in ");
  termPrint (t);
  printf ("\n");
}

/* termSubstituteList

   Not very efficient at the moment. Recursing through the term might be
   a lot easier. However, this works.

*/

Term
termSubstituteList (Term term, Substitutionlist sl)
{
  Term newt;
  Term oldt;

  if (sl == NULL)
    return termDuplicate (term);
  if (term == NULL)
    return NULL;

  newt = termSubstitute (term, sl->subst);
  sl = sl->next;
  while (sl != NULL)
    {
      oldt = newt;
      newt = termSubstitute (oldt, sl->subst);
      termDelete (oldt);
      sl = sl->next;
    }
  return newt;
}

Substitutionlist
makeSubstitutionList (Substitution subs)
{
  Substitutionlist sl;

  sl = memAlloc (sizeof (struct substitutionlist));
  sl->subst = subs;
  sl->next = NULL;
  return sl;
}

Substitutionlist
substitutionlistAdd (Substitutionlist sl, Term from, Term to)
{
  return substitutionlistConcat (sl,
				 makeSubstitutionList (makeSubstitution
						       (from, to)));
}

void
substitutionlistDestroy (Substitutionlist sl)
{
  if (sl != NULL)
    {
      substitutionDelete (sl->subst);
      substitutionlistDestroy (sl->next);
      memFree (sl, sizeof (struct substitutionlist));
    }
}

void
substitutionlistAnnihilate (Substitutionlist sl)
{
  if (sl != NULL)
    {
      substitutionDestroy (sl->subst);
      substitutionlistDestroy (sl->next);
      memFree (sl, sizeof (struct substitutionlist));
    }
}

Substitutionlist
substitutionlistConcat (Substitutionlist sl1, Substitutionlist sl2)
{
  Substitutionlist scan;

  if (sl1 == NULL)
    return sl2;
  scan = sl1;
  while (scan->next != NULL)
    scan = scan->next;
  scan->next = sl2;
  return sl1;
}

/* substitute over termlist */

Termlist
substitutionBatch (Termlist tl, Substitutionlist sl)
{
  Termlist newtl;

  if (tl == NULL)
    return NULL;
  if (sl == NULL)
    return termlistDuplicate (tl);
  newtl = NULL;
  while (tl != NULL)
    {
      newtl = termlistAdd (newtl, termSubstituteList (tl->term, sl));
      tl = tl->next;
    }
  return newtl;
}

/* substitute over roledef */

Roledef
substitutionRoledef (Roledef rdorig, Substitutionlist sl)
{
  Roledef rd, rdscan;

  rd = roledefDuplicate (rdorig);
  rdscan = rd;

  while (rdscan != NULL)
    {
      rdscan->from = termSubstituteList (rdscan->from, sl);
      rdscan->to = termSubstituteList (rdscan->to, sl);
      rdscan->message = termSubstituteList (rdscan->message, sl);
      rdscan = rdscan->next;
    }
  return rd;
}

/* substitute over knowledge structure */

Knowledge
substitutionKnowledge (Knowledge know, Substitutionlist sl)
{
  /* TODO this is wrong anyway, because it does not respect the knowledge invariants. We should remove the variables occurring on
     the left, and add to the knowledge the new stuff */

  Termlist repres, repres2;

  Knowledge know2 = emptyKnowledge ();
  knowledgeSetInverses (know2, knowledgeGetInverses (know));
  repres = knowledgeSet (know);
  repres2 = substitutionBatch (repres, sl);
  knowledgeAddTermlist (know2, repres2);
  termlistDelete (repres2);
  termlistDelete (repres);
  return know2;
}

void
substitutionlistPrint (Substitutionlist sl)
{
  int i = 1;

  if (sl == NULL)
    printf ("[empty substitutionlist]\n");
  else
    {
      while (sl != NULL)
	{
	  printf ("%i: ", i);
	  termPrint (sl->subst->from);
	  printf (" -> ");
	  termPrint (sl->subst->to);
	  printf ("\n");
	  i++;
	  sl = sl->next;
	}
    }
}
