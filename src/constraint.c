#include <stdio.h>
#include "memory.h"
#include "constraint.h"
#include "debug.h"
#include "system.h"



/* constraints currently are shallow copies */

Constraint
makeConstraint (Term term, Knowledge know)
{
  /* maybe knowDup can just be a link, but then it needs to be moved from destroy as well */
  Constraint co = memAlloc (sizeof (struct constraint));
  co->term = term;
  //co->know = knowledgeDuplicate(know);
  co->know = know;
  return co;
}


Constraint
constraintDuplicate (Constraint co)
{
  return makeConstraint (co->term, co->know);
}


void
constraintDestroy (Constraint cons)
{
  //knowledgeDelete(cons->know);
  if (cons != NULL)
    memFree (cons, sizeof (struct constraint));
}

/* constraints are typically added at the end, to maintain the order in which they were added */

Constraintlist
constraintlistAdd (Constraintlist cl, Constraint co)
{
  Constraintlist clnew = memAlloc (sizeof (struct constraintlist));

  clnew->constraint = co;
  clnew->next = NULL;
  if (cl == NULL)
    {
      clnew->prev = NULL;
      return clnew;
    }
  else
    {
      Constraintlist scan;

      scan = cl;
      while (scan->next != NULL)
	scan = scan->next;
      scan->next = clnew;
      clnew->prev = scan;
      return cl;
    }
}

Constraintlist
constraintlistConcat (Constraintlist cl1, Constraintlist cl2)
{
  Constraintlist scan;

  if (cl1 == NULL)
    return cl2;
  scan = cl1;
  while (scan->next != NULL)
    scan = scan->next;
  scan->next = cl2;
  return cl1;
}

Constraintlist
constraintlistRewind (Constraintlist cl)
{
  if (cl == NULL)
    return NULL;
  while (cl->prev != NULL)
    cl = cl->prev;
  return cl;
}


Constraintlist
constraintlistInsert (Constraintlist cl, Term term, Knowledge know)
{
  Constraintlist clnew = memAlloc (sizeof (struct constraintlist));

  clnew->constraint = makeConstraint (term, know);
  if (cl != NULL)
    {
      if (cl->next != NULL)
	{
	  clnew->next = cl->next;
	  cl->next->prev = cl;
	}
      else
	{
	  clnew->next = NULL;
	}
      clnew->prev = cl;
      cl->next = clnew;
      return constraintlistRewind (cl);
    }
  else
    {
      clnew->next = NULL;
      clnew->prev = NULL;
      return clnew;
    }
}

/* unlink a single constraint */

Constraintlist
constraintlistUnlink (Constraintlist cl)
{
  Constraintlist clnext, clprev;

  if (cl == NULL)
    return NULL;
  clprev = cl->prev;
  clnext = cl->next;

  if (clnext != NULL)
    {
      clnext->prev = clprev;
      cl->next = NULL;
    }
  if (clprev != NULL)
    {
      clprev->next = clnext;
      cl->prev = NULL;
      return constraintlistRewind (clprev);
    }
  else
    {
      return clnext;
    }
}


/* remove a single constraint */

Constraintlist
constraintlistRemove (Constraintlist cl)
{
  Constraintlist clnew;

  clnew = constraintlistUnlink (cl);
  memFree (cl, sizeof (struct constraintlist));
  return clnew;
}

/* remove all constraints from this point onwards */

void
constraintlistDelete (Constraintlist cl)
{
  Constraintlist cldel;

  /* no empty cl */
  if (cl == NULL)
    return;

  /* cut off previous */
  if (cl->prev != NULL)
    {
      /* TODO maybe this should cause a warning? */
      printf ("WARNING: clDelete with non-empty prev\n");
      cl->prev->next = NULL;
    }
  while (cl != NULL)
    {
      cldel = cl;
      cl = cl->next;
      memFree (cldel, sizeof (struct constraintlist));
    }
  return;
}

void
constraintlistDestroy (Constraintlist cl)
{
  Constraintlist cldel;

  /* no empty cl */
  if (cl == NULL)
    return;

  /* cut off previous */
  if (cl->prev != NULL)
    {
      /* TODO maybe this should cause a warning? */
      printf ("WARNING: clDestroy with non-empty prev\n");
      cl->prev = NULL;
    }
  while (cl != NULL)
    {
      cldel = cl;
      cl = cl->next;
      constraintDestroy (cldel->constraint);
      memFree (cldel, sizeof (struct constraintlist));
    }
}


Constraintlist
constraintlistDuplicate (Constraintlist oldcl)
{
  Constraintlist newcl = NULL;

  while (oldcl != NULL)
    {
      newcl =
	constraintlistAdd (newcl, constraintDuplicate (oldcl->constraint));
      oldcl = oldcl->next;
    }
  return newcl;
}

Constraintlist
constraintlistShallow (Constraintlist oldcl)
{
  Constraintlist newcl = NULL;

  while (oldcl != NULL)
    {
      newcl = constraintlistAdd (newcl, oldcl->constraint);
      oldcl = oldcl->next;
    }
  return newcl;
}

/* ----------------------------------------------------------

   Print stuff

---------------------------------------------------------- */

void
constraintPrint (Constraint co)
{
  indent ();
  printf ("Constraint ");
  if (co == NULL)
    {
      printf ("[empty]\n");
      return;
    }
  termPrint (co->term);
  printf (" :\n");
  knowledgePrint (co->know);
}

void
constraintlistPrint (Constraintlist cl)
{
  if (cl == NULL)
    {
      indent ();
      printf ("[empty constraintlist]\n");
      return;
    }
  while (cl != NULL)
    {
      constraintPrint (cl->constraint);
      cl = cl->next;
    }
}


/* ----------------------------------------------------------

   Now some real logic for the constraints

---------------------------------------------------------- */

/* eliminate all standalone variables */

void
msElim (Constraint co)
{
  Termlist tl;

  /* simple variables can only exist in basic */
  if (co->know == NULL)
    {
#ifdef DEBUG
      debug (5, "Exiting because co->know is empty.");
#endif
    }
  else
    {
      tl = co->know->basic;
      while (tl != NULL)
	{
	  if (isTermVariable (tl->term))
	    {
	      tl = termlistDelTerm (tl);
	      co->know->basic = tl;
	    }
	  else
	    tl = tl->next;
	}
    }
}


/* find the first constraint such that m is not a variable */
/* also, apply standalone elimination to it */

Constraintlist
firstNonVariable (Constraintlist cl)
{
  while (cl != NULL && isTermVariable (cl->constraint->term))
    {
      cl = cl->next;
    }
  if (cl != NULL)
    {
      msElim (cl->constraint);
      cl->constraint->term = deVar (cl->constraint->term);
      return cl;
    }
  else
    {
      return NULL;
    }
}
