/*
 * varbuf.c
 *
 * Operations on a variable substitutions buffer.
 * The type is actually defined in system.h
 */

#include "memory.h"
#include "system.h"

/*
 * create a new varbuffer from the current state of the system
 */

Varbuf
varbufInit (const System sys)
{
  Varbuf vb;
  Termlist tl;
  Term termfrom, termto;

  vb = (Varbuf) memAlloc (sizeof (struct varbuf));
  vb->from = NULL;
  vb->to = NULL;
  vb->empty = NULL;
  tl = sys->variables;
  while (tl != NULL)
    {
      if (realTermVariable (tl->term))
	{
	  /* this is actually a variable */
	  if (tl->term->subst == NULL)
	    {
	      /* non-instantiated */
	      vb->empty = termlistAdd (vb->empty, tl->term);
	    }
	  else
	    {
	      /* store instantiation */
	      termfrom = tl->term;
	      termto = termfrom->subst;
	      termfrom->subst = NULL;	// temp disable
	      vb->from = termlistAdd (vb->from, termfrom);
	      vb->to = termlistAdd (vb->to, termto);
	      termfrom->subst = termto;	// restore
	    }
	}
      tl = tl->next;
    }
  return vb;
}

/*
 * copy the variable state back into the system
 */

void
varbufSet (const System sys, Varbuf vb)
{
  Termlist tl1, tl2;

  tl1 = vb->from;
  tl2 = vb->to;
  while (tl1 != NULL && tl2 != NULL)
    {
      tl1->term->subst = tl2->term;
      tl1 = tl1->next;
      tl2 = tl2->next;
    }
  tl1 = vb->empty;
  while (tl1 != NULL)
    {
      tl1->term->subst = NULL;
      tl1 = tl1->next;
    }
}

/*
 * cleanup
 */

void
varbufDone (Varbuf vb)
{
  if (vb != NULL)
    {
      termlistDelete (vb->from);
      termlistDelete (vb->to);
      termlistDelete (vb->empty);
      memFree (vb, sizeof (struct varbuf));
    }
}
