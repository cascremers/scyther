/**
 * Initial intruder knowledge computation.
 */

#include "intruderknowledge.h"

//! Add a (copy of) a term to the intruder knowledge
void
addSTerm (const System sys, Term t, Termlist fromlist, Termlist tolist)
{
  Term t2;

  t2 = termLocal (t, fromlist, tolist);
  eprintf ("[ Adding ");
  termPrint (t2);
  eprintf (" to the initial intruder knowledge]\n");
}

//! Unfold the term for all possible options
void
addEnumTerm (const System sys, Term t, Term actor, Termlist todo,
	     Termlist fromlist, Termlist tolist)
{
  if (todo == NULL)
    {
      addSTerm (sys, t, fromlist, tolist);
    }
  else
    {
      if (termSubTerm (t, todo->term))
	{
	  // Occurs, we have to iterate
	  fromlist = termlistPrepend (fromlist, todo->term);

	  void iterateThis (Term to)
	  {
	    tolist = termlistPrepend (tolist, to);

	    addEnumTerm (sys, t, actor, todo->next, fromlist, tolist);

	    tolist = termlistDelTerm (tolist);
	  }

	  if (isTermEqual (todo->term, actor))
	    {
	      // Untrusted agents only
	      Termlist tl;

	      for (tl = sys->untrusted; tl != NULL; tl = tl->next)
		{
		  iterateThis (tl->term);
		}
	    }
	  else
	    {
	      // any agents
	      Termlist tl;

	      for (tl = sys->agentnames; tl != NULL; tl = tl->next)
		{
		  iterateThis (tl->term);
		}
	    }
	  fromlist = termlistDelTerm (fromlist);
	}
      else
	{
	  // Simply proceed to next
	  addEnumTerm (sys, t, actor, todo->next, fromlist, tolist);
	}
    }
}

//! Does t contain any of sublist?
int
anySubTerm (Term t, Termlist sublist)
{
  while (sublist != NULL)
    {
      if (termSubTerm (t, sublist->term))
	{
	  return true;
	}
      sublist = sublist->next;
    }
  return false;
}

void
initialIntruderKnowledge (const System sys)
{
  eprintf ("Computing initial intruder knowledge.\n\n");
  eprintf ("Agent names      : ");
  termlistPrint (sys->agentnames);
  eprintf ("\n");
  eprintf ("Untrusted agents : ");
  termlistPrint (sys->untrusted);
  eprintf ("\n");

  /*
   * display initial role knowledge
   */
  int deriveFromRole (Protocol p, Role r)
  {
    void addListKnowledge (Termlist tl, Term actor)
    {
      void addTermKnowledge (Term t)
      {
	if (anySubTerm (t, p->rolenames))
	  {
	    // Has rolename subterms. We have to enumerate those.
	    addEnumTerm (sys, t, actor, p->rolenames, NULL, NULL);
	  }
	else
	  {
	    // No actor subterm. Simply add.
	    addSTerm (sys, t, NULL, NULL);
	  }
      }

      while (tl != NULL)
	{
	  addTermKnowledge (tl->term);
	  tl = tl->next;
	}
    }


    eprintf ("Role ");
    termPrint (r->nameterm);
    eprintf (" knows ");
    termlistPrint (r->knows);
    eprintf ("\n");

    addListKnowledge (r->knows, r->nameterm);
    return true;
  }

  iterateRoles (sys, deriveFromRole);
}
