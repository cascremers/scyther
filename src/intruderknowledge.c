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

  /*
     eprintf ("[ Adding ");
     termPrint (t2);
     eprintf (" to the initial intruder knowledge]\n");
   */
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
  if (switches.check)
    {
      eprintf ("Computing initial intruder knowledge.\n\n");
      eprintf ("Agent names      : ");
      termlistPrint (sys->agentnames);
      eprintf ("\n");
      eprintf ("Untrusted agents : ");
      termlistPrint (sys->untrusted);
      eprintf ("\n");
    }

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
	    Term f;
	    // Has rolename subterms. We have to enumerate those.
	    /**
	     * Hack. Enumerating is not always good (or even desirable).
	     * If some I knows sk(I), sk should not be in the intruder knowledge.
	     * But for hash(I), we typically would have h; but if it is never used differently, it would suffice.
	     * To sommarize, the operational semantics definition is perfectly fine, but maybe a bit strict sometimes.
	     *
	     * The hack is that if function application:
	    */
	    f = getTermFunction (t);
	    if (f != NULL)
	      {
		// it's a function, right. So we see whether it is public. It is if it does not contain the actor...
		if (!termSubTerm (t, actor))
		  {
		    // no actor, then nothing secret I guess.
		    addSTerm (sys, f, NULL, NULL);
		    return;
		  }
		else
		  {
		    // has actor. but does it contain even more?

		    int allagents (Term t)
		    {
		      if (!inTermlist (sys->agentnames, t))
			{
			  if (!inTermlist (p->rolenames, t))
			    {
			      return false;
			    }
			}
		      return true;
		    }

		    if (!term_iterate_leaves (TermOp (t), allagents))
		      {
			// something else as well, so that probably means a hash or something like that.
			addSTerm (sys, f, NULL, NULL);
			return;
		      }
		  }
	      }
	    // otherwise, we enumerate
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

    if (switches.check)
      {
	eprintf ("Role ");
	termPrint (r->nameterm);
	eprintf (" knows ");
	termlistPrint (r->knows);
	eprintf ("\n");
      }

    addListKnowledge (r->knows, r->nameterm);
    return true;
  }

  iterateRoles (sys, deriveFromRole);
}
