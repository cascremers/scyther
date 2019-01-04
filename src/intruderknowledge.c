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

  if (switches.check)
    {
      globalError++;
      eprintf ("[ Adding ");
      termPrint (t2);
      eprintf (" to the initial intruder knowledge]\n");
      globalError--;
    }

  knowledgeAddTerm (sys->know, t2);
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
	  Termlist tl;

	  fromlist = termlistPrepend (fromlist, todo->term);
	  if (isTermEqual (todo->term, actor))
	    {
	      // Untrusted agents only
	      tl = sys->untrusted;
	    }
	  else
	    {
	      // any agents
	      tl = sys->agentnames;
	    }
	  while (tl != NULL)
	    {
	      tolist = termlistPrepend (tolist, tl->term);
	      addEnumTerm (sys, t, actor, todo->next, fromlist, tolist);
	      tolist = termlistDelTerm (tolist);
	      tl = tl->next;
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
  /*
     This was buggy and led to a segfault with Simon's example (bug report for wellformedness check);
     We didn't use it for years, but it did keep generating a trampoline for the dead code anyway. We 
     therefore completely removed it during the trampoline fall cleaning of 2018.
   */
  return;
}
