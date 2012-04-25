/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2012 Cas Cremers
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
 *
 *@file prune_theorems.c
 *
 * Prune stuff based on theorems.
 * Pruning leaves complete results.
 *
 */

#include "system.h"
#include "list.h"
#include "switches.h"
#include "binding.h"
#include "specialterm.h"
#include "hidelevel.h"
#include "depend.h"
#include "arachne.h"
#include "error.h"
#include "type.h"

extern Protocol INTRUDER;
extern int proofDepth;
extern int max_encryption_level;


//! Check locals occurrence
/*
 * Returns true if the order is correct
 */
int
correctLocalOrder (const System sys)
{
  int flag;

  int checkRun (int r1)
  {
    int checkTerm (Term t)
    {
      if (!isTermVariable (t))
	{
	  int r2;
	  int e1, e2;

	  // t is a term from r2 that occurs in r1
	  r2 = TermRunid (t);
	  e1 = firstOccurrence (sys, r1, t, ANYEVENT);
	  if (e1 >= 0)
	    {
	      if (roledef_shift (sys->runs[r1].start, e1)->type == RECV)
		{
		  e2 = firstOccurrence (sys, r2, t, SEND);
		  if (e2 >= 0)
		    {
		      // thus, it should not be the case that e1 occurs before e2
		      if (isDependEvent (r1, e1, r2, e2))
			{
			  // That's not good!
			  if (switches.output == PROOF)
			    {
			      indentPrint ();
			      eprintf ("Pruned because ordering for term ");
			      termSubstPrint (t);
			      eprintf
				(" cannot be correct: the first send r%ii%i occurs after the receive r%ii%i.\n",
				 r2, e2, r1, e1);
			    }
			  flag = false;
			  return false;
			}
		    }
		}
	    }
	  else
	    {
	      globalError++;
	      eprintf ("error: term ");
	      termSubstPrint (t);
	      eprintf
		(" from run %i should occur in run %i, but it doesn't.\n", r2,
		 r1);
	      globalError--;
	      error ("Abort");
	    }
	}
      return true;
    }

    return iterateLocalToOther (sys, r1, checkTerm);
  }

  flag = true;
  iterateRegularRuns (sys, checkRun);

  return flag;
}

//! Check all runs
/**
 * Returns false iff an agent type is wrong
 */
int
allAgentsType (const System sys)
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      Termlist agents;

      agents = sys->runs[run].rho;
      while (agents != NULL)
	{
	  if (!goodAgentType (agents->term))
	    {
	      return false;
	    }
	  agents = agents->next;
	}
    }
  return true;			// seems to be okay
}

//! Check initiator roles
/**
 * Returns false iff an agent type is wrong
 */
int
initiatorAgentsType (const System sys)
{
  int run;

  run = 0;
  while (run < sys->maxruns)
    {
      // Only for initiators
      if (sys->runs[run].role->initiator)
	{
	  Termlist agents;

	  agents = sys->runs[run].rho;
	  while (agents != NULL)
	    {
	      if (!goodAgentType (agents->term))
		{
		  return false;
		}
	      agents = agents->next;
	    }
	}
      run++;
    }
  return true;			// seems to be okay
}

//! Prune determination because of theorems
/**
 * When something is pruned because of this function, the state space is still
 * considered to be complete.
 *
 *@returns true iff this state is invalid because of a theorem
 */
int
prune_theorems (const System sys)
{
  List bl;
  int run;

  // Check all types of the local agents according to the matching type
  if (!checkAllSubstitutions (sys))
    {
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned because some local variable was incorrectly subsituted.\n");
	}
      return true;
    }

  // Prune if any initiator run talks to itself
  /**
   * This effectively disallows Alice from talking to Alice, for all
   * initiators. We still allow it for responder runs, because we assume the
   * responder is not checking this.
   */
  if (switches.initUnique)
    {
      if (selfInitiators (sys) > 0)
	{
	  // XXX TODO
	  // Still need to fix proof output for this
	  //
	  // Pruning because some agents are equal for this role.
	  return true;
	}
    }

  if (switches.respUnique)
    {
      if (selfResponders (sys) > 0)
	{
	  // XXX TODO
	  // Still need to fix proof output for this
	  //
	  // Pruning because some agents are equal for this role.
	  return true;
	}
    }

  if (switches.roleUnique)
    {
      if (!agentsUniqueRoles (sys))
	{
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned because agents are not performing unique roles.\n");
	    }
	  return true;
	}
    }

/*
The semantics imply that create event chose agent names, i.e., the range of rho is a subset of Agent.

For chosen name attacks we may want to loosen that. However, this requires inserting receive events for the non-actor role variables of responders, and we don't have that yet,
so technically this is a bug. Don't use.
*/
  if (switches.chosenName)
    {
      // Check if all actors are agents for responders (initiators come next)
      run = 0;
      while (run < sys->maxruns)
	{
	  if (!sys->runs[run].role->initiator)
	    {
	      Term actor;

	      actor = agentOfRun (sys, run);
	      if (!goodAgentType (actor))
		{
		  if (switches.output == PROOF)
		    {
		      indentPrint ();
		      eprintf ("Pruned because the actor ");
		      termPrint (actor);
		      eprintf (" of run %i is not of a compatible type.\n",
			       run);
		    }
		  return true;
		}
	    }
	  run++;
	}

      // Prune wrong agents type for initators
      if (!initiatorAgentsType (sys))
	{
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: an initiator role does not have the correct type for one of its agents.\n");
	    }
	  return true;
	}

    }
  else
    {
      // Prune wrong agents type for runs
      if (!allAgentsType (sys))
	{
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: some run does not have the correct type for one of its agents.\n");
	    }
	  return true;
	}
    }

  // Check if the actors of all other runs are not untrusted
  if (sys->untrusted != NULL)
    {
      int run;

      run = 1;
      while (run < sys->maxruns)
	{
	  if (sys->runs[run].protocol != INTRUDER)
	    {
	      if (sys->runs[run].rho != NULL)
		{
		  Term actor;

		  actor = agentOfRun (sys, run);
		  if (actor == NULL)
		    {
		      error ("Agent of run %i is NULL", run);
		    }
		  if (!isAgentTrusted (sys, actor))
		    {
		      if (switches.output == PROOF)
			{
			  indentPrint ();
			  eprintf
			    ("Pruned because the actor of run %i is untrusted.\n",
			     run);
			}
		      return true;
		    }
		}
	      else
		{
		  Protocol p;

		  globalError++;
		  eprintf ("error: Run %i: ", run);
		  role_name_print (run);
		  eprintf (" has an empty agents list.\n");
		  eprintf ("protocol->rolenames: ");
		  p = (Protocol) sys->runs[run].protocol;
		  termlistPrint (p->rolenames);
		  eprintf ("\n");
		  error ("Aborting.");
		  globalError--;
		  return true;
		}
	    }
	  run++;
	}
    }

  // Check for c-minimality
  {
    if (!bindings_c_minimal ())
      {
	if (switches.output == PROOF)
	  {
	    indentPrint ();
	    eprintf ("Pruned because this is not <=c-minimal.\n");
	  }
	return true;
      }
  }

  /*
   * Check for correct orderings involving local constants
   *
   * TODO: Clarify how this works with agent name variables in a non strict-typed setting.
   */
  if (!(switches.experimental & 8))
    {
      if (!correctLocalOrder (sys))
	{
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned because this does not have the correct local order.\n");
	    }
	  return true;
	}
    }

  /**
   * Check whether the bindings are valid
   */
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = bl->data;

      // Check for "Hidden" interm goals
      //! @todo in the future, this can be subsumed by adding TERM_Hidden to the hidelevel constructs
      if (termInTerm (b->term, TERM_Hidden))
	{
	  // Prune the state: we can never meet this
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned because intruder can never construnct ");
	      termPrint (b->term);
	      eprintf ("\n");
	    }
	  return true;
	}

      if (switches.experimental & 4)
	{
	  // Check for SK-type function occurrences
	  //!@todo Needs a LEMMA, although this seems to be quite straightforward to prove.
	  // The idea is that functions are never sent as a whole, but only used in applications.
	  //! @todo Subsumed by hidelevel lemma later
	  if (isTermFunctionName (b->term))
	    {
	      if (!inKnowledge (sys->know, b->term))
		{
		  // Not in initial knowledge of the intruder
		  if (switches.output == PROOF)
		    {
		      indentPrint ();
		      eprintf ("Pruned because the function ");
		      termPrint (b->term);
		      eprintf (" is not known initially to the intruder.\n");
		    }
		  return true;
		}
	    }
	}

      // Check for encryption levels
      /*
       * if (switches.match < 2
       *! @todo Doesn't work yet as desired for Tickets. Prove lemma first.
       */
      if (switches.experimental & 2)
	{
	  if (!hasTicketSubterm (b->term))
	    {
	      if (term_encryption_level (b->term) > max_encryption_level)
		{
		  // Prune: we do not need to construct such terms
		  if (switches.output == PROOF)
		    {
		      indentPrint ();
		      eprintf ("Pruned because the encryption level of ");
		      termPrint (b->term);
		      eprintf (" is too high.\n");
		    }
		  return true;
		}
	    }
	}

      // To be on the safe side, we currently limit the encryption level. 
      /**
       * This is valid *only* if there are no ticket-type variables.
       */
      if (term_encryption_level (b->term) > max_encryption_level)
	{
	  // Prune: we do not need to construct such terms
	  if (sys->hasUntypedVariable)
	    {
	      sys->current_claim->complete = false;
	    }
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned because the encryption level of ");
	      termPrint (b->term);
	      eprintf (" is too high.\n");
	    }
	  return true;
	}

      /**
       * Prune on the basis of hidelevel lemma
       */
      if (hidelevelImpossible (sys, b->term))
	{
	  // Prune: we do not need to construct such terms
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned because the hidelevel of ");
	      termPrint (b->term);
	      eprintf (" is impossible to satisfy.\n");
	    }
	  return true;
	}

      bl = bl->next;
    }

  /* check for singular roles */
  run = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].role->singular)
	{
	  // This is a singular role: it therefore should not occur later on again.
	  int run2;
	  Term rolename;

	  rolename = sys->runs[run].role->nameterm;
	  run2 = run + 1;
	  while (run2 < sys->maxruns)
	    {
	      Term rolename2;

	      rolename2 = sys->runs[run2].role->nameterm;
	      if (isTermEqual (rolename, rolename2))
		{
		  // This is not allowed: the singular role occurs twice in the semitrace.
		  // Thus we prune.
		  if (switches.output == PROOF)
		    {
		      indentPrint ();
		      eprintf ("Pruned because the singular role ");
		      termPrint (rolename);
		      eprintf (" occurs more than once in the semitrace.\n");
		    }
		  return true;
		}
	      run2++;
	    }
	}
      run++;
    }

  return false;
}
