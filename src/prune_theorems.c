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

extern Protocol INTRUDER;
extern int proofDepth;
extern int max_encryption_level;

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
  Termlist tl;
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
      return 1;
    }

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
		  eprintf (" of run %i is not of a compatible type.\n", run);
		}
	      return 1;
	    }
	}
      run++;
    }

  // Prune if any initiator run talks to itself
  /**
   * This effectively disallows Alice from talking to Alice, for all
   * initiators. We still allow it for responder runs, because we assume the
   * responder is not checking this.
   */
  if (switches.extravert)
    {
      int run;

      run = 0;
      while (run < sys->maxruns)
	{
	  // Check this run only if it is an initiator role
	  if (sys->runs[run].role->initiator)
	    {
	      // Check this initiator run
	      Termlist tl;

	      tl = sys->runs[run].agents;
	      while (tl != NULL)
		{
		  Termlist tlscan;

		  tlscan = tl->next;
		  while (tlscan != NULL)
		    {
		      if (isTermEqual (tl->term, tlscan->term))
			{
			  // XXX TODO
			  // Still need to fix proof output for this
			  //
			  // Pruning because some agents are equal for this role.
			  return 1;
			}
		      tlscan = tlscan->next;
		    }
		  tl = tl->next;
		}
	      run++;
	    }
	}
    }

  // Prune wrong agents type for initators
  if (!initiatorAgentsType ())
    {
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned: an initiator role does not have the correct type for one of its agents.\n");
	}
      return 1;
    }

  // Check if all agents of the main run are valid
  if (!isRunTrusted (sys, 0))
    {
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned because all agents of the claim run must be trusted.\n");
	}
      return 1;
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
	      if (sys->runs[run].agents != NULL)
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
		      return 1;
		    }
		}
	      else
		{
		  Protocol p;

		  globalError++;
		  eprintf ("Run %i: ", run);
		  role_name_print (run);
		  eprintf (" has an empty agents list.\n");
		  eprintf ("protocol->rolenames: ");
		  p = (Protocol) sys->runs[run].protocol;
		  termlistPrint (p->rolenames);
		  eprintf ("\n");
		  error ("Aborting.");
		  globalError--;
		  return 1;
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
	return 1;
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
	  return 1;
	}

      // Check for encryption levels
      /*
       * if (switches.match < 2
       */
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
	  return 1;
	}

      // Check for SK-type function occurrences
      //!@todo Needs a LEMMA, although this seems to be quite straightforward to prove.
      // The idea is that functions are never sent as a whole, but only used in applications.
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
	      return 1;
	    }
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
		  return 1;
		}
	      run2++;
	    }
	}
      run++;
    }

  return 0;
}
