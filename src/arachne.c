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
 *
 *@file arachne.c
 *
 * Introduces a method for proofs akin to the Athena modelchecker
 * http://www.ece.cmu.edu/~dawnsong/athena/
 *
 */

#include <stdlib.h>
#include <limits.h>
#include <float.h>
#include <string.h>
#include <assert.h>

#include "mymalloc.h"
#include "term.h"
#include "termlist.h"
#include "role.h"
#include "system.h"
#include "knowledge.h"
#include "compiler.h"
#include "states.h"
#include "mgu.h"
#include "arachne.h"
#include "error.h"
#include "claim.h"
#include "debug.h"
#include "binding.h"
#include "warshall.h"
#include "timer.h"
#include "type.h"
#include "switches.h"
#include "specialterm.h"
#include "cost.h"
#include "dotout.h"
#include "prune_bounds.h"
#include "prune_theorems.h"
#include "arachne.h"
#include "hidelevel.h"
#include "depend.h"
#include "xmlout.h"
#include "heuristic.h"
#include "tempfile.h"

extern int *graph;
extern int nodes;
extern int graph_uordblks;

static System sys;		//!< local buffer for the system pointer

int attack_length;		//!< length of the attack
int attack_leastcost;		//!< cost of the best attack sofar \sa cost.c

Protocol INTRUDER;		//!< intruder protocol
Role I_M;			//!< Initial knowledge role of the intruder
Role I_RRS;			//!< Encrypt role of the intruder
Role I_RRSD;			//!< Decrypt role of the intruder

int proofDepth;			//!< Current depth of the proof
int max_encryption_level;	//!< Maximum encryption level of any term

static int indentDepth;
static int prevIndentDepth;
static int indentDepthChanges;
static FILE *attack_stream;

/*
 * Forward declarations
 */

int iterate ();

/*
 * Program code
 */

//! Two simple helpers for arachneInit
Roledef
add_event (Roledef rd, int event, Term message)
{
  return roledefAdd (rd, event, NULL, NULL, NULL, message, NULL);
}

Role
add_role (Roledef rd, const char *rolenamestring)
{
  Role r;
  Term rolename;

  rolename = makeGlobalConstant (rolenamestring);
  r = roleCreate (rolename);
  r->roledef = rd;
  r->next = INTRUDER->roles;
  INTRUDER->roles = r;
  // compute_role_variables (sys, INTRUDER, r);
  return r;
}

//! Init Arachne engine
void
arachneInit (const System mysys)
{
  Roledef rd;

  sys = mysys;			// make sys available for this module as a global

  /**
   * Very important: turn role terms that are local to a run, into variables.
   */
  term_rolelocals_are_variables ();

  /*
   * Add intruder protocol roles
   */

  INTRUDER = protocolCreate (makeGlobalConstant (" INTRUDER "));

  rd = NULL;
  rd = add_event (rd, SEND, NULL);
  I_M = add_role (rd, "I_M: Atomic message");

  rd = NULL;
  rd = add_event (rd, RECV, NULL);
  rd = add_event (rd, RECV, NULL);
  rd = add_event (rd, SEND, NULL);
  I_RRS = add_role (rd, "I_E: Encrypt");

  rd = NULL;
  rd = add_event (rd, RECV, NULL);
  rd = add_event (rd, RECV, NULL);
  rd = add_event (rd, SEND, NULL);
  I_RRSD = add_role (rd, "I_D: Decrypt");

  sys->num_regular_runs = 0;
  sys->num_intruder_runs = 0;
  max_encryption_level = 0;

  indentDepth = 0;
  prevIndentDepth = 0;
  indentDepthChanges = 0;

  return;
}

//! Close Arachne engine
void
arachneDone ()
{
  return;
}

//------------------------------------------------------------------------
// Detail
//------------------------------------------------------------------------

//! Just a defined integer for invalid
#define INVALID		-1
//! can this roledef constitute a recv Goal?
#define isGoal(rd)	(rd->type == RECV && !rd->internal)
//! is this roledef already bound?
#define isBound(rd)	(rd->bound)

//! print current counter
void
counterPrint (const int annotate)
{
  statesFormat (sys->current_claim->states);
  eprintf ("\t");
  eprintf ("%i", annotate);
  eprintf ("\t");
}

//! Indent prefix print
void
indentPrefixPrint (const int annotate, const int jumps)
{
  if (switches.output == ATTACK && globalError == 0)
    {
      // Arachne, attack, not an error
      // We assume that means DOT output
      eprintf ("// ");
      counterPrint (annotate);
    }
  else
    {
      // If it is not to stdout, or it is not an attack...
      int i;

      counterPrint (annotate);
      for (i = 0; i < jumps; i++)
	{
	  if (i % 3 == 0)
	    eprintf ("|");
	  else
	    eprintf (" ");
	  eprintf (" ");
	}
    }
}

//! Indent print
/**
 * More subtle than before. Indentlevel changes now cause a counter to be increased, which is printed. Nice to find stuff in attacks.
 */
void
indentPrint ()
{
  if (indentDepth != prevIndentDepth)
    {
      indentDepthChanges++;
      while (indentDepth != prevIndentDepth)
	{
	  if (prevIndentDepth < indentDepth)
	    {
	      indentPrefixPrint (indentDepthChanges, prevIndentDepth);
	      eprintf ("{\n");
	      prevIndentDepth++;
	    }
	  else
	    {
	      prevIndentDepth--;
	      indentPrefixPrint (indentDepthChanges, prevIndentDepth);
	      eprintf ("}\n");
	    }
	}
    }
  indentPrefixPrint (indentDepthChanges, indentDepth);
}

//! Print indented binding
void
binding_indent_print (const Binding b, const int flag)
{
  indentPrint ();
  if (flag)
    eprintf ("!! ");
  binding_print (b);
  eprintf ("\n");
}

//! Keylevel tester: can this term ever be sent at this keylevel?
int
isKeylevelRight (Term t, const int kl)
{
  t = deVar (t);
  if (realTermLeaf (t))
    {
      // Leaf
      if (isTermVariable (t))
	{
	  // Variables are okay
	  return 1;
	}
      else
	{
	  // Constant, does it have a keylevel?
	  int mykl;

	  mykl = TermSymb (t)->keylevel;
	  if (mykl < INT_MAX)
	    {
	      // Sensible keylevel, so it must be possible
	      return (mykl <= kl);
	    }
	  else
	    {
	      // Never sent?
	      // So we can not expect it to come from that
	      return 0;
	    }
	}
    }
  else
    {
      // Node
      if (realTermTuple (t))
	{
	  // Tuple
	  return isKeylevelRight (TermOp1 (t), kl)
	    && isKeylevelRight (TermOp2 (t), kl);
	}
      else
	{
	  // Crypt
	  return isKeylevelRight (TermOp1 (t), kl)
	    && isKeylevelRight (TermOp2 (t), kl + 1);
	}
    }
}

//! Keylevel tester: can this term ever be sent at this keylevel?
/**
 * Depends on the keylevel lemma (so this will not be called when those lemmas
 * are disabled) and the keylevel constructors in symbol.c The idea is that
 * certain terms will never be sent.
 */
int
isPossiblySent (Term t)
{
  return isKeylevelRight (t, 0);
}

//! Wrapper for roleInstance
/**
 *@return Returns the run number
 */
int
semiRunCreate (const Protocol p, const Role r)
{
  int run;

  if (p == INTRUDER)
    sys->num_intruder_runs++;
  else
    sys->num_regular_runs++;
#ifdef DEBUG
  if (DEBUGL (5))
    {
      globalError++;
      eprintf ("Adding a run %i with semiRunCreate, ", sys->maxruns);
      termPrint (p->nameterm);
      eprintf (", ");
      termPrint (r->nameterm);
      eprintf ("\n");
      globalError--;
    }
#endif
  roleInstance (sys, p, r, NULL, NULL);
  run = sys->maxruns - 1;
  sys->runs[run].height = 0;
  return run;
}

//! Wrapper for roleDestroy
void
semiRunDestroy ()
{
  if (sys->maxruns > 0)
    {
      Protocol p;

      p = sys->runs[sys->maxruns - 1].protocol;
      roleInstanceDestroy (sys);
      if (p == INTRUDER)
	sys->num_intruder_runs--;
      else
	sys->num_regular_runs--;
    }
}

//! Fix the keylevels of any agents
/**
 * We simply extract the agent names from m0 (ugly hack)
 */
void
fixAgentKeylevels (void)
{
  Termlist tl, m0tl;

  m0tl = knowledgeSet (sys->know);
  tl = m0tl;
  while (tl != NULL)
    {
      Term t;

      t = deVar (tl->term);
      if (realTermLeaf (t))
	{
	  {
	    // a real agent type thing
	    if (TermSymb (t)->keylevel == INT_MAX)
	      {
		// Fix the keylevel
		TermSymb (t)->keylevel = 0;
	      }
	  }
	}
      tl = tl->next;
    }
  termlistDelete (m0tl);
}


//! After a role instance, or an extension of a run, we might need to add some goals
/**
 * From old to new. Sets the new height to new.
 *@returns The number of goals added (for destructions)
 */
int
add_recv_goals (const int run, const int old, const int new)
{
  if (new <= sys->runs[run].height)
    {
      return 0;
    }
  else
    {
      int count;
      int i;
      Roledef rd;

      sys->runs[run].height = new;
      i = old;
      rd = eventRoledef (sys, run, i);
      count = 0;
      while (i < new && rd != NULL)
	{
	  if (rd->type == RECV)
	    {
	      if (switches.output == PROOF)
		{
		  if (count == 0)
		    {
		      indentPrint ();
		      eprintf ("Thus, we must also produce ");
		    }
		  else
		    {
		      eprintf (", ");
		    }
		  termPrint (rd->message);
		}
	      count = count + goal_add (rd->message, run, i, 0);
	    }
	  rd = rd->next;
	  i++;
	}
      if ((count > 0) && switches.output == PROOF)
	{
	  eprintf ("\n");
	}
      return count;
    }
}

//! Determine trace length
int
get_semitrace_length ()
{
  int run;
  int length;

  run = 0;
  length = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].protocol != INTRUDER)
	{
	  // Non-intruder run: count length
	  // Subtract 'firstReal' to ignore chooses.
	  length = length + sys->runs[run].height - sys->runs[run].firstReal;
	}
      run++;
    }
  return length;
}

//! Count intruder events
int
countIntruderActions ()
{
  int count;
  int run;

  count = 0;
  run = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].protocol == INTRUDER)
	{
	  // Only intruder roles
	  if (sys->runs[run].role != I_M)
	    {
	      // The M_0 (initial knowledge) events don't count.
	      count++;
	    }
	}
      run++;
    }
  return count;
}

//------------------------------------------------------------------------
// Proof reporting
//------------------------------------------------------------------------

//! Protocol/role name of a run
void
role_name_print (const int run)
{
  eprintf ("protocol ");
  termPrint (sys->runs[run].protocol->nameterm);
  eprintf (", role ");
  termPrint (sys->runs[run].role->nameterm);
}

//! Adding a run/extending a run
void
proof_suppose_run (const int run, const int oldlength, const int newlength)
{
  if (switches.output == PROOF)
    {
      int reallength;

      indentPrint ();
      eprintf ("Suppose ");
      if (oldlength == 0)
	eprintf ("there is a ");
      else
	eprintf ("we extend ");
      reallength = roledef_length (sys->runs[run].start);
      if (reallength > newlength)
	eprintf ("semi-");
      eprintf ("run #%i of ", run);
      role_name_print (run);
      if (reallength > newlength)
	{
	  if (oldlength == 0)
	    eprintf (" of");
	  else
	    eprintf (" to");
	  eprintf (" length %i", newlength);
	}
      eprintf ("\n");
    }
}

//! Select a goal
void
proof_select_goal (Binding b)
{
  if (switches.output == PROOF)
    {
      Roledef rd;

      rd = roledef_shift (sys->runs[b->run_to].start, b->ev_to);
      indentPrint ();
      eprintf ("Selected goal: Where does term ");
      termPrint (b->term);
      eprintf (" occur first as an interm?\n");
      indentPrint ();
      eprintf ("* It is required for ");
      roledefPrint (rd);
      eprintf (" at index %i in run %i\n", b->ev_to, b->run_to);
    }
}

//! Cannot bind because of cycle
void
proof_cannot_bind (const Binding b, const int run, const int index)
{
  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf
	("Cannot bind this to run %i, index %i because that introduces a cycle.\n",
	 run, index);
    }
}

//! Test a binding
void
proof_suppose_binding (Binding b)
{
  if (switches.output == PROOF)
    {
      Roledef rd;

      indentPrint ();
      rd = roledef_shift (sys->runs[b->run_from].start, b->ev_from);
      eprintf ("Suppose it originates in run %i, at index %i\n", b->run_from,
	       b->ev_from);
      indentPrint ();
      eprintf ("* I.e. event ");
      roledefPrint (rd);
      eprintf ("\n");
      indentPrint ();
      eprintf ("* from ");
      role_name_print (b->run_from);
      eprintf ("\n");
    }
}

//------------------------------------------------------------------------
// Sub
//------------------------------------------------------------------------

//! Iterate over all events in the roles (including the intruder ones)
/**
 * Function is called with (protocol pointer, role pointer, roledef pointer, index)
 * and returns an integer. If it is false, iteration aborts.
 */
int
iterate_role_events (int (*func) ())
{
  Protocol p;

  p = sys->protocols;
  while (p != NULL)
    {
      Role r;

      r = p->roles;
      while (r != NULL)
	{
	  Roledef rd;
	  int index;

	  rd = r->roledef;
	  index = 0;
	  while (rd != NULL)
	    {
	      if (!func (p, r, rd, index))
		return 0;
	      index++;
	      rd = rd->next;
	    }
	  r = r->next;
	}
      p = p->next;
    }
  return 1;
}

//! Iterate over all send types in the roles (including the intruder ones)
/**
 * Input:
 *   func:
 *   state: void pointer to whatever that is passed on to func as well.
 *
 * Function is called with (protocol pointer, role pointer, roledef pointer, index, state)
 * and returns an integer. If it is false, iteration aborts.
 */
int
iterate_state_role_sends (int (*func) (), void *state)
{
  Protocol p;

  p = sys->protocols;
  while (p != NULL)
    {
      Role r;

      r = p->roles;
      while (r != NULL)
	{
	  Roledef rd;
	  int index;

	  rd = r->roledef;
	  index = 0;
	  while (rd != NULL)
	    {
	      if (rd->type == SEND)
		{
		  if (!func (p, r, rd, index, state))
		    return false;
		}
	      index++;
	      rd = rd->next;
	    }
	  r = r->next;
	}
      p = p->next;
    }
  return true;
}

//! Iterate over all send types in the roles (including the intruder ones)
/**
 * Function is called with (protocol pointer, role pointer, roledef pointer, index)
 * and returns an integer. If it is false, iteration aborts.
 */
int
iterate_role_sends (int (*func) ())
{
  Protocol p;

  p = sys->protocols;
  while (p != NULL)
    {
      Role r;

      r = p->roles;
      while (r != NULL)
	{
	  Roledef rd;
	  int index;

	  rd = r->roledef;
	  index = 0;
	  while (rd != NULL)
	    {
	      if (rd->type == SEND)
		{
		  if (!func (p, r, rd, index))
		    return 0;
		}
	      index++;
	      rd = rd->next;
	    }
	  r = r->next;
	}
      p = p->next;
    }
  return 1;
}


//! Create decryption role instance
/**
 * Note that this does not add any bindings for the receives.
 *
 *@param term	The term to be decrypted (implies decryption key)
 *@param key	The key that is needed to decrypt the term
 *
 *@returns The run id of the decryptor instance
 */
int
create_decryptor (const Term term, const Term key)
{
  if (term != NULL && isTermEncrypt (term))
    {
      Roledef rd;
      int run;

#ifdef DEBUG
      if (DEBUGL (5))
	{
	  globalError++;
	  eprintf ("Creating decryptor for term ");
	  termPrint (term);
	  eprintf (" and key ");
	  termPrint (key);
	  eprintf ("\n");
	  globalError--;
	}
#endif

      run = semiRunCreate (INTRUDER, I_RRSD);
      rd = sys->runs[run].start;
      rd->message = termDuplicateUV (term);
      rd->next->message = termDuplicateUV (key);
      rd->next->next->message = termDuplicateUV (TermOp (term));
      sys->runs[run].height = 3;
      proof_suppose_run (run, 0, 3);

      return run;
    }

  globalError++;
  eprintf ("Term for which a decryptor instance is requested: ");
  termPrint (term);
  eprintf ("\n");
  error ("Trying to build a decryptor instance for a non-encrypted term.");
  return -1;
}

//! Get the priority level of a key that is needed for a term (typical pk/sk distinction)
int
getPriorityOfNeededKey (const System sys, const Term keyneeded)
{
  int prioritylevel;

  /* Normally, a key gets higher priority, but unfortunately this is not propagated at the moment. Maybe later.
   */
  prioritylevel = 1;
  if (realTermEncrypt (keyneeded))
    {
      /* the key is a construction itself */
      if (inKnowledge (sys->know, TermKey (keyneeded)))
	{
	  /* the key is constructed by a public thing */
	  /* typically, this is a public key, so we postpone it  */
	  prioritylevel = -1;
	}
    }
  return prioritylevel;
}

//! Report failed binding
void
report_failed_binding (Binding b, int run, int index)
{
  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Failed to bind the binding at r%ii%i with term ", b->run_to,
	       b->ev_to);
      termPrint (b->term);
      eprintf (" to the source r%ii%i because of orderings.\n", run, index);
#ifdef DEBUG
      if (DEBUGL (5))
	{
	  dependPrint ();
	}
#endif
    }
}

//! Make a decryption chain from a binding to some run,index using the key list, and callback if this works.
/**
 * The key goals are bound to the goal, and then we iterate on that.
 *
 *@param b	binding to fix (bind), destination filled in
 *@param run	run of binding start
 *@param index	index in run of binding start
 * Callback return value is int, but is effectively ignored.
 */
void
createDecryptionChain (const Binding b, const int run, const int index,
		       Termlist keylist, int (*callback) (void))
{
  if (keylist == NULL)
    {
      // Immediate binding, no key needed.
      if (goal_bind (b, run, index))
	{
	  callback ();
	  goal_unbind (b);
	  return;
	}
      else
	{
	  report_failed_binding (b, run, index);
	}
    }
  else
    {
      Term tdecr, tkey;
      int smallrun;

      // Some decryptor is needed for the term in the list

      indentDepth++;

      tdecr = keylist->term;
      tkey = inverseKey (sys->know, TermKey (tdecr));
      smallrun = create_decryptor (tdecr, tkey);
      {
	Roledef rddecrypt;
	Binding bnew;
	int newgoals;
	int prioritylevel;

	/*
	 * 2. Add goal bindings
	 */

	rddecrypt = sys->runs[smallrun].start;
	// Add goal for tdecr copy
	newgoals = goal_add (rddecrypt->message, smallrun, 0, 0);
	if (newgoals != 1)
	  {
	    error
	      ("Added %i goals (instead of one) for decryptor goal 1, weird.",
	       newgoals);
	  }

	// This is the unique new goal 
	bnew = (Binding) sys->bindings->data;

	// Add goal for needed key copy
	prioritylevel = getPriorityOfNeededKey (sys, tkey);
	newgoals += goal_add (rddecrypt->next->message, smallrun, 1,
			      prioritylevel);

	if (switches.output == PROOF)
	  {
	    indentPrint ();
	    eprintf
	      ("This introduces the obligation to decrypt the following subterm: ");
	    termPrint (tdecr);
	    eprintf (" to be decrypted using ");
	    termPrint (tkey);
	    eprintf ("\n");

	    indentPrint ();
	    eprintf
	      ("To this end, we added two new goals and one new send: ");
	    termPrint (rddecrypt->message);
	    eprintf (",");
	    termPrint (rddecrypt->next->message);
	    eprintf (",");
	    termPrint (rddecrypt->next->next->message);
	    eprintf ("\n");
	  }

	/*
	 * 3. Bind open goal to decryptor? 
	 */
	if (goal_bind (b, smallrun, 2))
	  {
	    if (switches.output == PROOF)
	      {
		indentPrint ();
		eprintf ("Bound ");
		termPrint (b->term);
		eprintf (" to r%ii%i: trying new createDecryptionChain.\n",
			 smallrun, 2);
	      }

	    // Iterate with the new goal
	    createDecryptionChain (bnew, run, index, keylist->next, callback);
	    goal_unbind (b);
	  }
	else
	  {
	    report_failed_binding (b, smallrun, 2);
	  }
	/*
	 * clean up
	 */
	goal_remove_last (newgoals);
      }
      semiRunDestroy ();
      termDelete (tkey);

      indentDepth--;
    }
}

struct md_state
{
  int neworders;
  int allgood;
  Term tvar;
  Termlist sl;
};

//! makeDepend for next function
	    /** the idea is, that a substitution in run x with
	    * something containing should be wrapped; this
   * occurs for all subterms of other runs.
   */
int
makeDepend (Term tsmall, struct md_state *state)
{
  Term tsubst;

  tsubst = deVar (tsmall);
  if (!realTermVariable (tsubst))
    {
      // Only for non-variables (i.e. local constants)
      int r1, e1;

      r1 = TermRunid (tsubst);
      e1 = firstOccurrence (sys, r1, tsubst, SEND);
      if (e1 >= 0)
	{
	  int r2, e2;

	  r2 = TermRunid (state->tvar);
	  e2 = firstOccurrence (sys, r2, tsubst, RECV);
	  if (e2 >= 0)
	    {

	      if (dependPushEvent (r1, e1, r2, e2))
		{
		  state->neworders++;
		  return true;
		}
	      else
		{
		  state->allgood = false;
		  if (switches.output == PROOF)
		    {
		      indentPrint ();
		      eprintf ("Substitution for ");
		      termSubstPrint (state->sl->term);
		      eprintf (" (subterm ");
		      termPrint (tsmall);
		      eprintf (") could not be safely bound.\n");
		    }
		  return false;
		}
	    }
	}
    }
  return true;
}

struct betg_state
{
  Binding b;
  int run;
  int index;
  int newdecr;
};

void
wrapSubst (const Termlist sl, const struct betg_state *ptr_betgState,
	   const Termlist keylist)
{
  if (sl == NULL)
    {
      if (switches.output == PROOF)
	{
	  Roledef rd;

	  indentPrint ();
	  eprintf ("Suppose ");
	  termPrint ((ptr_betgState->b)->term);
	  eprintf (" originates first at run %i, event %i, as part of ",
		   ptr_betgState->run, ptr_betgState->index);
	  rd =
	    roledef_shift (sys->runs[ptr_betgState->run].start,
			   ptr_betgState->index);
	  termPrint (rd->message);
	  eprintf ("\n");
	}
      // new create key goals, bind etc.
      createDecryptionChain (ptr_betgState->b, ptr_betgState->run,
			     ptr_betgState->index, keylist, iterate);
    }
  else
    {
      struct md_state State;

      // TODO CONTEXT for makeDepend in State

      State.neworders = 0;
      State.sl = sl;
      State.tvar = sl->term;
      State.allgood = true;
      iterateTermOther (ptr_betgState->run, State.tvar, makeDepend, &State);
      if (State.allgood)
	{
	  // Recursive call
	  wrapSubst (sl->next, ptr_betgState, keylist);
	}
      while (State.neworders > 0)
	{
	  State.neworders--;
	  dependPopEvent ();
	}
    }
}

int
unifiesWithKeys (Termlist substlist, Termlist keylist,
		 struct betg_state *ptr_betgState)
{
  int old_length;
  int newgoals;

  assert (ptr_betgState != NULL);

  // TODO this is a hack: in this case we really should not use subterm
  // unification but interm instead. However, this effectively does the same
  // by avoiding branches that get immediately pruned anyway.
  if (!ptr_betgState->newdecr && keylist != NULL)
    {
      return true;
    }

  // We need some adapting because the height would increase; we therefore
  // have to add recv goals before we know whether it unifies.
  old_length = sys->runs[ptr_betgState->run].height;
  newgoals =
    add_recv_goals (ptr_betgState->run, old_length, ptr_betgState->index + 1);

  // wrap substitution lists
  wrapSubst (substlist, ptr_betgState, keylist);

  // undo
  goal_remove_last (newgoals);
  sys->runs[ptr_betgState->run].height = old_length;
  return true;
}

//! Try to bind a specific existing run to a goal.
/**
 * The idea is that we try to bind it this specific run and index. If this
 * requires keys, then we should add such goals as well with the required
 * decryptor things.
 *
 * The 'newdecr' boolean signals the addition of decryptors. If it is false, we should not add any.
 *
 * The key goals are bound to the goal. Iterates on success.
 */
void
bind_existing_to_goal (const Binding b, const int run, const int index,
		       int newdecr)
{
  Term bigterm;
  struct betg_state betgState;

  betgState.b = b;
  betgState.run = run;
  betgState.index = index;
  betgState.newdecr = newdecr;

  bigterm = roledef_shift (sys->runs[run].start, index)->message;
  subtermUnify (bigterm, b->term, NULL, NULL, unifiesWithKeys, &betgState);
}




//! Bind a goal to an existing regular run, if possible, by adding decr events
int
bind_existing_run (const Binding b, const Protocol p, const Role r,
		   const int index)
{
  int run, flag;
  int found;

  flag = 1;
  found = 0;
  for (run = 0; run < sys->maxruns; run++)
    {
      if (sys->runs[run].protocol == p && sys->runs[run].role == r)
	{
	  found++;
	  if (switches.output == PROOF)
	    {
	      if (found == 1)
		{
		  indentPrint ();
		  eprintf ("Can we bind it to an existing regular run of ");
		  termPrint (p->nameterm);
		  eprintf (", ");
		  termPrint (r->nameterm);
		  eprintf ("?\n");
		}
	      indentPrint ();
	      eprintf ("%i. Can we bind it to run %i?\n", found, run);
	    }
	  indentDepth++;
	  bind_existing_to_goal (b, run, index, true);
	  indentDepth--;
	}
    }
  if (switches.output == PROOF && found == 0)
    {
      indentPrint ();
      eprintf ("There is no existing run for ");
      termPrint (p->nameterm);
      eprintf (", ");
      termPrint (r->nameterm);
      eprintf ("\n");
    }
  return flag;
}

//! Bind a goal to a new run, possibly adding decr events
int
bind_new_run (const Binding b, const Protocol p, const Role r,
	      const int index)
{
  int run;

  run = semiRunCreate (p, r);
  proof_suppose_run (run, 0, index + 1);
  {
    int newgoals;

    newgoals = add_recv_goals (run, 0, index + 1);
    indentDepth++;
    bind_existing_to_goal (b, run, index, true);
    indentDepth--;
    goal_remove_last (newgoals);
  }
  semiRunDestroy ();
  return true;
}

//! Proof markers
void
proof_go_down (const Term label, const Term t)
{
  Termlist l;
  int depth;
  int len;

  if (switches.output != PROOF)
    return;
  // Prepend the terms (the list is in reverse)
  TERMLISTPREPEND (sys->proofstate, label);
  TERMLISTPREPEND (sys->proofstate, t);
  len = termlistLength (sys->proofstate) / 2;
  // Display state
  eprintf ("Proof state: branch at level %i\n", len);
  l = termlistForward (sys->proofstate);
  depth = 0;
  while (l != NULL)
    {
      int i;
      eprintf ("Proof state: ");

      for (i = 0; i < depth; i++)
	{
	  eprintf ("  ");
	}
      termPrint (l->prev->term);
      eprintf ("(");
      termPrint (l->term);
      eprintf ("); ");
      l = l->prev->prev;
      eprintf ("\n");
      depth++;
    }
}

void
proof_go_up (void)
{
  if (switches.output != PROOF)
    return;
  sys->proofstate = termlistDelTerm (sys->proofstate);
  sys->proofstate = termlistDelTerm (sys->proofstate);
  return;
}

//! Print the state of a binding (with indent)
int
binding_state_print (void *dt)
{
  binding_indent_print ((Binding) dt, 1);
  return 1;
}

//! Print the current semistate
void
printSemiState ()
{
  int run;
  int open;

  indentPrint ();
  eprintf ("!! --=[ Semistate ]=--\n");
  indentPrint ();
  eprintf ("!!\n");
  indentPrint ();
  eprintf ("!! Trace length: %i\n", get_semitrace_length ());
  open = 0;
  for (run = 0; run < sys->maxruns; run++)
    {
      int index;
      Role r;
      Roledef rd;
      Term oldagent;

      indentPrint ();
      eprintf ("!!\n");
      indentPrint ();
      eprintf ("!! [ Run %i, ", run);
      termPrint (sys->runs[run].protocol->nameterm);
      eprintf (", ");
      r = sys->runs[run].role;
      oldagent = r->nameterm->subst;
      r->nameterm->subst = NULL;
      termPrint (r->nameterm);
      r->nameterm->subst = oldagent;
      if (oldagent != NULL)
	{
	  eprintf (": ");
	  termPrint (oldagent);
	}
      eprintf (" ]\n");

      index = 0;
      rd = sys->runs[run].start;
      while (index < sys->runs[run].height)
	{
	  indentPrint ();
	  eprintf ("!! %i ", index);
	  roledefPrint (rd);
	  eprintf ("\n");
	  if (isGoal (rd) && !isBound (rd))
	    open++;
	  index++;
	  rd = rd->next;
	}
    }
  if (sys->bindings != NULL)
    {
      indentPrint ();
      eprintf ("!!\n");
      list_iterate (sys->bindings, binding_state_print);
    }
  indentPrint ();
  eprintf ("!!\n");
  indentPrint ();
  eprintf ("!! - open: %i -\n", open);
}

//! Check if a binding duplicates an old one: if so, simply connect
/**
 * If it returns true, it has bound the b_new binding, which we must unbind later.
 */
int
bind_old_goal (const Binding b_new)
{
  if (!b_new->done)
    {
      List bl;

      bl = sys->bindings;
      while (bl != NULL)
	{
	  Binding b_old;

	  b_old = (Binding) bl->data;
	  if (b_old->done && isTermEqual (b_new->term, b_old->term))
	    {
	      // Old is done and has the same term!
	      // So we try to copy this binding, and fix it.
	      if (goal_bind (b_new, b_old->run_from, b_old->ev_from))
		{
		  return true;
		}
	    }
	  bl = bl->next;
	}
    }
  // No old binding to connect to
  return false;
}

//! Bind an intruder goal by intruder composition construction
/**
 * Handles the case where the intruder constructs a composed term himself.
 */
int
bind_goal_new_encrypt (const Binding b)
{
  Term term;
  int flag;
  int can_be_encrypted;


  flag = 1;
  term = deVar (b->term);
  can_be_encrypted = 0;

  if (!realTermLeaf (term))
    {
      Term t1, t2;

      if (switches.intruder && (!realTermEncrypt (term)))
	{
	  // tuple construction
	  error ("Goal that is a tuple should not occur!");
	}

      // must be encryption
      t1 = TermOp (term);
      t2 = TermKey (term);

      if (t2 != TERM_Hidden)
	{
	  int run;

	  can_be_encrypted = 1;
	  run = semiRunCreate (INTRUDER, I_RRS);
	  {
	    int index;
	    Roledef rd;

	    rd = sys->runs[run].start;
	    rd->message = termDuplicateUV (t1);
	    rd->next->message = termDuplicateUV (t2);
	    rd->next->next->message = termDuplicateUV (term);
	    index = 2;
	    proof_suppose_run (run, 0, index + 1);
	    if (switches.output == PROOF)
	      {
		indentPrint ();
		eprintf ("* Encrypting ");
		termPrint (term);
		eprintf (" using term ");
		termPrint (t1);
		eprintf (" and key ");
		termPrint (t2);
		eprintf ("\n");
	      }

	    {
	      int newgoals;
	      newgoals = add_recv_goals (run, 0, index + 1);
	      {

		indentDepth++;
		if (goal_bind (b, run, index))
		  {
		    proof_suppose_binding (b);
		    flag = flag && iterate ();
		    goal_unbind (b);
		  }
		else
		  {
		    proof_cannot_bind (b, run, index);
		  }
		indentDepth--;
	      }
	      goal_remove_last (newgoals);
	    }
	  }
	  semiRunDestroy ();
	}
    }

  if (!can_be_encrypted)
    {
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Term ");
	  termPrint (b->term);
	  eprintf (" cannot be constructed by encryption.\n");
	}
    }

  return flag;
}

//! Bind an intruder goal by intruder construction
/**
 * Handles the case where the intruder constructs a composed term himself, or retrieves it from m0.
 * However, it must not already have been created in an intruder run; then it gets bound to that.
 */
int
bind_goal_new_intruder_run (const Binding b)
{
  int flag;

  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Can we bind ");
      termPrint (b->term);
      eprintf (" from a new intruder run?\n");
    }
  indentDepth++;
  //flag = flag && bind_goal_new_encrypt (b);
  flag = bind_goal_new_encrypt (b);
  indentDepth--;
  return flag;
}

//! Debug information?
void
debug_send_candidate (const Protocol p, const Role r, const Roledef rd,
		      const int index)
{
#ifdef DEBUG
  indentPrint ();
  eprintf ("Checking send candidate with message ");
  termPrint (rd->message);
  eprintf (" from ");
  termPrint (p->nameterm);
  eprintf (", ");
  termPrint (r->nameterm);
  eprintf (", index %i\n", index);
#endif
}

//! Dummy helper function for iterator; abort if sub-unification found
int
test_sub_unification (Termlist substlist, Termlist keylist, void *state)
{
  // A unification exists; return the signal
  return false;
}

//! Proof output for first match
void
proof_term_match_first (const int found, const Binding b)
{
  if (switches.output == PROOF && found == 1)
    {
      indentPrint ();
      eprintf ("The term ", found);
      termPrint (b->term);
      eprintf (" matches patterns from the role definitions. Investigate.\n");
    }
}

//! Proof output for any match
void
proof_term_match (const Protocol p, const Role r, const Roledef rd,
		  const int index, const int found)
{
  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("%i. It matches the pattern ", found);
      termPrint (rd->message);
      eprintf (" from ");
      termPrint (p->nameterm);
      eprintf (", ");
      termPrint (r->nameterm);
      eprintf (", at %i\n", index);
    }
}

//! Proof output for no match
void
proof_term_match_none (const Binding b, const int found)
{
  if (switches.output == PROOF && found == 0)
    {
      indentPrint ();
      eprintf ("The term ");
      termPrint (b->term);
      eprintf (" does not match any pattern from the role definitions.\n");
    }
}

//! Process good candidate
int
process_good_candidate (const Protocol p, const Role r, const Roledef rd,
			const int index, const Binding b, const int found)
{
  int sflag;

  // A good candidate
  proof_term_match_first (found, b);
  proof_term_match (p, r, rd, index, found);

  indentDepth++;

  // Bind to existing run
#ifdef DEBUG
  debug (5, "Trying to bind to existing run.");
#endif
  proof_go_down (TERM_DeEx, b->term);
  sflag = bind_existing_run (b, p, r, index);
  proof_go_up ();
  // bind to new run
#ifdef DEBUG
  debug (5, "Trying to bind to new run.");
#endif
  proof_go_down (TERM_DeNew, b->term);
  sflag = sflag && bind_new_run (b, p, r, index);
  proof_go_up ();

  indentDepth--;
  return sflag;
}

//! Helper struct to maintain state (continuation) during iteration
struct state_brs
{
  Binding binding;
  int found;
};

//! Helper for the next function bind_regular_goal
int
bind_this_role_send (Protocol p, Role r, Roledef rd, int index,
		     struct state_brs *bs)
{
  if (p == INTRUDER)
    {
      // No intruder roles here
      return true;
    }

  // Test for interm unification
  debug_send_candidate (p, r, rd, index);

  if (!subtermUnify
      (rd->message, (bs->binding)->term, NULL, NULL, test_sub_unification,
       NULL))
    {
      // A good candidate
      bs->found++;
      return process_good_candidate (p, r, rd, index, bs->binding, bs->found);
    }
  else
    {
      return true;
    }
}

//! Bind a regular goal
/**
 * Problem child. Valgrind did not like it. 
 * TODO maybe better since last rewrite; need to check again.
 */
int
bind_goal_regular_run (const Binding b)
{
  int flag;
  struct state_brs bs;

  // Bind to all possible sends of regular runs
  bs.found = 0;
  bs.binding = b;

  flag = iterate_state_role_sends (bind_this_role_send, &bs);

  proof_term_match_none (b, bs.found);
  return flag;
}


//! Bind to all possible sends of intruder runs
int
bind_goal_old_intruder_run (Binding b)
{
  int run;
  int flag;
  int found;

  found = 0;
  flag = 1;
  for (run = 0; run < sys->maxruns; run++)
    {
      if (sys->runs[run].protocol == INTRUDER)
	{
	  int ev;
	  Roledef rd;

	  rd = sys->runs[run].start;
	  ev = 0;
	  while (ev < sys->runs[run].height)
	    {
	      if (rd->type == SEND)
		{
		  found++;
		  if (switches.output == PROOF && found == 1)
		    {
		      indentPrint ();
		      eprintf
			("Suppose it is from an existing intruder run.\n");
		    }
		  indentDepth++;
		  bind_existing_to_goal (b, run, ev,
					 (sys->runs[run].role != I_RRS));
		  indentDepth--;
		}
	      rd = rd->next;
	      ev++;
	    }
	}
    }
  if (switches.output == PROOF && found == 0)
    {
      indentPrint ();
      eprintf ("No existing intruder runs to match to.\n");
    }
  return flag;
}

//! Bind a goal in all possible ways
int
bind_goal_all_options (const Binding b)
{
  if (b->blocked)
    {
      error ("Trying to bind a blocked goal!");
    }
  if (!b->done)
    {
      int flag;

      flag = 1;
      proof_select_goal (b);
      indentDepth++;

      // Consider a duplicate goal that we already bound before (C-minimality)
      // if (1 == 0)
      if (bind_old_goal (b))
	{
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Goal for term ");
	      termPrint (b->term);
	      eprintf (" was bound once before, linking up to #%i, %i.\n",
		       b->run_from, b->ev_from);
	    }

	  flag = flag && iterate ();

	  // Unbind again
	  goal_unbind (b);
	  indentDepth--;
	  return flag;
	}
      else
	{
	  int know_only;

	  know_only = false;

	  if (1 == 0)		// blocked for now
	    {
	      // Prune: if it is an SK type construct, ready
	      // No regular run will apply SK for you.
	      //!@todo This still needs a lemma, and a more generic (correct) algorithm!! It is currently
	      // actually false, e.g. for signing protocols, and password-like functions.
	      //
	      Term function;

	      function = getTermFunction (b->term);
	      if (function != NULL)
		{
		  if (!inKnowledge (sys->know, function))
		    {
		      // Prune because we didn't know it before, and it is never subterm-sent
		      if (switches.output == PROOF)
			{
			  indentPrint ();
			  eprintf ("* Because ");
			  termPrint (b->term);
			  eprintf
			    (" is never sent from a regular run, so we only intruder construct it.\n");
			}
		      know_only = true;
		    }
		}
	    }

	  if (switches.experimental & 16)
	    {
	      // Keylevel lemmas: improves on the previous one
	      if (!isPossiblySent (b->term))
		{
		  if (switches.output == PROOF)
		    {
		      eprintf
			("Rejecting a term as a regular bind because key levels are off: ");
		      termPrint (b->term);
		      if (know_only)
			{
			  eprintf (" [in accordance with function lemma]");
			}
		      else
			{
			  eprintf (" [stronger than function lemma]");
			}
		      eprintf ("\n");
		    }
		  know_only = true;
		}
	    }

	  if (!(switches.experimental & 32))
	    {
		    /**
		     * Note: this is slightly weaker than the previous & 16,
		     * but it actually differs in such minimal cases that it
		     * might be better to simply have the (much cleaner)
		     * keylevel lemma.
		     *
		     * That's why this is default and the other isn't.
		     */

	      // Hidelevel variant
	      int hlf;

	      hlf = hidelevelFlag (sys, b->term);
	      if (hlf == HLFLAG_NONE || hlf == HLFLAG_KNOW)
		{
		  know_only = true;
		}
	    }


	  // Allright, proceed

	  proofDepth++;
	  if (know_only)
	    {
	      // Special case: only from intruder
	      proof_go_down (TERM_CoOld, b->term);
	      flag = flag && bind_goal_old_intruder_run (b);
	      //flag = flag && bind_goal_new_intruder_run (b);
	      proof_go_up ();
	    }
	  else
	    {
	      // Normal case
	      flag = bind_goal_regular_run (b);
	      proof_go_down (TERM_CoOld, b->term);
	      flag = flag && bind_goal_old_intruder_run (b);
	      proof_go_up ();
	      proof_go_down (TERM_CoNew, b->term);
	      flag = flag && bind_goal_new_intruder_run (b);
	      proof_go_up ();
	    }
	  proofDepth--;

	  indentDepth--;
	  return flag;
	}
    }
  else
    {
      return 1;
    }
}

//! Create a generic new term of the same type, with a new run identifier.
/**
 * Output: the first element of the returned list.
 */
Termlist
createNewTermGeneric (Termlist tl, Term t)
{
  int freenumber;
  Termlist tlscan;
  Term newterm;

  /* Determine first free number */
  freenumber = sys->maxruns;
  tlscan = tl;
  while (tlscan != NULL)
    {
      Term ts;

      ts = tlscan->term;
      if (isLeafNameEqual (t, ts))
	{
	  if (TermRunid (ts) >= freenumber)
	    {
	      freenumber = TermRunid (ts) + 1;
	    }
	}
      tlscan = tlscan->next;
    }

  /* Make a new term with the free number */
  newterm = (Term) malloc (sizeof (struct term));
  memcpy (newterm, t, sizeof (struct term));
  TermRunid (newterm) = freenumber;

  /* The type of the new term should be that of the parent! */
  newterm->stype = termlistAppend (NULL, t);

  /* return */
  return termlistPrepend (tl, newterm);
}

//! Construct a list of already used constants
Termlist
findUsedConstants (const System sys)
{
  int run;
  Termlist tl;
  Termlist tlconst;

  tl = NULL;
  tlconst = NULL;
  for (run = 0; run < sys->maxruns; run++)
    {
      tl = termlistAddBasics (tl, sys->runs[run].rho);
      tl = termlistAddBasics (tl, sys->runs[run].sigma);
    }
  while (tl != NULL)
    {
      Term t;

      t = tl->term;
      if (!realTermVariable (t))
	{
	  tlconst = termlistAddNew (tlconst, t);
	}
      tl = tl->next;
    }
  termlistDelete (tl);
  return tlconst;
}

//! Retrieve a list of agent name candidates
Termlist
getAgentCandidates (Termlist seen)
{
  Termlist knowlist;
  Termlist candidatelist;
  Termlist li;			// list loop pointer

  knowlist = knowledgeSet (sys->know);
  candidatelist = NULL;
  for (li = knowlist; li != NULL; li = li->next)
    {
      Term t;

      t = li->term;
      if (isAgentType (t->stype))
	{
	  /* agent */
	  /* We don'typeterm want to instantiate untrusted agents. */
	  if (!inTermlist (sys->untrusted, t))
	    {
	      /* trusted agent */
	      if (!inTermlist (seen, t))
		{
		  /* This agent name is not in the list yet, so could be chosen */
		  candidatelist = termlistPrepend (candidatelist, t);
		}
	    }
	}
    }
  termlistDelete (knowlist);
  return candidatelist;
}

//! Get to string of term
const char *
getTermString (Term t)
{
  if (t != NULL)
    {
      if (TermSymb (t) != NULL)
	{
	  return (TermSymb (t)->text);
	}
    }
  return NULL;
}

//! Check the first character of two terms
int
isFirstCharEqual (Term t1, Term t2)
{
  const char *c1, *c2;

  c1 = getTermString (t1);
  c2 = getTermString (t2);
  if ((c1 == NULL) || (c2 == NULL))
    {
      return false;
    }
  else
    {
      return (c1[0] == c2[0]);
    }
}

//! Choose the best term from the (non-null) candidate list for the variable var
Term
chooseBestCandidate (Termlist candidatelist, Term var)
{
  Term last;
  Termlist li;			// list loop pointer

  // See if we have a candidate that starts with the same first character
  for (li = candidatelist; li != NULL; li = li->next)
    {
      last = li->term;
      if (isFirstCharEqual (last, var))
	{
	  return last;
	}
    }
  // If not, we may still want to invoke heuristics (Alice initiates, Bob responds)
  if (li == NULL)
    {
      // li==null happens if we did not break out of the loop, i.e., found nothing
      const char *c;

      c = getTermString (var);
      if (c != NULL)
	{
	  // Check if name starts with common prefix, resort to common name if still a candidate
	  if (strchr ("Ii", *c) && inTermlist (candidatelist, AGENT_Alice))
	    {
	      return AGENT_Alice;
	    }
	  if (strchr ("Rr", *c) && inTermlist (candidatelist, AGENT_Bob))
	    {
	      return AGENT_Bob;
	    }
	}
    }
  return last;
}

//! Create a new term with incremented run rumber, starting at sys->maxruns.
/**
 * This is a rather intricate function that tries to generate new terms of a
 * certain type. It first looks up things in the initial knowledge, checking
 * whether they are used already. After that, new ones are generated.
 *
 * Input:
 * - seen is a termlist that contains newly generated terms (usage: seen = createNewTerm(seen,.. )
 * - typeterm is the type name term (e.g., "Agent" term, "Data" in case not clear.)
 * - isagent is a boolean that is true iff we are looking for an agent name from the initial knowledge for a role
 * - var is the variable term of which we use the name
 *
 * Output: the first element of the returned list, which is otherwise equal to seen.
 */
Termlist
createNewTerm (Termlist seen, Term typeterm, int isagent, Term nameterm)
{
  /* Does if have an explicit type?
   * If so, we try to find a fresh name from the intruder knowledge first.
   */
  if (isagent)
    {
      Termlist candidatelist;

      candidatelist = getAgentCandidates (seen);
      if (candidatelist != NULL)
	{
	  Term t;

	  t = chooseBestCandidate (candidatelist, nameterm);
	  termlistDelete (candidatelist);
	  return termlistPrepend (seen, t);
	}
    }

  /* Not an agent or no free one found */
  return createNewTermGeneric (seen, typeterm);
}

//! Delete a term made in the previous constructions
/**
 * \sa createNewTerm
 */
void
deleteNewTerm (Term t)
{
  if (TermRunid (t) >= 0)
    {
      /* if it has a positive runid, it did not come from the intruder
       * knowledge, so it must have been constructed.
       */
      free (t);
    }
}

//! Make a trace concrete
/**
 * People find reading variables in attack outputs difficult.
 * Thus, we instantiate open variables in a sensible way to make things more readable.
 *
 * This happens after sys->maxruns is fixed. Intruder constants thus are numbered from sys->maxruns onwards.
 *
 * \sa makeTraceClass
 */
Termlist
makeTraceConcrete (const System sys)
{
  Termlist changedvars;
  Termlist tlnew;
  int run;

  changedvars = NULL;
  tlnew = findUsedConstants (sys);

  for (run = 0; run < sys->maxruns; run++)
    {
      Termlist tl;

      for (tl = termlistForward (sys->runs[run].locals); tl != NULL;
	   tl = tl->prev)
	{
	  Term basevar;

	  basevar = tl->term;

	  /* variable, and of some run? */
	  if (isTermVariable (basevar) && TermRunid (basevar) >= 0)
	    {
	      Term var;
	      Term name;
	      Termlist vartype;

	      var = deVar (basevar);
	      vartype = basevar->stype;
	      // Determine class name
	      if (vartype != NULL)
		{
		  // Take first type name
		  name = vartype->term;
		}
	      else
		{
		  // Just a generic name
		  name = TERM_Data;
		}
	      // We should turn this into an actual term
	      tlnew =
		createNewTerm (tlnew, name, isAgentType (var->stype),
			       basevar);
	      var->subst = tlnew->term;

	      // Store for undo later
	      TERMLISTADD (changedvars, var);
	    }
	}
    }
  termlistDelete (tlnew);
  return changedvars;
}

//! Make a trace a class again
/**
 * \sa makeTraceConcrete
 */
void
makeTraceClass (const System sys, Termlist varlist)
{
  Termlist tl;

  tl = varlist;
  while (tl != NULL)
    {
      Term var;

      var = tl->term;
      if (realTermVariable (var))
	{
	  deleteNewTerm (var->subst);
	  var->subst = NULL;
	}
      tl = tl->next;
    }
  termlistDelete (varlist);
}

//! Determine whether to filter to a single attack
int
useAttackBuffer (void)
{
  if (switches.useAttackBuffer)
    {
      // it is possible
      if (switches.prune != 0)
	{
	  // it is also desired
	  return true;
	}
    }
  return false;
}

//! Start attack output
void
attackOutputStart (void)
{
  if (useAttackBuffer ())
    {
      FILE *fd;

      // Close old file (if any)
      if (attack_stream != NULL)
	{
	  fclose (attack_stream);	// this automatically discards the old temporary file
	}
      // Create new file
      fd = (FILE *) scyther_tempfile ();
      attack_stream = fd;
      globalStream = (char *) attack_stream;
    }
}

//! Stop attack output
void
attackOutputStop (void)
{
  // Nothing to do, just leave the opened tmpfile
}

//! Copy one (finite) stream from beginning to end to another
/**
 * Ugly first implementation, something to improve later (although it is not
 * crucial code in any way)
 */
void
fcopy (FILE * fromstream, FILE * tostream)
{
  int c;

  // 'Just to be sure'
  fflush (fromstream);
  fseek (fromstream, 0, SEEK_SET);

  // Urgh, using the assignment in the loop condition, brrr. Fugly.
  // Discourage.
  while ((c = fgetc (fromstream)) != EOF)
    {
      fputc (c, tostream);
    }
}

//! Output an attack in the desired way
void
arachneOutputAttack ()
{
  Termlist varlist;

  // Make concrete
  if (switches.concrete)
    {
      varlist = makeTraceConcrete (sys);
    }
  else
    {
      varlist = NULL;
    }

  // Wrapper for the real output
  attackOutputStart ();

  // Generate the output, already!
  if (switches.xml)
    {
      xmlOutSemitrace (sys);
    }
  else
    {
      dotSemiState (sys);
    }

  // End wrapper
  attackOutputStop ();

  // Undo concretization
  makeTraceClass (sys, varlist);
}

//------------------------------------------------------------------------
// Main logic core
//------------------------------------------------------------------------


//! Selector to select the first tuple goal.
/**
 * Basically to get rid of -m2 tuple goals.
 * Nice iteration, I'd suppose
 */
Binding
select_tuple_goal ()
{
  List bl;
  Binding tuplegoal;

  bl = sys->bindings;
  tuplegoal = NULL;
  while (bl != NULL && tuplegoal == NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      // Ignore done stuff
      if (!b->blocked && !b->done)
	{
	  if (isTermTuple (b->term))
	    {
	      tuplegoal = b;
	    }
	}
      bl = bl->next;
    }
  return tuplegoal;
}


//! Iterate a binding
/**
 * For DY model, we unfold any tuples first, otherwise we skip that.
 */
int
iterateOneBinding (void)
{
  Binding btup;
  int flag;

  // marker
  flag = true;

  // Are there any tuple goals?
  if (switches.intruder)
    {
      // Maybe... (well, test)
      btup = select_tuple_goal ();
    }
  else
    {
      // No, there are non that need to be expanded (no intruder)
      btup = NULL;
    }
  if (btup != NULL)
    {
      /* Substitution or something resulted in a tuple goal: we immediately split them into compounds.
       */
      Term tuple;

      tuple = deVar (btup->term);
      if (realTermTuple (tuple))
	{
	  int count;
	  Term tupletermbuffer;

	  tupletermbuffer = btup->term;
	  /*
	   * We solve this by replacing the tuple goal by the left term, and adding a goal for the right term.
	   */
	  btup->term = TermOp1 (tuple);
	  count =
	    goal_add (TermOp2 (tuple), btup->run_to,
		      btup->ev_to, btup->level);

	  // Show this in output
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Expanding tuple goal ");
	      termPrint (tupletermbuffer);
	      eprintf (" into %i subgoals.\n", count);
	    }

	  // iterate
	  flag = iterate ();

	  // undo
	  goal_remove_last (count);
	  btup->term = tupletermbuffer;
	}
    }
  else
    {
      // No tuple goals; good
      Binding b;

		  /**
		   * Not pruned: count
		   */

      sys->states = statesIncrease (sys->states);
      sys->current_claim->states =
	statesIncrease (sys->current_claim->states);

		  /**
		   * Check whether its a final state (i.e. all goals bound)
		   */

      b = (Binding) select_goal (sys);
      if (b == NULL)
	{
	  /*
	   * all goals bound, check for property
	   */
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("All goals are now bound.\n");
	    }
	  sys->claims = statesIncrease (sys->claims);
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  flag = property_check (sys);
	}
      else
	{
	  /*
	   * bind this goal in all possible ways and iterate
	   */
	  flag = bind_goal_all_options (b);
	}
    }
  return flag;
}

//! Unfold this particular name in this way
void
iterateAgentUnfoldThis (const Term rolevar, const Term agent)
{
  Term buffer;

  buffer = rolevar->subst;
  rolevar->subst = agent;
  iterate ();
  rolevar->subst = buffer;
}

//! Unfold this particular name
void
iterateAgentUnfolding (const System sys, const Term rolevar)
{
  Termlist kl;
  int count;

  iterateAgentUnfoldThis (rolevar, AGENT_Eve);
  kl = knowledgeSet (sys->know);
  count = 0;
  while (kl != NULL && count < switches.agentUnfold)
    {
      Term t;

      t = deVar (kl->term);
      if (realTermLeaf (t) && inTermlist (t->stype, TERM_Agent))
	{
	  if (!inTermlist (sys->untrusted, t))
	    {
	      iterateAgentUnfoldThis (rolevar, t);
	      count++;
	    }
	}
      kl = kl->next;
    }
  termlistDelete (kl);
}

//! Unfold names 
/**
 * Returns true if nothing was unfolded and the iteration must be done.
 * Returns false when the iteration should not be done.
 */
int
doAgentUnfolding (const System sys)
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      Termlist tl;

      tl = sys->runs[run].rho;
      while (tl != NULL)
	{
	  Term t;

	  t = deVar (tl->term);
	  if (realTermVariable (t))
	    {
	      // Hey, this role name is still a variable.
	      // We don't want that and so we unfold it as expected.
	      iterateAgentUnfolding (sys, t);
	      return false;
	    }
	  tl = tl->next;
	}
    }
  return true;
}

//! Main recursive procedure for Arachne
int
iterate ()
{
  int flag;

  flag = 1;

  // check unfolding agent names
  if (switches.agentUnfold > 0)
    {
      if (!doAgentUnfolding (sys))
	return flag;
    }

  if (!prune_theorems (sys))
    {
      if (!prune_claim_specifics (sys))
	{
	  if (!prune_bounds (sys))
	    {

	      // Go and pick a binding for iteration
	      flag = iterateOneBinding ();
	    }
	  else
	    {
	      // Pruned because of bound!
	      sys->current_claim->complete = 0;
	    }
	}
    }

#ifdef DEBUG
  if (DEBUGL (5) && !flag)
    {
      warning ("Flag has turned 0!");
    }
#endif

  return flag;
}

//! Just before starting output of an attack.
//
//! A wrapper for the case in which we need to buffer attacks.
int
iterate_buffer_attacks (void)
{
  if (useAttackBuffer ())
    {
      // We are pruning attacks, so they should go into a temporary file.
      /*
       * Set up the temporary file pointer
       */
      char *buffer;
      int result;

      // Push the old situation onto the stack
      buffer = globalStream;

      // Start stuff
      attack_stream = NULL;
      attackOutputStart ();

      // Finally, proceed with iteration procedure
      result = iterate ();

      /* Now, if it has been set, we need to copy the output to the normal streams.
       */
      fcopy (attack_stream, (FILE *) buffer);

      // Close
      fclose (attack_stream);
      attack_stream = NULL;

      // Restore
      globalStream = buffer;

      return result;
    }
  else
    {
      // No attack buffering, just output all of them
      return iterate ();
    }
}

//! Helper for the next code.
int
realStart (void)
{
#ifdef DEBUG
  if (DEBUGL (5))
    {
      printSemiState ();
    }
#endif
  return iterate_buffer_attacks ();
}

//! Arachne single claim test
void
arachneClaimTest (Claimlist cl)
{
  // others we simply test...
  int run;
  int newruns;
  Protocol p;
  Role r;

  newruns = 0;
  sys->current_claim = cl;
  attack_length = INT_MAX;
  attack_leastcost = INT_MAX;
  cl->complete = 1;
  p = (Protocol) cl->protocol;
  r = (Role) cl->role;

  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Testing Claim ");
      termPrint (cl->type);
      eprintf (" from ");
      termPrint (p->nameterm);
      eprintf (", ");
      termPrint (r->nameterm);
      eprintf (" at index %i.\n", cl->ev);
    }
  indentDepth++;

  run = semiRunCreate (p, r);
  newruns++;
  {
    int newgoals;

    proof_suppose_run (run, 0, cl->ev + 1);
    newgoals = add_recv_goals (run, 0, cl->ev + 1);

		    /**
		     * Add initial knowledge node
		     */
    {
      Termlist m0tl;
      Term m0t;
      int m0run;

      m0tl = knowledgeSet (sys->know);
      if (m0tl != NULL)
	{
	  m0t = termlist_to_tuple (m0tl);
	  // eprintf("Initial intruder knowledge node for ");
	  // termPrint(m0t);
	  // eprintf("\n");
	  I_M->roledef->message = m0t;
	  m0run = semiRunCreate (INTRUDER, I_M);
	  newruns++;
	  proof_suppose_run (m0run, 0, 1);
	  sys->runs[m0run].height = 1;
	}
      else
	{
	  m0run = -1;
	}

      {
		      /**
		       * Add specific goal info and iterate algorithm
		       */
	add_claim_specifics (sys, cl,
			     roledef_shift (sys->runs[run].start, cl->ev),
			     realStart);
      }


      if (m0run != -1)
	{
	  // remove initial knowledge node
	  termDelete (m0t);
	  termlistDelete (m0tl);
	  semiRunDestroy ();
	  newruns--;
	}
    }
    // remove claiming run goals 
    goal_remove_last (newgoals);
    semiRunDestroy ();
    newruns--;
  }
  //! Destroy
  while (sys->maxruns > 0 && newruns > 0)
    {
      semiRunDestroy ();
      newruns--;
    }
#ifdef DEBUG
  if (sys->bindings != NULL)
    {
      error ("sys->bindings NOT empty after claim test.");
    }
  if (sys->maxruns != 0)
    {
      error ("%i undestroyed runs left after claim test.", sys->maxruns);
    }
  if (newruns != 0)
    {
      error ("Lost %i runs after claim test.", newruns);
    }
#endif

  //! Indent back
  indentDepth--;

  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Proof complete for this claim.\n");
    }
}

//! Arachne single claim inspection
int
arachneClaim ()
{
  Claimlist cl;

  // Skip the dummy claims or SID markers
  cl = sys->current_claim;
  if (!isClaimSignal (cl))
    {
      // Some claims are always true!
      if (!cl->alwaystrue)
	{
	  // others we simply test...
	  arachneClaimTest (cl);
	}
      claimStatusReport (sys, cl);
      if (switches.xml)
	{
	  xmlOutClaim (sys, cl);
	}
      return true;
    }
  return false;
}

//! Helper for arachne
int
determine_encrypt_max (Protocol p, Role r, Roledef rd, int index)
{
  int tlevel;

  tlevel = term_encryption_level (rd->message);
#ifdef DEBUG
  if (DEBUGL (3))
    {
      eprintf ("Encryption level %i found for term ", tlevel);
      termPrint (rd->message);
      eprintf ("\n");
    }
#endif
  if (tlevel > max_encryption_level)
    max_encryption_level = tlevel;
  return 1;
}

//! Print send information
int
print_send (Protocol p, Role r, Roledef rd, int index)
{
  eprintf ("IRS: ");
  termPrint (p->nameterm);
  eprintf (", ");
  termPrint (r->nameterm);
  eprintf (", %i, ", index);
  roledefPrint (rd);
  eprintf ("\n");
  return 1;
}


//! Main code for Arachne
/**
 * For this test, we manually set up some stuff.
 *
 * But later, this will just iterate over all claims.
 *
 * @TODO what does it return? And is that -1 valid, if nothing is tested?
 */
int
arachne ()
{
  Claimlist cl;
  int count;

  /*
   * set up claim role(s)
   */

  if (switches.runs == 0)
    {
      // No real checking.
      return -1;
    }

  if (sys->maxruns > 0)
    {
      error ("Something is wrong, number of runs >0.");
    }

  sys->num_regular_runs = 0;
  sys->num_intruder_runs = 0;

  max_encryption_level = 0;
  iterate_role_events (determine_encrypt_max);
#ifdef DEBUG
  if (DEBUGL (1))
    {
      eprintf ("Maximum encryption level: %i\n", max_encryption_level);
    }
#endif

  fixAgentKeylevels ();

  indentDepth = 0;
  proofDepth = 0;
  cl = sys->claimlist;
  count = 0;
  while (cl != NULL)
    {
      /**
       * Check each claim
       */
      sys->current_claim = cl;
      if (isClaimRelevant (cl))	// check for any filtered claims (switch)
	{
	  if (arachneClaim ())
	    {
	      count++;
	    }
	}

      // next
      cl = cl->next;
    }
  return count;
}

//! Construct knowledge set at some event, based on a semitrace.
/**
 * This is a very 'stupid' algorithm; it is just there because GijsH
 * requested it. It does in no way guarantee that this is the actual
 * knowledge set at the given point. It simply gives an underapproximation,
 * that will be correct in most cases. The main reason for this is that it
 * completely ignores any information on unbound variables, and regards them
 * as bound constants.
 *
 * Because everything is supposed to be bound, we conclude that even 'recv'
 * events imply a certain knowledge.
 *
 * If aftercomplete is 0 or false, we actually check the ordering; otherwise we
 * just assume the trace has finished.
 *
 * Use knowledgeDelete later to clean up.
 */
Knowledge
knowledgeAtArachne (const System sys, const int myrun, const int myindex,
		    const int aftercomplete)
{
  Knowledge know;
  int run;

  know = knowledgeDuplicate (sys->know);	// duplicate initial knowledge
  run = 0;
  while (run < sys->maxruns)
    {
      int index;
      int maxheight;
      Roledef rd;

      index = 0;
      rd = sys->runs[run].start;
      maxheight = sys->runs[run].height;
      if (run == myrun && myindex > maxheight)
	{
	  // local run index can override real step
	  maxheight = myindex;
	}

      while (rd != NULL && index < maxheight)
	{
	  // Check whether this event precedes myevent
	  if (aftercomplete || isDependEvent (run, index, myrun, myindex))
	    {
	      // If it is a send (trivial) or a recv (remarkable, but true
	      // because of bindings) we can add the message and the agents to
	      // the knowledge.
	      if (rd->type == SEND || rd->type == RECV)
		{
		  knowledgeAddTerm (know, rd->message);
		  if (rd->from != NULL)
		    knowledgeAddTerm (know, rd->from);
		  if (rd->to != NULL)
		    knowledgeAddTerm (know, rd->to);
		}
	      index++;
	      rd = rd->next;
	    }
	  else
	    {
	      // Not ordered before anymore, so we skip to the next run.
	      rd = NULL;
	    }
	}
      run++;
    }
  return know;
}

//! Determine whether a term is trivially known at some event in a partially ordered structure.
/**
 * Important: read disclaimer at knowledgeAtArachne()
 *
 * Returns true iff the term is certainly known at that point in the
 * semitrace.
 */
int
isTriviallyKnownAtArachne (const System sys, const Term t, const int run,
			   const int index)
{
  int result;
  Knowledge knowset;

  knowset = knowledgeAtArachne (sys, run, index, false);
  result = inKnowledge (knowset, t);
  knowledgeDelete (knowset);
  return result;
}

//! Determine whether a term is trivially known after execution of some partially ordered structure.
/**
 * Important: read disclaimer at knowledgeAtArachne()
 *
 * Returns true iff the term is certainly known after all events in the
 * semitrace.
 */
int
isTriviallyKnownAfterArachne (const System sys, const Term t, const int run,
			      const int index)
{
  int result;
  Knowledge knowset;

  knowset = knowledgeAtArachne (sys, run, index, true);
  result = inKnowledge (knowset, t);
  knowledgeDelete (knowset);
  return result;
}

//! Mark that we have no full proof
/**
 * Provides an interface for marking incomplete proofs.
 * Currently used in mgusubterm in mgu.c
 */
void
markNoFullProof (const Term tbig, const Term tsmall)
{
  // Comment in proof
  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Note: the pattern set will be incomplete, because ");
      termPrint (tbig);
      eprintf (" allows for infinitely many ways to subtermUnify ");
      termPrint (tsmall);
      eprintf (".\n");
    }
  sys->current_claim->complete = false;
}
