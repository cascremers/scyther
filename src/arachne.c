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
#ifdef DEBUG
#include <malloc.h>
#endif

#include "term.h"
#include "termlist.h"
#include "role.h"
#include "system.h"
#include "knowledge.h"
#include "compiler.h"
#include "states.h"
#include "mgu.h"
#include "arachne.h"
#include "memory.h"
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
int num_regular_runs;		//!< Current number of regular runs
int num_intruder_runs;		//!< Current number of intruder runs

static int indentDepth;
static int prevIndentDepth;
static int indentDepthChanges;
static FILE *attack_stream;

/*
 * Forward declarations
 */

int iterate ();
void printSemiState ();

/*
 * Program code
 */

//! Init Arachne engine
void
arachneInit (const System mysys)
{
  Roledef rd;
  Termlist tl, know0;

  void add_event (int event, Term message)
  {
    rd = roledefAdd (rd, event, NULL, NULL, NULL, message, NULL);
  }
  Role add_role (const char *rolenamestring)
  {
    Role r;
    Term rolename;

    rolename = makeGlobalConstant (rolenamestring);
    r = roleCreate (rolename);
    r->roledef = rd;
    rd = NULL;
    r->next = INTRUDER->roles;
    INTRUDER->roles = r;
    // compute_role_variables (sys, INTRUDER, r);
    return r;
  }

  sys = mysys;			// make sys available for this module as a global

  /**
   * Very important: turn role terms that are local to a run, into variables.
   */
  term_rolelocals_are_variables ();

  /*
   * Add intruder protocol roles
   */

  INTRUDER = protocolCreate (makeGlobalConstant (" INTRUDER "));

  // Initially empty roledef
  rd = NULL;

  add_event (SEND, NULL);
  I_M = add_role ("I_M: Atomic message");

  add_event (READ, NULL);
  add_event (READ, NULL);
  add_event (SEND, NULL);
  I_RRS = add_role ("I_E: Encrypt");

  add_event (READ, NULL);
  add_event (READ, NULL);
  add_event (SEND, NULL);
  I_RRSD = add_role ("I_D: Decrypt");

  num_regular_runs = 0;
  num_intruder_runs = 0;
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
//! can this roledef constitute a read Goal?
#define isGoal(rd)	(rd->type == READ && !rd->internal)
//! is this roledef already bound?
#define isBound(rd)	(rd->bound)

//! Indent prefix print
void
indentPrefixPrint (const int annotate, const int jumps)
{
  if (switches.output == ATTACK && globalError == 0)
    {
      // Arachne, attack, not an error
      // We assume that means DOT output
      eprintf ("// %i\t", annotate);
    }
  else
    {
      // If it is not to stdout, or it is not an attack...
      int i;

      eprintf ("%i\t", annotate);
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
    num_intruder_runs++;
  else
    num_regular_runs++;
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
	num_intruder_runs--;
      else
	num_regular_runs--;
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
add_read_goals (const int run, const int old, const int new)
{
  int count;
  int i;
  Roledef rd;

  sys->runs[run].height = new;
  i = old;
  rd = roledef_shift (sys->runs[run].start, i);
  count = 0;
  while (i < new && rd != NULL)
    {
      if (rd->type == READ)
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

//! Determine the run that follows from a substitution.
/**
 * After an Arachne unification, stuff might go wrong w.r.t. nonce instantiation.
 * This function determines the run that is implied by a substitution list.
 * @returns >= 0: a run, -1 for invalid, -2 for any run.
 */
int
determine_unification_run (Termlist tl)
{
  int run;

  run = -2;
  while (tl != NULL)
    {
      //! Again, hardcoded reference to compiler.c. Level -3 means a local constant for a role.
      if (tl->term->type != VARIABLE && TermRunid (tl->term) == -3)
	{
	  Term t;

	  t = tl->term->subst;

	  // It is required that it is actually a leaf, because we construct it.
	  if (!realTermLeaf (t))
	    {
	      return -1;
	    }
	  else
	    {
	      if (run == -2)
		{
		  // Any run
		  run = TermRunid (t);
		}
	      else
		{
		  // Specific run: compare
		  if (run != TermRunid (t))
		    {
		      return -1;
		    }
		}
	    }
	}
      tl = tl->next;
    }
  return run;
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

//! Create a new temporary file and return the pointer.
FILE *
scyther_tempfile (void)
{
  return tmpfile ();
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
 * Function is called with (protocol pointer, role pointer, roledef pointer, index)
 * and returns an integer. If it is false, iteration aborts.
 */
int
iterate_role_sends (int (*func) ())
{
  int send_wrapper (Protocol p, Role r, Roledef rd, int i)
  {
    if (rd->type == SEND)
      {
	return func (p, r, rd, i);
      }
    else
      {
	return 1;
      }
  }

  return iterate_role_events (send_wrapper);
}

//! Create decryption role instance
/**
 * Note that this does not add any bindings for the reads.
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
      Term tempkey;
      int run;

      run = semiRunCreate (INTRUDER, I_RRSD);
      rd = sys->runs[run].start;
      rd->message = termDuplicateUV (term);
      rd->next->message = termDuplicateUV (key);
      rd->next->next->message = termDuplicateUV (TermOp (term));
      sys->runs[run].height = 3;
      proof_suppose_run (run, 0, 3);

      return run;
    }
  else
    {
      globalError++;
      printf ("Term for which a decryptor instance is requested: ");
      termPrint (term);
      printf ("\n");
      error
	("Trying to build a decryptor instance for a non-encrypted term.");
    }
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

//! Try to bind a specific existing run to a goal.
/**
 * The key goals are bound to the goal.
 *
 *@todo This is currently NOT correct. The point is that the key chain
 * cannot uniquely define a path through a term in general, and
 * a rewrite of termMguSubterm is needed. It should not yield the
 * needed keys, but simply the path throught the term. This would enable
 * reconstruction of the keys anyway. TODO
 *      
 *@param b	binding to fix (bind), destination filled in
 *@param run	run of binding start
 *@param index	index in run of binding start
 */
int
bind_existing_to_goal (const Binding b, const int run, const int index)
{
  Roledef rd;
  int flag;
  int old_length;
  int newgoals;
  int found;

  int subterm_iterate (Termlist substlist, Termlist cryptlist)
  {
    int flag;

    found++;
    flag = 1;
    /**
     * Now create the new bindings
     */
    int newgoals;
    int newruns;
    int stillvalid;

    Binding smalltermbinding;

    stillvalid = true;		// New stuff is valid (no cycles)
    newgoals = 0;		// No new goals introduced (yet)
    newruns = 0;		// New runs introduced
    smalltermbinding = b;	// Start off with destination binding

    indentDepth++;
#ifdef DEBUG
    if (DEBUGL (4))
      {
	printf ("Trying to bind the small term ");
	termPrint (b->term);
	printf (" as coming from the big send ");
	termPrint (rd->message);
	printf (" , binding ");
	termPrint (b->term);
	printf ("\nCrypted list needed: ");
	termlistPrint (cryptlist);
	printf ("\n");
      }
#endif
    if (cryptlist != NULL && switches.output == PROOF)
      {
	indentPrint ();
	eprintf
	  ("This introduces the obligation to decrypt the following encrypted subterms: ");
	termlistPrint (cryptlist);
	eprintf ("\n");
      }

    /* The order of the cryptlist is inner -> outer */
    while (stillvalid && cryptlist != NULL && smalltermbinding != NULL)
      {
	/*
	 * Invariants:
	 *
	 * smalltermbinding     binding to be satisfied next (and for which a decryptor is needed)
	 */
	Term keyneeded;
	int prioritylevel;
	int smallrun;
	int count;
	Roledef rddecrypt;
	Binding bnew;
	int res;

	/*
	 * 1. Add decryptor
	 */

	keyneeded =
	  inverseKey (sys->know->inverses, TermKey (cryptlist->term));
	prioritylevel = getPriorityOfNeededKey (sys, keyneeded);
	smallrun = create_decryptor (cryptlist->term, keyneeded);
	rddecrypt = sys->runs[smallrun].start;
	termDelete (keyneeded);
	newruns++;

	/*
	 * 2. Add goal bindings
	 */

	count = goal_add (rddecrypt->message, smallrun, 0, 0);
	newgoals = newgoals + count;
	if (count >= 0)
	  {
	    if (count > 1)
	      {
		error
		  ("Added more than one goal for decryptor goal 1, weird.");
	      }
	    else
	      {
		// This is the unique new goal then
		bnew = (Binding) sys->bindings->data;
	      }
	  }
	else
	  {
	    // No new binding? Weird, but fair enough
	    bnew = NULL;
	  }
	newgoals =
	  newgoals + goal_add (rddecrypt->next->message, smallrun, 1,
			       prioritylevel);

	/*
	 * 3. Bind open goal to decryptor
	 */

	res = goal_bind (smalltermbinding, smallrun, 2);	// returns 0 iff invalid
	if (res != 0)
	  {
	    // Allright, good binding, proceed with next
	    smalltermbinding = bnew;
	  }
	else
	  {
	    stillvalid = false;
	  }

	/* progression */
	cryptlist = cryptlist->next;
      }

    /*
     * Decryptors for any nested keys have been added. Now we can fill the
     * final binding.
     */

    if (stillvalid)
      {
	if (goal_bind (smalltermbinding, run, index))
	  {
	    proof_suppose_binding (b);
#ifdef DEBUG
	    if (DEBUGL (4))
	      {
		indentPrint ();
		eprintf ("Added %i new goals, iterating.\n", newgoals);
	      }
#endif
	    /* Iterate process */
	    indentDepth++;
	    flag = flag && iterate ();
	    indentDepth--;
	  }
	else
	  {
	    proof_cannot_bind (b, run, index);
	  }
      }

    goal_remove_last (newgoals);
    while (newruns > 0)
      {
	semiRunDestroy ();
	newruns--;
      }
    goal_unbind (b);

    indentDepth--;
    return flag;
  }

  //----------------------------
  // Roledef entry
  rd = roledef_shift (sys->runs[run].start, index);

  // Fix length
  old_length = sys->runs[run].height;
  if ((index + 1) > old_length)
    newgoals = add_read_goals (run, old_length, index + 1);
  else
    newgoals = 0;

  // Bind to existing run
  found = 0;
  flag = termMguSubTerm (b->term, rd->message,
			 subterm_iterate, sys->know->inverses, NULL);
  // Did it work?
  if (found == 0 && switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Cannot bind ");
      termPrint (b->term);
      eprintf (" to run %i, index %i because it does not subterm-unify.\n",
	       run, index);
    }
  // Reset length
  goal_remove_last (newgoals);
  sys->runs[run].height = old_length;
  return flag;
}

//! Bind a goal to an existing regular run, if possible
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
	  flag = flag && bind_existing_to_goal (b, run, index);
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

//! Bind a goal to a new run
int
bind_new_run (const Binding b, const Protocol p, const Role r,
	      const int index)
{
  int run;
  int flag;
  int newgoals;

  run = semiRunCreate (p, r);
  proof_suppose_run (run, 0, index + 1);
  {
    newgoals = add_read_goals (run, 0, index + 1);
    indentDepth++;
    flag = bind_existing_to_goal (b, run, index);
    indentDepth--;
    goal_remove_last (newgoals);
  }
  semiRunDestroy ();
  return flag;
}

//! Print the current semistate
void
printSemiState ()
{
  int run;
  int open;
  List bl;

  int binding_state_print (void *dt)
  {
    binding_indent_print ((Binding) dt, 1);
    return 1;
  }

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
	      // So we copy this binding, and fix it.
	      b_new->run_from = b_old->run_from;
	      b_new->ev_from = b_old->ev_from;
	      b_new->done = 1;
	      return 1;
	    }
	  bl = bl->next;
	}
    }
  // No old binding to connect to
  return 0;
}

//! Create a new intruder run to generate knowledge from m0
int
bind_goal_new_m0 (const Binding b)
{
  Termlist m0tl, tl;
  int flag;
  int found;


  flag = 1;
  found = 0;
  m0tl = knowledgeSet (sys->know);
  tl = m0tl;
  while (flag && tl != NULL)
    {
      Term m0t;
      Termlist subst;

      m0t = tl->term;
      subst = termMguTerm (b->term, m0t);
      if (subst != MGUFAIL)
	{
	  int run;

	  I_M->roledef->message = m0t;
	  run = semiRunCreate (INTRUDER, I_M);
	  proof_suppose_run (run, 0, 1);
	  sys->runs[run].height = 1;
	  {
	    indentDepth++;
	    if (goal_bind (b, run, 0))
	      {
		found++;
		proof_suppose_binding (b);
		if (switches.output == PROOF)
		  {
		    indentPrint ();
		    eprintf ("* I.e. retrieving ");
		    termPrint (b->term);
		    eprintf (" from the initial knowledge.\n");
		  }
		flag = flag && iterate ();
	      }
	    else
	      {
		proof_cannot_bind (b, run, 0);
	      }
	    goal_unbind (b);
	    indentDepth--;
	  }
	  semiRunDestroy ();


	  termlistSubstReset (subst);
	  termlistDelete (subst);
	}

      tl = tl->next;
    }

  if (found == 0 && switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Term ");
      termPrint (b->term);
      eprintf (" cannot be constructed from the initial knowledge.\n");
    }
  termlistDelete (m0tl);


  return flag;
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
      int run;
      int index;
      int newgoals;
      Roledef rd;
      Term t1, t2;

      if (!realTermEncrypt (term))
	{
	  // tuple construction
	  error ("Goal that is a tuple should not occur!");
	}

      // must be encryption
      t1 = TermOp (term);
      t2 = TermKey (term);

      if (t2 != TERM_Hidden)
	{
	  can_be_encrypted = 1;
	  run = semiRunCreate (INTRUDER, I_RRS);
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
	  newgoals = add_read_goals (run, 0, index + 1);

	  indentDepth++;
	  if (goal_bind (b, run, index))
	    {
	      proof_suppose_binding (b);
	      flag = flag && iterate ();
	    }
	  else
	    {
	      proof_cannot_bind (b, run, index);
	    }
	  goal_unbind (b);
	  indentDepth--;
	  goal_remove_last (newgoals);
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
  flag = bind_goal_new_m0 (b);
  flag = flag && bind_goal_new_encrypt (b);
  indentDepth--;
  return flag;
}

//! Bind a regular goal
/**
 * Problem child. Valgrind does not like it.
 */
int
bind_goal_regular_run (const Binding b)
{
  int flag;
  int found;

  int test_sub_unification (Termlist substlist, Termlist keylist)
  {
    // A unification exists; return the signal
    return 0;
  }
  /*
   * This is a local function so we have access to goal
   */
  int bind_this_role_send (Protocol p, Role r, Roledef rd, int index)
  {
    if (p == INTRUDER)
      {
	// No intruder roles here
	return 1;
      }

    // Test for interm unification
#ifdef DEBUG
    if (DEBUGL (5))
      {
	indentPrint ();
	eprintf ("Checking send candidate with message ");
	termPrint (rd->message);
	eprintf (" from ");
	termPrint (p->nameterm);
	eprintf (", ");
	termPrint (r->nameterm);
	eprintf (", index %i\n", index);
      }
#endif
    if (!termMguSubTerm
	(b->term, rd->message, test_sub_unification, sys->know->inverses,
	 NULL))
      {
	int sflag;

	// A good candidate
	found++;
	if (switches.output == PROOF && found == 1)
	  {
	    indentPrint ();
	    eprintf ("The term ", found);
	    termPrint (b->term);
	    eprintf
	      (" matches patterns from the role definitions. Investigate.\n");
	  }
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
	indentDepth++;

	// Bind to existing run
	sflag = bind_existing_run (b, p, r, index);
	// bind to new run
	sflag = sflag && bind_new_run (b, p, r, index);

	indentDepth--;
	return sflag;
      }
    else
      {
	return 1;
      }
  }


  // Bind to all possible sends of regular runs
  found = 0;
  flag = iterate_role_sends (bind_this_role_send);
  if (switches.output == PROOF && found == 0)
    {
      indentPrint ();
      eprintf ("The term ");
      termPrint (b->term);
      eprintf (" does not match any pattern from the role definitions.\n");
    }
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
		  flag = flag && bind_existing_to_goal (b, run, ev);
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
bind_goal (const Binding b)
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
	  b->done = 0;
	  indentDepth--;
	  return flag;
	}
      else
	{
	  int know_only;

	  know_only = 0;

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
		      know_only = 1;
		    }
		}
	    }

	  if (switches.experimental & 4 == 0)
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
		  know_only = 1;
		}
	    }
#ifdef DEBUG
	  else
	    {
	      if (DEBUGL (5) && know_only == 1)
		{
		  eprintf
		    ("Keylevel lemma is weaker than function lemma for term ");
		  termPrint (b->term);
		  eprintf ("\n");
		}
	    }
#endif

	  proofDepth++;
	  if (know_only)
	    {
	      // Special case: only from intruder
	      flag = flag && bind_goal_old_intruder_run (b);
	      flag = flag && bind_goal_new_intruder_run (b);
	    }
	  else
	    {
	      // Normal case
	      {
		flag = bind_goal_regular_run (b);
	      }
	      flag = flag && bind_goal_old_intruder_run (b);
	      flag = flag && bind_goal_new_intruder_run (b);
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
  freenumber = 0;
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
  newterm = (Term) memAlloc (sizeof (struct term));
  memcpy (newterm, t, sizeof (struct term));
  TermRunid (newterm) = freenumber;

  /* return */
  return termlistPrepend (tl, newterm);
}

//! Create a new term with incremented run rumber, starting at sys->maxruns.
/**
 * This is a rather intricate function that tries to generate new terms of a
 * certain type. It first looks up things in the initial knowledge, checking
 * whether they are used already. After that, new ones are generated.
 *
 * Output: the first element of the returned list.
 */
Termlist
createNewTerm (Termlist tl, Term t, int isagent)
{
  /* Does if have an explicit type?
   * If so, we try to find a fresh name from the intruder knowledge first.
   */
  if (isagent)
    {
      Termlist knowlist;
      Termlist kl;

      knowlist = knowledgeSet (sys->know);
      kl = knowlist;
      while (kl != NULL)
	{
	  Term k;

	  k = kl->term;
	  if (isAgentType (k->stype))
	    {
	      /* agent */
	      /* We don't want to instantiate untrusted agents. */
	      if (!inTermlist (sys->untrusted, k))
		{
		  /* trusted agent */
		  if (!inTermlist (tl, k))
		    {
		      /* This agent name is not in the list yet. */
		      return termlistPrepend (tl, k);
		    }
		}
	    }
	  kl = kl->next;
	}
      termlistDelete (knowlist);
    }

  /* Not an agent or no free one found */
  return createNewTermGeneric (tl, t);
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
      memFree (t, sizeof (struct term));
    }
}

//! Make a trace concrete
/**
 * People find reading variables in attack outputs difficult.
 * Thus, we instantiate them in a sensible way to make things more readable.
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
  tlnew = NULL;
  run = 0;

  while (run < sys->maxruns)
    {
      Termlist tl;

      tl = sys->runs[run].locals;
      while (tl != NULL)
	{
	  /* variable, and of some run? */
	  if (isTermVariable (tl->term) && TermRunid (tl->term) >= 0)
	    {
	      Term var;
	      Term name;
	      Termlist vartype;

	      var = deVar (tl->term);
	      vartype = var->stype;
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
	      tlnew = createNewTerm (tlnew, name, isAgentType (var->stype));
	      var->subst = tlnew->term;

	      // Store for undo later
	      changedvars = termlistAdd (changedvars, var);
	    }
	  tl = tl->next;
	}
      run++;
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
      deleteNewTerm (var->subst);
      var->subst = NULL;

      tl = tl->next;
    }
  termlistDelete (varlist);
}

//! Start attack output
void
attackOutputStart (void)
{
  if (switches.prune == 2)
    {
      FILE *fd;

      // Close old file (if any)
      if (attack_stream != NULL)
	{
	  fclose (attack_stream);	// this automatically discards the old temporary file
	}
      // Create new file
      fd = scyther_tempfile ();
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


//! Main recursive procedure for Arachne
int
iterate ()
{
  int flag;


  flag = 1;
  if (!prune_theorems (sys))
    {
      if (!prune_claim_specifics (sys))
	{
	  if (!prune_bounds (sys))
	    {
	      Binding b;

	      // Are there any tuple goals?
	      b = select_tuple_goal ();
	      if (b != NULL)
		{
		  // Expand tuple goal
		  int count;

		  // mark as blocked for iteration
		  binding_block (b);
		  // simply adding will detect the tuple and add the new subgoals
		  count = goal_add (b->term, b->run_to, b->ev_to, b->level);

		  // Show this in output
		  if (switches.output == PROOF)
		    {
		      indentPrint ();
		      eprintf ("Expanding tuple goal ");
		      termPrint (b->term);
		      eprintf (" into %i subgoals.\n", count);
		    }

		  // iterate
		  flag = iterate ();

		  // undo
		  goal_remove_last (count);
		  binding_unblock (b);
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

		  b = select_goal (sys);
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
		      flag = bind_goal (b);
		    }
		}
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
  if (switches.prune != 2)
    {
      return iterate ();
    }
  else
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
}

//! Main code for Arachne
/**
 * For this test, we manually set up some stuff.
 *
 * But later, this will just iterate over all claims.
 */
int
arachne ()
{
  Claimlist cl;

  int print_send (Protocol p, Role r, Roledef rd, int index)
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

  int determine_encrypt_max (Protocol p, Role r, Roledef rd, int index)
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

  /*
   * set up claim role(s)
   */

  if (switches.runs == 0)
    {
      // No real checking.
      return;
    }

  if (sys->maxruns > 0)
    {
      error ("Something is wrong, number of runs >0.");
    }

  num_regular_runs = 0;
  num_intruder_runs = 0;

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
  while (cl != NULL)
    {
      /**
       * Check each claim
       */

      // Skip the dummy claims
      if (!isTermEqual (cl->type, CLAIM_Empty))
	{
	  // Any other claims might be filterered
	  if (switches.filterClaim == NULL
	      || switches.filterClaim == cl->type)
	    {
	      // Some claims are always true!
	      if (!cl->alwaystrue)
		{
		  // others we simply test...
		  int run;
		  Protocol p;
		  Role r;

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
		  proof_suppose_run (run, 0, cl->ev + 1);
		  add_read_goals (run, 0, cl->ev + 1);

	      /**
	       * Add specific goal info
	       */
		  add_claim_specifics (sys, cl,
				       roledef_shift (sys->runs[run].start,
						      cl->ev));

#ifdef DEBUG
		  if (DEBUGL (5))
		    {
		      printSemiState ();
		    }
#endif
		  iterate_buffer_attacks ();

		  //! Destroy
		  while (sys->bindings != NULL)
		    {
		      goal_remove_last (1);
		    }
		  while (sys->maxruns > 0)
		    {
		      semiRunDestroy ();
		    }

		  //! Indent back
		  indentDepth--;

		  if (switches.output == PROOF)
		    {
		      indentPrint ();
		      eprintf ("Proof complete for this claim.\n");
		    }
		}
	    }
	}
      // next
      cl = cl->next;
    }
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
 * Because everything is supposed to be bound, we conclude that even 'read'
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

  goal_graph_create ();		// ensure a valid ordering graph
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
	  if (aftercomplete || isOrderedBefore (run, index, myrun, myindex))
	    {
	      // If it is a send (trivial) or a read (remarkable, but true
	      // because of bindings) we can add the message and the agents to
	      // the knowledge.
	      if (rd->type == SEND || rd->type == READ)
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
