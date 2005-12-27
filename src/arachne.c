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

extern int *graph;
extern int nodes;
extern int graph_uordblks;

static System sys;
static int attack_length;
static int attack_leastcost;

Protocol INTRUDER;		// Pointers, to be set by the Init
Role I_M;			// Same here.
Role I_RRS;
Role I_RRSD;

static int indentDepth;
static int prevIndentDepth;
static int indentDepthChanges;
static int proofDepth;
static int max_encryption_level;
static int num_regular_runs;
static int num_intruder_runs;
static FILE *attack_stream;

struct goalstruct
{
  int run;
  int index;
  Roledef rd;
};

typedef struct goalstruct Goal;

/**
 * Forward declarations
 */

int iterate ();
void printSemiState ();

/**
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

/*
 * runs[rid].step is now the number of 'valid' events within the run, but we
 * call it 'length' here.
 */
#define INVALID		-1
#define isGoal(rd)	(rd->type == READ && !rd->internal)
#define isBound(rd)	(rd->bound)
#define length		step

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

//! Determine whether a term is a functor
int
isTermFunctionName (Term t)
{
  t = deVar (t);
  if (t != NULL && isTermLeaf (t) && t->stype != NULL
      && inTermlist (t->stype, TERM_Function))
    return 1;
  return 0;
}

//! Determine whether a term is a function application. Returns the function term.
Term
getTermFunction (Term t)
{
  t = deVar (t);
  if (t != NULL)
    {
      if (realTermEncrypt (t) && isTermFunctionName (TermKey (t)))
	{
	  return TermKey (t);
	}
    }
  return NULL;
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
 * Depends on the keylevel lemma (TODO) and the keylevel constructors in symbol.c
 * The idea is that certain terms will never be sent.
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
  sys->runs[run].length = 0;
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
 * From old to new. Sets the new length to new.
 *@returns The number of goals added (for destructions)
 */
int
add_read_goals (const int run, const int old, const int new)
{
  int count;
  int i;
  Roledef rd;

  sys->runs[run].length = new;
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
	  length = length + sys->runs[run].length - sys->runs[run].firstReal;
	}
      run++;
    }
  return length;
}

//! Check whether a binding (goal) is selectable
int
is_goal_selectable (const Binding b)
{
  if (b != NULL)
    {
      if (!b->blocked && !b->done)
	{
	  return 1;
	}
    }
  return 0;
}

//! Count selectable goals
int
count_selectable_goals ()
{
  List bl;
  int n;

  n = 0;
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      if (is_goal_selectable (b))
	{
	  n++;
	}
      bl = bl->next;
    }
  return n;
}

//! Return first selectable goal in the list
/**
 * The return list entry is either NULL, or a selectable goal.
 */
List
first_selectable_goal (List bl)
{
  while (bl != NULL && !is_goal_selectable ((Binding) bl->data))
    {
      bl = bl->next;
    }
  return bl;
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

//! Check this variables whether it is a good agent type
/**
 * Checks for leaf/etc and correct agent type
 */
int
goodAgentType (Term agent)
{
  agent = deVar (agent);

  if (!realTermLeaf (agent))
    {				// not a leaf
      return false;
    }
  else
    {				// real leaf
      if (isTermVariable (agent))
	{
	  // Variable: check type consistency (should have a solution)
	  // Not yet: depends on matching mode also
	}
      else
	{
	  // Constant: allow only exact type
	  if (!inTermlist (agent->stype, TERM_Agent))
	    {
	      return false;
	    }
	}
    }

  return true;
}

//! Check initiator roles
/**
 * Returns false iff an agent type is wrong
 */
int
initiatorAgentsType ()
{
  int run;

  run = 0;
  while (run < sys->maxruns)
    {
      // Only for initiators
      if (sys->runs[run].role->initiator)
	{
	  Termlist agents;

	  agents = sys->runs[run].agents;
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
      sys->runs[run].step = 3;
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
 *@param subterm determines whether it is a subterm unification or not.
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
  old_length = sys->runs[run].length;
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
  sys->runs[run].length = old_length;
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

//! Convert a list of ranks to a list of lines (0..)
/**
 * The interesting bit is that the ranks include the intruder events. Thus, we need to filter those out of
 * the system.
 *
 * Returns the baseline of the highest number + 1; thus the number of lines.
 */
int
ranks_to_lines (int *ranks, const int nodes)
{
  int ranksdone, baseline;

  ranksdone = 0;		// All values lower than this have been done, so it is the next value
  baseline = 0;			// The line numbers that get assigned
  while (1)
    {
      int newlow;
      int run;
      int i;

      // Determine lowest rank for non-intruder events, that has not been done
      newlow = INT_MAX;
      run = 0;
      while (run < sys->maxruns)
	{
	  if (sys->runs[run].protocol != INTRUDER)
	    {
	      int ev;

	      ev = 0;
	      while (ev < sys->runs[run].step)
		{
		  int nrank;

		  nrank = ranks[node_number (run, ev)];
		  if (nrank < newlow && nrank >= ranksdone)
		    {
		      newlow = nrank;
		    }
		  ev++;
		}
	    }
	  run++;
	}
      if (newlow == INT_MAX)
	{
	  // All are done
	  return baseline;
	}
      // Convert the nodes between ranksdone and newlow to baseline
      i = 0;
      while (i < nodes)
	{
	  if (ranks[i] <= newlow && ranks[i] >= ranksdone)
	    {
	      ranks[i] = baseline;
	    }
	  i++;
	}
      baseline++;
      ranksdone = newlow + 1;
    }
}


//! Iterate over all events that have an incoming arrow to the current one (forgetting the intruder for a moment)
void
iterate_incoming_arrows (void (*func) (), const int run, const int ev)
{
  /**
   * Determine wheter to draw an incoming arrow to this event.
   * We check all other runs, to see if they are ordered.
   */
  int run2;

  run2 = 0;
  while (run2 < sys->maxruns)
    {
      if (run2 != run && sys->runs[run2].protocol != INTRUDER)
	{
	  // Is this run before the event?
	  int ev2;
	  int found;

	  found = 0;
	  ev2 = sys->runs[run2].length;
	  while (found == 0 && ev2 > 0)
	    {
	      ev2--;
	      if (graph[graph_nodes (nodes, run2, ev2, run, ev)] != 0)
		{
		  found = 1;
		}
	    }

	  if (found == 1)
	    {
	      // It is before the event, and thus we would like to draw it.
	      // However, if there is another path along which we can get here, forget it
	      /**
	       * Note that this algorithm is similar to Floyd's algorithm for all shortest paths.
	       * The goal here is to select only the path with distance 1 (as viewed from the regular runs),
	       * so we can simplify stuff a bit.
	       * Nevertheless, using Floyd first would probably be faster.
	       */
	      int other_route;
	      int run3;
	      int ev3;

	      other_route = 0;
	      run3 = 0;
	      ev3 = 0;
	      while (other_route == 0 && run3 < sys->maxruns)
		{
		  if (sys->runs[run3].protocol != INTRUDER)
		    {
		      ev3 = 0;
		      while (other_route == 0 && ev3 < sys->runs[run3].length)
			{
			  if (graph
			      [graph_nodes
			       (nodes, run2, ev2, run3, ev3)] != 0
			      &&
			      graph[graph_nodes
				    (nodes, run3, ev3, run, ev)] != 0)
			    {
			      // other route found
			      other_route = 1;
			    }
			  ev3++;
			}
		    }
		  run3++;
		}
	      if (other_route == 0)
		{
		  func (run2, ev2);
		}


	    }
	}
      run2++;
    }
}

//! Iterate over all events that have an outgoing arrow from the current one (forgetting the intruder for a moment)
void
iterate_outgoing_arrows (void (*func) (), const int run, const int ev)
{
  /**
   * Determine wheter to draw an incoming arrow to this event.
   * We check all other runs, to see if they are ordered.
   */
  int run2;

  run2 = 0;
  while (run2 < sys->maxruns)
    {
      if (run2 != run && sys->runs[run2].protocol != INTRUDER)
	{
	  // Is this run after the event?
	  int ev2;
	  int found;

	  found = 0;
	  ev2 = 0;
	  while (found == 0 && ev2 < sys->runs[run2].length)
	    {
	      if (graph[graph_nodes (nodes, run, ev, run2, ev2)] != 0)
		{
		  found = 1;
		}
	      else
		{
		  ev2++;
		}
	    }

	  if (found == 1)
	    {
	      // It is after the event, and thus we would like to draw it.
	      // However, if there is another path along which we can get there, forget it
	      /**
	       * Note that this algorithm is similar to Floyd's algorithm for all shortest paths.
	       * The goal here is to select only the path with distance 1 (as viewed from the regular runs),
	       * so we can simplify stuff a bit.
	       * Nevertheless, using Floyd first would probably be faster.
	       */
	      int other_route;
	      int run3;
	      int ev3;

	      other_route = 0;
	      run3 = 0;
	      ev3 = 0;
	      while (other_route == 0 && run3 < sys->maxruns)
		{
		  if (sys->runs[run3].protocol != INTRUDER)
		    {
		      ev3 = 0;
		      while (other_route == 0 && ev3 < sys->runs[run3].length)
			{
			  if (graph
			      [graph_nodes
			       (nodes, run, ev, run3, ev3)] != 0
			      &&
			      graph[graph_nodes
				    (nodes, run3, ev3, run2, ev2)] != 0)
			    {
			      // other route found
			      other_route = 1;
			    }
			  ev3++;
			}
		    }
		  run3++;
		}
	      if (other_route == 0)
		{
		  func (run2, ev2);
		}
	    }
	}
      run2++;
    }
}

//! Display the current semistate using LaTeX output format.
/**
 * This is not as nice as we would like it. Furthermore, the function is too big, and needs to be split into functional parts that
 * will allow the generation of dot code as well.
 */
void
latexSemiState ()
{
  static int attack_number = 0;
  int run;
  Protocol p;
  int *ranks;
  int maxrank, maxline;

  // Open graph
  attack_number++;
  eprintf ("\\begin{msc}{Attack on ");
  p = (Protocol) sys->current_claim->protocol;
  termPrint (p->nameterm);
  eprintf (", role ");
  termPrint (sys->current_claim->rolename);
  eprintf (", claim type ");
  termPrint (sys->current_claim->type);
  eprintf ("}\n%% Attack number %i\n", attack_number);
  eprintf ("\n");

  // Needed for the bindings later on: create graph
  goal_graph_create ();		// create graph
  if (warshall (graph, nodes) == 0)	// determine closure
    {
      eprintf
	("%% This graph was not completely closed transitively because it contains a cycle!\n");
    }

  ranks = memAlloc (nodes * sizeof (int));
  maxrank = graph_ranks (graph, ranks, nodes);	// determine ranks

  // Convert ranks to lines
  maxline = ranks_to_lines (ranks, nodes);

  // Draw headings (boxes)
  run = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].protocol != INTRUDER)
	{
	  eprintf ("\\declinst{r%i}{}{run %i}\n", run, run);
	}
      run++;
    }
  eprintf ("\\nextlevel\n\n");

  // Draw all events (according to ranks)
  {
    int myline;

    myline = 0;
    while (myline < maxline)
      {
	int count;
	int run;

	count = 0;
	run = 0;
	while (run < sys->maxruns)
	  {
	    if (sys->runs[run].protocol != INTRUDER)
	      {
		int ev;

		ev = 0;
		while (ev < sys->runs[run].step)
		  {
		    if (myline == ranks[node_number (run, ev)])
		      {
			Roledef rd;

			void outgoing_arrow (const int run2, const int ev2)
			{
			  Roledef rd2;
			  int delta;

			  rd2 = roledef_shift (sys->runs[run2].start, ev2);

			  eprintf ("\\mess{");
			  /*
			     // Print the term
			     // Maybe, if more than one outgoing, and different send/reads, we might want to change this a bit.
			     if (rd->type == SEND)
			     {
			     if (rd2->type == CLAIM)
			     {
			     roledefPrint(rd);
			     }
			     if (rd2->type == READ)
			     {
			     eprintf("$");
			     if (isTermEqual(rd->message, rd2->message))
			     {
			     termPrint(rd->message);
			     }
			     else
			     {
			     termPrint(rd->message);
			     eprintf(" \\longrightarrow ");
			     termPrint(rd2->message);
			     }
			     eprintf("$");
			     }
			     }
			     else
			     {
			     roledefPrint(rd);
			     }
			   */
			  /*
			     roledefPrint (rd);
			     eprintf (" $\\longrightarrow$ ");
			     roledefPrint (rd2);
			   */

			  eprintf ("}{r%i}{r%i}", run, run2);
			  delta = ranks[node_number (run2, ev2)] - myline;
			  if (delta != 0)
			    {
			      eprintf ("[%i]", delta);
			    }
			  eprintf ("\n");
			  count++;
			}

			// We have found an event on this line
			// We only need to consider reads and claims, but for fun we just consider everything.
			rd = roledef_shift (sys->runs[run].start, ev);
			iterate_outgoing_arrows (outgoing_arrow, run, ev);
			eprintf ("\\action{");
			roledefPrint (rd);
			eprintf ("}{r%i}\n", run);
		      }
		    ev++;
		  }
	      }
	    run++;
	  }
	eprintf ("\\nextlevel\n");
	myline++;
      }
  }

  // clean memory
  memFree (ranks, nodes * sizeof (int));	// ranks

  // close graph
  eprintf ("\\nextlevel\n\\end{msc}\n\n");
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
      while (index < sys->runs[run].length)
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

//! Give an indication of the amount of consequences binding a term has
/**
 * Given a term, returns a float. 0: maximum consequences, 1: no consequences.
 */
float
termBindConsequences (Term t)
{
  Termlist openVariables;

  openVariables = termlistAddVariables (NULL, t);
  if (openVariables == NULL)
    {
      // No variables, no consequences
      return 1;
    }
  else
    {
      // For each run event in the semitrace, check whether it contains any
      // of the open variables.
      int totalCount;
      int affectedCount;
      int run;

      totalCount = 0;
      affectedCount = 0;
      run = 0;
      while (run < sys->maxruns)
	{
	  Roledef rd;
	  int step;

	  rd = sys->runs[run].start;
	  step = 0;
	  while (step < sys->runs[run].length)
	    {
	      Termlist tl;

	      tl = openVariables;
	      while (tl != NULL)
		{
		  if ((rd->type == READ || rd->type == SEND)
		      && termSubTerm (rd->message, tl->term))
		    {
		      // This run event contains the open variable
		      affectedCount++;
		      tl = NULL;
		    }
		  else
		    {
		      tl = tl->next;
		    }
		}
	      totalCount++;
	      step++;
	      rd = rd->next;
	    }
	  run++;
	}

      termlistDelete (openVariables);
      if (totalCount > 0)
	{
	  // Valid computation
	  return (float) (totalCount - affectedCount) / totalCount;
	}
      else
	{
	  // No consequences, ensure no division by 0
	  return 1;
	}
    }
}

//! Determine whether a term is an open nonce variable
/**
 * Does not explore subterms
 */
int
isOpenNonceVar (Term t)
{
  t = deVar (t);
  if (realTermVariable (t))
    {
      return inTermlist (t->stype, TERM_Nonce);
    }
  else
    {
      return 0;
    }
}

//! Count unique open variables in term
/**
 */
int
count_open_variables (const Term t)
{
  Termlist tl;
  int n;

  tl = NULL;
  termlistAddVariables (tl, t);
  n = 0;
  while (tl != NULL)
    {
      if (!inTermlist (tl->next, t))
	{
	  if (isOpenNonceVar (t))
	    {
	      n = n + 1;
	    }
	}
      tl = tl->next;
    }
  termlistDelete (tl);
  return n;
}

//! Athena-like factor
/**
 * Lower is better (more nonce variables)
 */
float
term_noncevariables_level (const Term t)
{
  int onv;
  const int enough = 2;

  onv = count_open_variables (t);
  if (onv >= enough)
    {
      return 0;
    }
  else
    {
      return 1 - (onv / enough);
    }
}

//------------------------------------------------------------------------
// Larger logical componentents
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

//! Goal selection
/**
 * Selects the most constrained goal.
 *
 * First selection is on level; thus, keys are selected first.
 *
 * Because the list starts with the newest terms, and we use <= (as opposed to <), we
 * ensure that for goals with equal constraint levels, we select the oldest one.
 *
 * --select-goal has two distint interpretations. If it is 0 or greater, it a
 * selection mask. If it is smaller than 0, it is some special tactic.
 *
 * selection masks for --select-goal
 *	1:	constrain level of term
 * 	2:	key or not
 * 	4:	consequences determination
 * 	8:	select also single variables (that are not role variables)
 * 	16:	single variables are better
 *
 * special tactics for --select-goal
 *	-1:	random goal selection
 *
 */
Binding
select_goal_masked ()
{
  List bl;
  Binding best;
  float min_constrain;
  int mode;

  // mode bits local storage
  mode = switches.arachneSelector;

  // Find the most constrained goal
  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Listing open goals that might be chosen: ");
    }
  min_constrain = FLT_MAX;
  bl = sys->bindings;
  best = NULL;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;

      // Only if not done and not blocked
      if (is_goal_selectable (b))
	{
	  int allow;
	  Term gterm;

	  allow = 0;
	  gterm = deVar (b->term);
	  if (mode & 8)
	    {
	      // check for singular variable
	      if (realTermVariable (gterm))
		{
		  // singular variable only if it is not a role name variable
		  allow = !gterm->roleVar;
		}
	      else
		{
		  // not a singular variable, allow
		  allow = 1;
		}
	    }
	  else
	    {
	      // Normally (mode & 8 == 0) we ignore any singular variables
	      allow = !realTermVariable (gterm);
	    }

	  if (allow)
	    {
	      float buf_constrain;
	      int buf_weight;
	      int smode;

	      void adapt (const int w, const float fl)
	      {
		buf_constrain = buf_constrain + w * fl;
		buf_weight = buf_weight + w;
	      }

	      void erode (const int w, const float fl)
	      {
		if (smode & 1)
		  {
		    adapt (w, fl);
		  }
		smode = smode / 2;
	      }

	      // buf_constrain is the addition of the factors before division by weight
	      buf_constrain = 0;
	      buf_weight = 0;

	      if (switches.output == PROOF && best != NULL)
		eprintf (", ");

	      // We will shift this mode variable
	      smode = mode;

	      // Determine buf_constrain levels
	      // Bit 0: 1 constrain level
	      erode (1, term_constrain_level (b->term));
	      // Bit 1: 2 key level (inverted)
	      erode (1, 0.5 * (1 - b->level));
	      // Bit 2: 4 consequence level
	      erode (1, termBindConsequences (b->term));
	      // Bit 3: 8 single variables first
	      erode (1, 1 - isTermVariable (b->term));
	      // Bit 4: 16 nonce variables level (Cf. what I think is in Athena)
	      erode (1, term_noncevariables_level (b->term));
	      // Define legal range
	      if (smode > 0)
		error ("--goal-select mode %i is illegal", mode);

	      // Weigh result
	      if (buf_weight == 0 || buf_constrain <= min_constrain)
		{
		  min_constrain = buf_constrain;
		  best = b;
		  if (switches.output == PROOF)
		    eprintf ("*");
		}
	      if (switches.output == PROOF)
		{
		  termPrint (b->term);
		  if (mode & 2)
		    {
		      eprintf ("[%i]", b->level);
		    }
		  eprintf ("<%.2f>", buf_constrain);
		}
	    }
	}
      bl = bl->next;
    }
  if (switches.output == PROOF)
    {
      if (best == NULL)
	eprintf ("none");
      eprintf ("\n");
    }
  return best;
}

//! Goal selection special case -1: random
/**
 * Simply picks an open goal randomly. Has to be careful to skip singular stuff etc.
 */
Binding
select_goal_random ()
{
  int n;

  n = count_selectable_goals ();
  if (n > 0)
    {
      int choice;
      List bl;

      // Choose a random goal between 0 and n
      choice = rand () % n;

      // Fetch it
      bl = sys->bindings;
      while (choice >= 0)
	{
	  bl = first_selectable_goal (bl);
	  if (bl == NULL)
	    {
	      error ("Random chooser selected a NULL goal.");
	    }
	  choice--;
	}
      return (Binding) bl->data;
    }
  else
    {
      return NULL;
    }
}

//! Goal selection function, generic
Binding
select_goal ()
{
  if (switches.arachneSelector >= 0)
    {
      // Masked
      return select_goal_masked ();
    }
  else
    {
      // Special cases
      switch (switches.arachneSelector)
	{
	case -1:
	  return select_goal_random ();
	  break;
	}
      error ("Unknown value (<0) for --goal-select.");
    }
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
	  sys->runs[run].length = 1;
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


// Bind to all possible sends of intruder runs
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
	  while (ev < sys->runs[run].length)
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
      int know_only;
      Term function;

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
	  // Prune: if it is an SK type construct, ready
	  // No regular run will apply SK for you.
	  //!@todo This still needs a lemma, and a more generic (correct) algorithm!!

	  know_only = 0;
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

//! Prune determination because of theorems
/**
 *@returns true iff this state is invalid because of a theorem
 */
int
prune_theorems ()
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

  return 0;
}

//! Prune determination for bounds
/**
 *@returns true iff this state is invalid for some reason
 */
int
prune_bounds ()
{
  Termlist tl;
  List bl;

  /* prune for time */
  if (passed_time_limit ())
    {
      // Oh no, we ran out of time!
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned: ran out of allowed time (-T %i switch)\n",
		   get_time_limit ());
	}
      // Pruned because of time bound!
      sys->current_claim->timebound = 1;
      return 1;
    }

  /* prune for proof depth */
  if (proofDepth > switches.maxproofdepth)
    {
      // Hardcoded limit on proof tree depth
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned: proof tree too deep: %i (-d %i switch)\n",
		   proofDepth, switches.maxproofdepth);
	}
      return 1;
    }

  /* prune for trace length */
  if (switches.maxtracelength < INT_MAX)
    {
      int tracelength;
      int run;

      /* compute trace length of current semistate */
      tracelength = 0;
      run = 0;
      while (run < sys->maxruns)
	{
	  /* ignore intruder actions */
	  if (sys->runs[run].protocol != INTRUDER)
	    {
	      tracelength = tracelength + sys->runs[run].step;
	    }
	  run++;
	}
      /* test */
      if (tracelength > switches.maxtracelength)
	{
	  // Hardcoded limit on proof tree depth
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned: trace too long: %i (-l %i switch)\n",
		       tracelength, switches.maxtracelength);
	    }
	  return 1;
	}
    }

  if (num_regular_runs > switches.runs)
    {
      // Hardcoded limit on runs
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned: too many regular runs (%i).\n", num_regular_runs);
	}
      return 1;
    }

  // This needs some foundation. Probably * 2^max_encryption_level
  //!@todo Fix this bound
  if ((switches.match < 2)
      && (num_intruder_runs >
	  ((double) switches.runs * max_encryption_level * 8)))
    {
      // Hardcoded limit on iterations
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned: %i intruder runs is too much. (max encr. level %i)\n",
	     num_intruder_runs, max_encryption_level);
	}
      return 1;
    }

  // Limit on exceeding any attack length
  if (get_semitrace_length () >= attack_length)
    {
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned: attack length %i.\n", attack_length);
	}
      return 1;
    }

  /* prune for cheaper */
  if (switches.prune == 2 && attack_leastcost <= attackCost (sys))
    {
      // We already had an attack at least this cheap.
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned: attack cost exceeds a previously found attack.\n");
	}
      return 1;
    }

  // Limit on attack count
  if (enoughAttacks (sys))
    return 1;

  // Limit on intruder events count
  if (switches.maxIntruderActions < INT_MAX || !(switches.intruder))
    {
      // Only check if actually used
      if (!(switches.intruder)
	  || countIntruderActions () > switches.maxIntruderActions)
	{
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: more than %i encrypt/decrypt events in the semitrace.\n",
		 switches.maxIntruderActions);
	    }
	  return 1;
	}
    }

  // No pruning because of bounds
  return 0;
}

//! Prune determination for specific properties
/**
 * Sometimes, a property holds in part of the tree. Thus, we don't need to explore that part further if we want to find an attack.
 *
 *@returns true iff this state is invalid for some reason
 */
int
prune_claim_specifics ()
{
  if (sys->current_claim->type == CLAIM_Niagree)
    {
      if (arachne_claim_niagree (sys, 0, sys->current_claim->ev))
	{
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: niagree holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  if (sys->current_claim->type == CLAIM_Nisynch)
    {
      if (arachne_claim_nisynch (sys, 0, sys->current_claim->ev))
	{
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: nisynch holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  return 0;
}

//! Setup system for specific claim test
add_claim_specifics (const Claimlist cl, const Roledef rd)
{
  if (cl->type == CLAIM_Secret)
    {
      /**
       * Secrecy claim
       */
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("* To verify the secrecy claim, we add the term ");
	  termPrint (rd->message);
	  eprintf (" as a goal.\n");
	  indentPrint ();
	  eprintf
	    ("* If all goals can be bound, this constitutes an attack.\n");
	}

      /**
       * We say that a state exists for secrecy, but we don't really test wheter the claim can
       * be reached (without reaching the attack).
       */
      cl->count = statesIncrease (cl->count);
      goal_add (rd->message, 0, cl->ev, 0);	// Assumption that all claims are in run 0
    }
}

//! Count a false claim
/**
 * Counts global attacks as well as claim instances.
 */
void
count_false ()
{
  sys->attackid++;
  sys->current_claim->failed = statesIncrease (sys->current_claim->failed);
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
      if (switches.latex == 1)
	{
	  latexSemiState ();
	}
      else
	{
	  dotSemiState (sys);
	}
    }

  // End wrapper
  attackOutputStop ();

  // Undo concretization
  makeTraceClass (sys, varlist);
}

//------------------------------------------------------------------------
// Main logic core
//------------------------------------------------------------------------

//! Check properties
int
property_check ()
{
  int flag;
  int cost;

  flag = 1;

  /* Do we need any? */
  if (enoughAttacks (sys))
    return flag;

  /**
   * By the way the claim is handled, this automatically means a flaw.
   */
  count_false ();
  if (switches.output == ATTACK)
    {
      arachneOutputAttack ();
    }
  // Store attack cost if cheaper
  cost = attackCost (sys);
  if (cost < attack_leastcost)
    {
      // Cheapest attack
      attack_leastcost = cost;
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("New cheaper attack found with cost %i.\n", cost);
	}
    }

  return flag;
}

//! Main recursive procedure for Arachne
int
iterate ()
{
  int flag;


  flag = 1;
  if (!prune_theorems ())
    {
      if (!prune_claim_specifics ())
	{
	  if (!prune_bounds ())
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

		  /**
		   * Check whether its a final state (i.e. all goals bound)
		   */

		  b = select_goal ();
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
		      flag = property_check ();
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
		  add_claim_specifics (cl,
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
      int maxstep;
      Roledef rd;

      index = 0;
      rd = sys->runs[run].start;
      maxstep = sys->runs[run].step;
      if (run == myrun && myindex > maxstep)
	{
	  // local run index can override real step
	  maxstep = myindex;
	}

      while (rd != NULL && index < maxstep)
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
