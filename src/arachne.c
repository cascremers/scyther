/**
 *
 *@file arachne.c
 *
 * Introduces a method for proofs akin to the Athena modelchecker
 * http://www.ece.cmu.edu/~dawnsong/athena/
 *
 */

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

extern Term CLAIM_Secret;
extern Term CLAIM_Nisynch;
extern Term CLAIM_Niagree;
extern Term TERM_Agent;
extern Term TERM_Hidden;

static System sys;
static Claimlist current_claim;

Protocol INTRUDER;		// Pointers, to be set by the Init
Role I_M;			// Same here.
Role I_F;
Role I_T;
Role I_V;
Role I_R;
Role I_E;
Role I_D;
Role I_RRS;

static int indentDepth;
static int max_encryption_level;

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

/**
 * Program code
 */

//! Init Arachne engine
void
arachneInit (const System mysys)
{
  Term GVT;
  Roledef rd = NULL;
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
  GVT = makeGlobalVariable ("GlobalVariable");

  add_event (SEND, GVT);
  I_M = add_role ("I_M: Atomic message");

  add_event (READ, NULL);
  add_event (READ, NULL);
  add_event (SEND, NULL);
  I_RRS = add_role ("I_D: Encrypt");

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

//! Indent print
void
indentPrint ()
{
  int i;

  for (i = 0; i < indentDepth; i++)
    {
      if (i % 3 == 0)
	eprintf ("|");
      else
	eprintf (" ");
      eprintf (" ");
    }
}

//! Print indented binding
void
binding_indent_print (Binding b, int flag)
{
  indentPrint ();
  if (flag)
    eprintf ("!! ");
  binding_print (b);
  eprintf ("\n");
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
	  if (sys->output == PROOF)
	    {
	      if (count == 0)
		{
		  indentPrint ();
		  eprintf ("* Thus, we must also produce ");
		}
	      else
		{
		  eprintf (", ");
		}
	      termPrint (rd->message);
	    }
	  goal_add (rd->message, run, i);
	  count++;
	}
      rd = rd->next;
      i++;
    }
  if ((count > 0) && sys->output == PROOF)
    {
      eprintf ("\n");
    }
  return count;
}

//! Remove n goals
void
remove_read_goals (int n)
{
  while (n > 0)
    {
      goal_remove_last ();
      n--;
    }
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
      if (tl->term->type != VARIABLE && tl->term->right.runid == -3)
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
		  run = t->right.runid;
		}
	      else
		{
		  // Specific run: compare
		  if (run != t->right.runid)
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
  if (sys->output == PROOF)
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
	  eprintf (" length %i");
	}
      eprintf ("\n");
    }
}

//! Select a goal
void
proof_select_goal (Binding b)
{
  if (sys->output == PROOF)
    {
      Roledef rd;

      rd = roledef_shift (sys->runs[b->run_to].start, b->ev_to);
      indentDepth--;
      indentPrint ();
      eprintf ("Selected goal: Where does term ");
      termPrint (b->term);
      eprintf (" originate first?\n");
      indentPrint ();
      eprintf ("* It is required for ");
      roledefPrint (rd);
      eprintf (" at index %i in run %i\n", b->ev_to, b->run_to);
      indentDepth++;
    }
}

//! Cannot bind because of cycle
void
proof_cannot_bind (const Binding b, const int run, const int index)
{
  if (sys->output == PROOF)
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
  if (sys->output == PROOF)
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

//! Try to bind a specific existing run to a goal.
/**
 * The key goals are bound to the goal.
 *@param subterm determines whether it is a subterm unification or not.
 */
int
bind_existing_to_goal (const Binding b, const int run, const int index)
{
  Roledef rd;
  int flag;
  int old_length;
  int newgoals;

  int subterm_iterate (Termlist substlist, Termlist keylist)
  {
    int flag;

    flag = 1;
    if (goal_bind (b, run, index))
      {
	int keycount;
	Termlist tl;

	proof_suppose_binding (b);
	if (keylist != NULL && sys->output == PROOF)
	  {
	    indentPrint ();
	    eprintf
	      ("* This introduces the obligation to produce the following keys: ");
	    termlistPrint (keylist);
	    eprintf ("\n");
	  }
	keycount = 0;
	tl = keylist;
	while (tl != NULL)
	  {
	    int keyrun;

	    goal_add (tl->term, b->run_to, b->ev_to);
	    tl = tl->next;
	    keycount++;
	  }

	flag = flag && iterate ();

	while (keycount > 0)
	  {
	    goal_remove_last ();
	    keycount--;
	  }
      }
    else
      {
	proof_cannot_bind (b, run, index);
      }
    goal_unbind (b);
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
  flag = termMguSubTerm (b->term, rd->message,
			 subterm_iterate, sys->know->inverses, NULL);
  // Reset length
  remove_read_goals (newgoals);
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
	  if (sys->output == PROOF)
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
  if (sys->output == PROOF && found == 0)
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

  roleInstance (sys, p, r, NULL, NULL);
  run = sys->maxruns - 1;
  proof_suppose_run (run, 0, index + 1);
  newgoals = add_read_goals (run, 0, index + 1);
  indentDepth++;
  flag = bind_existing_to_goal (b, run, index);
  indentDepth--;
  remove_read_goals (newgoals);
  roleInstanceDestroy (sys);
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

//------------------------------------------------------------------------
// Larger logical componentents
//------------------------------------------------------------------------

//! Goal selection
/**
 * Should be ordered to prefer most constrained; for now, it is simply the first one encountered.
 */
Binding
select_goal ()
{
  List bl;
  Binding best;
  float min_constrain;

  min_constrain = 2;		// 1 is the maximum, but we want to initialize it.
  best = NULL;
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      if (!b->done)
	{
	  // We don't care about singular agent variables, so...
	  if (!
	      (isTermVariable (b->term)
	       && inTermlist (b->term->stype, TERM_Agent)))
	    {
	      float cons;

	      cons = term_constrain_level (b->term);
	      if (cons < min_constrain)
		{
		  min_constrain = cons;
		  best = b;
		}
	    }
	}
      bl = bl->next;
    }
  return best;
}

//! Create a new intruder run to generate knowledge from m0
int
bind_goal_new_m0 (const Binding b)
{
  Termlist m0tl;
  int flag;

  flag = 1;
  m0tl = knowledgeSet (sys->know);
  while (flag && m0tl != NULL)
    {
      Term m0t;
      Termlist subst;

      m0t = m0tl->term;
      subst = termMguTerm (b->term, m0t);
      if (subst != MGUFAIL)
	{
	  int run;

	  roleInstance (sys, INTRUDER, I_M, NULL, NULL);
	  run = sys->maxruns - 1;
	  proof_suppose_run (run, 0, 1);
	  sys->runs[run].start->message = termDuplicate (b->term);
	  sys->runs[run].length = 1;
	  indentDepth++;
	  if (goal_bind (b, run, 0))
	    {
	      proof_suppose_binding (b);
	      if (sys->output == PROOF)
		{
		  indentPrint ();
		  eprintf ("* Retrieving ");
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
	  roleInstanceDestroy (sys);
	  termlistSubstReset (subst);
	  termlistDelete (subst);
	}

      m0tl = m0tl->next;
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

  flag = 1;
  term = b->term;

  if (!realTermLeaf (term))
    {
      int run;
      int index;
      int newgoals;
      Roledef rd;
      Term t1, t2;

      if (realTermTuple (term))
	{
	  // tuple construction
	  error ("Goal that is a tuple should not occur!");
	}

      // must be encryption
      t1 = term->left.op;
      t2 = term->right.key;

      roleInstance (sys, INTRUDER, I_RRS, NULL, NULL);
      run = sys->maxruns - 1;
      rd = sys->runs[run].start;
      rd->message = termDuplicate (t1);
      rd->next->message = termDuplicate (t2);
      rd->next->next->message = termDuplicate (term);
      index = 2;
      proof_suppose_run (run, 0, index + 1);
      if (sys->output == PROOF)
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
      remove_read_goals (newgoals);
      roleInstanceDestroy (sys);
    }
  return flag;
}

//! Bind an intruder goal by intruder construction
/**
 * Handles the case where the intruder constructs a composed term himself.
 */
int
bind_goal_new_intruder_run (const Binding b)
{
  return (bind_goal_new_m0 (b) && bind_goal_new_encrypt (b));
}

//! Bind a regular goal
int
bind_goal_regular_run (const Binding b)
{
  int flag;
  int found;

  /*
   * This is a local function so we have access to goal
   */
  int bind_this_role_send (Protocol p, Role r, Roledef rd, int index)
  {
    int test_unification (Termlist substlist)
    {
      // A unification exists; return the signal
      return 0;
    }

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
	(b->term, rd->message, test_unification, sys->know->inverses, NULL))
      {
	int flag;

	// A good candidate
	found++;
	if (sys->output == PROOF)
	  {
	    indentPrint ();
	    eprintf ("* ");
	    termPrint (b->term);
	    eprintf (" matches the pattern ");
	    termPrint (rd->message);
	    eprintf (" from ");
	    termPrint (p->nameterm);
	    eprintf (", ");
	    termPrint (r->nameterm);
	    eprintf (", at %i\n", index);
	  }
	// Bind to existing run
	flag = bind_existing_run (b, p, r, index);
	// bind to new run
	flag = flag && bind_new_run (b, p, r, index);
	return flag;
      }
    else
      {
	return 1;
      }
  }

  // Bind to all possible sends of regular runs
#ifdef DEBUG
  if (DEBUGL (5))
    {
      indentPrint ();
      eprintf ("Try regular role send.\n");
    }
#endif
  found = 0;
  flag = iterate_role_sends (bind_this_role_send);
  if (sys->output == PROOF && found == 0)
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

#ifdef DEBUG
  if (DEBUGL (5))
    {
      indentPrint ();
      eprintf ("Try existing intruder send.\n");
    }
#endif

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
		  flag = flag && bind_existing_to_goal (b, run, ev);
		}
	      rd = rd->next;
	      ev++;
	    }
	}
    }
  return flag;
}

//! Bind a goal in all possible ways
int
bind_goal (const Binding b)
{
  if (!b->done)
    {
      int flag;

      proof_select_goal (b);
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("A. Suppose it is from a regular protocol role.\n");
	}
      indentDepth++;
      flag = bind_goal_regular_run (b);
      indentDepth--;
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("B. Suppose it is from an existing intruder run.\n");
	}
      indentDepth++;
      flag = flag && bind_goal_old_intruder_run (b);
      indentDepth--;
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("C. Suppose it is from a new intruder run.\n");
	}
      indentDepth++;
      flag = flag && bind_goal_new_intruder_run (b);
      indentDepth--;
      return flag;
    }
  else
    {
      return 1;
    }
}

//! Prune determination
/**
 *@returns true iff this state is invalid for some reason
 */
int
prune ()
{
  Termlist tl;
  List bl;

  if (indentDepth > 20)
    {
      // Hardcoded limit on iterations
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned because too many iteration levels.\n");
	}
      return 1;
    }
  if (sys->maxruns > sys->switchRuns)
    {
      // Hardcoded limit on runs
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned because too many runs.\n");
	}
      return 1;
    }

  // Check if all agents are valid
  tl = sys->runs[0].agents;
  while (tl != NULL)
    {
      Term agent;

      agent = deVar (tl->term);
      if (!realTermLeaf (agent))
	{
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned because agent cannot be compound term.\n");
	    }
	  return 1;
	}
      if (!inTermlist (agent->stype, TERM_Agent))
	{
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned because agent must contain agent type.\n");
	    }
	  return 1;
	}
      if (!realTermVariable (agent) && inTermlist (sys->untrusted, agent))
	{
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned because all agents of the claim run must be trusted.\n");
	    }
	  return 1;
	}
      tl = tl->next;
    }

  // Check for c-minimality
  if (!bindings_c_minimal ())
    {
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned because this is not <=c-minimal.\n");
	}
      return 1;
    }

  // Check for "Hidden" interm goals
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = bl->data;
      if (termInTerm (b->term, TERM_Hidden))
	{
	  // Prune the state: we can never meet this
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned because intruder can never construnct ");
	      termPrint (b->term);
	      eprintf ("\n");
	    }
	  return 1;
	}
      bl = bl->next;
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
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("* To verify the secrecy claim, we add the term ");
	  termPrint (rd->message);
	  eprintf (" as a goal.\n");
	  indentPrint ();
	  eprintf
	    ("* If all goals can be bound, this constitutes an attack.\n");
	}
      goal_add (rd->message, 0, cl->ev);	// Assumption that all claims are in run 0
    }
}

//! Count a false claim
void
count_false ()
{
  current_claim->failed = statesIncrease (current_claim->failed);
}

//------------------------------------------------------------------------
// Main logic core
//------------------------------------------------------------------------

//! Check properties
int
property_check ()
{
  int flag;

  flag = 1;
  if (current_claim->type == CLAIM_Secret)
    {
      // Secrecy claim
      /**
       * By the way the claim is handled, this automatically means a flaw.
       */
      count_false ();
      if (sys->output == ATTACK)
	printSemiState ();
    }
  return flag;
}

//! Main recursive procedure for Arachne
int
iterate ()
{
  int flag;

  flag = 1;
  if (!prune ())
    {
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
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("All goals are now bound.");
	    }
	  sys->claims = statesIncrease (sys->claims);
	  current_claim->count = statesIncrease (current_claim->count);
	  flag = flag && property_check ();
	}
      else
	{
	  /*
	   * bind this goal in all possible ways and iterate
	   */
	  flag = bind_goal (b);
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
  /*
   * set up claim role(s)
   */

  if (sys->maxruns > 0)
    {
      error ("Something is wrong, number of runs >0.");
    }

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
    if (tlevel > max_encryption_level)
      max_encryption_level = tlevel;
    return 1;
  }

  max_encryption_level = 0;
  iterate_role_sends (determine_encrypt_max);

#ifdef DEBUG
  if (DEBUGL (1))
    {
      eprintf ("Maximum encryption level: %i\n", max_encryption_level);
      iterate_role_sends (print_send);
    }
#endif

  indentDepth = 0;
  cl = sys->claimlist;
  while (cl != NULL)
    {
      /**
       * Check each claim
       */
      Protocol p;
      Role r;

      if (sys->switchClaimToCheck == NULL
	  || sys->switchClaimToCheck == cl->type)
	{
	  current_claim = cl;
	  p = (Protocol) cl->protocol;
	  r = (Role) cl->role;

	  roleInstance (sys, p, r, NULL, NULL);
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Testing Claim ");
	      termPrint (cl->type);
	      eprintf (" from ");
	      role_name_print (0);
	      eprintf (" at index %i.\n", cl->ev);
	    }
	  proof_suppose_run (0, 0, cl->ev + 1);
	  add_read_goals (sys->maxruns - 1, 0, cl->ev + 1);


	  /**
	   * Add specific goal info
	   */
	  add_claim_specifics (cl,
			       roledef_shift (sys->runs[0].start, cl->ev));

#ifdef DEBUG
	  if (DEBUGL (5))
	    {
	      printSemiState ();
	    }
#endif

	  /*
	   * iterate
	   */
	  iterate ();

	  //! Destroy
	  while (sys->maxruns > 0)
	    {
	      roleInstanceDestroy (sys);
	    }
	}
      // next
      cl = cl->next;
    }
}
