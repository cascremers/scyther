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
extern Term TERM_Function;

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
static int num_regular_runs;
static int num_intruder_runs;

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
  I_RRS = add_role ("I_E: Encrypt");

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
  if (t != NULL && inTermlist (t->stype, TERM_Function))
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
      if (realTermEncrypt (t) && isTermFunctionName (t->right.key))
	{
	  return t->right.key;
	}
    }
  return NULL;
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
		  eprintf ("Thus, we must also produce ");
		}
	      else
		{
		  eprintf (", ");
		}
	      termPrint (rd->message);
	    }
	  goal_add (rd->message, run, i, 0);
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
	  eprintf (" length %i", newlength);
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
  int found;

  int subterm_iterate (Termlist substlist, Termlist keylist)
  {
    int flag;

    found++;
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
	      ("This introduces the obligation to produce the following keys: ");
	    termlistPrint (keylist);
	    eprintf ("\n");
	  }
	keycount = 0;
	tl = keylist;
	while (tl != NULL)
	  {
	    int keyrun;

	    goal_add (tl->term, b->run_to, b->ev_to, 1);
	    tl = tl->next;
	    keycount++;
	  }

	indentDepth++;
	flag = flag && iterate ();
	indentDepth--;

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
  found = 0;
  flag = termMguSubTerm (b->term, rd->message,
			 subterm_iterate, sys->know->inverses, NULL);
  // Did it work?
  if (found == 0 && sys->output == PROOF)
    {
      indentPrint ();
      eprintf ("Cannot bind ");
      termPrint (b->term);
      eprintf (" to run %i, index %i because it does not subterm-unify.\n",
	       run, index);
    }
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

  run = semiRunCreate (p, r);
  proof_suppose_run (run, 0, index + 1);
  newgoals = add_read_goals (run, 0, index + 1);
  indentDepth++;
  flag = bind_existing_to_goal (b, run, index);
  indentDepth--;
  remove_read_goals (newgoals);
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
 * Selects the most constrained goal.
 *
 * First selection is on level; thus, keys are selected first.
 *
 * Because the list starts with the newest terms, and we use <= (as opposed to <), we
 * ensure that for goals with equal constraint levels, we select the oldest one.
 */
Binding
select_goal ()
{
  List bl;
  Binding best;
  float min_constrain;
  int max_level;

  if (sys->output == PROOF)
    {
      indentPrint ();
      eprintf ("Listing open goals that might be chosen: ");
    }
  max_level = -1;		// 0 is the minimum level
  best = NULL;
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      if (!b->done)
	{
	  // We don't care about singular variables.
	  /**
	   * Note that to mirror the modelchecker semantics, we should check whether the type exists in M_0.
	   */
	  if (!isTermVariable (b->term))
	    {
	      float cons;

	      if (sys->output == PROOF && best != NULL)
		eprintf (", ");
	      if (b->level >= max_level)
		{
		  if (b->level > max_level)
		    {
		      max_level = b->level;
		      min_constrain = 1;	// 1 is the maximum
		    }
		  cons = term_constrain_level (b->term);
		  if (cons <= min_constrain)
		    {
		      min_constrain = cons;
		      best = b;
		      if (sys->output == PROOF)
			eprintf ("*");
		    }
		}
	      if (sys->output == PROOF)
		{
		  termPrint (b->term);
		  eprintf ("[%i]", b->level);
		}
	    }
	}
      bl = bl->next;
    }
  if (sys->output == PROOF)
    {
      if (best == NULL)
	eprintf ("none");
      eprintf ("\n");
    }
  return best;
}

//! Create a new intruder run to generate knowledge from m0
int
bind_goal_new_m0 (const Binding b)
{
  Termlist m0tl;
  int flag;
  int found;

  flag = 1;
  found = 0;
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

	  run = semiRunCreate (INTRUDER, I_M);
	  proof_suppose_run (run, 0, 1);
	  sys->runs[run].start->message = termDuplicate (b->term);
	  sys->runs[run].length = 1;
	  indentDepth++;
	  if (goal_bind (b, run, 0))
	    {
	      found++;
	      proof_suppose_binding (b);
	      if (sys->output == PROOF)
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
	  semiRunDestroy ();

	  termlistSubstReset (subst);
	  termlistDelete (subst);
	}

      m0tl = m0tl->next;
    }

  if (found == 0 && sys->output == PROOF)
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
      t1 = term->left.op;
      t2 = term->right.key;

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
	  semiRunDestroy ();
	}
    }

  if (!can_be_encrypted)
    {
      if (sys->output == PROOF)
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
 * Handles the case where the intruder constructs a composed term himself.
 */
int
bind_goal_new_intruder_run (const Binding b)
{
  int flag;

  if (sys->output == PROOF)
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
	if (sys->output == PROOF && found == 1)
	  {
	    indentPrint ();
	    eprintf ("The term ", found);
	    termPrint (b->term);
	    eprintf
	      (" matches patterns from the role definitions. Investigate.\n");
	  }
	if (sys->output == PROOF)
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
	flag = bind_existing_run (b, p, r, index);
	// bind to new run
	flag = flag && bind_new_run (b, p, r, index);
	indentDepth--;
	return flag;
      }
    else
      {
	return 1;
      }
  }

 
  // Bind to all possible sends of regular runs
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
		  if (sys->output == PROOF && found == 1)
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
  if (sys->output == PROOF && found == 0)
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
  if (!b->done)
    {
      int flag;
      int know_only;
      Term function;

      proof_select_goal (b);
      indentDepth++;

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
	      if (sys->output == PROOF)
		{
		  indentPrint ();
		  eprintf ("* Because ");
		  termPrint (b->term);
		  eprintf (" is never sent from a regular run (STILL NEEDS LEMMA!), we only intruder construct it.\n");
		}
	      know_only = 1;
	    }
	}
      
      if (know_only)
	{
	  // Special case: only from intruder
          flag = flag && bind_goal_old_intruder_run (b);
          flag = flag && bind_goal_new_intruder_run (b);
	}
      else
	{
	  // Normal case
	  flag = bind_goal_regular_run (b);
	  flag = flag && bind_goal_old_intruder_run (b);
	  flag = flag && bind_goal_new_intruder_run (b);
	}

      indentDepth--;
      return flag;
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
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned because intruder can never construnct ");
	      termPrint (b->term);
	      eprintf ("\n");
	    }
	  return 1;
	}

      // Check for encryption levels
      if (sys->match < 2
	  && (term_encryption_level (b->term) > max_encryption_level))
	{
	  // Prune: we do not need to construct such terms
	  if (sys->output == PROOF)
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
	      if (sys->output == PROOF)
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

  if (num_regular_runs > sys->switchRuns)
    {
      // Hardcoded limit on runs
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned: too many regular runs (%i).\n", num_regular_runs);
	}
      return 1;
    }

  // This needs some foundation. Probably * 2^max_encryption_level
  //!@todo Fix this bound
  if ((sys->match < 2)
      && (num_intruder_runs >
	  ((double) sys->switchRuns * max_encryption_level * 8)))
    {
      // Hardcoded limit on iterations
      if (sys->output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned: %i intruder runs is too much. (max encr. level %i)\n",
	     num_intruder_runs, max_encryption_level);
	}
      return 1;
    }
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
  if (current_claim->type == CLAIM_Niagree)
    {
      if (arachne_claim_niagree (sys, 0, current_claim->ev))
	{
          current_claim->count = statesIncrease (current_claim->count);
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned: niagree holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  if (current_claim->type == CLAIM_Nisynch)
    {
      if (arachne_claim_nisynch (sys, 0, current_claim->ev))
	{
          current_claim->count = statesIncrease (current_claim->count);
	  if (sys->output == PROOF)
	    {
	      indentPrint ();
	      eprintf ("Pruned: nisynch holds in this part of the proof tree.\n");
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

      /**
       * We say that a state exists for secrecy, but we don't really test wheter the claim can
       * be reached (without reaching the attack).
       */
      cl->count = statesIncrease (cl->count);
      goal_add (rd->message, 0, cl->ev, 0);	// Assumption that all claims are in run 0
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

  /**
   * By the way the claim is handled, this automatically means a flaw.
   */
  count_false ();
  if (sys->output == ATTACK)
    printSemiState ();

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
		      eprintf ("All goals are now bound.\n");
		    }
		  sys->claims = statesIncrease (sys->claims);
		  current_claim->count = statesIncrease (current_claim->count);
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
	  else
	    {
	      // Pruned because of bound!
	      current_claim->complete = 0;
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
    if (tlevel > max_encryption_level)
      max_encryption_level = tlevel;
    return 1;
  }

  /*
   * set up claim role(s)
   */

  if (sys->maxruns > 0)
    {
      error ("Something is wrong, number of runs >0.");
    }

  num_regular_runs = 0;
  num_intruder_runs = 0;

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
	  int run;

	  current_claim = cl;
	  cl->complete = 1;
	  p = (Protocol) cl->protocol;
	  r = (Role) cl->role;

	  if (sys->output == PROOF)
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
			       roledef_shift (sys->runs[run].start, cl->ev));
#ifdef DEBUG
	  if (DEBUGL (5))
	    {
	      printSemiState ();
	    }
#endif
	  // Iterate
	  iterate ();

	  //! Destroy
	  while (sys->bindings != NULL)
	    {
	      remove_read_goals (1);
	    }
	  while (sys->maxruns > 0)
	    {
	      semiRunDestroy ();
	    }
	  indentDepth--;
	}
      // next
      cl = cl->next;
    }
}
