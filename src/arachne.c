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

static System sys;
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

#ifdef DEBUG
static char *explanation;	// Pointer to a string that describes what we just tried to do
static int e_run;
static Term e_term1;
static Term e_term2;
static Term e_term3;
#endif

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
#ifdef DEBUG
  int i;

  for (i = 0; i < indentDepth; i++)
    eprintf ("%i    ", i);
#else
  eprintf (">> ");
#endif
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


//! Iterate but discard the info of the termlist
int
mgu_iterate (const Termlist tl)
{
  return iterate ();
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
	  goal_add (rd->message, run, i);
	  count++;
	}
      rd = rd->next;
      i++;
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
bind_existing_to_goal (const Binding b, const int index, const int run,
		       const int subterm)
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

#ifdef DEBUG
	if (DEBUGL (5))
	  {
	    binding_indent_print (b, 0);
	    indentPrint ();
	    eprintf ("Adding key list for subterm iteration: ");
	    termlistPrint (keylist);
	    eprintf ("\n");
	  }
#endif
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
#ifdef DEBUG
	if (DEBUGL (5))
	  {
	    indentPrint ();
	    eprintf ("Aborted binding existing run because of cycle.\n");
	  }
#endif
	flag = 0;
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

#ifdef DEBUG
  if (DEBUGL (3))
    {
      explanation = "Bind existing run (generic) ";
      e_run = run;
      e_term1 = b->term;
    }
#endif
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
		   const int index, const int subterm)
{
  int run, flag;

#ifdef DEBUG
  if (DEBUGL (4))
    {
      indentPrint ();
      eprintf ("Trying to bind ");
      termPrint (b->term);
      eprintf (" to an existing (of %i runs) instance of ", sys->maxruns);
      termPrint (p->nameterm);
      eprintf (", ");
      termPrint (r->nameterm);
      eprintf (" (%i)\n", subterm);
    }
#endif
  flag = 1;
  for (run = 0; run < sys->maxruns; run++)
    {
      if (sys->runs[run].protocol == p && sys->runs[run].role == r)
	{
	  flag = flag && bind_existing_to_goal (b, index, run, subterm);
	}
    }
  return flag;
}

//! Bind a goal to a new run
int
bind_new_run (const Binding b, const Protocol p, const Role r,
	      const int index, const int subterm)
{
  int run;
  int flag;
  int newgoals;

  roleInstance (sys, p, r, NULL, NULL);
  run = sys->maxruns - 1;
  newgoals = add_read_goals (run, 0, index + 1);
#ifdef DEBUG
  if (DEBUGL (4))
    {
      indentPrint ();
      eprintf ("Trying to bind ");
      termPrint (b->term);
      eprintf (" to a new instance of ");
      termPrint (p->nameterm);
      eprintf (", ");
      termPrint (r->nameterm);
      eprintf (", run %i (subterm:%i)\n", run, subterm);
    }
#endif
  flag = bind_existing_to_goal (b, index, run, 1);
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
	  // We don't care about singular variables, so...
	  if (!isTermVariable (b->term))
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

//! Bind an intruder goal by intruder construction
/**
 * Handles the case where the intruder constructs a composed term himself.
 */
int
bind_goal_new_intruder_run (const Binding b)
{
  Term term;
  Termlist m0tl;
  int flag;
  int run;

  flag = 1;
  term = b->term;
  /**
   * Three options.
   *
   * 1. Constructed from smaller composite terms
   */
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
      newgoals = add_read_goals (run, 0, index+1);
#ifdef DEBUG
      if (DEBUGL (3))
	{
	  indentPrint ();
	  eprintf ("Encrypting ");
	  termPrint (term);
	  eprintf (" using term ");
	  termPrint (t1);
	  eprintf (" and key ");
	  termPrint (t2);
	  eprintf ("\n");
	}
#endif
      if (goal_bind (b, run, index))
	{
          flag = flag && iterate ();
	}
      goal_unbind (b);
      remove_read_goals (newgoals);
      roleInstanceDestroy (sys);
    }
  /**
   * 2. Constructed from bigger term and decryption key
   */
  /*
     if (!realTermLeaf (term))
     {
     if (realTermEncrypt (term))
     {
     Term t1, t2;

     t1 = term->left.op;
     t2 = term->right.key;

     goal_add (t1, b->run_to, b->ev_to);
     goal_add (t2, b->run_to, b->ev_to);
     #ifdef DEBUG
     if (DEBUGL (3))
     {
     indentPrint ();
     eprintf ("Deriving ");
     termPrint (term);
     eprintf (" from encrypted term ");
     termPrint (t1);
     eprintf (" and key ");
     termPrint (t2);
     eprintf ("\n");
     }
     #endif
     flag = flag && iterate ();
     goal_remove_last ();
     goal_remove_last ();
     }

     }
   */

  /**
   * 3. Retrieved from M_0
   */
  m0tl = knowledgeSet (sys->know);
  while (flag && m0tl != NULL)
    {
      Term m0t;
      Termlist subst;

      m0t = m0tl->term;
      subst = termMguTerm (term, m0t);
      if (subst != MGUFAIL)
	{
	  int run;

	  roleInstance (sys, INTRUDER, I_M, NULL, NULL);
	  run = sys->maxruns - 1;
	  sys->runs[run].start->message = termDuplicate (term);
	  sys->runs[run].length = 1;
	  if (goal_bind (b, run, 0))
	    {
#ifdef DEBUG
	      if (DEBUGL (3))
		{
		  if (DEBUGL (5))
		    {
		      binding_indent_print (b, 0);
		    }
		  indentPrint ();
		  eprintf ("Retrieving ");
		  termPrint (term);
		  eprintf (" from the initial knowledge.\n");
		}
#endif
	      flag = flag && iterate ();
	    }
	  goal_unbind (b);
	  roleInstanceDestroy (sys);
	  termlistSubstReset (subst);
	  termlistDelete (subst);
	}

      m0tl = m0tl->next;
    }
  termlistDelete (m0tl);
  /**
   * return result
   */
  return flag;
}


//! Bind a regular goal
int
bind_goal_regular_run (const Binding b)
{
  int flag;

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
#ifdef DEBUG
	if (DEBUGL (5))
	  {
	    indentPrint ();
	    eprintf ("Term ");
	    termPrint (b->term);
	    eprintf (" can possibly be bound by role ");
	    termPrint (r->nameterm);
	    eprintf (", index %i\n", index);
	  }
#endif
	// Bind to existing run
	flag = bind_existing_run (b, p, r, index, 1);
	// bind to new run
	flag = flag && bind_new_run (b, p, r, index, 1);
	return flag;
      }
    else
      {
	// Cannot unify: no attacks
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
  return iterate_role_sends (bind_this_role_send);
}


// Bind to all possible sends of intruder runs
int bind_goal_old_intruder_run (Binding b)
{
  int run;
  int flag;

#ifdef DEBUG
  if (DEBUGL (5))
    {
      indentPrint ();
      eprintf ("Try regular intruder send.\n");
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
                  flag = flag && bind_existing_to_goal (b, ev, run, 1);
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

      flag = bind_goal_regular_run (b);
      flag = flag && bind_goal_old_intruder_run (b);
      flag = flag && bind_goal_new_intruder_run (b);
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

  if (indentDepth > 20)
    {
      // Hardcoded limit on iterations
#ifdef DEBUG
      if (DEBUGL (3))
	{
	  indentPrint ();
	  eprintf ("Pruned because too many iteration levels.\n");
	}
#endif
      return 1;
    }
  if (sys->maxruns > sys->switchRuns)
    {
      // Hardcoded limit on runs
#ifdef DEBUG
      if (DEBUGL (3))
	{
	  indentPrint ();
	  eprintf ("Pruned because too many runs.\n");
	}
#endif
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
#ifdef DEBUG
	  if (DEBUGL (3))
	    {
	      indentPrint ();
	      eprintf ("Pruned because agent cannot be compound term.\n");
	    }
#endif
	  return 1;
	}
      if (!inTermlist (agent->stype, TERM_Agent))
	{
#ifdef DEBUG
	  if (DEBUGL (3))
	    {
	      indentPrint ();
	      eprintf ("Pruned because agent must contain agent type.\n");
	    }
#endif
	  return 1;
	}
      if (!realTermVariable (agent) && inTermlist (sys->untrusted, agent))
	{
#ifdef DEBUG
	  if (DEBUGL (3))
	    {
	      indentPrint ();
	      eprintf
		("Pruned because all agents of the claim run must be trusted.\n");
	    }
#endif
	  return 1;
	}
      tl = tl->next;
    }

  // Check for c-minimality
  if (!bindings_c_minimal ())
    {
#ifdef DEBUG
      if (DEBUGL (3))
	{
	  indentPrint ();
	  eprintf ("Pruned because this is not <=c-minimal.\n");
	}
#endif
      return 1;
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
      goal_add (rd->message, 0, cl->ev);	// Assumption that all claims are in run 0
    }
}

//------------------------------------------------------------------------
// Main logic core
//------------------------------------------------------------------------

//! Main recursive procedure for Arachne
int
iterate ()
{
  int flag;

  flag = 1;
  indentDepth++;
  if (!prune ())
    {
      Binding b;

      /**
       * Not pruned: count
       */

      sys->states = statesIncrease (sys->states);
#ifdef DEBUG
      if (DEBUGL (3) && explanation != NULL)
	{
	  indentDepth--;
	  indentPrint ();
	  indentDepth++;
	  eprintf ("ITERATE: %s", explanation);

	  if (e_run != INVALID)
	    eprintf ("#%i ", e_run);
	  if (e_term1 != NULL)
	    {
	      termPrint (e_term1);
	      eprintf (" ");
	    }
	  if (e_term2 != NULL)
	    {
	      termPrint (e_term2);
	      eprintf (" ");
	    }
	  if (e_term3 != NULL)
	    {
	      termPrint (e_term3);
	      eprintf (" ");
	    }
	  eprintf (" ]}>=--\n");
	}
#endif

      /**
       * Check whether its a final state (i.e. all goals bound)
       */

      b = select_goal ();
      if (b == NULL)
	{
	  /*
	   * all goals bound, check for property
	   */
	  sys->claims = statesIncrease (sys->claims);
#ifdef DEBUG
	  if (DEBUGL (3))
	    {
	      printSemiState ();
	    }
#endif
	  //!@todo Property check in Arachne.
	}
      else
	{
#ifdef DEBUG
	  if (DEBUGL (3))
	    {
	      indentPrint ();
	      eprintf ("Trying to bind goal ");
	      termPrint (b->term);
	      eprintf (" from run %i, index %i.\n", b->run_to, b->ev_to);
	    }
#endif
	  /*
	   * bind this goal in all possible ways and iterate
	   */
	  flag = bind_goal (b);
	}
    }
#ifdef DEBUG
  explanation = NULL;
  e_run = INVALID;
  e_term1 = NULL;
  e_term2 = NULL;
  e_term3 = NULL;
#endif
  indentDepth--;
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
#ifdef DEBUG
	  explanation = NULL;
	  e_run = INVALID;
	  e_term1 = NULL;
	  e_term2 = NULL;
	  e_term3 = NULL;
#endif

	  p = (Protocol) cl->protocol;
	  r = (Role) cl->role;
#ifdef DEBUG
	  if (DEBUGL (2))
	    {
	      indentPrint ();
	      eprintf ("Testing Claim ");
	      termPrint (cl->type);
	      eprintf (" in protocol ");
	      termPrint (p->nameterm);
	      eprintf (", role ");
	      termPrint (r->nameterm);
	      eprintf (" at index %i.\n", cl->ev);
	    }
#endif

	  roleInstance (sys, p, r, NULL, NULL);
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
