/**
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
#include "compiler.h"
#include "states.h"
#include "mgu.h"
#include "arachne.h"

static System sys;
Protocol INTRUDER;		// Pointers, to be set by the Init
Role I_GOAL;			// Same here.
Role I_TEE;
Role I_SPLIT;
Role I_TUPLE;
Role I_ENCRYPT;
Role I_DECRYPT;

static int indentDepth;

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
  Roledef rd = NULL;

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

  add_event (READ, NULL);
  I_GOAL = add_role (" I_GOAL ");

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
#define isBound(rd)	(rd->bind_run != INVALID)
#define length		step

//! Indent print
void
indentPrint ()
{
#ifdef DEBUG
  int i;

  for (i = 0; i < indentDepth; i++)
    eprintf ("|   ");
#else
  eprintf (">> ");
#endif
}

//! Iterate but discard the info of the termlist
int
mgu_iterate (const Termlist tl)
{
  return iterate ();
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

//! Generate a new intruder goal
int
create_intruder_goal (Term t)
{
  int run;
  Roledef rd;

  roleInstance (sys, INTRUDER, I_GOAL, NULL);
  run = sys->maxruns - 1;
  rd = sys->runs[run].start;
  sys->runs[run].length = 1;
  rd->message = termDuplicate (t);
#ifdef DEBUG
  explanation = "Adding intruder goal for message ";
  e_term1 = t;
#endif
  return run;
}

//! Generates a new intruder goal, iterates
/**
 * Sloppy, does not unify term but hardcodes it into the stuff.
 */
int
add_intruder_goal_iterate (Goal goal)
{
  // [x][todo][cc] remove debug you know the drill
  //!@debug Remove this
  return 1;

  int flag;
  int run;

  run = create_intruder_goal (goal.rd->message);
  goal.rd->bind_run = run;
  goal.rd->bind_index = 0;

  flag = iterate ();

  roleInstanceDestroy (sys);	// destroy the created run
  goal.rd->bind_run = INVALID;
  return flag;
}

//! Bind a goal to an existing regular run, if possible
int
bind_existing_run (const Goal goal, const Protocol p, const Role r,
		   const int index)
{
  int run, flag;

#ifdef DEBUG
  indentPrint ();
  eprintf ("Trying to bind ");
  termPrint (goal.rd->message);
  eprintf (" to an existing instance of ");
  termPrint (p->nameterm);
  eprintf (", ");
  termPrint (r->nameterm);
  eprintf ("\n");
#endif
  flag = 1;
  goal.rd->bind_index = index;
  for (run = 0; run < sys->maxruns; run++)
    {
      if (sys->runs[run].protocol == p && sys->runs[run].role == r)
	{
	  int old_length;
	  Roledef rd;

	  // Roledef entry
	  rd = roledef_shift (sys->runs[run].start, index);

	  // mgu and iterate
	  old_length = sys->runs[run].length;
	  if (index >= old_length)
	    sys->runs[run].length = index + 1;
#ifdef DEBUG
	  explanation = "Bind existing run";
	  e_run = run;
	  e_term1 = goal.rd->message;
#endif
	  goal.rd->bind_run = run;

	  flag = (flag
		  && termMguInTerm (goal.rd->message, rd->message,
				    mgu_iterate));
	  sys->runs[run].length = old_length;
	}
    }
  goal.rd->bind_run = -1;
  return flag;
}

//! Bind a goal to a new run
int
bind_new_run (const Goal goal, const Protocol p, const Role r,
	      const int index)
{
  int run;
  int flag;
  Roledef rd;
  int old_run;
  int old_index;

  roleInstance (sys, p, r, NULL);
  run = sys->maxruns - 1;
  sys->runs[run].length = index + 1;
  old_run = goal.rd->bind_run;
  old_index = goal.rd->bind_index;
  goal.rd->bind_run = run;
  goal.rd->bind_index = index;
#ifdef DEBUG
  explanation = "Bind new run";
  e_run = run;
  e_term1 = r->nameterm;
  rd = roledef_shift (sys->runs[run].start, index);
  e_term2 = rd->message;
#endif

  flag = iterate ();

  goal.rd->bind_run = old_run;
  goal.rd->bind_index = old_index;

  roleInstanceDestroy (sys);
  return flag;
}

//! Print the current semistate
void
printSemiState ()
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      int index;
      Roledef rd;

      indentPrint ();
      eprintf ("[ Run %i, ", run);
      termPrint (sys->runs[run].role->nameterm);
      eprintf (" ]\n");

      index = 0;
      rd = sys->runs[run].start;
      while (index < sys->runs[run].length)
	{
	  indentPrint ();
	  eprintf ("\\ %i ", index);
	  roledefPrint (rd);
	  eprintf ("\n");
	  index++;
	  rd = rd->next;
	}
    }
}

//------------------------------------------------------------------------
// Larger logical componentents
//------------------------------------------------------------------------

//! Goal selection
/**
 * Should be ordered to prefer most constrained; for now, it is simply the first one encountered.
 */
Goal
select_goal ()
{
  Goal goal;
  int run;

  goal.run = INVALID;
  goal.rd = NULL;
  for (run = 0; run < sys->maxruns; run++)
    {
      Roledef rd;
      int index;

      index = 0;
      rd = sys->runs[run].start;
      while (rd != NULL && index < sys->runs[run].length)
	{
	  if (isGoal (rd) && !isBound (rd))
	    {
	      // Return this goal
	      goal.run = run;
	      goal.index = index;
	      goal.rd = rd;
	      return goal;
	    }
	  index++;
	  rd = rd->next;
	}
    }
  return goal;
}

//! Bind a regular goal
int
bind_goal_regular (const Goal goal)
{
  int flag;
  /*
   * This is a local function so we have access to goal
   */
  int bind_this_role_send (Protocol p, Role r, Roledef rd, int index)
  {
    int bind_this_unification (Termlist substlist)
    {
      int run, flag;

      run = determine_unification_run (substlist);
      if (run == -1)
	return 1;
#ifdef DEBUG
      indentPrint ();
      eprintf ("Term ");
      termPrint (goal.rd->message);
      eprintf (" can possibly be bound by role ");
      termPrint (r->nameterm);
      eprintf (", index %i, forced_run %i\n", index, run);
#endif
      /**
       * Two options; as this, it is from an existing run,
       * or from a new one.
       */
      flag = 1;
      if (run == -2)
	{
	  flag = flag && bind_new_run (goal, p, r, index);
	}
      return (flag && bind_existing_run (goal, p, r, index));
    }

    if (p == INTRUDER)
      {
	/* only bind to regular runs */
	return 1;
      }
    else
      {
	// Test for interm unification
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
	return termMguInTerm (goal.rd->message, rd->message,
			      bind_this_unification);
      }
  }

  // Bind to all possible sends or intruder node;
#ifdef DEBUG
  indentPrint ();
  eprintf ("Try regular role send.\n");
#endif
  flag = iterate_role_sends (bind_this_role_send);
#ifdef DEBUG
  indentPrint ();
  eprintf ("Try intruder send.\n");
#endif
  return (flag && add_intruder_goal_iterate (goal));
}

//! Bind an intruder goal to a regular run
int
bind_intruder_to_regular (Goal goal)
{
  int bind_this_roleevent (Protocol p, Role r, Roledef rd, int index)
  {
    int bind_this_unification (Termlist substlist, Termlist keylist)
    {
      int flag;
      int keygoals;
      Termlist tl;
      int run;

      run = determine_unification_run (substlist);
      if (run == -1)
	return 1;

      /**
       * the list of keys is added as a new goal.
       */
      keygoals = 0;
      tl = keylist;
      while (tl != NULL)
	{
	  keygoals++;
	  create_intruder_goal (tl->term);
	  //!@todo This needs a mapping Pi relation as well.

	  tl = tl->next;
	}
      /**
       * Two options; as this, it is from an existing run,
       * or from a new one.
       */

      flag = 1;
      if (run == -2)
	{
	  flag = flag && bind_new_run (goal, p, r, index);
	}
      flag = flag && bind_existing_run (goal, p, r, index);

      /**
       * deconstruct key list goals
       */
      while (keygoals > 0)
	{
	  roleInstanceDestroy (sys);
	  keygoals--;
	}

      return flag;
    }

  /**
   * Note that we only bind to regular runs here
   */
    if (p == INTRUDER)
      {
	return 1;		// don't abort scans
      }
    else
      {				// Test for subterm unification
	return termMguSubTerm (goal.rd->message, rd->message,
			       bind_this_unification, sys->know->inverses,
			       NULL);
      }
  }

  // Bind to all possible sends?
  return iterate_role_sends (bind_this_roleevent);
}

//! Bind an intruder goal by intruder construction
/**
 * Handles the case where the intruder constructs a composed term himself.
 */
int
bind_intruder_to_construct (const Goal goal)
{
  Term term;

  term = goal.rd->message;
  if (!realTermLeaf (term))
    {
      Term t1, t2;
      int flag;

      if (realTermTuple (term))
	{
	  // tuple construction
	  t1 = term->left.op1;
	  t2 = term->right.op2;
	}
      else
	{
	  // must be encryption
	  t1 = term->left.op;
	  t2 = term->right.key;
	}
      create_intruder_goal (t1);
      create_intruder_goal (t2);

      flag = iterate ();

      roleInstanceDestroy (sys);
      roleInstanceDestroy (sys);
      return flag;
    }
  else
    {
      return 1;
    }
}


//! Bind an intruder goal
/**
 * Computes F2 as in Athena explanations.
 */
int
bind_goal_intruder (const Goal goal)
{
  return (bind_intruder_to_regular (goal) &&
	  bind_intruder_to_construct (goal));
}

//! Bind a goal in all possible ways
int
bind_goal (const Goal goal)
{
  if (sys->runs[goal.run].protocol == INTRUDER)
    {
      return bind_goal_intruder (goal);
    }
  else
    {
      return bind_goal_regular (goal);
    }
}

//! Prune determination
/**
 *@returns true iff this state is invalid for some reason
 */
int
prune ()
{
  if (indentDepth > 10)
    {
      // Hardcoded limit on iterations
#ifdef DEBUG
      indentPrint ();
      eprintf ("Pruned because too many iteration levels.\n");
#endif
      return 1;
    }
  if (sys->maxruns > 5)
    {
      // Hardcoded limit on runs
#ifdef DEBUG
      indentPrint ();
      eprintf ("Pruned because too many runs.\n");
#endif
      return 1;
    }
  return 0;
}

//------------------------------------------------------------------------
// Main logic core
//------------------------------------------------------------------------

//! Main recursive procedure for Arachne
int
iterate ()
{
  int flag;
  Goal goal;

  flag = 1;
  indentDepth++;
  if (!prune ())
    {
      /**
       * Not pruned: count
       */

      sys->states = statesIncrease (sys->states);
#ifdef DEBUG
      if (explanation != NULL)
	{
	  indentPrint ();
	  eprintf ("%s ", explanation);

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
	  eprintf ("\n");
	}
#endif

      /**
       * Check whether its a final state (i.e. all goals bound)
       */

      goal = select_goal ();
      if (goal.run == INVALID)
	{
	  /*
	   * all goals bound, check for property
	   */
	  sys->claims = statesIncrease (sys->claims);
	  printSemiState ();
	  //!@todo Property check in Arachne.
	}
      else
	{
#ifdef DEBUG
	  indentPrint ();
	  eprintf ("Trying to bind goal ");
	  termPrint (goal.rd->message);
	  eprintf (" from run %i, index %i.\n", goal.run, goal.index);
#endif
	  /*
	   * bind this goal in all possible ways and iterate
	   */
	  flag = bind_goal (goal);
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
  /*
   * set up claim role(s)
   */

  if (sys->maxruns > 0)
    {
      sys->runs[0].length = roledef_length (sys->runs[0].start);
    }

#ifdef DEBUG
  int print_send (Protocol p, Role r, Roledef rd, int index)
  {
    eprintf ("IRS: ");
    termPrint (p->nameterm);
    eprintf (", ");
    termPrint (r->nameterm);
    eprintf (", %i, ", index);
    roledefPrint (rd);
    eprintf ("\n");
  }

  iterate_role_sends (print_send);

  explanation = NULL;
  e_run = INVALID;
  e_term1 = NULL;
  e_term2 = NULL;
  e_term3 = NULL;
#endif
  indentDepth = 0;
  printSemiState ();

  /*
   * iterate
   */
  iterate ();
}
