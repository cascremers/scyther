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
#include "states.h"
#include "mgu.h"
#include "arachne.h"

static System sys;
static Protocol INTRUDER;	// Pointers, to be set by the Init
static Role I_GOAL;		// Same here.

#ifdef DEBUG
static char *explanation;	// Pointer to a string that describes what we just tried to do
static int indentDepth;
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
  sys = mysys;			// make sys available for this module as a global
  /*
   * Add intruder protocol roles
   */
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

#ifdef DEBUG
//! Indent print
void
indentPrint ()
{
  int i;

  for (i = 0; i < indentDepth; i++)
    eprintf ("|   ");
}
#endif

//! Iterate but discard the info of the termlist
int
mgu_iterate (const Termlist tl)
{
  return iterate ();
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
		  int flag;

		  flag = func (p, r, rd, index);
		  if (!flag)
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

//! Generates a new intruder goal, iterates
/**
 * Sloppy, does not unify term but hardcodes it into the stuff.
 */
int
add_intruder_goal (Goal goal)
{
  int run;
  int flag;
  Roledef rd;

  roleInstance (sys, INTRUDER, I_GOAL, NULL);
  run = sys->maxruns - 1;
  goal.rd->bind_run = run;
  goal.rd->bind_index = 0;
  rd = sys->runs[run].start;
  termDelete (rd->message);
  rd->message = goal.rd->message;

#ifdef DEBUG
  explanation = "Adding intruder goal";
#endif
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

  flag = 1;
  for (run = 0; run < sys->maxruns; run++)
    {
      if (sys->runs[run].protocol == p && sys->runs[run].role == r)
	{
	  int i;
	  int old_length;
	  Roledef rd;

	  // find roledef entry
	  rd = sys->runs[run].start;
	  for (i = 0; i < index; i++)
	    rd = rd->next;

	  // mgu and iterate
	  old_length = sys->runs[run].length;
	  if (index >= old_length)
	    sys->runs[run].length = index + 1;
#ifdef DEBUG
	  explanation = "Bind existing run";
#endif
	  flag =
	    flag & termMguInTerm (goal.rd->message, rd->message, mgu_iterate);
	  sys->runs[run].length = old_length;
	}
    }
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

  roleInstance (sys, p, r, NULL);
  run = sys->maxruns - 1;
  sys->runs[run].length = index + 1;
  goal.rd->bind_run = run;
  goal.rd->bind_index = index;
  rd = roledef_shift (sys->runs[run].start, index);
#ifdef DEBUG
  explanation = "Bind new run";
#endif

  iterate ();

  goal.rd->bind_run = INVALID;
  roleInstanceDestroy (sys);
  return flag;
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
  int bind_this (Protocol p, Role r, Roledef rd, int index)
  {
    int element_f1 (Termlist substlist)
    {
      /**
       * Two options; as this, it is from an existing run,
       * or from a new one.
       *
       * Note that we only bind to regular runs here
       */
      int flag;

      if (p == INTRUDER)
	{
	  return 1;		// don't abort scans
	}
      flag = bind_existing_run (goal, p, r, index);
      if (flag)
	{
	  flag = bind_new_run (goal, p, r, index);
	}
      return flag;
    }

    // Test for interm unification
    return termMguInTerm (goal.rd->message, rd->message, element_f1);
  }

  // Bind to all possible sends?
  flag = iterate_role_sends (bind_this);
  // Bind to an intruder node?
  if (flag)
    {
      add_intruder_goal (goal);	// creates a new run
    }
  return flag;
}

//! Bind an intruder goal
int
bind_goal_intruder (const Goal goal)
{
  //!@todo Fix intruder goal stuff
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
#ifdef DEBUG
  indentDepth++;
#endif
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
	  eprintf ("%s\n", explanation);
	  explanation = NULL;
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
  indentDepth--;
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
  /*
   * set up claim role(s)
   */

  if (sys->maxruns > 0)
    {
      sys->runs[0].length = roledef_length (sys->runs[0].start);
    }

#ifdef DEBUG
  explanation = NULL;
  indentDepth = 0;
#endif

  /*
   * iterate
   */
  iterate ();
}
