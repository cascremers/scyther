/**
 *@file arachne.c
 *
 * Introduces a method for proofs akin to the Athena modelchecker
 * http://www.ece.cmu.edu/~dawnsong/athena/
 *
 */

#include "term.h"
#include "role.h"
#include "system.h"
#include "arachne.h"

Term INTRUDER_ROLE;

struct goalstruct
{
  int run;
  int index;
};

typedef struct goalstruct Goal;

//! Init Arachne engine
void
arachneInit (const System sys)
{
  /*
   * Add intruder protocol roles
   */
  return;
}

//! Close Arachne engine
void
arachneDone (const System sys)
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
#define isGoal(rd)	(rd->type == READ)
#define isBound(rd)	(rd->bind_run != INVALID)
#define length		step

//------------------------------------------------------------------------
// Sub
//------------------------------------------------------------------------

//------------------------------------------------------------------------
// Larger logical componentents
//------------------------------------------------------------------------

//! Goal selection
/**
 * Should be ordered to prefer most constrained; for now, it is simply the first one encountered.
 */
Goal
select_goal (const System sys)
{
  Goal goal;
  int run;

  goal.run = INVALID;
  for (run = 0; run < sys->maxruns; run++)
    {
      Roledef rd;
      int index;

      index = 0;
      rd = runPointerGet (sys, run);
      while (rd != NULL && index < sys->runs[run].length)
	{
	  if (isGoal (rd) && !isBound (rd))
	    {
	      // Return this goal
	      goal.run = run;
	      goal.index = index;
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
bind_goal_regular (const System sys, const Goal goal)
{
}

//! Bind an intruder goal
int
bind_goal_intruder (const System sys, const Goal goal)
{
}

//! Bind a goal in all possible ways
int
bind_goal (const System sys, const Goal goal)
{
  if (isTermEqual (sys->runs[goal.run].protocol->nameterm, INTRUDER_ROLE))
    {
      return bind_goal_intruder (sys, goal);
    }
  else
    {
      return bind_goal_regular (sys, goal);
    }
}

//! Prune determination
/**
 *@returns true iff this state is invalid for some reason
 */
int
prune (const System sys)
{
  return 0;
}

//------------------------------------------------------------------------
// Main logic core
//------------------------------------------------------------------------

//! Main recursive procedure for Arachne
int
iterate (const System sys)
{
  Goal goal;

  /**
   * Possibly prune this state
   */

  if (prune (sys))
    return 0;

  /**
   * If not pruned, check whether its a final state (i.e. all goals bound)
   */

  goal = select_goal (sys);
  if (goal.run == INVALID)
    {
      /*
       * all goals bound, check for property
       */
      return 1;
    }
  else
    {
      /*
       * bind this goal in all possible ways and iterate
       */
      return bind_goal (sys, goal);
    }
}

//! Main code for Arachne
/**
 * For this test, we manually set up some stuff.
 */
int
arachne (const System sys)
{
  /*
   * set up claim role(s)
   */

  /*
   * iterate
   */
  iterate (sys);
}
