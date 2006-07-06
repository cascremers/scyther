/**
 *
 *@file cost.c
 *
 * Determine cost of a given semitrace in sys
 * Constructed for Arachne results, unreliable otherwise.
 *
 */
#include "switches.h"
#include "system.h"
#include <limits.h>

//************************************************************************
// Private methods
//************************************************************************

//************************************************************************
// Public methods
//************************************************************************

//! Determine cost of an attack
/*
 * This should also work on uncompleted semitraces, and should be monotonous
 * (i.e. further iterations should increase the cost only) so that it can be
 * used for branch and bound.
 *
 * A lower value (closer to 0) is a more feasible attack.
 */
int
attackCost (const System sys)
{
  if (switches.prune == 0)
    {
      return 0;
    }
  if (switches.prune == 1)
    {
      // Select the first attack.
      // Implied by having the cost of traces after finding an attack to be always higher.
      //
      if (sys->current_claim->failed > 0)
	{
	  // we already have an attack
	  return INT_MAX;
	}
      else
	{
	  // return some value relating to the cost (anything less than int_max will do)
	  return 1;
	}
    }
  if (switches.prune == 2)
    {
      // Use nice heuristic cf. work of Gijs Hollestelle. Hand-picked parameters.
      int cost;

      cost = 0;

      //cost += get_semitrace_length ();

      cost += 10 * selfInitiators (sys);
      cost += 7 * selfResponders (sys);
      cost += 10 * sys->num_regular_runs;
      cost += 3 * countInitiators (sys);
      cost += 2 * countBindingsDone ();
      cost += 1 * sys->num_intruder_runs;

      return cost;
    }
  error ("Unknown pruning method (cost function not found)");
}
