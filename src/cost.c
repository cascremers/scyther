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
  int cost;

  cost = 0;

  cost += get_semitrace_length ();
  cost += 8 * selfInitiators (sys);
  cost += 4 * selfResponders (sys);

  return cost;
}
