/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2013 Cas Cremers
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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
#include "binding.h"
#include "error.h"
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
computeAttackCost (const System sys)
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

//! Compute attack cost in different pruning contexts.
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
      return computeAttackCost (sys);
    }
  error ("Unknown pruning method (cost function not found)");
  return 0;
}
