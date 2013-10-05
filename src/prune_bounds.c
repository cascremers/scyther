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
 *@file prune_bounds.c
 *
 * Prune stuff based on bounds
 *
 */

#include <limits.h>

#include "termlist.h"
#include "list.h"
#include "switches.h"
#include "timer.h"
#include "arachne.h"
#include "system.h"
#include "termmap.h"
#include "cost.h"

extern int attack_length;
extern int attack_leastcost;
extern Protocol INTRUDER;
extern int proofDepth;
extern int max_encryption_level;

//! Forward declarations
int tooManyOfRole (const System sys);

//! Prune determination for bounds
/**
 * When something is pruned here, the state space is not complete anymore.
 *
 *@returns true iff this state is invalid for some reason
 */
int
prune_bounds (const System sys)
{
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

  /* prune for number of attacks if we are actually outputting them */
  if (enoughAttacks (sys))
    {
      // Oh no, we ran out of possible attacks!
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned: we already found the maximum number of attacks.\n");
	}
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

  /* prune for runs */
  if (sys->num_regular_runs > switches.runs)
    {
      // Hardcoded limit on runs
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned: too many regular runs (%i).\n",
		   sys->num_regular_runs);
	}
      return 1;
    }

  /* prune for role instances max */
  if (tooManyOfRole (sys))
    {
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Pruned: too many instances of a particular role.\n");
	}
      return 1;
    }

  // This needs some foundation. Probably * 2^max_encryption_level
  //!@todo Remove later
  /**
   * This should be removed once the hidelevel lemma works correctly
   */
  if (switches.experimental & 1)
    {
      if ((switches.match < 2)
	  && (sys->num_intruder_runs >
	      ((double) switches.runs * max_encryption_level * 8)))
	{
	  // Hardcoded limit on iterations
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: %i intruder runs is too much. (max encr. level %i)\n",
		 sys->num_intruder_runs, max_encryption_level);
	    }
	  return 1;
	}
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
  if (switches.prune != 0 && attack_leastcost <= attackCost (sys))
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

  // Pruning involving the number of intruder actions
  {
    // Count intruder actions
    int actioncount;

    actioncount = countIntruderActions ();

    // Limit intruder actions in any case
    if (!switches.intruder)
      {
	if (actioncount > 0)
	  {
	    if (switches.output == PROOF)
	      {
		indentPrint ();
		eprintf
		  ("Pruned: no intruder allowed.\n",
		   switches.maxIntruderActions);
	      }
	    return 1;
	  }
      }

    // Limit on intruder events count
    if (actioncount > switches.maxIntruderActions)
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

//! Detect when there are too many instances of a certain role
int
tooManyOfRole (const System sys)
{
  int toomany;

  toomany = false;
  if (switches.maxOfRole > 0)
    {
      Termmap f;
      int run;

      f = NULL;
      for (run = 0; run < sys->maxruns; run++)
	{
	  if (sys->runs[run].protocol != INTRUDER)
	    {
	      // maybe this conflicts with equal protocols...? TODO
	      Term role;
	      int count;

	      role = sys->runs[run].role->nameterm;
	      count = termmapGet (f, role);
	      if (count == -1)
		count = 1;
	      else
		count++;
	      f = termmapSet (f, role, count);
	      if (count > switches.maxOfRole)
		{
		  toomany = true;
		  break;
		}
	    }
	}
      termmapDelete (f);
    }
  return toomany;
}
