/**
 *
 *@file cost.c
 *
 * Determine cost of a given semitrace in sys
 * Constructed for Arachne results, unreliable otherwise.
 *
 */
#include "switches.h"

//************************************************************************
// Private methods
//************************************************************************

int
selfInitiator (const System sys, const int run)
{
  int self_initiator;

  self_initiator = false;
  if (sys->runs[run].role->initiator)
    {
      // An initiator
      Termlist agents;
      Termlist seen;

      agents = sys->runs[run].agents;
      seen = NULL;
      while (agents != NULL)
	{
	  Term agent;

	  agent = agents->term;
	  if (inTermlist (seen, agent))
	    {
	      // This agent was already in the seen list
	      self_initiator = true;
	    }
	  else
	    {
	      termlistAdd (seen, agent);
	    }
	  agents = agents->next;
	}
      termlistDelete (seen);
    }
  return self_initiator;
}

//! Count the number of any self-initiators
int
selfInitiators (const System sys)
{
  int count;
  int run;

  count = 0;
  run = 0;
  while (run < sys->maxruns)
    {
      if (selfInitiator (sys, run))
	{
	  count++;
	}
      run++;
    }
  return count;
}

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
  cost += 5 * selfInitiators (sys);

  return cost;
}
