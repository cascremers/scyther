/**
 *@file arachne.c
 *
 * Introduces a method for proofs akin to the Athena modelchecker
 * http://www.ece.cmu.edu/~dawnsong/athena/
 *
 */

#include "system.h"
#include "arachne.h"

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

//! Prune determination
/**
 *@returns true iff this state is invalid for some reason
 */
int
prune (const System sys)
{
  return 0;
}

//! Main recursive procedure for Arachne
int
iterate (const System sys)
{
  /**
   * Possibly prune this state
   */

  if (prune (sys))
    return 0;

  /**
   * If not pruned, check whether its a final state (i.e. all goals bound)
   * - Yes: check whether property holds
   * - No:  iterate further
   */
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
