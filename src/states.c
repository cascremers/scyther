#include "states.h"

/* States counter operations
 *
 * Note that these are also used for encountered claims and such.
 */

__inline__ states_t
statesIncrease (const states_t states)
{
  return states + 1;
}

__inline__ double
statesDouble (const states_t states)
{
  return (double) states;
}

__inline__ int
statesSmallerThan (const states_t states, unsigned long int reflint)
{
  if (states < (states_t) reflint)
    return 1;
  else
    return 0;
}

//! Sensible output for number of states/claims
/**
 * Acts like a modified form of %g
 */
__inline__ void
statesFormat (const states_t states)
{
  eprintf ("%lu", states);
}
