#ifndef STATES
#define STATES
/**
 * Header file for the states counter datatype.
 *
 * Previously, the states number was just a unsigned int, but that
 * turned out to be insufficient.
 */

#include <stdio.h>

typedef unsigned long int states_t;
#define STATES0 0

__inline__ states_t statesIncrease (const states_t states);
__inline__ double statesDouble (const states_t states);
__inline__ int statesSmallerThan (const states_t states, unsigned long int reflint);
__inline__ void statesFormat (const states_t states);

#endif
