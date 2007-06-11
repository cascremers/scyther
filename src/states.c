/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007 Cas Cremers
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

#include "states.h"
#include "symbol.h"

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
