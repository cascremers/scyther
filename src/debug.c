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
 *@file debug.c
 *\brief Debugging code.
 *
 * It is hoped that this code will become redundant over time.
 */
#include <stdio.h>
#include <stdlib.h>
#include "debug.h"
#include "system.h"
#include "error.h"

static int debuglevel;

//! Set the debuglevel from the main code.
void
debugSet (int level)
{
  debuglevel = level;
}

//! Test whether some debuglevel is meant to be printed.
/**
 *@param level The debuglevel
 *@return True iff level is smaller than, or equal to, the last set debuglevel.
 *\sa debugSet()
 */
int
debugCond (int level)
{
  return (level <= debuglevel);
}

//! Print some debug string for some level, if desired.
/**
 *@param level The debuglevel
 *@param string The string to be displayed for this level.
 *@return If the debuglevel is higher than the level, the string is ignored.
 * Otherwise it will be printed.
 *\sa debugCond()
 */
void
debug (int level, char *string)
{
#ifdef DEBUG
  if (debugCond (level))
    {
      indent ();
      printfstderr ("DEBUG [%i]: %s\n", level, string);
    }
#endif
}
