/**
 *@file debug.c
 *\brief Debugging code.
 *
 * It is hoped that this code will become redundant over time.
 */
#include <stdio.h>
#include <stdlib.h>
#include "debug.h"
#include "runs.h"

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
      fprintf (stderr, "DEBUG [%i]: %s\n", level, string);
    }
#endif
}
