#include <stdio.h>
#include <stdlib.h>
#include "debug.h"
#include "runs.h"

static int debuglevel;

void
debugSet (int level)
{
  debuglevel = level;
}

int
debugCond (int level)
{
  return (level <= debuglevel);
}

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
