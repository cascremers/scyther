/* my own memory functions (not yet) */

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <mcheck.h>
#include "memory.h"
#include "debug.h"

/* for displaying the sizes */

#include "terms.h"
#include "termlists.h"
#include "knowledge.h"
#include "substitutions.h"
#include "runs.h"

void
memInit ()
{
#ifdef DEBUG
  if (DEBUGL (5))
    {
      void sp (char *txt, int size)
      {
	printf ("Size of %s : %i\n", txt, size);
      }
      printf ("Data structure size.\n\n");
      sp ("pointer", sizeof (Term));
      sp ("term node", sizeof (struct term));
      sp ("termlist node", sizeof (struct termlist));
      sp ("knowledge node", sizeof (struct knowledge));
      sp ("substituition node", sizeof (struct substitution));
      sp ("substlist node", sizeof (struct substitutionlist));
      sp ("roledef node", sizeof (struct roledef));
      sp ("system node", sizeof (struct system));
      printf ("\n");
    }
  mtrace ();
#endif
  return;
}

void
memDone (int sw)
{
  return;
}
