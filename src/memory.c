/**
 *@file
 * \brief Memory functions
 *
 * These are not really used anymore, so maybe they should be removed.
 * 
 * \par Performance
 * Tests showed that memory pooling was actually much less efficient than
 * having \c malloc() trying to fit stuff into the memory caches.
 */

/* my own memory functions (not yet) */

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#ifdef DEBUG
#include <mcheck.h>
#endif
#include "memory.h"
#include "debug.h"

/* for displaying the sizes */

#include "terms.h"
#include "termlists.h"
#include "knowledge.h"
#include "substitutions.h"
#include "system.h"

//! Open memory code.
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

//! Close memory code.
void
memDone (int sw)
{
  return;
}
