#include <stdio.h>
#include <stdlib.h>
#include "terms.h"
#include "runs.h"
#include "debug.h"
#include "output.h"

extern int globalLatex;

/* reportQuit is called after each violation, because it might need to abort the process */
void
reportQuit (System sys)
{
  /* determine quit or not */
  if (sys->prune >= 3)
    {
      indent ();
      printf ("Quitting after %li claims, at the first violated claim.\n",
	      sys->claims);
      sys->maxtracelength = 0;
    }
}

void
reportStart (System sys)
{
  if (!sys->latex)
    {
      indent ();
      printf ("<REPORT>\n");
      indent ();
    }
  statesPrint (sys);
}

void
reportMid (System sys)
{
  indent ();
  printf ("Trace length %i.\n", 1 + sys->step);
  if (globalLatex)
      printf("\n");
  tracePrint (sys);
}


void
reportEnd (System sys)
{
  if (!sys->latex)
    {
      indent ();
      printf ("<REPORT>\n");
    }
  reportQuit (sys);
}

void
reportSecrecy (System sys, Term t)
{
  if (!sys->report)
    {
      reportQuit (sys);
      return;
    }
  reportStart (sys);
  indent ();
  printf ("Secrecy violation of $");
  termPrint (t);
  printf ("$\n");
  if (globalLatex)
      printf("\n");
  reportMid (sys);
  reportEnd (sys);
}
