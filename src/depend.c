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
 * @file depend.c
 * \brief interface for graph code from the viewpoint of events.
 *
 */

#include <stdlib.h>
#include <string.h>
#include "depend.h"
#include "term.h"
#include "system.h"
#include "binding.h"
#include "warshall.h"
#include "debug.h"
#include "error.h"

/*
 * Generic structures
 * ---------------------------------------------------------------
 */
//! Event dependency structure
struct depeventgraph
{
  //! Flag denoting what it was made for (newrun|newbinding)
  int fornewrun;
  //! Number of runs;
  int runs;
  //! System where it derives from
  System sys;
  //! Number of nodes
  int n;
  //! Rowsize
  int rowsize;
  //! Graph structure
  unsigned int *G;
  //! Zombie dummy push
  int zombie;
  //! Previous graph
  struct depeventgraph *prev;
};

//! Pointer shorthard
typedef struct depeventgraph *Depeventgraph;

/*
 * External
 * ---------------------------------------------------------------
 */

extern Protocol INTRUDER;	//!< The intruder protocol
extern Role I_M;		//!< special role; precedes all other events always

/*
 * Globals
 * ---------------------------------------------------------------
 */

Depeventgraph currentdepgraph = NULL;

/*
 * Default code
 * ---------------------------------------------------------------
 */

//! Default init
void
dependInit (const System sys)
{
  currentdepgraph = NULL;
}

//! Pring
void
dependPrint ()
{
  Depeventgraph dg;

  eprintf ("Printing DependEvent stack, top first.\n\n");
  for (dg = currentdepgraph; dg != NULL; dg = dg->prev)
    {
      eprintf ("%i nodes, %i rowsize, %i zombies, %i runs: created for new ",
	       dg->n, dg->rowsize, dg->zombie, dg->runs);
      if (dg->fornewrun)
	{
	  eprintf ("run");
	}
      else
	{
	  eprintf ("binding");
	}
      eprintf ("\n");
    }
  eprintf ("\n");
#ifdef DEBUG
  {
    int n1;
    int r1;
    int o1;

    r1 = 0;
    o1 = 0;
    eprintf ("Printing dependency graph.\n");
    eprintf ("Y axis nodes comes before X axis node.\n");
    for (n1 = 0; n1 < nodeCount (); n1++)
      {
	int n2;
	int r2;
	int o2;

	if ((n1 - o1) >= currentdepgraph->sys->runs[r1].rolelength)
	  {
	    o1 += currentdepgraph->sys->runs[r1].rolelength;
	    r1++;
	    eprintf ("\n");
	  }
	r2 = 0;
	o2 = 0;
	eprintf ("%5i : ", n1);
	for (n2 = 0; n2 < nodeCount (); n2++)
	  {
	    if ((n2 - o2) >= currentdepgraph->sys->runs[r2].rolelength)
	      {
		o2 += currentdepgraph->sys->runs[r2].rolelength;
		r2++;
		eprintf (" ");
	      }
	    eprintf ("%i", getNode (n1, n2));
	  }
	eprintf ("\n");

      }
    eprintf ("\n");
  }
#endif
}

//! Default cleanup
void
dependDone (const System sys)
{
  if (currentdepgraph != NULL)
    {
      globalError++;
      eprintf ("\n\n");
      dependPrint ();
      globalError--;
      error
	("depgraph stack (depend.c) not empty at dependDone, bad iteration?");
    }
}

/*
 * Libs
 * ---------------------------------------------------------------
 */

//! Convert from event to node in a graph (given that sys is set)
int
eventtonode (const Depeventgraph dgx, const int r, const int e)
{
  int i;
  int n;

  n = 0;
  for (i = 0; i < dgx->sys->maxruns; i++)
    {
      if (i == r)
	{
	  // this run
#ifdef DEBUG
	  if (dgx->sys->runs[i].rolelength <= e)
	    {
	      error ("Bad offset for eventtonode");
	    }
#endif
	  return (n + e);
	}
      else
	{
	  // not this run, add offset
	  n += dgx->sys->runs[i].rolelength;
	}
    }
  error ("Bad offset (run number too high?) for eventtonode");
  return 0;
}

//! Return the number of nodes in a graph
int
countnodes (const Depeventgraph dgx)
{
  int i;
  int nodes;

  nodes = 0;
  for (i = 0; i < dgx->sys->maxruns; i++)
    {
      nodes += dgx->sys->runs[i].rolelength;
    }
  return nodes;
}

//! Graph size given the number of nodes
unsigned int
getGraphSize (const Depeventgraph dgx)
{
  return (dgx->n * dgx->rowsize);
}

//! Create graph from sys
Depeventgraph
dependCreate (const System sys)
{
  Depeventgraph dgnew;

  dgnew = (Depeventgraph) MALLOC (sizeof (struct depeventgraph));
  dgnew->sys = sys;
  dgnew->fornewrun = true;
  dgnew->runs = sys->maxruns;
  dgnew->zombie = 0;
  dgnew->prev = NULL;
  dgnew->n = countnodes (dgnew);	// count nodes works on ->sys
  dgnew->rowsize = WORDSIZE (dgnew->n);
  dgnew->G = (unsigned int *) CALLOC (1, getGraphSize (dgnew) * sizeof (unsigned int));	// works on ->n and ->rowsize

  return dgnew;
}

//! Copy graph from current one
Depeventgraph
dependCopy (const Depeventgraph dgold)
{
  Depeventgraph dgnew;

  // Copy old to new
  dgnew = (Depeventgraph) MALLOC (sizeof (struct depeventgraph));
  memcpy ((void *) dgnew, (void *) dgold,
	  (size_t) sizeof (struct depeventgraph));

  // New copy
  dgnew->fornewrun = false;
  dgnew->zombie = 0;

  // copy inner graph
  dgnew->G =
    (unsigned int *) MALLOC (getGraphSize (dgold) * sizeof (unsigned int));
  memcpy ((void *) dgnew->G, (void *) dgold->G,
	  getGraphSize (dgold) * sizeof (unsigned int));

  return dgnew;
}

//! Destroy graph
void
dependDestroy (const Depeventgraph dgold)
{
  FREE (dgold->G);
  FREE (dgold);
}

//! push graph to stack (generic)
void
dependPushGeneric (Depeventgraph dgnew)
{
  dgnew->prev = currentdepgraph;
  currentdepgraph = dgnew;
}

//! restore graph from stack (generic)
void
dependPopGeneric (void)
{
  Depeventgraph dgprev;

  dgprev = currentdepgraph->prev;
  dependDestroy (currentdepgraph);
  currentdepgraph = dgprev;
}

// Dependencies from role order
void
dependDefaultRoleOrder (void)
{
  int r;

  for (r = 0; r < currentdepgraph->sys->maxruns; r++)
    {
      int e;

      for (e = 1; e < currentdepgraph->sys->runs[r].rolelength; e++)
	{
	  setDependEvent (r, e - 1, r, e);
	}
    }
}

// Dependencies fro bindings order
void
dependDefaultBindingOrder (void)
{
  List bl;

  for (bl = currentdepgraph->sys->bindings; bl != NULL; bl = bl->next)
    {
      Binding b;

      b = (Binding) bl->data;
      if (valid_binding (b))
	{
	  int r1, e1, r2, e2;

	  r1 = b->run_from;
	  e1 = b->ev_from;
	  r2 = b->run_to;
	  e2 = b->ev_to;
	  if (!((r1 == r2) && (e1 == e2)))
	    {
	      // Not a self-binding
	      setDependEvent (r1, e1, r2, e2);
	    }
	}
    }
}

//! Construct graph dependencies from sys
/**
 * uses currentdepgraph->sys
 */
void
dependFromSys (void)
{
  dependDefaultRoleOrder ();
  dependDefaultBindingOrder ();
}

//! Detect whether the graph has a cycle. If so, a node can get to itself (through the cycle)
int
hasCycle ()
{
  int n;

  for (n = 0; n < currentdepgraph->n; n++)
    {
      if (getNode (n, n))
	{
	  return true;
	}

    }
  return false;
}

/*
 * Public Code
 * ---------------------------------------------------------------
 */

//! get node
int
getNode (const int n1, const int n2)
{
  return BIT (currentdepgraph->G + currentdepgraph->rowsize * n1, n2);
}

//! set node
void
setNode (const int n1, const int n2)
{
  SETBIT (currentdepgraph->G + currentdepgraph->rowsize * n1, n2);
}

//! Count nodes
int
nodeCount (void)
{
  return countnodes (currentdepgraph);
}

/*
 * Simple setting
 */
void
setDependEvent (const int r1, const int e1, const int r2, const int e2)
{
  int n1, n2;

  n1 = eventtonode (currentdepgraph, r1, e1);
  n2 = eventtonode (currentdepgraph, r2, e2);
  setNode (n1, n2);
}

/*
 * Simple testing
 */
int
isDependEvent (const int r1, const int e1, const int r2, const int e2)
{
  int n1, n2;

  n1 = eventtonode (currentdepgraph, r1, e1);
  n2 = eventtonode (currentdepgraph, r2, e2);
  return getNode (n1, n2);
}

//! create new graph after adding runs or events (new number of nodes)
void
dependPushRun (const System sys)
{
#ifdef DEBUG
  debug (5, "Push dependGraph for new run\n");
#endif
  dependPushGeneric (dependCreate (sys));
  dependFromSys ();
}

//! restore graph to state after previous run add
void
dependPopRun (void)
{
  if (!currentdepgraph->fornewrun)
    {
      globalError++;
      dependPrint ();
      globalError--;
      error ("Trying to pop graph created for new binding.");
    }
#ifdef DEBUG
  debug (5, "Pop dependGraph for new run\n");
#endif
  dependPopGeneric ();
}

//! create new graph by adding event bindings
/*
 * The push code returns true or false: if false, the operation fails because
 * it there is now a cycle in the graph, and there is no need to pop the
 * result.
 */
int
dependPushEvent (const int r1, const int e1, const int r2, const int e2)
{
  if (isDependEvent (r2, e2, r1, e1))
    {
      // Adding would imply a cycle, so we won't do that.
#ifdef DEBUG
      if (DEBUGL (3))
	{
	  eprintf ("Cycle detected for binding %i,%i -> %i,%i.\n", r1, e1, r2,
		   e2);
	}
      if (DEBUGL (5))
	{
	  dependPrint ();
	}
#endif
      return false;
    }
  else
    {
      // No immediate cycle: new graph, return true TODO disabled
      if ((1 == 1) && (((r1 == r2) && (e1 == e2))
		       || isDependEvent (r1, e1, r2, e2)))
	{
	  // if n->n or the binding already existed, no changes
	  // no change: add zombie
	  currentdepgraph->zombie += 1;
#ifdef DEBUG
	  debug (5, "Push dependGraph for new event (zombie push)\n");
	  if (DEBUGL (5))
	    {
	      globalError++;
	      eprintf ("r%ii%i --> r%ii%i\n", r1, e1, r2, e2);
	      globalError--;
	    }
#endif
	}
      else
	{
	  // change: make new graph copy of the old one
	  dependPushGeneric (dependCopy (currentdepgraph));
	  // really new?
	  if (!isDependEvent (r1, e1, r2, e2))
	    {
	      // add new binding
	      setDependEvent (r1, e1, r2, e2);
	      // recompute closure
	      transitive_closure (currentdepgraph->G, currentdepgraph->n);
	      // check for cycles
	      if (hasCycle ())
		{
		  //warning ("Cycle slipped undetected by the reverse check.");
		  // Closure introduced cycle, undo it
		  dependPopEvent ();
		  return false;
		}
#ifdef DEBUG
	      debug (5, "Push dependGraph for new event (real push)\n");
	      if (DEBUGL (5))
		{
		  globalError++;
		  eprintf ("r%ii%i --> r%ii%i\n", r1, e1, r2, e2);
		  globalError--;
		}
#endif
	    }
	}
      return true;
    }
}

//! restore graph to state before previous binding add
void
dependPopEvent (void)
{
  if (currentdepgraph->zombie > 0)
    {
      // zombie pushed
#ifdef DEBUG
      debug (5, "Pop dependGraph for new event (zombie pop)\n");
#endif
      currentdepgraph->zombie -= 1;
    }
  else
    {
      if (currentdepgraph->fornewrun)
	{
	  globalError++;
	  dependPrint ();
	  globalError--;
	  error ("Trying to pop graph created for new run.");
	}
      else
	{
	  // real graph
#ifdef DEBUG
	  debug (5, "Pop dependGraph for new event (real pop)\n");
#endif
	  dependPopGeneric ();
	}
    }
}

//! Current event to node
int
eventNode (const int r, const int e)
{
  return eventtonode (currentdepgraph, r, e);
}

//! Iterate over any preceding events
int
iteratePrecedingEvents (const System sys, int (*func) (int run, int ev),
			const int run, const int ev)
{
  int run2;

  for (run2 = 0; run2 < sys->maxruns; run2++)
    {
      int ev2;

      for (ev2 = 0; ev2 < sys->runs[run2].step; ev2++)
	{
	  if (isDependEvent (run2, ev2, run, ev))
	    {
	      if (!func (run2, ev2))
		{
		  return false;
		}
	    }
	}
    }
  return true;
}
