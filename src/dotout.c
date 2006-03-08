#include <stdlib.h>
#include <limits.h>
#include "system.h"
#include "switches.h"
#include "arachne.h"
#include "binding.h"
#include "depend.h"

extern Protocol INTRUDER;	// Pointers, to be set by the Init of arachne.c
extern Role I_M;		// Same here.
extern Role I_RRS;
extern Role I_RRSD;

#define INVALID		-1
#define isGoal(rd)	(rd->type == READ && !rd->internal)
#define isBound(rd)	(rd->bound)
#define length		step


//! Draw node
void
node (const System sys, const int run, const int index)
{
  if (sys->runs[run].protocol == INTRUDER)
    {
      if (sys->runs[run].role == I_M)
	{
	  eprintf ("m0");
	}
      else
	{
	  eprintf ("i%i", run);
	}
    }
  else
    {
      eprintf ("r%ii%i", run, index);
    }
}


//! Determine ranks for all nodes
/**
 * Some crude algorithm I sketched on the blackboard.
 */
int
graph_ranks (int *ranks, int nodes)
{
  int i;
  int todo;
  int rank;

#ifdef DEBUG
  if (hasCycle ())
    {
      error ("Graph ranks tried, but a cycle exists!");
    }
#endif

  i = 0;
  while (i < nodes)
    {
      ranks[i] = INT_MAX;
      i++;
    }

  todo = nodes;
  rank = 0;
  while (todo > 0)
    {
      // There are still unassigned nodes
      int n;

      n = 0;
      while (n < nodes)
	{
	  if (ranks[n] == INT_MAX)
	    {
	      // Does this node have incoming stuff from stuff with equal rank or higher?
	      int refn;

	      refn = 0;
	      while (refn < nodes)
		{
		  if (ranks[refn] >= rank && getNode (refn, n))
		    refn = nodes + 1;
		  else
		    refn++;
		}
	      if (refn == nodes)
		{
		  ranks[n] = rank;
		  todo--;
		}
	    }
	  n++;
	}
      rank++;
    }
  return rank;
}


//! Iterate over events (in non-intruder runs) in which some value term occurs first.
// Function should return true for iteration to continue.
int
iterate_first_regular_occurrences (const System sys,
				   int (*func) (int run, int ev),
				   const Term t)
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      if (sys->runs[run].protocol != INTRUDER)
	{
	  int ev;
	  Roledef rd;

	  rd = sys->runs[run].start;
	  for (ev = 0; ev < sys->runs[run].step; ev++)
	    {
	      if (termSubTerm (rd->from, t) ||
		  termSubTerm (rd->to, t) || termSubTerm (rd->message, t))
		{
		  // Allright, t occurs here in this run first
		  if (!func (run, ev))
		    {
		      return false;
		    }
		  break;
		}
	    }
	}
    }
  return true;
}

//! Iterate over all events that have an incoming arrow to the current one (forgetting the intruder for a moment)
void
iterate_incoming_arrows (const System sys, void (*func) (), const int run,
			 const int ev)
{
  /**
   * Determine wheter to draw an incoming arrow to this event.
   * We check all other runs, to see if they are ordered.
   */
  int run2;

  run2 = 0;
  while (run2 < sys->maxruns)
    {
      if (run2 != run && sys->runs[run2].protocol != INTRUDER)
	{
	  // Is this run before the event?
	  int ev2;
	  int found;

	  found = 0;
	  ev2 = sys->runs[run2].length;
	  while (found == 0 && ev2 > 0)
	    {
	      ev2--;
	      if (isDependEvent (run2, ev2, run, ev))
		{
		  found = 1;
		}
	    }

	  if (found == 1)
	    {
	      // It is before the event, and thus we would like to draw it.
	      // However, if there is another path along which we can get here, forget it
	      /**
	       * Note that this algorithm is similar to Floyd's algorithm for all shortest paths.
	       * The goal here is to select only the path with distance 1 (as viewed from the regular runs),
	       * so we can simplify stuff a bit.
	       * Nevertheless, using Floyd first would probably be faster.
	       */
	      int other_route;
	      int run3;
	      int ev3;

	      other_route = 0;
	      run3 = 0;
	      ev3 = 0;
	      while (other_route == 0 && run3 < sys->maxruns)
		{
		  if (sys->runs[run3].protocol != INTRUDER)
		    {
		      ev3 = 0;
		      while (other_route == 0 && ev3 < sys->runs[run3].length)
			{
			  if (isDependEvent (run2, ev2, run3, ev3)
			      && isDependEvent (run3, ev3, run, ev))
			    {
			      // other route found
			      other_route = 1;
			    }
			  ev3++;
			}
		    }
		  run3++;
		}
	      if (other_route == 0)
		{
		  func (run2, ev2);
		}


	    }
	}
      run2++;
    }
}

//! Iterate over all events that have an outgoing arrow from the current one (forgetting the intruder for a moment)
void
iterate_outgoing_arrows (const System sys, void (*func) (), const int run,
			 const int ev)
{
  /**
   * Determine wheter to draw an incoming arrow to this event.
   * We check all other runs, to see if they are ordered.
   */
  int run2;

  run2 = 0;
  while (run2 < sys->maxruns)
    {
      if (run2 != run && sys->runs[run2].protocol != INTRUDER)
	{
	  // Is this run after the event?
	  int ev2;
	  int found;

	  found = 0;
	  ev2 = 0;
	  while (found == 0 && ev2 < sys->runs[run2].length)
	    {
	      if (isDependEvent (run, ev, run2, ev2))
		{
		  found = 1;
		}
	      else
		{
		  ev2++;
		}
	    }

	  if (found == 1)
	    {
	      // It is after the event, and thus we would like to draw it.
	      // However, if there is another path along which we can get there, forget it
	      /**
	       * Note that this algorithm is similar to Floyd's algorithm for all shortest paths.
	       * The goal here is to select only the path with distance 1 (as viewed from the regular runs),
	       * so we can simplify stuff a bit.
	       * Nevertheless, using Floyd first would probably be faster.
	       */
	      int other_route;
	      int run3;
	      int ev3;

	      other_route = 0;
	      run3 = 0;
	      ev3 = 0;
	      while (other_route == 0 && run3 < sys->maxruns)
		{
		  if (sys->runs[run3].protocol != INTRUDER)
		    {
		      ev3 = 0;
		      while (other_route == 0 && ev3 < sys->runs[run3].length)
			{
			  if (isDependEvent (run, ev, run3, ev3)
			      && isDependEvent (run3, ev3, run2, ev2))
			    {
			      // other route found
			      other_route = 1;
			    }
			  ev3++;
			}
		    }
		  run3++;
		}
	      if (other_route == 0)
		{
		  func (run2, ev2);
		}
	    }
	}
      run2++;
    }
}


//! Draw the dependencies (returns from_intruder_count)
int
drawBindings (const System sys)
{
  int run;
  int from_intruder_count;

  // We now determine them ourselves between existing runs
  run = 0;
  from_intruder_count = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].protocol != INTRUDER)
	{
	  int ev;

	  ev = 0;
	  while (ev < sys->runs[run].length)
	    {
	      int incoming_arrow_count;

	      void incoming_arrow (int run2, int ev2)
	      {
		Roledef rd, rd2;

		incoming_arrow_count++;
		/*
		 * We have decided to draw this binding,
		 * from run2,ev2 to run,ev
		 * However, me might need to decide some colouring for this node.
		 */
		eprintf ("\t");
		node (sys, run2, ev2);
		eprintf (" -> ");
		node (sys, run, ev);
		eprintf (" ");
		// decide color
		rd = roledef_shift (sys->runs[run].start, ev);
		rd2 = roledef_shift (sys->runs[run2].start, ev2);
		if (rd->type == CLAIM)
		  {
		    // Towards a claim, so only indirect dependency
		    eprintf ("[color=cornflowerblue]");
		  }
		else
		  {
		    // Not towards claim should imply towards read,
		    // but we check it to comply with future stuff.
		    if (rd->type == READ && rd2->type == SEND)
		      {
			// We want to distinguish where it is from a 'broken' send
			if (isTermEqual (rd->message, rd2->message))
			  {
			    if (isTermEqual
				(rd->from, rd2->from)
				&& isTermEqual (rd->to, rd2->to))
			      {
				// Wow, a perfect match. Leave the arrow as-is :)
				eprintf ("[color=darkgreen]");
			      }
			    else
			      {
				// Same message, different people
				eprintf
				  ("[label=\"redirect\",color=darkorange2]");
			      }
			  }
			else
			  {
			    // Not even the same message, intruder construction
			    eprintf ("[label=\"construct\",color=red]");
			  }
		      }
		  }
		// close up
		eprintf (";\n");
	      }

	      incoming_arrow_count = 0;
	      iterate_incoming_arrows (sys, incoming_arrow, run, ev);

	      ev++;
	    }
	}
      run++;
    }
  return from_intruder_count;
}


//! Draw simple runs
void
drawSimpleRuns (const System sys)
{
  int run;

  // Draw graph
  // First, all simple runs
  run = 0;
  while (run < sys->maxruns)
    {
      Roledef rd;
      int index;

      index = 0;
      rd = sys->runs[run].start;
      if (sys->runs[run].protocol != INTRUDER && sys->runs[run].length > 0)
	{
	  // Regular run

	  /* DISABLED subgraphs
	     eprintf ("\tsubgraph cluster_run%i {\n", run);
	     eprintf ("\t\tlabel = \"");
	     eprintf ("#%i: ", run);
	     termPrint (sys->runs[run].protocol->nameterm);
	     eprintf (", ");
	     agentsOfRunPrint (sys, run);
	     eprintf ("\";\n", run);
	     if (run == 0)
	     {
	     eprintf ("\t\tcolor = red;\n");
	     }
	     else
	     {
	     eprintf ("\t\tcolor = blue;\n");
	     }
	   */


	  // Display the respective events
	  while (index < sys->runs[run].length)
	    {
	      // Print node itself
	      eprintf ("\t\t");
	      node (sys, run, index);
	      eprintf (" [");
	      if (run == 0 && index == sys->current_claim->ev)
		{
		  eprintf
		    ("style=filled,fillcolor=mistyrose,color=salmon,shape=doubleoctagon,");
		}
	      else
		{
		  eprintf ("shape=box,");
		}
	      eprintf ("label=\"");
	      roledefPrintShort (rd);
	      eprintf ("\"]");
	      eprintf (";\n");

	      // Print binding to previous node
	      if (index > sys->runs[run].firstReal)
		{
		  // index > 0
		  eprintf ("\t\t");
		  node (sys, run, index - 1);
		  eprintf (" -> ");
		  node (sys, run, index);
		  eprintf (" [style=\"bold\", weight=\"10.0\"]");
		  eprintf (";\n");
		}
	      else
		{
		  // index <= firstReal
		  if (index == sys->runs[run].firstReal)
		    {
		      // index == firstReal
		      Roledef rd;
		      int send_before_read;
		      int done;

		      // Determine if it is an active role or note
		      /**
		       *@todo note that this will probably become a standard function call for role.h
		       */
		      rd =
			roledef_shift (sys->runs[run].start,
				       sys->runs[run].firstReal);
		      done = 0;
		      send_before_read = 0;
		      while (!done && rd != NULL)
			{
			  if (rd->type == READ)
			    {
			      done = 1;
			    }
			  if (rd->type == SEND)
			    {
			      done = 1;
			      send_before_read = 1;
			    }
			  rd = rd->next;
			}
		      // Draw the first box
		      // This used to be drawn only if done && send_before_read, now we always draw it.
		      eprintf ("\t\ts%i [label=\"Run %i: ", run, run);
		      termPrint (sys->runs[run].protocol->nameterm);
		      eprintf (", ");
		      termPrint (sys->runs[run].role->nameterm);
		      eprintf ("\\n");
		      agentsOfRunPrint (sys, run);
		      eprintf ("\", shape=diamond];\n");
		      eprintf ("\t\ts%i -> ", run);
		      node (sys, run, index);
		      eprintf (" [weight=\"10.0\"];\n");
		    }
		}
	      index++;
	      rd = rd->next;
	    }
	  /* DISABLED subgraphs
	     eprintf ("\t}\n");
	   */
	}
      run++;
    }
}

//! Choose term node
void
chooseTermNode (const Term t)
{
  eprintf ("CHOOSE");
  {
    char *rsbuf;

    rsbuf = RUNSEP;
    RUNSEP = "x";
    termPrint (t);
    RUNSEP = rsbuf;
  }
}

//! Show intruder choices
void
drawIntruderChoices (const System sys)
{
  Termlist shown;
  List bl;

  shown = NULL;
  for (bl = sys->bindings; bl != NULL; bl = bl->next)
    {
      Binding b;

      b = (Binding) bl->data;
      if ((!b->blocked) && (!b->done) && isTermVariable (b->term))
	{
	  /*
	   * If the binding is not blocked, but also not done,
	   * the intruder can apparently satisfy it at will.
	   */

	  if (!inTermlist (shown, b->term))
	    {
	      int firsthere (int run, int ev)
	      {
					/**
					 * @todo This is not very efficient,
					 * but maybe that is not really
					 * needed here.
					 */
		int notearlier (int run2, int ev2)
		{
		  if (sys->runs[run2].protocol != INTRUDER)
		    {
		      return (!roledefSubTerm
			      (eventRoledef (sys, run2, ev2), b->term));
		    }
		  else
		    {
		      return true;
		    }
		}

		if (iteratePrecedingEvents (sys, notearlier, run, ev))
		  {
		    eprintf ("\t");
		    chooseTermNode (b->term);
		    eprintf (" -> ");
		    node (sys, run, ev);
		    eprintf (" [color=\"darkgreen\"];\n");
		  }
		return true;
	      }

	      // If the first then we add a header
	      if (shown == NULL)
		{
		  eprintf ("// Showing intruder choices.\n");
		}
	      // Not in the list, show new node
	      shown = termlistAdd (shown, b->term);
	      eprintf ("\t");
	      chooseTermNode (b->term);
	      eprintf (" [label=\"Class: any ");
	      termPrint (b->term);
	      eprintf ("\",color=\"darkgreen\"];\n");

	      iterate_first_regular_occurrences (sys, firsthere, b->term);
	    }
	}

    }

  if (shown != NULL)
    {
      eprintf ("\n");
    }
  termlistDelete (shown);
}


//! Display the current semistate using dot output format.
/**
 * This is not as nice as we would like it. Furthermore, the function is too big.
 */
void
dotSemiState (const System sys)
{
  static int attack_number = 0;
  int run;
  Protocol p;
  int *ranks;
  int maxrank;
  int from_intruder_count;
  int nodes;

  // Open graph
  attack_number++;
  eprintf ("digraph semiState%i {\n", attack_number);
  eprintf ("\tlabel = \"[Id %i] Protocol ", sys->attackid);
  p = (Protocol) sys->current_claim->protocol;
  termPrint (p->nameterm);
  eprintf (", role ");
  termPrint (sys->current_claim->rolename);
  eprintf (", claim type ");
  termPrint (sys->current_claim->type);
  eprintf ("\";\n");

  // Needed for the bindings later on: create graph

  nodes = nodeCount ();
  ranks = malloc (nodes * sizeof (int));
  maxrank = graph_ranks (ranks, nodes);	// determine ranks

#ifdef DEBUG
  // For debugging purposes, we also display an ASCII version of some stuff in the comments
  printSemiState ();
  // Even draw all dependencies for non-intruder runs
  // Real nice debugging :(
  {
    int run;

    run = 0;
    while (run < sys->maxruns)
      {
	int ev;

	ev = 0;
	while (ev < sys->runs[run].length)
	  {
	    int run2;
	    int notfirstrun;

	    eprintf ("// precedence: r%ii%i <- ", run, ev);
	    run2 = 0;
	    notfirstrun = 0;
	    while (run2 < sys->maxruns)
	      {
		int notfirstev;
		int ev2;

		notfirstev = 0;
		ev2 = 0;
		while (ev2 < sys->runs[run2].length)
		  {
		    if (isDependEvent (run2, ev2, run, ev))
		      {
			if (notfirstev)
			  eprintf (",");
			else
			  {
			    if (notfirstrun)
			      eprintf (" ");
			    eprintf ("r%i:", run2);
			  }
			eprintf ("%i", ev2);
			notfirstrun = 1;
			notfirstev = 1;
		      }
		    ev2++;
		  }
		run2++;
	      }
	    eprintf ("\n");
	    ev++;
	  }
	run++;
      }
  }
#endif

  // First, simple runs
  drawSimpleRuns (sys);
  // Second, all bindings.
  from_intruder_count = drawBindings (sys);

  // Third, the intruder node (if needed)
  if (from_intruder_count > 0)
    {
      eprintf
	("\tintruder [label=\"Initial intruder knowledge\", color=red];\n");
    }

  // For debugging we might add more stuff: full dependencies
#ifdef DEBUG
  {
    int r1;

    for (r1 = 0; r1 < sys->maxruns; r1++)
      {
	if (sys->runs[r1].protocol != INTRUDER)
	  {
	    int e1;

	    for (e1 = 0; e1 < sys->runs[r1].step; e1++)
	      {
		int r2;

		for (r2 = 0; r2 < sys->maxruns; r2++)
		  {
		    if (sys->runs[r2].protocol != INTRUDER)
		      {
			int e2;

			for (e2 = 0; e2 < sys->runs[r2].step; e2++)
			  {
			    if (isDependEvent (r1, e1, r2, e2))
			      {
				eprintf ("\tr%ii%i -> r%ii%i [color=grey];\n",
					 r1, e1, r2, e2);
			      }
			  }
		      }
		  }
	      }
	  }
      }
  }
#endif

  // Fourth, all ranking info
  {
    int myrank;

#ifdef DEBUG
    {
      int n;

      eprintf ("/* ranks: %i\n", maxrank);
      n = 0;
      while (n < nodes)
	{
	  eprintf ("%i ", ranks[n]);
	  n++;
	}
      eprintf ("\n*/\n\n");
    }
#endif
    myrank = 0;
    while (myrank < maxrank)
      {
	int count;
	int run;
	int run1;
	int ev1;

	count = 0;
	run = 0;
	while (run < sys->maxruns)
	  {
	    if (sys->runs[run].protocol != INTRUDER)
	      {
		int ev;

		ev = 0;
		while (ev < sys->runs[run].step)
		  {
		    if (myrank == ranks[eventNode (run, ev)])
		      {
			if (count == 0)
			  eprintf ("\t{ rank = same; ");
			count++;
			eprintf ("r%ii%i; ", run, ev);
		      }
		    ev++;
		  }
	      }
	    run++;
	  }
	if (count > 0)
	  eprintf ("}\t\t// rank %i\n", myrank);
	myrank++;
      }
  }

  // Intruder choices
  drawIntruderChoices (sys);

#ifdef DEBUG
  // Debug: print dependencies
  if (DEBUGL (3))
    {
      dependPrint ();
    }
#endif

  // clean memory
  free (ranks);			// ranks

  // close graph
  eprintf ("};\n\n");
}
