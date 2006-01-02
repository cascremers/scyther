/**
 * Handle bindings for Arache engine.
 */

#include "list.h"
#include "role.h"
#include "label.h"
#include "system.h"
#include "binding.h"
#include "warshall.h"
#include "memory.h"
#include "debug.h"
#include "term.h"
#include "termmap.h"
#include "arachne.h"
#include "switches.h"
#include <malloc.h>

static System sys;		//!< local storage of system pointer
int *graph = NULL;		//!< graph data
int nodes = 0;			//!< number of nodes in the graph
int graph_uordblks = 0;

extern Protocol INTRUDER;	//!< The intruder protocol
extern Role I_M;		//!< special role; precedes all other events always

/*
 * Forward declarations
 */

void goal_graph_destroy ();

/*
 *
 * Assist stuff
 *
 */

//! Create mem for binding
Binding
binding_create (Term term, int run_to, int ev_to)
{
  Binding b;

  b = memAlloc (sizeof (struct binding));
  b->done = 0;
  b->blocked = 0;
  b->run_from = -1;
  b->ev_from = -1;
  b->run_to = run_to;
  b->ev_to = ev_to;
  goal_graph_destroy ();
  b->term = term;
  b->level = 0;
  return b;
}

//! Remove mem for binding
void
binding_destroy (Binding b)
{
  if (b->done)
    {
      goal_unbind (b);
    }
  memFree (b, sizeof (struct binding));
}

//! Test whether one event is ordered before another
/**
 * Is only guaranteed to yield trustworthy results after a new graph is created, using
 * goal_graph_create ()
 */
int
isOrderedBefore (const int run1, const int ev1, const int run2, const int ev2)
{
  return graph[graph_nodes (nodes, run2, ev2, run2, ev2)];
}

/*
 *
 * Main
 *
 */

//! Init module
void
bindingInit (const System mysys)
{
  sys = mysys;
  sys->bindings = NULL;
  graph = NULL;
  nodes = 0;
  graph_uordblks = 0;
}

//! Close up
void
bindingDone ()
{
  int delete (Binding b)
  {
    binding_destroy (b);
    return 1;
  }
  list_iterate (sys->bindings, delete);
  list_destroy (sys->bindings);
}

//! Destroy graph
void
goal_graph_destroy ()
{
  if (graph != NULL)
    {
#ifdef DEBUG
      struct mallinfo mi_free;
      int mem_free;

      mi_free = mallinfo ();
      mem_free = mi_free.uordblks;
#endif
      memFree (graph, (nodes * nodes) * sizeof (int));
      graph = NULL;
#ifdef DEBUG
      mi_free = mallinfo ();
      if (mem_free - mi_free.uordblks != graph_uordblks)
	error ("Freeing gave a weird result.");
#endif
      graph_uordblks = 0;
      nodes = 0;
    }
}

//! Compute unclosed graph
void
goal_graph_create ()
{
  int run, ev;
  int last_m;
  List bl;

  goal_graph_destroy ();

  // Setup graph
  nodes = node_count ();

  {
    struct mallinfo create_mi;
    int create_mem_before;

    if (graph_uordblks != 0)
      error
	("Trying to create graph stuff without 0 uordblks for it first, but it is %i.",
	 graph_uordblks);
    create_mi = mallinfo ();
    create_mem_before = create_mi.uordblks;
    graph = memAlloc ((nodes * nodes) * sizeof (int));
    create_mi = mallinfo ();
    graph_uordblks = create_mi.uordblks - create_mem_before;
  }

  {

    graph_fill (graph, nodes, 0);

    // Setup run order
    run = 0;
    last_m = -1;		// last I_M run
    while (run < sys->maxruns)
      {
	ev = 1;
	//!@todo This now reference to step, but we intend "length" as in Arachne.
	while (ev < sys->runs[run].step)
	  {
	    graph[graph_nodes (nodes, run, ev - 1, run, ev)] = 1;
	    ev++;
	  }
	// Enforce I_M ordering
	if (sys->runs[run].protocol == INTRUDER && sys->runs[run].role == I_M)
	  {
	    if (last_m != -1)
	      {
		graph[graph_nodes (nodes, last_m, 0, run, 0)] = 1;
	      }
	    last_m = run;
	  }
	// Next
	run++;
      }
    // Setup bindings order
    bl = sys->bindings;
    while (bl != NULL)
      {
	Binding b;

	b = (Binding) bl->data;
	if (valid_binding (b))
	  {
#ifdef DEBUG
	    if (graph_nodes
		(nodes, b->run_from, b->ev_from, b->run_to,
		 b->ev_to) >= (nodes * nodes))
	      error ("Node out of scope for %i,%i -> %i,%i.\n", b->run_from,
		     b->ev_from, b->run_to, b->ev_to);
#endif
	    graph[graph_nodes
		  (nodes, b->run_from, b->ev_from, b->run_to, b->ev_to)] = 1;
	  }
	bl = bl->next;
      }
    // Setup local constants order
    run = 0;
    while (run < sys->maxruns)
      {
	if (sys->runs[run].protocol != INTRUDER)
	  {
	    int run2;

	    run2 = 0;
	    while (run2 < sys->maxruns)
	      {
		if (sys->runs[run].protocol != INTRUDER && run != run2)
		  {
		    // For these two runs, we check whether run has any variables that are mapped
		    // to constants from run2
		    Termlist tl;

		    tl = sys->runs[run].locals;
		    while (tl != NULL)
		      {
			Term t;

			t = tl->term;
			if (t->type == VARIABLE && TermRunid (t) == run
			    && t->subst != NULL)
			  {
			    // t is a variable of run
			    Termlist tl2;

			    tl2 = sys->runs[run2].locals;
			    while (tl2 != NULL)
			      {
				Term t2;

				t2 = tl2->term;
				if (realTermLeaf (t2) && t2->type != VARIABLE
				    && TermRunid (t2) == run2)
				  {
				    // t2 is a constant of run2
				    if (isTermEqual (t, t2))
				      {
					// Indeed, run depends on the run2 constant t2. Thus we must store this order.
					// The first send of t2 in run2 must be before the first (read) event in run with t2.
					int ev2;
					int done;
					Roledef rd2;

					done = 0;
					ev2 = 0;
					rd2 = sys->runs[run2].start;
					while (!done
					       && ev2 < sys->runs[run2].step)
					  {
					    if (rd2->type == SEND
						&& termSubTerm (rd2->message,
								t2))
					      {
						// Allright, we send it here at ev2 first
						int ev;
						Roledef rd;

						ev = 0;
						rd = sys->runs[run].start;
						while (!done
						       && ev <
						       sys->runs[run].step)
						  {
						    if (termSubTerm
							(rd->message, t2))
						      {
							// Term occurs here in run
							if (rd->type == READ)
							  {
							    // It's read here first.
							    // Order and be done with it.
							    graph[graph_nodes
								  (nodes,
								   run2, ev2,
								   run, ev)] =
							      1;
#ifdef DEBUG
							    if (DEBUGL (5))
							      {
								eprintf
								  ("* [local originator] term ");
								termPrint
								  (t2);
								eprintf
								  (" is bound using %i, %i before %i,%i\n",
								   run2, ev2,
								   run, ev);
							      }
#endif
							    done = 1;
							  }
							else
							  {
							    // It doesn't occur first in a READ, which shouldn't be happening
							    if (switches.
								output ==
								PROOF)
							      {
								eprintf
								  ("Term ");
								termPrint
								  (t2);
								eprintf
								  (" from run %i occurs in run %i, term ",
								   run2, run);
								termPrint (t);
								eprintf
								  (" before it is read?\n");
							      }
							    // Thus, we create an artificial loop
							    if (sys->runs[0].
								step > 1)
							      {
								// This forces a loop, and thus prunes
								graph
								  [graph_nodes
								   (nodes, 0,
								    1, 0,
								    0)] = 1;
							      }
							  }
						      }
						    rd = rd->next;
						    ev++;
						  }
						done = 1;
					      }
					    rd2 = rd2->next;
					    ev2++;
					  }
				      }
				  }
				tl2 = tl2->next;
			      }
			  }
			tl = tl->next;
		      }
		  }
		run2++;
	      }
	  }
	run++;
      }
  }
}


/**
 *
 * Externally available functions
 *
 */

//! Yield node count
int
node_count ()
{
  int count;
  int run;

  count = 0;
  for (run = 0; run < sys->maxruns; run++)
    {
      //!@todo This now reference to step, but we intend "length" as in Arachne.
      count = count + sys->runs[run].step;
    }
  return count;
}

//! Yield node number given run, ev
__inline__ int
node_number (int run, int ev)
{
  int node;

  node = ev;
  while (run > 0)
    {
      run--;
      //!@todo This now reference to step, but we intend "length" as in Arachne.
      node = node + sys->runs[run].step;
    }
  return node;
}

//! Yield graph index, given node1, node2 numbers
__inline__ int
graph_index (const int node1, const int node2)
{
  return ((node1 * nodes) + node2);
}

//! Yield graph index, given (node1), (node2) tuples
__inline__ int
graph_nodes (const int nodes, const int run1, const int ev1, const int run2,
	     const int ev2)
{
  int node1;
  int node2;

  node1 = node_number (run1, ev1);
#ifdef DEBUG
  if (node1 < 0 || node1 >= nodes)
    error ("node_number %i out of scope %i for %i,%i.", node1, nodes, run1,
	   ev1);
#endif
  node2 = node_number (run2, ev2);
#ifdef DEBUG
  if (node2 < 0 || node2 >= nodes)
    error ("node_number %i out of scope %i for %i,%i.", node2, nodes, run2,
	   ev2);
#endif
  return graph_index (node1, node2);
}

//! Print a binding (given a binding list pointer)
int
binding_print (const Binding b)
{
  if (b->done)
    eprintf ("Binding (%i,%i) --( ", b->run_from, b->ev_from);
  else
    eprintf ("Unbound --( ");
  termPrint (b->term);
  eprintf (" )->> (%i,%i)", b->run_to, b->ev_to);
  if (b->blocked)
    eprintf ("[blocked]");
  return 1;
}


//! Add a goal
/**
 * The int parameter 'level' is just to store additional info. Here, it stores priorities for a goal.
 * Higher level goals will be selected first. Typically, a normal goal is level 0, a key is 1.
 */
int
goal_add (Term term, const int run, const int ev, const int level)
{
  term = deVar (term);
#ifdef DEBUG
  if (term == NULL)
    error ("Trying to add an emtpy goal term");
  if (run >= sys->maxruns)
    error ("Trying to add a goal for a run that does not exist.");
  if (ev >= sys->runs[run].step)
    error
      ("Trying to add a goal for an event that is not in the semistate yet.");
#endif
  if (realTermTuple (term))
    {
      return goal_add (TermOp1 (term), run, ev, level) +
	goal_add (TermOp2 (term), run, ev, level);
    }
  else
    {
      // Determine whether we already had it
      int nope;

      int testSame (void *data)
      {
	Binding b;

	b = (Binding) data;
	if (isTermEqual (b->term, term) && run == b->run_to && ev == b->ev_to)
	  {			// abort scan, report
	    return 0;
	  }
	else
	  {			// proceed with scan
	    return 1;
	  }
      }

      nope = list_iterate (sys->bindings, testSame);
      if (nope)
	{
	  // Add a new binding
	  Binding b;
	  b = binding_create (term, run, ev);
	  b->level = level;
	  sys->bindings = list_insert (sys->bindings, b);
#ifdef DEBUG
	  if (DEBUGL (3))
	    {
	      eprintf ("Adding new binding for ");
	      termPrint (term);
	      eprintf (" to run %i, ev %i.\n", run, ev);
	    }
#endif
	  return 1;
	}
    }
  return 0;
}

//! Add a goal, and bind it immediately.
// If the result is negative, no goals will have been added, as the resulting state must be pruned (cycle) */
int
goal_add_fixed (Term term, const int run, const int ev, const int fromrun,
		const int fromev)
{
  int newgoals, n;
  List l;
  int res;

  newgoals = goal_add (term, run, ev, 0);
  l = sys->bindings;
  n = newgoals;
  res = 1;
  while (res != 0 && n > 0 && l != NULL)
    {
      Binding b;

      b = (Binding) l->data;
      if (b->done)
	{
	  globalError++;
	  binding_print (b);
	  error (" problem with new fixed binding!");
	}
      res = goal_bind (b, fromrun, fromev);	// returns 0 if it must be pruned
      l = l->next;
      n--;
    }
  if (res != 0)
    {
      return newgoals;
    }
  else
    {
      goal_remove_last (newgoals);
      return -1;
    }
}

//! Remove a goal
void
goal_remove_last (int n)
{
  while (n > 0)
    {
      if (sys->bindings != NULL)
	{
	  Binding b;

	  b = (Binding) sys->bindings->data;
	  binding_destroy (b);
	  sys->bindings = list_delete (sys->bindings);
	  n--;
	}
      else
	{
	  error
	    ("goal_remove_last error: trying to remove %i too many bindings.",
	     n);
	}
    }
}

//! Bind a goal (0 if it must be pruned)
int
goal_bind (const Binding b, const int run, const int ev)
{
  if (b->blocked)
    {
      error ("Trying to bind a blocked goal.");
    }
  if (!b->done)
    {
#ifdef DEBUG
      if (run >= sys->maxruns || sys->runs[run].step <= ev)
	error ("Trying to bind to something not yet in the semistate.");
#endif
      b->done = 1;
      b->run_from = run;
      b->ev_from = ev;
      goal_graph_create ();
      return warshall (graph, nodes);
    }
  else
    {
      globalError++;
      binding_print (b);
      error ("Trying to bind a bound goal again.");
    }
}

//! Unbind a goal
void
goal_unbind (const Binding b)
{
  if (b->done)
    {
      goal_graph_destroy (b);
      b->done = 0;
    }
  else
    {
      error ("Trying to unbind an unbound goal again.");
    }
}

//! Bind a goal as a dummy (block)
/**
 * Especially made for tuple expansion
 */
int
binding_block (Binding b)
{
  if (!b->blocked)
    {
      b->blocked = 1;
      return 1;
    }
  else
    {
      error ("Trying to block a goal again.");
    }
}

//! Unblock a binding
int
binding_unblock (Binding b)
{
  if (b->blocked)
    {
      b->blocked = 0;
      return 1;
    }
  else
    {
      error ("Trying to unblock a non-blocked goal.");
    }
}

//! Determine whether some label set is ordered w.r.t. send/read order.
/**
 * Assumes all these labels exist in the system, within length etc, and that the run mappings are valid.
 */
int
labels_ordered (Termmap runs, Termlist labels)
{
  goal_graph_create ();
  if (warshall (graph, nodes) == 0)
    {
      error ("Testing ordering of label set for a graph with a cycle.");
    }

  while (labels != NULL)
    {
      // Given this label, and the mapping of runs, we want to know if the order is okay. Thus, we need to know sendrole and readrole
      Labelinfo linfo;
      int send_run, send_ev, read_run, read_ev;

      int get_index (const int run)
      {
	Roledef rd;
	int i;

	i = 0;
	rd = sys->runs[run].start;
	while (rd != NULL && !isTermEqual (rd->label, labels->term))
	  {
	    rd = rd->next;
	    i++;
	  }
#ifdef DEBUG
	if (rd == NULL)
	  error
	    ("Could not locate send or read for label, after niagree holds, to test for order.");
#endif
	return i;
      }

      linfo = label_find (sys->labellist, labels->term);
      send_run = termmapGet (runs, linfo->sendrole);
      read_run = termmapGet (runs, linfo->readrole);
      send_ev = get_index (send_run);
      read_ev = get_index (read_run);
      if (graph[graph_nodes (nodes, send_run, send_ev, read_run, read_ev)] ==
	  0)
	{
	  // Not ordered; false
	  return 0;
	}

      // Proceed
      labels = labels->next;
    }
  return 1;
}

//! Check whether the binding denotes a sensible thing such that we can use run_from and ev_from
int
valid_binding (Binding b)
{
  if (b->done && !b->blocked)
    return 1;
  else
    return 0;
}

//! Check for unique origination
/*
 * Contrary to a previous version, we simply check for unique origination.
 * This immediately takes care of any 'occurs before' things. Complexity is N
 * log N.
 *
 * Each term should originate only at one point (thus in one binding)
 *
 *@returns True, if it's okay. If false, it needs to be pruned.
 */
int
unique_origination ()
{
  List bl;

  bl = sys->bindings;

  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      // Check for a valid binding; it has to be 'done' and sensibly bound (not as in tuple expanded stuff)
      if (valid_binding (b))
	{
	  Termlist terms;

	  terms = tuple_to_termlist (b->term);
	  if (terms != NULL)
	    {
	      /* Apparently this is a good term.
	       * Now we check whether it occurs in any previous bindings as well.
	       */

	      List bl2;

	      bl2 = sys->bindings;
	      while (bl2 != bl)
		{
		  Binding b2;

		  b2 = (Binding) bl2->data;
		  if (valid_binding (b2))
		    {
		      Termlist terms2, sharedterms;

		      terms2 = tuple_to_termlist (b2->term);
		      sharedterms = termlistConjunct (terms, terms2);

		      // Compare terms
		      if (sharedterms != NULL)
			{
			  // Apparently, this binding shares a term.
			  // Equal terms should originate at the same point
			  if (b->run_from != b2->run_from ||
			      b->ev_from != b2->ev_from)
			    {
			      // Not equal: thus no unique origination.
			      return 0;
			    }
			}
		      termlistDelete (terms2);
		      termlistDelete (sharedterms);
		    }
		  bl2 = bl2->next;
		}
	    }
	  termlistDelete (terms);
	}
      bl = bl->next;
    }
  return 1;
}

//! Prune invalid state w.r.t. <=C minimal requirement
/**
 * Intuition says this can be done a lot more efficient. Luckily this is the prototype.
 *
 *@returns True, if it's okay. If false, it needs to be pruned.
 */
int
bindings_c_minimal ()
{
  List bl;

  if (switches.experimental == 1)
    {
      if (unique_origination () == 0)
	{
	  return 0;
	}
    }

  // Ensure a fresh state graph
  goal_graph_create ();
  // Recompute closure; does that work?
  if (!warshall (graph, nodes))
    {
      List l;

      globalError++;
      l = sys->bindings;
      while (l != NULL)
	{
	  Binding b;

	  b = (Binding) l->data;
	  binding_print (b);
	  eprintf ("\n");
	  l = l->next;
	}
      error ("Detected a cycle when testing for c-minimality");
    }

  // For all goals
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      // Check for a valid binding; it has to be 'done' and sensibly bound (not as in tuple expanded stuff)
      if (valid_binding (b))
	{
	  int run;
	  int node_from;

	  node_from = node_number (b->run_from, b->ev_from);
	  // Find all preceding events
	  for (run = 0; run < sys->maxruns; run++)
	    {
	      int ev;

	      //!@todo hardcoded reference to step, should be length
	      for (ev = 0; ev < sys->runs[run].step; ev++)
		{
		  int node_comp;

		  node_comp = node_number (run, ev);
		  if (graph[graph_index (node_comp, node_from)] > 0)
		    {
		      // this node is *before* the from node
		      Roledef rd;

		      rd = roledef_shift (sys->runs[run].start, ev);
		      if (termInTerm (rd->message, b->term))
			{
			  // This term already occurs as interm in a previous node!
#ifdef DEBUG
			  if (DEBUGL (4))
			    {
			      // Report this
			      indentPrint ();
			      eprintf ("Binding for ");
			      termPrint (b->term);
			      eprintf
				(" at r%i i%i is not c-minimal because it occurred before at r%i i%i in ",
				 b->run_from, b->ev_from, run, ev);
			      termPrint (rd->message);
			      eprintf ("\n");
			    }
#endif
			  return 0;
			}
		    }
		}
	    }
	}
      bl = bl->next;
    }
  return 1;
}
