/**
 * Handle bindings for Arache engine.
 */

#include "list.h"
#include "system.h"
#include "binding.h"
#include "warshall.h"
#include "memory.h"
#include "debug.h"
#include "term.h"

static System sys;
static int *graph;
static int nodes;

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
  b->child = 0;
  b->run_from = -1;
  b->ev_from = -1;
  b->run_to = run_to;
  b->ev_to = ev_to;
  graph = NULL;
  nodes = 0;
  b->term = term;
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
      memFree (graph, (nodes * nodes) * sizeof (int));
      graph = NULL;
    }
}

//! Compute unclosed graph
void
goal_graph_create ()
{
  int run, ev;
  List bl;

  goal_graph_destroy ();

  // Setup graph
  nodes = node_count ();
  graph = memAlloc ((nodes * nodes) * sizeof (int));
  graph_fill (graph, nodes, 0);

  // Setup run order
  run = 0;
  while (run < sys->maxruns)
    {
      ev = 1;
      //!@todo This now reference to step, but we intend "length" as in Arachne.
      while (ev < sys->runs[run].step)
	{
	  graph[graph_nodes (nodes, run, ev - 1, run, ev)] = 1;
	  ev++;
	}
      run++;
    }
  // Setup bindings order
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      if (b->done)
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
  return 1;
}


//! Add a goal
void
goal_add (Term term, const int run, const int ev)
{
  term = deVar (term);
  if (realTermTuple (term))
    {
      int width;
      int flag;
      int i;

      flag = 1;
      width = tupleCount (term);
      i = 0;
      while (i < width)
	{
	  goal_add (tupleProject (term, i), run, ev);
	  if (i > 0)
	    {
	      Binding b;

	      b = (Binding) sys->bindings->data;
	      b->child = 1;
	    }
	  i++;
	}
    }
  else
    {
      Binding b;

      b = binding_create (term, run, ev);
      sys->bindings = list_insert (sys->bindings, b);
    }
}

//! Remove a goal
void
goal_remove_last ()
{
  Binding b;
  int child;

  child = 1;
  while (child && (sys->bindings != NULL))
    {
      b = (Binding) sys->bindings->data;
      child = b->child;
      binding_destroy (b);
      sys->bindings = list_delete (sys->bindings);
    }
}

//! Bind a goal (0 if it must be pruned)
int
goal_bind (const Binding b, const int run, const int ev)
{
  if (!b->done)
    {
      b->done = 1;
      b->run_from = run;
      b->ev_from = ev;
      goal_graph_create (b);
      return warshall (graph, nodes);
    }
  else
    {
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

  // Ensure a state graph
  if (graph == NULL)
    {
      goal_graph_create ();
      // Recompute closure; does that work?
      if (!warshall (graph, nodes))
	{
	  // Hmm, cycle
	  return 0;
	}
    }

  // For all goals
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      if (b->done)
	{
	  int run;
	  int node_from;

	  node_from = node_number (b->run_from, b->ev_from);
	  // Find all preceding events
	  for (run = 0; run <= sys->maxruns; run++)
	    {
	      int ev;

	      //!@todo hardcoded reference to step, should be length
	      for (ev = 0; run < sys->runs[run].step; ev++)
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
