/**
 * Handle bindings for Arache engine.
 */

#include "list.h"
#include "system.h"
#include "binding.h"
#include "warshall.h"
#include "memory.h"
#include "debug.h"

/*
 * Idea is the ev_from *has to* precede the ev_to
 */
struct binding
{
  int run_from;
  int ev_from;

  int run_to;
  int ev_to;

  int *graph;
  int nodes;
};

typedef struct binding *Binding;

static System sys;

/*
 *
 * Assist stuff
 *
 */

//! Create mem for binding
Binding
binding_create (int run_from, int ev_from, int run_to, int ev_to)
{
  Binding b;

  b = memAlloc (sizeof (struct binding));
  b->run_from = run_from;
  b->ev_from = ev_from;
  b->run_to = run_to;
  b->ev_to = ev_to;
  b->graph = NULL;
  b->nodes = 0;
  return b;
}

//! Remove mem for binding
void
binding_destroy (Binding b)
{
  if (b->graph != NULL)
    {
      memFree (b->graph, (b->nodes * b->nodes) * sizeof (int));
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
graph_index (const int nodes, const int node1, const int node2)
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
  return graph_index (nodes, node1, node2);
}

//! Compute closure graph
/**
 *@returns 0 iff there is a cycle, 1 otherwise
 */
int
closure_graph (Binding b)
{
  int nodes;
  int *graph;
  int run, ev;
  List bl;

  // Setup graph
  nodes = node_count ();
  graph = memAlloc ((nodes * nodes) * sizeof (int));
  graph_fill (graph, nodes, 0);
  b->nodes = nodes;
  b->graph = graph;

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
#ifdef DEBUG
      if (graph_nodes (nodes, b->run_from, b->ev_from, b->run_to, b->ev_to) >=
	  (nodes * nodes))
	error ("Node out of scope for %i,%i -> %i,%i.\n", b->run_from,
	       b->ev_from, b->run_to, b->ev_to);
#endif
      graph[graph_nodes (nodes, b->run_from, b->ev_from, b->run_to, b->ev_to)]
	= 1;
      bl = bl->next;
    }
  return warshall (graph, nodes);
}

//! Print a binding (given a binding list pointer)
int
binding_print (void *bindany)
{
  Binding b;

  b = (Binding) bindany;
  eprintf ("Binding (%i,%i) --->> (%i,%i)\n", b->run_from, b->ev_from,
	   b->run_to, b->ev_to);
  return 1;
}

//! Add a binding
/**
 * Note that bindings are added to the head of the list.
 *@returns True iff is a valid additional binding. False if not.
 */
int
binding_add (int run_from, int ev_from, int run_to, int ev_to)
{
  Binding b;
  int flag;

#ifdef DEBUG
  if (DEBUGL (5))
    {
      eprintf ("Adding binding (%i,%i) --->> (%i,%i)\n", run_from, ev_from,
	       run_to, ev_to);
    }
  if (ev_from >= sys->runs[run_from].step)
    error ("run_from event index too large for scenario.");
  if (ev_to >= sys->runs[run_to].step)
    error ("run_to event index too large for scenario.");
  if (run_from < 0 || run_from >= sys->maxruns)
    error ("run_from out of scope.");
  if (run_to < 0 || run_to >= sys->maxruns)
    error ("run_to out of scope.");
#endif
  b = binding_create (run_from, ev_from, run_to, ev_to);
  sys->bindings = list_insert (sys->bindings, b);

  /*
   * Compute closure graph etc.
   */
  flag = closure_graph (b);
#ifdef DEBUG
  if (DEBUGL (5))
    {
      eprintf ("Adding binding result %i\n", flag);
    }
#endif
  return flag;
}

//! Remove last additions, including last manual addition
/**
 * Note that this concerns the head of the list.
 */
void
binding_remove_last ()
{
  Binding b;

  if (sys->bindings != NULL)
    {
      b = (Binding) sys->bindings->data;
      binding_destroy (b);
      sys->bindings = list_delete (sys->bindings);
    }
}
