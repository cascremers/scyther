/**
 * Warshall's algorithm for transitive closure computation.
 */

#include "warshall.h"
#include "debug.h"

void
graph_fill (int *graph, int nodes, int value)
{
  int node;

  node = 0;
  while (node < (nodes * nodes))
    {
      graph[node] = value;
      node++;
    }
}

//! Show a graph
void
graph_display (int *graph, int nodes)
{
  int i;

  int index (const int i, const int j)
  {
    return (i * nodes + j);
  }

  i = 0;
  while (i < nodes)
    {
      int j;
      j = 0;
      while (j < nodes)
	{
	  eprintf ("%i ", graph[index (i, j)]);
	  j++;
	}
      eprintf ("\n");
      i++;
    }
}


//! Apply warshall's algorithm to determine the closure of a graph
/**
 * If j<i and k<j, then k<i.
 * Could be done more efficiently but that is irrelevant here.
 *
 *@param graph A pointer to the integer array of nodes*nodes elements.
 *@param nodes The number of nodes in the graph.
 *@Returns 0 if there is a cycle; and the algorithm aborts, 1 if there is no cycle and the result is okay.
 */
int
warshall (int *graph, int nodes)
{
  int i;

  int index (const int i, const int j)
  {
    return (i * nodes + j);
  }

  i = 0;
  while (i < nodes)
    {
      int j;

      j = 0;
      while (j < nodes)
	{
	  if (graph[index (j, i)] == 1)
	    {
	      int k;

	      k = 0;
	      while (k < nodes)
		{
		  if (graph[index (k, j)] == 1)
		    {
		      /**
		       * Previously, we tested k == i (self-loop).
		       * Now we test 2-node loops, i.e. wether there is also a path from i to k.
		       */
		      if (graph[index (i, k)] > 0)
			{
			  // Oh no! A cycle.
			  graph[index (k, i)] = 2;
#ifdef DEBUG
			  if (DEBUGL (5))
			    {
			      graph_display (graph, nodes);
			    }
#endif
			  return 0;
			}
		      graph[index (k, i)] = 1;
		    }
		  k++;
		}
	    }
	  j++;
	}
      i++;
    }
  return 1;
}
