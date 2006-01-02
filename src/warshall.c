/**
 *@file warshall.c
 *
 * Warshall's algorithm for transitive closure computation.
 *
 * Currently this is the slow integer-instead-of-bit olde slowe version.
 */

#include <limits.h>
#include "warshall.h"
#include "debug.h"

//! fill the graph with some value
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
  int k;

  int index (const int x, const int y)
  {
    return (x * nodes + y);
  }

  k = 0;
  while (k < nodes)
    {
      int i;

      i = 0;
      while (i < nodes)
	{
	  if (graph[index (i, k)] == 1)
	    {
	      int j;

	      j = 0;
	      while (j < nodes)
		{
		  if (graph[index (k, j)] == 1)
		    {
		      if (i == j)
			{
			  // Oh no! A cycle.
			  graph[index (i, j)] = 2;
#ifdef DEBUG
			  if (DEBUGL (5))
			    {
			      graph_display (graph, nodes);
			    }
#endif
			  return 0;
			}
		      graph[index (i, j)] = 1;
		    }
		  j++;
		}
	    }
	  i++;
	}
      k++;
    }
  return 1;
}


//! Determine ranks for all nodes
/**
 * Some crude algorithm I sketched on the blackboard.
 */
int
graph_ranks (int *graph, int *ranks, int nodes)
{
  int i;
  int todo;
  int rank;

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
		  if (ranks[refn] >= rank
		      && graph[graph_index (refn, n)] != 0)
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
