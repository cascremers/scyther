/**
 * Temp file. I just forgot Warshall...
 *
 */

void
graph_fill (int *graph, int nodes, int value)
{
  int node;

  node = (nodes * nodes);
  while (node > 0)
    {
      node--;
      graph[node] = value;
    }
}

/**
 * return 1 if no cycle
 * return 0 if cycle
 */
int
warshall (int *graph, int size)
{
  int i;

  int index2 (i, j)
  {
    return (i * size + j);
  }

  i = 0;
  while (i < size)
    {
      int j;

      j = 0;
      while (j < size)
	{
	  if (graph[index2 (j, i)] == 1)
	    {
	      int k;

	      k = 0;
	      while (k < size)
		{
		  if (graph[index2 (k, j)] == 1)
		    {
		      if (k == i)
			{
			  return 0;
			}
		      graph[index2 (k, i)] = 1;
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
