/*
 * tracebuf.c
 *
 * trace buffer operations
 */

#include <stdio.h>
#include <stdlib.h>
#include "runs.h"
#include "memory.h"
#include "tracebuf.h"
#include "varbuf.h"

/* reconstruct the knowledge sequence, -1 if it can be done, event nr of last depending read otherwise.
 * There is one exception: if it returns tb->length, the required terms are not in the last knowledge 
 */

int
tracebufRebuildKnow(struct tracebuf *tb)
{
  Knowledge k;
  Roledef rd;
  int i;
  int flag;
  Termlist tl;

  if (tb == NULL || tb->length == 0)
    {
      /* stupid, but true */
      return -1;
    }

  flag = -1;
  k = knowledgeDuplicate(tb->know[0]);
  i = 0;
  while (i < tb->length)
    {
      rd = tb->event[i];
      if (tb->status[i] != S_RED)
	{
	  /* simulate execution of the event */
	  switch (rd->type)
	    {
	    case READ:
	      if (!inKnowledge (k, rd->message))
		{
		  flag = i;
		}
	      break;
	    case SEND:
	      knowledgeAddTerm (k, rd->message);
	      break;
	    case CLAIM:
	      /* TODO parse term requirements ? */
	      /* Probably not needed */
	      break;
	    default:
	      /* Anything else */
	      break;
	    }
	}
      /* write the new knowledge, overwriting old stuff */
      knowledgeDelete (tb->know[i+1]);
      tb->know[i+1] = knowledgeDuplicate (k);

      i++;
    }
  tl = tb->requiredterms;
  while (tl != NULL)
    {
      if (!inKnowledge (k, tl->term))
        {
          flag = tb->length;
        }
      tl = tl->next;
    }
  knowledgeDelete(k);
  return flag;
}

/*
 * traceBufInit
 *
 * initializes the trace buffer.
 */

struct tracebuf*
tracebufInit (void)
{
  struct tracebuf *tb = (struct tracebuf *) memAlloc(sizeof(struct tracebuf));
  tb->length = 0;
  tb->reallength = 0;
  tb->event = NULL;
  tb->know = NULL;
  tb->run = NULL;
  tb->status = NULL;
  tb->link = NULL;
  tb->requiredterms = NULL;
  tb->violatedclaim = 0;
  tb->variables = NULL;
  return tb;
}

void
tracebufDone (struct tracebuf *tb)
{
  if (tb == NULL)
    {
      return;
    }

  Roledef rd;

  varbufDone (tb->variables);
  if (tb->length > 0)
    {
      int i;

      i = 0;
      /* note: knowledge domain is length+1 */
      knowledgeDelete(tb->know[0]);
      while (i < tb->length)
	{
      	  rd = tb->event[i];
	  termDelete (rd->from);
	  termDelete (rd->to);
	  termDelete (rd->message);
          roledefDelete(rd);
	  knowledgeDelete(tb->know[i+1]);
	  i++;
	}

      memFree(tb->know, (i+1) * sizeof (struct knowledge*));
      memFree(tb->event, i * sizeof (struct roledef*));
      memFree(tb->run, i * sizeof(int));
      memFree(tb->status, i * sizeof(int));
      memFree(tb->link, i * sizeof(int));
    }
  memFree(tb, sizeof(tracebuf));
}

struct tracebuf*
tracebufSet (const System sys, int length, int claimev)
{
  struct tracebuf *tb;
  int i;
  Roledef rd;

  /* TODO For the constraint logic approach, we would simply insert 
   * any constant from the constraint for a variable.
   */

  tb = tracebufInit();
  if (length == 0)
    {
      return tb;
    }
  tb->length = length;
  tb->reallength = length;
  tb->variables = (Varbuf) varbufInit (sys);
  tb->event = (Roledef *) memAlloc(length * sizeof(struct roledef*));
  tb->status = (int *) memAlloc(length * sizeof(int));
  tb->link = (int *) memAlloc(length * sizeof(int));
  tb->run = (int *) memAlloc(length * sizeof(int));
  tb->know = (Knowledge *) memAlloc((length + 1) * sizeof (struct knowledge*));

  /* when duplicating the knowledge, we want to instantiate the variables as well
   */

  tb->know[0] = knowledgeSubstDo (sys->traceKnow[0]);

  i = 0;
  while (i < length)
    {
      rd = roledefDuplicate1 (sys->traceEvent[i]);
      if (rd == NULL)
	{
	  printf("Empty event in trace at %i of %i?\n",i,length);
	  exit(1);
	}

      /* make a copy without variables */ 
      rd->to      = termDuplicateUV (rd->to);
      rd->from    = termDuplicateUV (rd->from);
      rd->message = termDuplicateUV (rd->message);

      tb->event[i] = rd;
      tb->link[i] = -1;
      tb->status[i] = S_UNK;
      tb->run[i] = sys->traceRun[i];
      tb->know[i+1] = NULL;
      i++;
    }

  /* mark claim */
  tb->violatedclaim = claimev;
  tb->status[claimev] = S_OKE;
  tracebufRebuildKnow (tb);
  return tb;
}
