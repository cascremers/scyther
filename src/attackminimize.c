#include <stdio.h>
#include <stdlib.h>
#include "system.h"
#include "tracebuf.h"

//! Help counter for the number of unknowns.
int cUnk = 0;
//! Help counter for the number of todos.
int cTod = 0;

//! Mark all events of the same run before the event as required.
/**
 *@param sys The system.
 *@param tb The attack buffer.
 *@param ev The reference event index.
 */
void
markback (const System sys, struct tracebuf *tb, int ev)
{
  int run = tb->run[ev];

  while (ev >= 0)
    {
      if (tb->run[ev] == run)
	{
	  switch (tb->event[ev]->type)
	    {
	    case READ:
	      switch (tb->status[ev])
		{
		case S_UNK:
		  cUnk--;
		case S_RED:
		  tb->status[ev] = S_TOD;
		  cTod++;
		  break;
		case S_TOD:
		case S_OKE:
		  break;
		}
	      break;
	    case SEND:
	    case CLAIM:
	      if (tb->status[ev] == S_UNK)
		{
		  cUnk--;
		}
	      tb->status[ev] = S_OKE;
	      break;
	    }
	}
      ev--;
    }
}

//! Minimize the attack.
void
attackMinimize (const System sys, struct tracebuf *tb)
{
  int i;
  int j;

  cUnk = 0;
  cTod = 0;

  for (i = 0; i < tb->length; i++)
    {
      switch (tb->status[i])
	{
	case S_UNK:
	  cUnk++;
	  break;
	case S_TOD:
	  cTod++;
	  break;
	default:
	  break;
	}
    }

  markback (sys, tb, tb->violatedclaim);

  while (cUnk + cTod > 0)
    {
      while (cTod > 0)
	{
	  for (i = 0; i < tb->length; i++)
	    // kies een i; laten we de eerste maar pakken
	    {
	      if (tb->status[i] == S_TOD)
		break;
	    }
	  if (i == tb->length)
	    {
	      eprintf ("Some step error.\n");
	      exit (1);
	    }

	  j = i;
	  while (j >= 0 && inKnowledge (tb->know[j], tb->event[i]->message))
	    {
	      // zoek waar m in de kennis komt
	      j--;
	    }
	  tb->status[i] = S_OKE;
	  cTod--;
	  if (j >= 0)
	    {
	      markback (sys, tb, j);
	    }
	}
      while (cTod == 0 && cUnk > 0)
	{
	  for (i = tb->length - 1; i >= 0; i--)
	    // pak laatste i
	    {
	      if (tb->status[i] == S_UNK)
		break;
	    }
	  if (i < 0)
	    {
	      eprintf ("Some i<0 error.\n");
	      exit (1);
	    }

	  tb->status[i] = S_RED;
	  cUnk--;
	  tb->reallength--;

	  j = tracebufRebuildKnow (tb);
	  if (j > -1)
	    {
	      tb->reallength++;
	      markback (sys, tb, i);
	      if (j < tb->length)
		{
		  tb->link[j] = (tb->link[j] > i ? tb->link[j] : i);
		}
	    }
	}
    }
}
