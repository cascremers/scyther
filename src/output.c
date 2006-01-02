/*
 * output.c
 *
 * Outputs an attack.
 * Currently, every attack is printed.
 * TODO move attacks to a buffer, and print _only_ the shortest one.
 */

#include <stdlib.h>
#include <stdio.h>
#include "system.h"
#include "latex.h"
#include "switches.h"


void
linePrint (int i)
{
  indent ();
  while (i > 0)
    {
      printf ("--------");
      i--;
    }
  printf ("\n");
}

int
correspondingSend (const System sys, int rd)
{

  int labelMatch = 0;
  int toMatch = 0;
  int fromMatch = 0;
  int tofromMatch = 0;
  int messageMatch = 0;
  int nMatches = 0;
  int maxNMatches = 0;

  int readEvent = rd;
  int sendEvent = -1;
  int bestSendEvent = -1;

  for (sendEvent = readEvent; sendEvent >= 0; sendEvent--)
    {
      if (sys->traceEvent[sendEvent]->type == SEND)
	{
	  /* do all the different kind of matchings first */

	  labelMatch =
	    isTermEqualFn (sys->traceEvent[sendEvent]->label,
			   sys->traceEvent[readEvent]->label);
	  toMatch =
	    isTermEqualFn (sys->traceEvent[sendEvent]->to,
			   sys->traceEvent[readEvent]->to);
	  fromMatch =
	    isTermEqualFn (sys->traceEvent[sendEvent]->from,
			   sys->traceEvent[readEvent]->from);
	  tofromMatch = toMatch || fromMatch;
	  messageMatch =
	    isTermEqualFn (sys->traceEvent[sendEvent]->message,
			   sys->traceEvent[readEvent]->message);

	  /* calculate the score */

	  nMatches = labelMatch + tofromMatch + messageMatch;

	  if (nMatches == 3)
	    {
	      /* bingo! success on all matches */

	      //printf("Found perfect match: %d\n", s);
	      bestSendEvent = sendEvent;
	      break;
	    }
	  if (nMatches > maxNMatches)
	    {
	      /* if we found a better candidate than we already had, we'll update */

	      //printf("Comparing SEND #%d: ",s);
	      //if (labelMatch) printf("label ");
	      //if (toMatch) printf("to ");
	      //if (fromMatch) printf("from ");
	      //if (messageMatch) printf("message ");
	      //printf("\n");

	      /* however, we first want to be sure that at least some matches are successful */

	      if (labelMatch && messageMatch)
		{
		  /* strongest restriction: message and label should match */

		  maxNMatches = nMatches;
		  bestSendEvent = sendEvent;

		}
	      else if (messageMatch)
		{
		  /* if label AND message don't match: */
		  /* at least message should match */

		  maxNMatches = nMatches;
		  bestSendEvent = sendEvent;
		}
	      else if (labelMatch)
		{
		  /* if message doesn't match */
		  /* the label should matches */

		  maxNMatches = nMatches;
		  bestSendEvent = sendEvent;
		}
	      //printf("Best match: %d  maxNMatches: %d\n", s, maxNMatches);
	    }
	}
    }

  //bestSendEvent = NULL;
  if (bestSendEvent == -1)
    {
      /*Termlist tl;
         Term t;

         //newtl = knowledgeNew(sys->traceKnow[i],sys->traceKnow[i+1]);

         for (tl = sys->traceKnow[rd]->basic; tl != NULL; tl = tl->next)
         {
         t = tl->term;
         termPrint(t);
         printf(" - ");
         }
         printf("\n");
         for (tl = sys->traceKnow[rd]->encrypt; tl != NULL; tl = tl->next)
         {
         t = tl->term;
         termPrint(t);
         printf(" - ");
         }
         printf("\n");
         for (tl = sys->traceKnow[rd]->inverses; tl != NULL; tl = tl->next)
         {
         t = tl->term;
         termPrint(t);
         printf(" - ");
         }
         printf("\n"); */

      int u;

      for (u = 0; u < rd; u++)
	{
	  if (sys->traceEvent[u]->type == SEND)
	    {


	      //termPrint(readEvent->message);
	      //printf("\n");
	      knowledgePrint (sys->traceKnow[u]);
	      //printf("Is received message in knowledge after SEND %d? %d\n", u, inKnowledge(sys->traceKnow[u+1],readEvent->message));
	      if (inKnowledge
		  (sys->traceKnow[u + 1],
		   sys->traceEvent[readEvent]->message))
		{
		  bestSendEvent = u;
		  break;
		}
	    }
	}
    }

  if (bestSendEvent == -1)
    {
      printf ("!! Could not find a matching SEND\n");
    }
  else
    {
      //latexMessagePrint(sys, bestSendEvent, readEvent);
      //printf("Latex: ");
      //termPrint(bestSendEvent->from);
      //printf(" -> ");
      if (!isTermEqualFn
	  (sys->traceEvent[bestSendEvent]->to,
	   sys->traceEvent[readEvent]->to))
	{
	  //termPrint(bestSendEvent->to);
	  //printf(" -> ");
	}
      if (!isTermEqualFn
	  (sys->traceEvent[bestSendEvent]->from,
	   sys->traceEvent[readEvent]->from))
	{
	  //termPrint(readEvent->from);
	  //printf(" -> ");
	}
      //termPrint(readEvent->to);
      //printf("\n");
    }
  return bestSendEvent;
}

void
tracePrint (const System sys)
{
  int i, j;
  int lastrid;
  int width;
  Termlist newtl;

  void sticks (int i)
  {
    while (i > 0)
      {
	printf ("|\t");
	i--;
      }
  }

  void sticksLine (void)
  {
    sticks (width);
    printf ("\n");
  }

  if (switches.latex)
    {
      //latexTracePrint(sys);
      return;
    }

  /* fix the 'next' knowledge, this is required because sometimes
   * when calling this function, the next knowledge is not stored
   * yet, but required for the general form of the output . */

  sys->traceKnow[sys->step + 1] = sys->know;


  /* how wide is the trace? */
  width = 0;
  for (i = 0; i <= sys->step; i++)
    {
      if (sys->traceRun[i] >= width)
	width = sys->traceRun[i] + 1;
    }

  linePrint (width);
  indent ();
  printf ("Dumping trace:\n");
  linePrint (width);

  /* first some parameter issues */

  knowledgePrint (sys->traceKnow[0]);
  /* also print inverses */
  indent ();
  printf ("Inverses: ");
  knowledgeInversesPrint (sys->traceKnow[0]);
  printf ("\n");

  /* Trace columns header.  First the run identifier and role.  On the
   * second line we have the perceived agents for each partner role.
   * These are printed in the same order as the role specification in the
   * protocol. */

  linePrint (width);
  indent ();

  for (i = 0; i < width; i++)
    {
      termPrint (sys->runs[i].role->nameterm);
      printf ("#%i\t", i);
    }
  printf ("\n");
  for (i = 0; i < width; i++)
    {
      termPrint (agentOfRun (sys, i));
      printf ("\t");
    }
  printf ("\n");

  for (i = 0; i < width; i++)
    {
      agentsOfRunPrint (sys, i);
      printf ("\t");
    }
  printf ("\n");

  /* now we print the actual trace */

  linePrint (width);
  lastrid = -1;
  for (i = 0; i <= sys->step; i++)
    {
      /* yields extra newlines between switching of runs */

      j = sys->traceRun[i];
      if (j != lastrid)
	{
	  sticksLine ();
	  lastrid = j;
	}

      /* print the actual event */

      indent ();
      sticks (j);
      roledefPrint (sys->traceEvent[i]);

      //if (sys->traceEvent[i]->type == READ && !sys->traceEvent[i]->internal)
      //{
      /* calls routine to find the best SEND-candidate */
      /* the result is not yet being used */

      //      printf("\n");
      //      correspondingSend(sys, i);
      //}

      /* have we learnt anything new? */
      newtl = knowledgeNew (sys->traceKnow[i], sys->traceKnow[i + 1]);
      if (newtl != NULL)
	{
	  printf ("\n");
	  sticksLine ();
	  sticks (width);
	  printf ("/* Intruder learns ");
	  termlistPrint (newtl);
	  termlistDelete (newtl);
	  printf (" */");
	  lastrid = -1;
	}

      /* new line */
      printf ("\n");
    }

  switch (switches.clp)
    {
    case 1:
      indent ();
      printf ("---[ constraints ]-----\n");
      constraintlistPrint (sys->constraints);
      break;
    default:
      break;
    }
  linePrint (width);
}



void
attackDisplayAscii (const System sys)
{
  int i, j;
  int length;
  int lastrid;
  int width;
  Termlist newtl;
  struct tracebuf *tb;

  void sticks (int i)
  {
    while (i > 0)
      {
	printf ("|\t");
	i--;
      }
  }

  void sticksLine (void)
  {
    sticks (width);
    printf ("\n");
  }

  /* attack trace buffer */
  tb = sys->attack;
  length = sys->attack->length;

  /* set variables */
  varbufSet (sys, tb->variables);

  /* how wide is the trace? */
  width = 0;
  for (i = 0; i < length; i++)
    {
      if (tb->run[i] >= width)
	width = tb->run[i] + 1;
    }

  linePrint (width);
  indent ();
  printf ("Dumping trace:\n");
  linePrint (width);

  /* first some parameter issues */

  knowledgePrint (tb->know[0]);
  printf ("Variables: ");
  termlistPrint (sys->variables);
  printf ("\n");

  /* Trace columns header.  First the run identifier and role.  On the
   * second line we have the perceived agents for each partner role.
   * These are printed in the same order as the role specification in the
   * protocol. */

  linePrint (width);
  indent ();

  for (i = 0; i < width; i++)
    {
      termPrint (sys->runs[i].role->nameterm);
      printf ("#%i\t", i);
    }
  printf ("\n");
  for (i = 0; i < width; i++)
    {
      termPrint (agentOfRun (sys, i));
      printf ("\t");
    }
  printf ("\n");

  for (i = 0; i < width; i++)
    {
      agentsOfRunPrint (sys, i);
      printf ("\t");
    }
  printf ("\n");

  /* now we print the actual trace */

  linePrint (width);
  lastrid = -1;
  for (i = 0; i < length; i++)
    {
      /* yields extra newlines between switching of runs */

      j = tb->run[i];
      if (j != lastrid)
	{
	  sticksLine ();
	  lastrid = j;
	}

      /* print the actual event */

      indent ();
      sticks (j);
      roledefPrint (tb->event[i]);

      //if (sys->traceEvent[i]->type == READ && !sys->traceEvent[i]->internal)
      //{
      /* calls routine to find the best SEND-candidate */
      /* the result is not yet being used */

      //      printf("\n");
      //      correspondingSend(sys, i);
      //}

      /* have we learnt anything new? */
      newtl = knowledgeNew (tb->know[i], tb->know[i + 1]);
      if (newtl != NULL)
	{
	  printf ("\n");
	  sticksLine ();
	  sticks (width);
	  printf ("/* Intruder learns ");
	  termlistPrint (newtl);
	  termlistDelete (newtl);
	  printf (" */");
	  lastrid = -1;
	}

      /* new line */
      printf ("\n");
    }

  linePrint (width);
}


void
attackDisplay (const System sys)
{
  if (switches.latex)
    {
      attackDisplayLatex (sys);
    }
  else
    {
      attackDisplayAscii (sys);
    }
}

/* 
 *-------------------------------------------
 * state space graph section
 *-------------------------------------------
 */

void
graphInit (const System sys)
{
  Termlist tl;

  /* drawing state space. */
  printf ("digraph Statespace {\n");

  /* label */
  printf ("\tcomment = \"$");
  commandlinePrint (stdout);
  printf ("\";\n");

  /* fit stuff onto the page */
  printf ("\trankdir=LR;\n");
  printf ("\tsize=\"8.5,11\";\n");
  //printf ("\tpage=\"8.5,11\";\n");
  printf ("\tfontsize=\"6\";\n");
  printf ("\tfontname=\"Helvetica\";\n");
  printf ("\tmargin=0.5;\n");
  printf ("\tnodesep=0.06;\n");
  printf ("\tranksep=0.01;\n");
  printf ("\torientation=landscape;\n");
  printf ("\tcenter=true;\n");
  // printf ("\tlabeljust=\"r\";\n");
  printf ("\tconcentrate=true;\n");

  /* node/edge defaults */
  printf
    ("\tnode [shape=\"point\",fontsize=\"4\",fontname=\"Helvetica\"];\n");
  printf ("\tedge [fontsize=\"4\",fontname=\"Helvetica\"];\n");

  /* start with initial node 0 */
  printf ("\tn");
  statesFormat (STATES0);
  printf (" [shape=box,height=0.2,label=\"M0: ");
  tl = knowledgeSet (sys->know);
  termlistPrint (tl);
  termlistDelete (tl);
  printf ("\"];\n");
}

void
graphDone (const System sys)
{
  /* drawing state space. close up. */
  printf ("}\n");
}

void
graphNode (const System sys)
{
  Termlist newtl;
  states_t thisNode, parentNode;
  int index;
  int run;
  Roledef rd;

  /* determine node numbers */
  index = sys->step - 1;
  parentNode = sys->traceNode[index];
  thisNode = sys->states;
  rd = sys->traceEvent[index];
  run = sys->traceRun[index];

  /* add node */
  printf ("\tn");
  statesFormat (thisNode);
  printf (" [");

  newtl = knowledgeNew (sys->traceKnow[index], sys->traceKnow[index + 1]);
  if (newtl != NULL)
    {
      /* knowledge added */
      printf ("shape=box,height=0.2,label=\"M + ");
      termlistPrint (newtl);
      termlistDelete (newtl);
      printf ("\"");
    }
  else
    {
      /* no added knowledge */
      if (switches.scenario != 0 &&
	  rd != NULL &&
	  rd == sys->runs[run].start &&
	  rd->type == READ && run == sys->lastChooseRun)
	{
	  /* last choose; scenario selected */
	  printf ("shape=box,height=0.2,label=\"Scenario %i: ",
		  sys->countScenario);
	  scenarioPrint (sys);
	  printf ("\"");
	}
      else
	{
	  printf ("label=\"\"");
	}
    }
  printf ("];\n");

  /* add edge */
  printf ("\tn");
  statesFormat (parentNode);
  printf (" -> n");
  statesFormat (thisNode);
  /* add label */
  printf (" [label=\"");

  // Print step 
  printf ("%i:", sys->runs[run].step - 1);

  if (rd->type == CLAIM && (!isRunTrusted (sys, run)))
    {
      printf ("Skip claim in #%i\"", run);
    }
  else
    {
      // Print event
      roledefPrint (rd);
      printf ("#%i\"", run);
      if (rd->type == CLAIM)
	{
	  printf (",shape=house,color=green");
	}
    }
  /* a choose? */
  if (rd->type == READ && rd->internal)
    {
      printf (",color=blue");
      //printf (",style=dotted");
    }
  printf ("]");
  printf (";\n");
}

void
graphNodePath (const System sys, const int length, const char *nodepar)
{
  int i;
  states_t thisNode;

  i = 0;
  while (i < length)
    {
      /* determine node number */
      thisNode = sys->traceNode[i];

      /* color node */
      printf ("\tn");
      statesFormat (thisNode);
      printf (" [%s];\n", nodepar);
      i++;
    }
}

void
graphEdgePath (const System sys, const int length, const char *edgepar)
{
  int i;
  states_t thisNode, prevNode;

  i = 0;
  prevNode = sys->traceNode[i];
  while (i < length)
    {
      /* determine node number */
      thisNode = sys->traceNode[i + 1];

      /* color edge */
      printf ("\tn");
      statesFormat (prevNode);
      printf (" -> n");
      statesFormat (thisNode);
      printf (" [%s];\n", edgepar);
      prevNode = thisNode;
      i++;
    }
}

void
graphPath (const System sys, int length)
{
  graphNodePath (sys, length, "style=bold,color=red");
  graphEdgePath (sys, length - 1, "style=bold,color=red");
}

//! Scenario for graph; bit of a hack
void
graphScenario (const System sys, const int run, const Roledef rd)
{
  /* Add scenario node */
  printf ("\ts%i [shape=box,height=0.2,label=\"Scenario %i: ",
	  sys->countScenario, sys->countScenario);
  scenarioPrint (sys);
  printf ("\"];\n");

  /* draw edge */
  printf ("\tn%i -> s%i", sys->traceNode[sys->step], sys->countScenario);
  printf (" [color=blue,label=\"");
  printf ("%i:", sys->runs[run].step);
  roledefPrint (rd);
  printf ("#%i", run);
  printf ("\"];\n");
}
