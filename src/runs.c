#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "terms.h"
#include "termlists.h"
#include "knowledge.h"
#include "runs.h"
#include "memory.h"
#include "constraints.h"
#include "debug.h"
#include "output.h"
#include "tracebuf.h"

/* from compiler.o */
extern Term TERM_Type;

/* for e.g. termprinting */
int globalLatex;

static int indentState = 0;
static int indentDepth = 0;

Run
makeRun ()
{
  return (Run) memAlloc (sizeof (struct run));
}

Roledef
makeRoledef ()
{
  return (Roledef) memAlloc (sizeof (struct roledef));
}

System
systemInit ()
{
  System sys = (System) memAlloc (sizeof (struct system));

  /* initially, no trace ofcourse */
  sys->step = 0;
  sys->shortestattack = INT_MAX;
  sys->attack = tracebufInit();

  /* switches */
  sys->porparam = 0;		// multi-purpose parameter
  sys->latex = 0;		// latex output?

  /* set illegal traversal by default, to make sure it is set
     later */
  sys->traverse = 0;
  sys->report = 1;
  sys->switch_maxtracelength = INT_MAX;
  sys->maxtracelength = INT_MAX;

  /* init rundefs */
  sys->maxruns = 0;
  sys->runs = NULL;
  /* no protocols yet */
  sys->protocols = NULL;
  sys->locals = NULL;
  sys->variables = NULL;
  sys->untrusted = NULL;
  sys->secrets = NULL;		// list of claimed secrets
  sys->attack = NULL;

  /* matching CLP */
  sys->constraints = NULL;	// no initial constraints

  /* reset global counters */
  systemReset (sys);

  return sys;
}

void
systemReset (const System sys)
{
  /* some initial counters */
  sys->statesLow = 0;		// number of explored states
  sys->statesHigh = 0;		// this is not as ridiculous as it might seem
  sys->explore = 1;		// do explore the space
  sys->claims = 0;		// number of claims encountered
  sys->failed = 0;		// number of failed claims
  sys->knowPhase = 0;		// knowledge transition id

  termlistDestroy (sys->secrets);	// remove old secrets list
  sys->secrets = NULL;		// list of claimed secrets

  /* transfer switches */
  sys->maxtracelength = sys->switch_maxtracelength;

  /* POR init */
  sys->PORphase = -1;
  sys->PORdone = 1;		// mark as 'something done' with previous reads

  /* global latex switch: ugly, but otherwise I must carry it into every
   * single subprocedure such as termPrint */

  globalLatex = sys->latex;
}

void
systemDone (System sys)
{
  int run;
  int s;

  /* clear globals, which were defined in systemStart */

  s = sys->maxtracelength + 1;
  memFree (sys->traceEvent, s * sizeof (Roledef));
  memFree (sys->traceRun, s * sizeof (int));
  memFree (sys->traceKnow, s * sizeof (Knowledge));

  /* clear roledefs */
  for (run = 0; run < sys->maxruns; run++)
    roledefDestroy (runPointerGet (sys, run));

  /* clear substructures */
  termlistDestroy (sys->secrets);

  /* clear main system */
  systemDestroy (sys);
}

double
statesApproximation (System sys)
{
  if (sys->statesHigh == 0)
    return (double) sys->statesLow;
  else
    return (double) (sys->statesLow + (sys->statesHigh * ULONG_MAX));
}

void
statesPrintShort (System sys)
{
  printf ("%.3e", statesApproximation (sys));
}

void
statesPrint (System sys)
{
  if (sys->statesHigh == 0)
    {
      printf ("%g", (double) sys->statesLow);
    }
  else
    {
      double dstates;

      dstates = sys->statesLow + (sys->statesHigh * ULONG_MAX);
      printf ("%.3e (...)", dstates);
    }
  printf (" states traversed.\n");
  if (globalLatex)
      printf("\n");
}

void
systemDestroy (System sys)
{
  memFree (sys->runs, sys->maxruns * sizeof (struct run));
  memFree (sys, sizeof (struct system));
}

/* ensureValidRun

   Makes sure memory is allocated for instantiating this run.
   Note: This is meant to be used BEFORE using runPointerSet.
*/

void
ensureValidRun (System sys, int run)
{
  int i, oldsize;

  if (run < sys->maxruns)
    return;

  /* this amount of memory was not allocated yet */
  /* (re)allocate  space */
  /* Note, this is never explicitly freed, because it is never
     copied */

  sys->runs = (Run) memRealloc (sys->runs, sizeof (struct run) * (run + 1));

  /* update size parameter */
  oldsize = sys->maxruns;
  sys->maxruns = run + 1;

  /* create runs, set the new pointer(s) to NULL */
  for (i = oldsize; i < sys->maxruns; i++)
    {
      /* init run */
      struct run myrun = sys->runs[i];
      myrun.role = NULL;
      myrun.agents = NULL;
      myrun.index = NULL;
      myrun.start = NULL;
      myrun.know = knowledgeDuplicate (sys->know);
    }
}

void
runAdd (System sys, int run, int type, Term label, Term from, Term to,
	Term msg)
{
  Roledef newEvent;
  Roledef scan;

  newEvent = roledefInit (type, label, from, to, msg);
  ensureValidRun (sys, run);
  if (runPointerGet (sys, run) == NULL)
    {
      sys->runs[run].start = newEvent;
      runPointerSet (sys, run, newEvent);
    }
  else
    {
      scan = runPointerGet (sys, run);
      while (scan->next != NULL)
	scan = scan->next;
      scan->next = newEvent;
    }
}

void
roledefPrint (Roledef rd)
{
  if (rd == NULL)
    {
      printf ("[Empty roledef]\n");
      return;
    }
  if (rd->type == READ && rd->internal)
    {
      /* special case: internal read == choose ! */
      printf ("CHOOSE(");
      termPrint (rd->message);
      printf (")");
      return;
    }
  if (rd->type == READ)
    printf ("READ");
  if (rd->type == SEND)
    printf ("SEND");
  if (rd->type == CLAIM)
    printf ("CLAIM");
  if (rd->label != NULL)
    {
      if (globalLatex)
	{
	  printf ("$_{");
	  termPrint (rd->label);
	  printf ("}$");
	}
      else
	{
	  printf ("_");
	  termPrint (rd->label);
	}
    }
  if (globalLatex)
    printf ("$");
  printf ("\t(");
  termPrint (rd->from);
  printf (",");
  if (rd->type == CLAIM)
    printf (" ");
  termPrint (rd->to);
  printf (", ");
  termPrint (rd->message);
  printf (" )");
  if (globalLatex)
    printf ("$");
}

void
runPrint (Roledef rd)
{
  int i;

  indent ();
  i = 0;
  while (rd != NULL)
    {
      printf ("%i: ", i);
      roledefPrint (rd);
      printf ("\n");
      i++;
      rd = rd->next;
    }
}

void
runsPrint (System sys)
{
  int i;

  indent ();
  printf ("[ Run definitions ]\n");
  for (i = 0; i < (sys->maxruns); i++)
    {
      indent ();
      printf ("Run definition %i:\n", i);
      runPrint (runPointerGet (sys, i));
      printf ("\n");
    }
}

/*
 * returns a pointer to the agent name term
 */

Term
agentOfRunRole (const System sys, const int run, const Term role)
{
  Termlist roles = sys->runs[run].protocol->rolenames;
  Termlist agents= sys->runs[run].agents;

  /* TODO stupid reversed order, lose that soon */
  agents = termlistForward(agents);
  while (agents != NULL && roles != NULL)
    {
      if (isTermEqual(roles->term, role))
	{
	  return agents->term;
	}
      agents = agents->prev;
      roles = roles->next;
    }
  return NULL;
}

/*
 * returns a pointer to the agent name term
 */

Term
agentOfRun (const System sys, const int run)
{
  return agentOfRunRole(sys,run,sys->runs[run].role->nameterm);
}

Roledef
roledefDuplicate1 (const Roledef rd)
{
  if (rd == NULL)
    return NULL;
  Roledef newrd = makeRoledef ();
  memcpy (newrd, rd, sizeof (struct roledef));
  newrd->next = NULL;
  return newrd;
}
    
Roledef
roledefDuplicate (Roledef rd)
{
  if (rd == NULL)
    return NULL;
  Roledef newrd = roledefDuplicate1 (rd);
  newrd->next = roledefDuplicate (rd->next);
  return newrd;
}

void
roledefDelete (Roledef rd)
{
  if (rd == NULL)
    return;
  roledefDelete (rd->next);
  memFree (rd, sizeof (struct roledef));
  return;
}

void
roledefDestroy (Roledef rd)
{
  if (rd == NULL)
    return;
  roledefDestroy (rd->next);
  termDelete (rd->from);
  termDelete (rd->to);
  termDelete (rd->message);
  memFree (rd, sizeof (struct roledef));
  return;
}

/*
   Instantiate a role by making a new run.

   This involves creation of a new run(id).
   Copy & subst of Roledef, Agent knowledge.
   Tolist might contain type constants.
*/

void
roleInstance (const System sys, const Protocol protocol, const Role role,
	      const Termlist paramlist)
{
  int rid;
  Run runs;
  Roledef rd;
  Termlist scanfrom, scanto;
  Termlist fromlist = NULL;
  Termlist tolist = NULL;
  Term extterm = NULL;

  /* claim runid, allocate space */
  rid = sys->maxruns;
  ensureValidRun (sys, rid);
  runs = sys->runs;

  /* duplicate roledef in buffer rd */
  rd = roledefDuplicate (role->roledef);

  /* scan for types in agent list */
  /* scanners */
  scanfrom = protocol->rolenames;
  scanto = paramlist;
  while (scanfrom != NULL && scanto != NULL)
    {
      fromlist = termlistAdd (fromlist, scanfrom->term);
      if (scanto->term->stype != NULL &&
	  inTermlist (scanto->term->stype, TERM_Type))
	{
	  /* There is a TYPE constant in the parameter list.
	   * Generate a new local variable for this run, with this type */
	  Term newvar = makeTermType (VARIABLE, scanfrom->term->symb, rid);
	  sys->variables = termlistAdd (sys->variables, newvar);
	  newvar->stype = termlistAdd (NULL, scanto->term);
	  tolist = termlistAdd (tolist, newvar);
	  /* newvar is apparently new, but it might occur
	   * in the first event if it's a read, in which
	   * case we forget it */
	  if (!(rd->type == READ && termOccurs (rd->message, scanfrom->term)))
	    {
	      /* but this is already set in the first
	       * read... */
	      /* TODO scan might be more complex, but
	       * this will do for now. I.e. occurring
	       * first in a read will do */
	      extterm = makeTermTuple (newvar, extterm);
	    }
	}
      else
	{
	  /* not a type constant, add to list */
	  tolist = termlistAdd (tolist, scanto->term);
	}
      scanfrom = scanfrom->next;
      scanto = scanto->next;
    }

  /* prefix a read for such reads. TODO: this should also cover any external stuff */
  if (extterm != NULL)
    {
      Roledef rdnew;

      rdnew = roledefInit (READ, NULL, NULL, NULL, extterm);
      /* this is an internal action! */
      rdnew->internal = 1;
      rdnew->next = rd;
      rd = rdnew;
    }

  /* set parameters */
  runs[rid].protocol = protocol;
  runs[rid].role = role;
  runs[rid].agents = termlistDuplicate (tolist);
  runs[rid].start = rd;
  runs[rid].index = rd;

  /* duplicate all locals form this run */
  scanto = role->locals;
  while (scanto != NULL)
    {
      Term t = scanto->term;
      if (!inTermlist (fromlist, t))
	{
	  if (realTermLeaf (t))
	    {
	      Term newt = makeTermType (t->type, t->symb, rid);
	      if (realTermVariable (newt))
		{
	          sys->variables = termlistAdd (sys->variables, newt);
		}
	      newt->stype = t->stype;
	      fromlist = termlistAdd (fromlist, t);
	      tolist = termlistAdd (tolist, newt);
	    }
	}
      scanto = scanto->next;
    }

  /* TODO this is not what we want yet, also local knowledge. The local
   * knowledge (list?) also needs to be substituted on invocation. */
  runs[rid].know = knowledgeDuplicate (sys->know);

  /* now adjust the local run copy */

  rd = runs[rid].start;
  while (rd != NULL)
    {
      rd->from = termLocal (rd->from, fromlist, tolist, role->locals, rid);
      rd->to = termLocal (rd->to, fromlist, tolist, role->locals, rid);
      rd->message =
	termLocal (rd->message, fromlist, tolist, role->locals, rid);
      rd = rd->next;
    }
  termlistDelete (fromlist);
  runs[rid].locals = tolist;
}

Roledef
roledefInit (int type, Term label, Term from, Term to, Term msg)
{
  Roledef newEvent;

  newEvent = makeRoledef ();
  newEvent->internal = 0;
  newEvent->type = type;
  newEvent->label = label;
  newEvent->from = from;
  newEvent->to = to;
  newEvent->message = msg;
  newEvent->forbidden = NULL;	// no forbidden stuff
  newEvent->knowPhase = -1;	// we haven't explored any knowledge yet
  newEvent->next = NULL;
  return newEvent;
}

Roledef
roledefAdd (Roledef rd, int type, Term label, Term from, Term to, Term msg)
{
  Roledef scan;

  if (rd == NULL)
    return roledefInit (type, label, from, to, msg);

  scan = rd;
  while (scan->next != NULL)
    scan = scan->next;
  scan->next = roledefInit (type, label, from, to, msg);
  return rd;
}


/* allocate memory for traces, runs have to be known for that */

void
systemStart (System sys)
{
  int i, s;
  Roledef rd;

  s = 0;
  for (i = 0; i < sys->maxruns; i++)
    {
      rd = runPointerGet (sys, i);
      while (rd != NULL)
	{
	  s++;
	  rd = rd->next;
	}
    }

  /* this is the maximum trace length */
  if (sys->maxtracelength > s)
    sys->maxtracelength = s;

  /* trace gets one added entry for buffer */
  s = sys->maxtracelength + 1;

  /* freed in systemDone */
  sys->traceEvent = memAlloc (s * sizeof (Roledef));
  sys->traceRun = memAlloc (s * sizeof (int));
  sys->traceKnow = memAlloc (s * sizeof (Knowledge));

  /* clear, for niceties */
  for (i = 0; i < s; i++)
    {
      sys->traceEvent[i] = NULL;
      sys->traceRun[i] = 0;
      sys->traceKnow[i] = NULL;
    }
}

void
indentActivate ()
{
  indentState = 1;
}

void
indentSet (int i)
{
  if (indentState)
    indentDepth = i;
}

void
indent ()
{
  int i = indentDepth;
  int j = 0;
  while (i > 0)
    {
      printf ("%i  ", j);
      i--;
      j++;
    }
}

Protocol
protocolCreate (Term name)
{
  Protocol p;

  p = memAlloc (sizeof (struct protocol));
  p->nameterm = name;
  p->rolenames = NULL;
  p->next = NULL;
  p->roles = NULL;
  p->locals = NULL;
  return p;
}

Role
roleCreate (Term name)
{
  Role r;

  r = memAlloc (sizeof (struct role));
  r->nameterm = name;
  r->next = NULL;
  r->locals = NULL;
  r->roledef = NULL;
  return r;
}

void
locVarPrint (Termlist tl)
{
  if (tl == NULL)
    {
      printf ("No local terms.\n");
    }
  else
    {
      printf ("Local terms: ");
      printf ("[");
      while (tl != NULL)
	{
	  termPrint (tl->term);
	  if (tl->term->stype != NULL)
	    {
	      printf (":");
	      termlistPrint (tl->term->stype);
	    }
	  tl = tl->next;
	  if (tl != NULL)
	    printf (",");
	}
      printf ("]");
      printf ("\n");
    }
}

void
protocolPrint (Protocol p)
{
  if (p == NULL)
    return;

  indent ();
  printf ("[[Protocol : ");
  termPrint (p->nameterm);
  printf (" (");
  termlistPrint (p->rolenames);
  printf (")]]\n");
  locVarPrint (p->locals);
  rolesPrint (p->roles);
}

void
protocolsPrint (Protocol p)
{
  while (p != NULL)
    {
      protocolPrint (p);
      p = p->next;
    }
}

void
rolePrint (Role r)
{
  if (r == NULL)
    return;

  indent ();
  printf ("[[Role : ");
  termPrint (r->nameterm);
  printf ("]]\n");
  locVarPrint (r->locals);

  Roledef rd = r->roledef;
  while (rd != NULL)
    {
      roledefPrint (rd);
      printf ("\n");
      rd = rd->next;
    }
}

void
rolesPrint (Role r)
{
  if (r == NULL)
    {
      printf ("Empty role.");
    }
  else
    {
      while (r != NULL)
	{
	  rolePrint (r);
	  r = r->next;
	}
    }
}

int
untrustedAgent (System sys, Termlist agents)
{
  while (agents != NULL)
    {
      if (isTermVariable (agents->term))
	{
	  if (sys->clp)
	    {
	      /* clp: variables are difficult */
	      /* TODO Add as constraint that they're
	       * trusted */
	      /* However, that is a branch as well :(
	       */
	      /* claim secret is _really_ a instant-multiple
	       * read. If it is succesful, we sound
	       * the alert */
	    }
	}
      else
	{
	  if (inTermlist (sys->untrusted, agents->term))
	    return 1;
	}
      agents = agents->next;
    }
  return 0;
}

int
getMaxTraceLength (const System sys)
{
  Roledef rd;
  int maxlen;
  int run;

  maxlen = 0;
  for (run = 0; run < sys->maxruns; run++)
    {
      rd = runPointerGet (sys, run);
      while (rd != NULL)
	{
	  rd = rd->next;
	  maxlen++;
	}
    }
  return maxlen;
}

/*
 * Nicely format the role and agents we think we're talking to.
 */

void
agentsOfRunPrint (const System sys, const int run)
{
  Term role = sys->runs[run].role->nameterm;
  Termlist roles = sys->runs[run].protocol->rolenames;

  termPrint(role);
  printf("(");
  while (roles != NULL)
    {
      termPrint(agentOfRunRole(sys,run,roles->term));
      roles = roles->next;
      if (roles != NULL)
	{
	  printf(",");
	}
    }
  printf(")");
}

/*
 * explain a violated claim at point i in the trace
 */

void
violatedClaimPrint (const System sys, const int i)
{
  printf("Claim stuk");
}

/*
 * attackLength yields the real (user friendly) length of an attack by omitting
 * the redundant events but also the choose events.
 */

int attackLength(struct tracebuf* tb)
{
    int len,i;

    len = 0;
    i = 0;
    while (i < tb->length)
    {
        if (tb->status[i] != S_RED)
	{
	    /* apparently not redundant */
	    if (!(tb->event[i]->type == READ && tb->event[i]->internal))
	    {
	        /* and no internal read, so it counts */
	        len++;
	    }
	}
	i++;
    }
    return len;
}
