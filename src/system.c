/**
 * @file system.c 
 * \brief system related logic.
 */
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "term.h"
#include "termlist.h"
#include "knowledge.h"
#include "system.h"
#include "memory.h"
#include "constraint.h"
#include "debug.h"
#include "output.h"
#include "tracebuf.h"
#include "role.h"

/* from compiler.o */
extern Term TERM_Type;

//! Global flag that signals LaTeX output.
/**
 * True iff LaTeX output is desired.
 */
int globalLatex;

//! Switch for indent or not.
static int indentState = 0;
//! Current indent depth.
static int indentDepth = 0;

//! Allocate memory the size of a run struct.
Run
makeRun ()
{
  return (Run) memAlloc (sizeof (struct run));
}



//! Initialise a system structure.
/**
 *@return A system structure pointer with initial values.
 */
System
systemInit ()
{
  System sys = (System) memAlloc (sizeof (struct system));

  /* initially, no trace ofcourse */
  sys->step = 0;
  sys->shortestattack = INT_MAX;
  sys->attack = tracebufInit();

  /* switches */
  sys->output = ATTACK;		// default is to show the attacks
  sys->porparam = 0;		// multi-purpose parameter
  sys->latex = 0;		// latex output?
  sys->switchScenario = 0;
  sys->switchForceChoose = 1;	// force explicit chooses by default
  sys->switchChooseFirst = 0;	// no priority to chooses by default
  sys->switchReadSymm = 0;	// don't force read symmetries by default
  sys->switchAgentSymm = 1;	// default enable agent symmetry
  sys->switchSymmOrder = 0;	// don't force symmetry order reduction by default
  sys->switchNomoreClaims = 1;	// default cutter when there are no more claims
  sys->switchReduceEndgame = 1;	// default cutter of last events in a trace
  sys->switchClaims = 0;	// default don't report on claims

  /* set illegal traversal by default, to make sure it is set
     later */
  sys->traverse = 0;
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
  sys->synchronising_labels = NULL;
  sys->attack = NULL;
  /* no protocols => no protocol preprocessed */
  sys->rolecount = 0;
  sys->roleeventmax = 0;
  sys->claimlist = NULL;

  /* matching CLP */
  sys->constraints = NULL;	// no initial constraints

  /* reset global counters */
  systemReset (sys);

  return sys;
}

//! Reset a system state after some exploration.
/**
 *@param sys A system structure pointer.
 *@return Counter values have been reset.
 */
void
systemReset (const System sys)
{
  Claimlist cl;

  /* some initial counters */
  sys->states = statesIncrease (STATES0);	//!< Initial state is not explored, so start counting at 1
  sys->interval = statesIncrease (STATES0);	//!< To keep in line with the states
  sys->claims = STATES0;
  sys->failed = STATES0;
  sys->countScenario = 0;
  sys->explore = 1;		// do explore the space
  cl = sys->claimlist;
  while (cl != NULL)
    {
      cl->count = STATES0;
      cl->failed = STATES0;
      cl = cl->next;
    }
  
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

//! Initialize runtime system (according to cut traces, limited runs)
void
systemRuns (const System sys)
{
  int run;

  sys->lastChooseRun = -1;
  for (run = 0; run < sys->maxruns; run++)
    {
      Roledef rd;

      rd = runPointerGet (sys, run);
      if (rd != NULL &&
	  rd->internal &&
	  rd->type == READ)
	{
	  /* increasing run traversal, so this yields max */
	  sys->lastChooseRun = run;
	}
    }
#ifdef DEBUG
  if (sys->switchScenario < 0)
    {
      warning ("Last run with a choose: %i",sys->lastChooseRun);
    }
#endif
}

//! Delete a system structure and clear used memory for all buffers.
/**
 * Is more thorough than systemDestroy().
 *\sa systemDestroy()
 */
void
systemDone (const System sys)
{
  int run;
  int s;

  /* clear globals, which were defined in systemStart */

  s = sys->maxtracelength + 1;
  memFree (sys->traceEvent, s * sizeof (Roledef));
  memFree (sys->traceRun, s * sizeof (int));
  memFree (sys->traceKnow, s * sizeof (Knowledge));
  memFree (sys->traceNode, s * sizeof (states_t));

  /* clear roledefs */
  for (run = 0; run < sys->maxruns; run++)
    roledefDestroy (runPointerGet (sys, run));

  /* clear substructures */
  termlistDestroy (sys->secrets);

  /* clear main system */
  systemDestroy (sys);
}

//! Print a short version of the number of states.
void
statesPrintShort (const System sys)
{
  if (globalError == 0)
    statesFormat (stdout, sys->states);
  else
    statesFormat (stderr, sys->states);
}

//! Print the number of states.
void
statesPrint (const System sys)
{
  statesFormat (stdout, sys->states);
  printf (" states traversed.\n");
  if (globalLatex)
      printf("\n");
}

//! Destroy a system memory block and system::runs
/**
 * Ignores any other substructes.
 *\sa systemDone()
 */
void
systemDestroy (const System sys)
{
  memFree (sys->runs, sys->maxruns * sizeof (struct run));
  memFree (sys, sizeof (struct system));
}

//! Ensures that a run can be added to the system.
/**
 * Allocates memory to allow a run to be added, if needed.
 * This is meant to be used before using runPointerSet().
 */

void
ensureValidRun (const System sys, int run)
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
      myrun.step = 0;
      myrun.index = NULL;
      myrun.start = NULL;
      myrun.know = knowledgeDuplicate (sys->know);
      myrun.prevSymmRun = -1;
      myrun.firstNonAgentRead = -1;
    }
}

//! Print a run.
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

//! Print all runs in the system structure.
void
runsPrint (const System sys)
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

//! Yield the agent name term in a role, for a run in the system.
/**
 *@param sys The system.
 *@param run The run in which we are interested.
 *@param role The role of which we want to know the agent.
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

//! Yield the actor agent of a run in the system.
/**
 *@param sys The system.
 *@param run The run in which we are interested.
 */
Term
agentOfRun (const System sys, const int run)
{
  return agentOfRunRole(sys,run,sys->runs[run].role->nameterm);
}

/**
 * A new run is created; now we want to know if it depends on any previous run.
 * This occurs when there is a smaller runid with an identical protocol role, with the 
 * same agent pattern. However, there must be at least a variable in the pattern or no
 * symmetry gains are to be made.
 *
 * Return -1 if there is no such symmetry.
 */
int staticRunSymmetry (const System sys,const int rid)
{
  int ridSymm;		// previous symmetrical run
  Termlist agents;	// list of agents for rid
  Run runs;		// shortcut usage

  ridSymm = -1;
  runs = sys->runs;
  agents = runs[rid].agents;
  while (agents != NULL)
    {
      if (isTermVariable(agents->term))
          ridSymm = rid - 1;
      agents = agents->next;
    }
  /* there is no variable in this roledef, abort */
  if (ridSymm == -1)
      return -1;

  agents = runs[rid].agents;
  while (ridSymm >= 0)
    {
      /* compare protocol name, role name */
      if (runs[ridSymm].protocol == runs[rid].protocol &&
	  runs[ridSymm].role     == runs[rid].role)
	{
	  /* same stuff */
	  int isEqual;
	  Termlist al, alSymm;	// agent lists

	  isEqual = 1;
	  al = agents;
	  alSymm = runs[ridSymm].agents;
	  while (isEqual && al != NULL)
	    {
	      /* determine equality */
	      if (isTermVariable (al->term))
		{
		  /* case 1: variable, should match type */
		  if (isTermVariable (alSymm->term))
		    {
		      if (!isTermlistEqual (al->term->stype, alSymm->term->stype))
			  isEqual = 0;
		    }
		  else
		    {
		      isEqual = 0;
		    }
		}
	      else
		{
		  /* case 2: constant, should match */
		  if (!isTermEqual (al->term, alSymm->term))
		      isEqual = 0;
		}
	      alSymm = alSymm->next;
	      al = al->next;
	    }
	  if (al == NULL && isEqual)
	    {
	      /* this candidate is allright */
#ifdef DEBUG
  	      warning ("Symmetry detection. #%i can depend on #%i.",rid,ridSymm);
#endif
	      return ridSymm;
	    }
	}
      ridSymm--;
    }
  return -1;	// signal that no symmetrical run was found
}

//! Determine first read with variables besides agents
/**
 *@todo For now, we assume it is simply the first read after the choose, if there is one.
 */
int firstNonAgentRead (const System sys, int rid)
{
  int step;
  Roledef rd;

  if (sys->runs[rid].prevSymmRun == -1)
    {
      /* if there is no symmetrical run, then this doesn't apply at all */
      return -1;
    }
  rd = sys->runs[rid].start;
  step = 0;
  while (rd != NULL && rd->internal && rd->type == READ)	// assumes lazy LR eval
    {
      rd = rd->next;
      step++;
    }
  if (rd != NULL && !rd->internal && rd->type == READ)		// assumes lazy LR eval
    {
#ifdef DEBUG
      warning ("First read %i with dependency on symmetrical found in run %i.", step, rid);
#endif
      return step;
    }
  /* no such read */
  return -1;
}


//! Instantiate a role by making a new run.
/**
 * This involves creation of a new run(id).
 * Copy & subst of Roledef, Agent knowledge.
 * Tolist might contain type constants.
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
  Term newvar;

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
	  newvar = makeTermType (VARIABLE, scanfrom->term->left.symb, rid);
	  sys->variables = termlistAdd (sys->variables, newvar);
	  newvar->stype = termlistAdd (NULL, scanto->term);
	  tolist = termlistAdd (tolist, newvar);
	  /* newvar is apparently new, but it might occur
	   * in the first event if it's a read, in which
	   * case we forget it */
	  if (sys->switchForceChoose || !(rd->type == READ && termOccurs (rd->message, scanfrom->term)))
	    {
	      /* this term is forced as a choose, or it does not occur in the (first) read event */
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

      rdnew = roledefInit (READ, NULL, NULL, NULL, extterm, NULL);
      /* this is an internal action! */
      rdnew->internal = 1;
      rdnew->next = rd;
      rd = rdnew;
      /* mark the first real action */
      runs[rid].firstReal = 1;
    }
  else
    {
      runs[rid].firstReal = 0;
    }

  /* set parameters */
  runs[rid].protocol = protocol;
  runs[rid].role = role;
  runs[rid].agents = termlistDuplicate (tolist);
  runs[rid].start = rd;
  runs[rid].index = rd;
  runs[rid].step = 0;

  /* duplicate all locals form this run */
  scanto = role->locals;
  while (scanto != NULL)
    {
      Term t = scanto->term;
      if (!inTermlist (fromlist, t))
	{
	  if (realTermLeaf (t))
	    {
	      Term newt = makeTermType (t->type, t->left.symb, rid);
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

  /* Determine symmetric run */
  runs[rid].prevSymmRun = staticRunSymmetry (sys, rid);		// symmetry reduction static analysis

  /* Determine first read with variables besides agents */
  runs[rid].firstNonAgentRead = firstNonAgentRead (sys, rid);	// symmetry reduction type II
}


//! Initialise the second system phase.
/**
 * Allocates memory for traces.
 * The number of runs has to be known for this procedure.
 *\sa systemInit()
 */

void
systemStart (const System sys)
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
  sys->traceNode = memAlloc (s * sizeof (states_t));

  /* clear, for niceties */
  for (i = 0; i < s; i++)
    {
      sys->traceEvent[i] = NULL;
      sys->traceRun[i] = 0;
      sys->traceKnow[i] = NULL;
      sys->traceNode[i] = STATES0;
    }
}

//! Activate indenting.
void
indentActivate ()
{
  indentState = 1;
}

//! Set indent depth.
void
indentSet (int i)
{
  if (indentState)
    indentDepth = i;
}

//! Print the prefix of a line suitable for the current indent level.
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

//! Create an empty protocol structure with a name.
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

//! Print all local terms in a term list.
//@todo What is this doing here? This should be in termlists.c!
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

//! Print a protocol.
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

//! Print a list of protocols.
void
protocolsPrint (Protocol p)
{
  while (p != NULL)
    {
      protocolPrint (p);
      p = p->next;
    }
}

//! Determine whether there is an untrusted agent.
/**
 *@param sys The system, containing system::untrusted.
 *@param agents A list of agents to be verified.
 *@return True iff any agent in the list is untrusted.
 */
int
untrustedAgent (const System sys, Termlist agents)
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

//! Yield the maximum length of a trace by analysing the runs in the system.
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

//! Nicely format the role and agents we think we're talking to.
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

//! Explain a violated claim at point i in the trace.

void
violatedClaimPrint (const System sys, const int i)
{
  printf("Claim stuk");
}

//! Yield the real length of an attack.
/**
 * AttackLength yields the real (user friendly) length of an attack by omitting
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

void
commandlinePrint (FILE *stream, const System sys)
{
  /* print command line */
  int i;

  fprintf (stream, "$");
  for (i = 0; i < sys->argc; i++)
    fprintf (stream, " %s", sys->argv[i]);
}

//! Get the number of roles in the system.
int compute_rolecount (const System sys)
{
  Protocol pr;
  int n;

  n = 0;
  pr = sys->protocols;
  while (pr != NULL)
    {
      n = n + termlistLength(pr->rolenames);
      pr = pr->next;
    }
  return n;
}

//! Compute the maximum number of events in a single role in the system.
int compute_roleeventmax (const System sys)
{
  Protocol pr;
  int maxev;

  maxev = 0;
  pr = sys->protocols;
  while (pr != NULL)
    {
      Role r;

      r = pr->roles;
      while (r != NULL)
	{
	  Roledef rd;
	  int n;

	  rd = r->roledef;
	  n = 0;
	  while (rd != NULL)
	    {
	      n++;
	      rd = rd->next;
	    }
	  if (n > maxev) maxev = n;
	  r = r->next;
	}
      pr = pr->next;
    }
  return maxev;
}

//! Print the role, agents of a run
void
runInstancePrint (const System sys, const int run)
{
  termPrint (sys->runs[run].role->nameterm);
  termlistPrint (sys->runs[run].agents);
}

//! Print an instantiated scenario (chooses and such)
void
scenarioPrint (const System sys)
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      runInstancePrint (sys, run);
      if (run < sys->maxruns - 1)
	{
          printf ("\t");
	}
    }
}
