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
#include "debug.h"
#include "role.h"
#include "mgu.h"
#include "switches.h"
#include "binding.h"
#include "depend.h"
#include "specialterm.h"

//! Global count of protocols
int protocolCount;

//! External
extern Protocol INTRUDER;

//! Switch for indent or not.
static int indentState = 0;
//! Current indent depth.
static int indentDepth = 0;

//! Allocate memory the size of a run struct.
Run
makeRun ()
{
  return (Run) malloc (sizeof (struct run));
}



//! Initialise a system structure.
/**
 *@return A system structure pointer with initial values.
 */
System
systemInit ()
{
  System sys = (System) malloc (sizeof (struct system));

  /* initially, no trace ofcourse */
  sys->step = 0;
  sys->shortestattack = INT_MAX;
  sys->maxtracelength = INT_MAX;

  /* init rundefs */
  sys->maxruns = 0;
  sys->runs = NULL;
  /* no protocols yet */
  protocolCount = 0;
  sys->protocols = NULL;
  sys->locals = NULL;
  sys->variables = NULL;
  sys->untrusted = NULL;
  sys->globalconstants = NULL;
  sys->hidden = NULL;
  sys->secrets = NULL;		// list of claimed secrets
  sys->synchronising_labels = NULL;
  /* no protocols => no protocol preprocessed */
  sys->rolecount = 0;
  sys->roleeventmax = 0;
  sys->claimlist = NULL;
  sys->labellist = NULL;
  sys->attackid = 0;		// First attack will have id 1, because the counter is increased before any attacks are displayed.

  bindingInit (sys);
  sys->bindings = NULL;
  sys->current_claim = NULL;

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
  sys->interval = sys->states;	//!< To keep in line with the states
  sys->claims = STATES0;
  sys->failed = STATES0;
  sys->explore = 1;		// do explore the space
  cl = sys->claimlist;
  while (cl != NULL)
    {
      cl->count = STATES0;
      cl->failed = STATES0;
      cl = cl->next;
    }

  termlistDestroy (sys->secrets);	// remove old secrets list
  sys->secrets = NULL;		// list of claimed secrets

  /* transfer switches */
  sys->maxtracelength = switches.maxtracelength;

  /* propagate mgu_mode */

  setMguMode (switches.match);
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
      if (rd != NULL && rd->internal && rd->type == READ)
	{
	  /* increasing run traversal, so this yields max */
	  sys->lastChooseRun = run;
	}
    }
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
  free (sys->traceEvent);
  free (sys->traceRun);
  free (sys->traceKnow);
  free (sys->traceNode);

  /* clear roledefs */
  while (sys->maxruns > 0)
    {
      roleInstanceDestroy (sys);
    }

  /* undo bindings (for arachne) */

  bindingDone ();

  /* clear substructures */
  termlistDestroy (sys->secrets);

  /* clear main system */
  systemDestroy (sys);
}

//! Print a short version of the number of states.
void
statesPrintShort (const System sys)
{
  statesFormat (sys->states);
}

//! Print the number of states.
void
statesPrint (const System sys)
{
  statesFormat (sys->states);
  eprintf (" states traversed.\n");
}

//! Destroy a system memory block and system::runs
/**
 * Ignores any other substructes.
 *\sa systemDone()
 */
void
systemDestroy (const System sys)
{
  free (sys->runs);
  free (sys);
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
  /* update size parameter */
  oldsize = sys->maxruns;
  sys->maxruns = run + 1;
  sys->runs = (Run) realloc (sys->runs, sizeof (struct run) * (sys->maxruns));

  /* create runs, set the new pointer(s) to NULL */
  for (i = oldsize; i < sys->maxruns; i++)
    {
      /* init run */
      sys->runs[i].protocol = NULL;
      sys->runs[i].role = NULL;
      sys->runs[i].step = 0;
      sys->runs[i].rolelength = 0;

      sys->runs[i].index = NULL;
      sys->runs[i].start = NULL;
      sys->runs[i].know = NULL;

      sys->runs[i].rho = NULL;
      sys->runs[i].sigma = NULL;
      sys->runs[i].constants = NULL;

      sys->runs[i].locals = NULL;
      sys->runs[i].artefacts = NULL;
      sys->runs[i].substitutions = NULL;


      sys->runs[i].prevSymmRun = -1;
      sys->runs[i].firstNonAgentRead = -1;
      sys->runs[i].firstReal = 0;
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
      eprintf ("%i: ", i);
      roledefPrint (rd);
      eprintf ("\n");
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
  eprintf ("[ Run definitions ]\n");
  for (i = 0; i < (sys->maxruns); i++)
    {
      indent ();
      eprintf ("Run definition %i:\n", i);
      runPrint (runPointerGet (sys, i));
      eprintf ("\n");
    }
}

//! Determine whether a term is sent or claimed, but not read first in a roledef
/**
 * @returns True iff the term occurs, and is sent/claimed first. If this returns true,
 * we have to prefix a read.
 */
int
not_read_first (const Roledef rdstart, const Term t)
{
  Roledef rd;

  rd = rdstart;
  while (rd != NULL)
    {
      if (termSubTerm (rd->message, t))
	{
	  return (rd->type != READ);
	}
      rd = rd->next;
    }
  /* this term is not read or sent explicitly, which is no problem */
  /* So we signal we don't have to prefix a read */
  return 0;
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
  Termlist agents;

  // Agent variables have the same symbol as the role names, so
  // we can scan for this.
  agents = sys->runs[run].rho;
  while (agents != NULL)
    {
      Term agent;

      agent = agents->term;
      if (TermSymb (role) == TermSymb (agent))
	{
	  return agent;
	}
      else
	{
	  agents = agents->next;
	}
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
  return agentOfRunRole (sys, run, sys->runs[run].role->nameterm);
}

/**
 * A new run is created; now we want to know if it depends on any previous run.
 * This occurs when there is a smaller runid with an identical protocol role, with the 
 * same agent pattern. However, there must be at least a variable in the pattern or no
 * symmetry gains are to be made.
 *
 * Return -1 if there is no such symmetry.
 */
int
staticRunSymmetry (const System sys, const int rid)
{
  int ridSymm;			// previous symmetrical run
  Termlist agents;		// list of agents for rid
  Run runs;			// shortcut usage

  ridSymm = -1;
  runs = sys->runs;
  agents = runs[rid].rho;
  while (agents != NULL)
    {
      if (isTermVariable (agents->term))
	ridSymm = rid - 1;
      agents = agents->next;
    }
  /* there is no variable in this roledef, abort */
  if (ridSymm == -1)
    return -1;

  agents = runs[rid].rho;
  while (ridSymm >= 0)
    {
      /* compare protocol name, role name */
      if (runs[ridSymm].protocol == runs[rid].protocol &&
	  runs[ridSymm].role == runs[rid].role)
	{
	  /* same stuff */
	  int isEqual;
	  Termlist al, alSymm;	// agent lists

	  isEqual = 1;
	  al = agents;
	  alSymm = runs[ridSymm].rho;
	  while (isEqual && al != NULL)
	    {
	      /* determine equality */
	      if (isTermVariable (al->term))
		{
		  /* case 1: variable, should match type */
		  if (isTermVariable (alSymm->term))
		    {
		      if (!isTermlistEqual
			  (al->term->stype, alSymm->term->stype))
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
	      warning ("Symmetry detection. #%i can depend on #%i.", rid,
		       ridSymm);
#endif
	      return ridSymm;
	    }
	}
      ridSymm--;
    }
  return -1;			// signal that no symmetrical run was found
}

//! Determine first read with variables besides agents
/**
 *@todo For now, we assume it is simply the first read after the choose, if there is one.
 */
int
firstNonAgentRead (const System sys, int rid)
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
  if (rd != NULL && !rd->internal && rd->type == READ)	// assumes lazy LR eval
    {
#ifdef DEBUG
      warning
	("First read %i with dependency on symmetrical found in run %i.",
	 step, rid);
#endif
      return step;
    }
  /* no such read */
  return -1;
}


/*************************************************
 *
 * Support code for roleInstance
 *
*************************************************/

//! Prefix a read before a given run.
/**
 * Maybe this simply needs integration in the role definitions. However, in practice it
 * depends on the specific scenario. For Arachne it can thus depend on the roledef.
 *
 * Stores the (new) rd pointer in start and index
 */
void
run_prefix_read (const System sys, const int run, Roledef rd,
		 const Term extterm)
{
  /* prefix a read for such reads. TODO: this should also cover any external stuff */
  if (extterm != NULL)
    {
      Roledef rdnew;

      rdnew = roledefInit (READ, NULL, NULL, NULL, extterm, NULL);
      /* this is an internal action! */
      rdnew->internal = 1;
      /* Store this new pointer */
      rdnew->next = rd;
      rd = rdnew;
      /* mark the first real action */
      sys->runs[run].firstReal++;
    }
  /* possibly shifted rd */
  sys->runs[run].start = rd;
  sys->runs[run].index = rd;
}


//! Create a new local
/**
 * Given a term, construct a new local term. Returns NULL if no such term was constructed.
 */
Term
create_new_local (const Term t, const int rid)
{
  if (t != NULL && realTermLeaf (t))
    {
      Term newt;

      newt = makeTermType (t->type, TermSymb (t), rid);
      newt->stype = t->stype;

      return newt;
    }
  else
    {
      return NULL;
    }
}

//! Localize run
/**
 * Takes a run roledef list and substitutes fromlist into tolist terms.
 * Furthermore, localizes all substitutions occurring in this, which termLocal
 * does not. Any localized substitutions are stored as well in a list.
 */
void
run_localize (const System sys, const int rid, Termlist fromlist,
	      Termlist tolist, Termlist substlist)
{
  Roledef rd;

  rd = sys->runs[rid].start;
  while (rd != NULL)
    {
      rd->from = termLocal (rd->from, fromlist, tolist);
      rd->to = termLocal (rd->to, fromlist, tolist);
      rd->message = termLocal (rd->message, fromlist, tolist);
      rd = rd->next;
    }

  // Substlist is NULL currently? No usage of this last stuff now
  // TODO
  if (substlist != NULL)
    {
      error ("Substlist should be NULL in run_localize");
    }
  sys->runs[rid].substitutions = NULL;
  while (substlist != NULL)
    {
      Term t;

      t = substlist->term;
      if (t->subst != NULL)
	{
	  t->subst = termLocal (t->subst, fromlist, tolist);
	  sys->runs[rid].substitutions =
	    termlistAdd (sys->runs[rid].substitutions, t);
	}
      substlist = substlist->next;
    }
}


//! Instantiate a role by making a new run for Arachne
/**
 * This involves creation of a new run(id).
 * Copy & subst of Roledef, Agent knowledge.
 * Tolist might contain type constants.
*/

void
roleInstanceArachne (const System sys, const Protocol protocol,
		     const Role role, const Termlist paramlist,
		     Termlist substlist)
{
  int rid;
  Run runs;
  Roledef rd;
  Termlist fromlist = NULL;	// deleted at the end
  Termlist tolist = NULL;	// -> .locals
  Term extterm = NULL;		// construction thing (will go to artefacts)

  /* claim runid, allocate space */
  rid = sys->maxruns;
  ensureValidRun (sys, rid);	// creates a new block
  runs = sys->runs;		// simple structure pointer transfer (shortcut)

  /* duplicate roledef in buffer rd */
  /* Notice that it is not stored (yet) in the run structure,
   * and that termDuplicate is used internally
   */
  rd = roledefDuplicate (role->roledef);

  /* set parameters */
  /* generic setup of inherited stuff */
  runs[rid].protocol = protocol;
  runs[rid].role = role;
  runs[rid].step = 0;
  runs[rid].firstReal = 0;

  /* Now we need to create local terms corresponding to rho, sigma, and any local constants.
   *
   * We maintain our stuff in a from/to list.
   */

  void createLocal (Term oldt, int isvariable, int isrole)
  {
    Term newt;

    // Create new term with the same symbol
    if (isvariable)
      {
	// Force variable
	newt = makeTermType (VARIABLE, TermSymb (oldt), rid);
      }
    else
      {
	// Force local (weirdly enough called global)
	newt = makeTermType (GLOBAL, TermSymb (oldt), rid);
      }
    newt->stype = oldt->stype;	// copy list of types
    newt->roleVar = isrole;	// set role status

    // Add to copy list
    TERMLISTADD (fromlist, oldt);
    TERMLISTADD (tolist, newt);

    // Add to registration lists
    // Everything to destructor list
    TERMLISTADD (runs[rid].artefacts, newt);
    // Variable / Constant?
    if (isvariable)
      {
	TERMLISTADD (sys->variables, newt);
	if (isrole)
	  {
	    // role variable
	    /*
	     * We use append to make sure the order is
	     * consistent with the role names list.
	     */
	    TERMLISTAPPEND (runs[rid].rho, newt);
	    if (!role->initiator)
	      {
		// For non-initiators, we prepend the reading of the role names

		// XXX disabled for now TODO [x] [cc]
		if (0 == 1 && not_read_first (rd, oldt))
		  {
		    /* this term is forced as a choose, or it does not occur in the (first) read event */
		    if (extterm == NULL)
		      {
			extterm = newt;
		      }
		    else
		      {
			extterm = makeTermTuple (newt, extterm);
			// NOTE: don't these get double deleted? By roledefdestroy?
			TERMLISTAPPEND (runs[rid].artefacts, extterm);
		      }
		  }
	      }
	  }
	else
	  {
	    // normal variable
	    TERMLISTAPPEND (runs[rid].sigma, newt);
	  }
      }
    else
      {
	// local constant
	TERMLISTADD (runs[rid].constants, newt);
      }
  }

  void createLocals (Termlist list, int isvariable, int isrole)
  {
    while (list != NULL)
      {
	createLocal (list->term, isvariable, isrole);
	list = list->next;
      }
  }

  // Create rho, sigma, constants
  createLocals (protocol->rolenames, true, true);
  createLocals (role->declaredvars, true, false);
  createLocals (role->declaredconsts, false, false);

  /* Now we prefix the read before rd, if extterm is not NULL.  Even if
   * extterm is NULL, rd is still set as the start and the index pointer of
   * the run.
   */
  run_prefix_read (sys, rid, rd, extterm);

  /* TODO this is not what we want yet, also local knowledge. The local
   * knowledge (list?) also needs to be substituted on invocation. */
  runs[rid].know = NULL;

  /* now adjust the local run copy */
  run_localize (sys, rid, fromlist, tolist, substlist);

  termlistDelete (fromlist);
  runs[rid].locals = tolist;

  /* erase any substitutions in the role definition, as they are now copied */
  termlistSubstReset (role->variables);

  /* length */
  runs[rid].rolelength = roledef_length (runs[rid].start);
  /* [[[ Hack ]]] this length is minimally 3 (to help the construction of the encryptors/decryptors from bare roledefs */
  if (runs[rid].rolelength < 3)
    {
      runs[rid].rolelength = 3;
    }

  /* new graph to create */
  dependPushRun (sys);
}


//! Instantiate a role by making a new run
/**
 * Just forwards to Arachne version.
 *
 * This involves creation of a new run(id).
 * Copy & subst of Roledef, Agent knowledge.
 * Tolist might contain type constants.
*/
void
roleInstance (const System sys, const Protocol protocol, const Role role,
	      const Termlist paramlist, Termlist substlist)
{
  roleInstanceArachne (sys, protocol, role, paramlist, substlist);
}

//! Destroy roleInstance
/**
 * Destroys the run with the highest index number
 */
void
roleInstanceDestroy (const System sys)
{
  if (sys->maxruns > 0)
    {
      int runid;
      struct run myrun;
      Termlist substlist;

      runid = sys->maxruns - 1;
      myrun = sys->runs[runid];

      // Reset graph
      dependPopRun ();

      // Destroy roledef
      roledefDestroy (myrun.start);

      // Destroy artefacts
      //
      termlistDelete (myrun.rho);
      termlistDelete (myrun.sigma);
      termlistDelete (myrun.constants);

      // sys->variables might contain locals from the run: remove them
      {
	Termlist tl;

	tl = sys->variables;
	while (tl != NULL)
	  {
	    Term t;

	    t = tl->term;
	    if (realTermLeaf (t) && TermRunid (t) == runid)
	      {
		Termlist tlnext;

		tlnext = tl->next;
		// remove from list; return pointer to head
		sys->variables = termlistDelTerm (tl);
		tl = tlnext;
	      }
	    else
	      {
		// proceed
		tl = tl->next;
	      }
	  }
      }

      /**
       * Undo the local copies of the substitutions. We cannot restore them however, so this might
       * prove a problem. We assume that the substlist fixes this at roleInstance time; it should be exact.
       */
      substlist = myrun.substitutions;
      while (substlist != NULL)
	{
	  Term t;

	  t = substlist->term;
	  if (t->subst != NULL)
	    {
	      termDelete (t->subst);
	      t->subst = NULL;
	    }
	  substlist = substlist->next;
	}
      termlistDelete (myrun.substitutions);

      /*
       * Artefact removal can only be done if knowledge sets are empty, as with Arachne
       */
      {
	Termlist artefacts;
	// Remove artefacts
	artefacts = myrun.artefacts;
	while (artefacts != NULL)
	  {
	    free (artefacts->term);
	    artefacts = artefacts->next;
	  }
      }

      // remove lists
      termlistDelete (myrun.artefacts);
      termlistDelete (myrun.locals);

      // Destroy run struct allocation in array using realloc
      // Reduce run count
      sys->maxruns = sys->maxruns - 1;
      sys->runs =
	(Run) realloc (sys->runs, sizeof (struct run) * (sys->maxruns));
    }
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
  sys->traceEvent = malloc (s * sizeof (Roledef));
  sys->traceRun = malloc (s * sizeof (int));
  sys->traceKnow = malloc (s * sizeof (Knowledge));
  sys->traceNode = malloc (s * sizeof (states_t));

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
      eprintf ("%i  ", j);
      i--;
      j++;
    }
}

//! Create an empty protocol structure with a name.
Protocol
protocolCreate (Term name)
{
  Protocol p;

  p = malloc (sizeof (struct protocol));
  p->nameterm = name;
  p->roles = NULL;
  p->rolenames = NULL;
  p->locals = NULL;
  p->next = NULL;
  return p;
}

//! Print all local terms in a term list.
//@todo What is this doing here? This should be in termlists.c!
void
locVarPrint (Termlist tl)
{
  if (tl == NULL)
    {
      eprintf ("No local terms.\n");
    }
  else
    {
      eprintf ("Local terms: ");
      eprintf ("[");
      while (tl != NULL)
	{
	  termPrint (tl->term);
	  if (tl->term->stype != NULL)
	    {
	      eprintf (":");
	      termlistPrint (tl->term->stype);
	    }
	  tl = tl->next;
	  if (tl != NULL)
	    eprintf (",");
	}
      eprintf ("]");
      eprintf ("\n");
    }
}

//! Print a protocol.
void
protocolPrint (Protocol p)
{
  if (p == NULL)
    return;

  indent ();
  eprintf ("[[Protocol : ");
  termPrint (p->nameterm);
  eprintf (" (");
  termlistPrint (p->rolenames);
  eprintf (")]]\n");
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

//! Determine whether an agent term is trusted
/**
 * 1 (True) means trusted, 0 is untrusted
 */
int
isAgentTrusted (const System sys, Term agent)
{
  agent = deVar (agent);
  if (!realTermVariable (agent) && inTermlist (sys->untrusted, agent))
    {
      // Untrusted agent in the list
      return 0;
    }
  return 1;
}

//! Determine whether there is an untrusted agent.
/**
 *@return True iff all agent in the list are trusted.
 */
int
isAgentlistTrusted (const System sys, Termlist agents)
{
  while (agents != NULL)
    {
      if (!isAgentTrusted (sys, agents->term))
	{
	  return 0;
	}
      agents = agents->next;
    }
  return 1;
}

//! Determine whether all agents of a run are trusted
/**
 * Returns 0 (False) if they are not trusted, otherwise 1 (True)
 */
int
isRunTrusted (const System sys, const int run)
{
  if (run >= 0 && run < sys->maxruns)
    {
      if (!isAgentlistTrusted (sys, sys->runs[run].rho))
	{
	  return 0;
	}
    }
  return 1;
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
  int notfirst;

  termPrint (role);
  eprintf (":");
  termPrint (agentOfRunRole (sys, run, role));
  eprintf (" (");
  notfirst = 0;
  while (roles != NULL)
    {
      if (!isTermEqual (role, roles->term))
	{
	  if (notfirst)
	    eprintf (", ");
	  termPrint (roles->term);
	  eprintf (":");
	  termPrint (agentOfRunRole (sys, run, roles->term));
	  notfirst = 1;
	}
      roles = roles->next;
    }
  eprintf (")");
}

//! Explain a violated claim at point i in the trace.

void
violatedClaimPrint (const System sys, const int i)
{
  eprintf ("Claim stuk");
}

void
commandlinePrint (FILE * stream)
{
  /* print command line */
  int i;

  for (i = 0; i < switches.argc; i++)
    fprintf (stream, " %s", switches.argv[i]);
}

//! Get the number of roles in the system.
int
compute_rolecount (const System sys)
{
  Protocol pr;
  int n;

  n = 0;
  pr = sys->protocols;
  while (pr != NULL)
    {
      n = n + termlistLength (pr->rolenames);
      pr = pr->next;
    }
  return n;
}

//! Compute the maximum number of events in a single role in the system.
int
compute_roleeventmax (const System sys)
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
	  if (n > maxev)
	    maxev = n;
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
  termlistPrint (sys->runs[run].rho);
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
	  eprintf ("\t");
	}
    }
}

//! Iterate over all roles (AND)
/**
 * Function called gets (sys,protocol,role)
 * If it returns 0, iteration aborts.
 */
int
system_iterate_roles (const System sys, int (*func) ())
{
  Protocol p;

  p = sys->protocols;
  while (p != NULL)
    {
      Role r;

      r = p->roles;
      while (r != NULL)
	{
	  if (!func (sys, p, r))
	    return 0;
	  r = r->next;
	}
      p = p->next;
    }
  return 1;
}

//! Determine whether we don't need any more attacks
/**
 * Returns 1 (true) iff no more attacks are needed.
 */
int
enoughAttacks (const System sys)
{
  if (switches.maxAttacks != 0)
    {
      if (sys->attackid >= switches.maxAttacks)
	{
	  return 1;
	}
    }
  return 0;
}

//! Iterate over runs.
/**
 * Callback should return true in order to continue.
 */
int
iterateRuns (const System sys, int (*callback) (int r))
{
  int r;

  for (r = 0; r < sys->maxruns; r++)
    {
      if (!callback (r))
	{
	  return false;
	}
    }
  return true;
}

//! Iterate over non-intruder runs.
/**
 * Callback should return true in order to continue.
 */
int
iterateRegularRuns (const System sys, int (*callback) (int r))
{
  int regular (int r)
  {
    if (sys->runs[r].protocol != INTRUDER)
      {
	return callback (r);
      }
    return true;
  }

  return iterateRuns (sys, regular);
}

// Iterate over events in a certain run (increasing through role)
int
iterateEvents (const System sys, const int run,
	       int (*callback) (Roledef rd, int ev))
{
  int e;
  Roledef rd;

  rd = sys->runs[run].start;
  for (e = 0; e < sys->runs[run].step; e++)
    {
      if (!callback (rd, e))
	{
	  return false;
	}
      rd = rd->next;
    }
  return true;
}

// Iterate over event type in a certain run (increasing through role)
/**
 * If evtype == ANYEVENT then it does not matter.
 */
int
iterateEventsType (const System sys, const int run, const int evtype,
		   int (*callback) (Roledef rd, int ev))
{
  int selectEvent (Roledef rd, int e)
  {
    if (evtype == ANYEVENT || rd->type == evtype)
      {
	return callback (rd, e);
      }
    return true;
  }

  return iterateEvents (sys, run, selectEvent);
}

// Iterate over all 'others': local variables of a run that are instantiated and contain some term of another run.
int
iterateLocalToOther (const System sys, const int myrun,
		     int (*callback) (Term tlocal))
{
  Termlist tlo, tls;
  int flag;

  int addOther (Term t)
  {
    tlo = termlistAddNew (tlo, t);
    return true;
  }

  flag = true;
  tlo = NULL;
  // construct all others occuring in the reads
  for (tls = sys->runs[myrun].sigma; tls != NULL; tls = tls->next)
    {
      Term tt;

      tt = tls->term;
      if (realTermVariable (tt) && tt->subst != NULL);
      {
	iterateTermOther (myrun, tt->subst, addOther);
      }
    }
  // now iterate over all of them
  for (tls = tlo; flag && (tls != NULL); tls = tls->next)
    {
      if (!callback (tls->term))
	{
	  flag = false;
	}
    }

  // clean up
  termlistDelete (tlo);
  return flag;
}

//! Get first read/send occurrence (event index) of term t in run r
int
firstOccurrence (const System sys, const int r, Term t, int evtype)
{
  int firste;

  int checkOccurs (Roledef rd, int e)
  {
    if (termSubTerm (rd->message, t) || termSubTerm (rd->from, t)
	|| termSubTerm (rd->to, t))
      {
	firste = e;
	return false;
      }
    return true;
  }

  firste = -1;
  iterateEventsType (sys, r, evtype, checkOccurs);
#ifdef DEBUG
  if (DEBUGL (3))
    {
      if (firste == -1)
	{
	  globalError++;
	  eprintf ("Warning: Desired term ");
	  termPrint (t);
	  eprintf (" does not occur");
	  eprintf (" in run %i in event type %i.\n", r, evtype);
	  runPrint (sys->runs[r].start);
	  eprintf ("\n");
	  globalError--;
	}
    }
#endif
  return firste;
}

//! Get the roledef of an event
Roledef
eventRoledef (const System sys, const int run, const int ev)
{
  return roledef_shift (sys->runs[run].start, ev);
}

//! count the number of initiators
int
countInitiators (const System sys)
{
  int run;
  int count;

  count = 0;
  for (run = 0; run < sys->maxruns; run++)
    {
      if (sys->runs[run].role->initiator)
	{
	  count++;
	}
    }
  return count;
}

//! determine whether a run talks to itself
int
selfSession (const System sys, const int run)
{
  int self_session;
  Termlist agents;
  Termlist seen;

  if (sys->runs[run].protocol == INTRUDER)
    {
      // Intruder has no self sessions
      return false;
    }

  self_session = false;

  agents = sys->runs[run].rho;
  seen = NULL;
  while (agents != NULL)
    {
      Term agent;

      agent = deVar (agents->term);
      if (inTermlist (seen, agent))
	{
	  // This agent was already in the seen list
	  self_session = true;
	  break;
	}
      else
	{
	  seen = termlistAdd (seen, agent);
	}
      agents = agents->next;
    }
  termlistDelete (seen);

  return self_session;
}

//! determine whether a run is a so-called self-responder
/**
 * Alice starting a run with Bob, Charlie, Bob is also counted as self-response.
 */
int
selfResponder (const System sys, const int run)
{
  if (sys->runs[run].role->initiator)
    {
      return false;
    }
  else
    {
      return selfSession (sys, run);
    }
}

//! Count the number of any self-responders
int
selfResponders (const System sys)
{
  int count;
  int run;

  count = 0;
  run = 0;
  while (run < sys->maxruns)
    {
      if (selfResponder (sys, run))
	{
	  count++;
	}
      run++;
    }
  return count;
}

//! determine whether a run is a so-called self-initiator
/**
 * Alice starting a run with Bob, Charlie, Bob is also counted as self-initiation.
 */
int
selfInitiator (const System sys, const int run)
{
  if (sys->runs[run].role->initiator)
    {
      return selfSession (sys, run);
    }
  else
    {
      return false;
    }
}

//! Count the number of any self-initiators
int
selfInitiators (const System sys)
{
  int count;
  int run;

  count = 0;
  run = 0;
  while (run < sys->maxruns)
    {
      if (selfInitiator (sys, run))
	{
	  count++;
	}
      run++;
    }
  return count;
}
