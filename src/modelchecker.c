/*!\file modelchecker.c
 * \brief The main procedures guiding the (optimized) traversal of the state space.
 *
 * This file implements various traversal methods through the state space.
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "substitution.h"
#include "knowledge.h"
#include "system.h"
#include "debug.h"
#include "modelchecker.h"
#include "report.h"
#include "memory.h"
#include "match_basic.h"
#include "match_clp.h"
#include "output.h"
#include "tracebuf.h"
#include "attackminimize.h"
#include "claim.h"
#include "switches.h"

/*

	A model checker. Really.
*/

extern Term CLAIM_Secret;
extern Term CLAIM_Nisynch;
extern Term CLAIM_Niagree;

/*
   Some forward declarations.
*/

__inline__ int traverseSimple (const System oldsys);
__inline__ int traverseNonReads (const System oldsys);
__inline__ int traversePOR4 (const System oldsys);
__inline__ int traversePOR5 (const System oldsys);
__inline__ int traversePOR6 (const System oldsys);
__inline__ int traversePOR7 (const System oldsys);
__inline__ int traversePOR8 (const System oldsys);
int propertyCheck (const System sys);
int executeTry (const System sys, int run);
int claimSecrecy (const System sys, const Term t);
int violateClaim (const System sys, int length, int claimev, Termlist reqt);
Termlist secrecyUnfolding (Term t, const Knowledge know);

/*
   Main code.
*/

void
statePrint (const System sys)
{
  int i, s;
  Roledef rd;

  indent ();
  printf ("state %i: ", sys->step);
  for (i = 0; i < sys->maxruns; i++)
    {
      s = 0;
      rd = runPointerGet (sys, i);
      while (rd != NULL)
	{
	  rd = rd->next;
	  s++;
	}
      printf ("%i ", s);
    }
  printf (" - phase %i, done %i", sys->PORphase, sys->PORdone);
  printf ("\n");
}

//! Scenario selection makes sure implicit and explicit chooses are selected first.
/**
 * This help function traverses any chooses first.
 */
__inline__ int
traverse_chooses_first (const System sys)
{
  int run_scan;

  for (run_scan = 0; run_scan < sys->maxruns; run_scan++)
    {
      Roledef rd_scan;

      rd_scan = runPointerGet (sys, run_scan);
      if (rd_scan != NULL &&	// Not empty run
	  rd_scan == sys->runs[run_scan].start &&	// First event
	  rd_scan->type == READ)	// Read
	{
	  if (executeTry (sys, run_scan))
	    return 1;
	}
    }
  return 0;
}

//! Main traversal call.
/**
 * Branches into submethods.
 */
int
traverse (const System sys)
{
  /* maybe chooses have precedence over _all_ methods */
  if (switches.chooseFirst)
    {
      if (traverse_chooses_first (sys))
	return 1;
    }

  /* branch for traversal methods */
  switch (switches.traverse)
    {
    case 1:
      return traverseSimple (sys);
    case 2:
      return traverseNonReads (sys);
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
      error ("%i is an obsolete traversal method.", switches.traverse);
    case 8:
      return traversePOR4 (sys);
    case 9:
      return traversePOR5 (sys);
    case 10:
      return traversePOR6 (sys);
    case 11:
      return traversePOR7 (sys);
    case 12:
      return traversePOR8 (sys);
    default:
      error ("%i is NOT an existing traversal method.", switches.traverse);
    }
}

//! Progress counters to next step.
/**
 * Does not really execute anything, it's just bookkeeping, progressing
 * counters and such.
 *
 *@returns If it returns TRUE, explore. If false, don't traverse.
 */

int
executeStep (const System sys, const int run)
{
  Roledef runPoint;
  runPoint = runPointerGet (sys, run);
#ifdef DEBUG
  if (DEBUGL (3))
    {
      indent ();
      printf ("exec: ");
      roledefPrint (runPoint);
      printf ("#%i\n", run);
    }
#endif
  sys->runs[run].step++;
  runPointerSet (sys, run, runPoint->next);

  /* store knowledge for this step */
  (sys->step)++;
  sys->traceKnow[sys->step] = sys->know;

  /* check for properties */
  propertyCheck (sys);

  /* set indent for printing */
  indentSet (sys->step);
  /* hmmm, but what should it return if not exploring? */
  if (!sys->explore)
    return 0;

  /* we want to explore it, but are we allowed by pruning? */
  if (sys->step >= sys->maxtracelength)
    {
      /* cut off traces that are too long */
#ifdef DEBUG
      if (DEBUGL (4))
	{
	  indent ();
	  printf ("trace cut off.\n");
	  if (DEBUGL (5))
	    {
	      (sys->step)--;
	      tracePrint (sys);
	      (sys->step)++;
	    }
	}
#endif
      return 0;
    }

  /* we will explore this state, so count it. */
  sys->states = statesIncrease (sys->states);

  /* what about scenario exploration? */
  if (switches.scenario && sys->step + 1 > switches.scenarioSize)
    {
      /* count states within scenario */
      sys->statesScenario = statesIncrease (sys->statesScenario);
    }

  /* show progression */
  if (switches.reportStates > 0)
    {
      sys->interval = statesIncrease (sys->interval);
      if (!statesSmallerThan
	  (sys->interval, (unsigned long int) switches.reportStates))
	{
	  globalError++;
	  sys->interval = STATES0;
	  eprintf ("States ");
	  statesFormat (sys->states);
	  eprintf (" \r");
	  globalError--;
	}
    }

  /* store new node numbder */
  sys->traceNode[sys->step] = sys->states;
  /* the construction below always assumes MAX_GRAPH_STATES to be smaller than the unsigned long it, which seems realistic. */
  if (switches.output == STATESPACE
      && statesSmallerThan (sys->states, MAX_GRAPH_STATES))
    {
      /* display graph */
      graphNode (sys);
    }
  return 1;
}

//! Determine end of run after removing end reads, and optionally claims.
Roledef
removeDangling (Roledef rd, const int killclaims)
{
  Roledef rdkill;

  rdkill = rd;
  while (rd != NULL)
    {
      if (rd->type == SEND || (!killclaims && rd->type == CLAIM))
	rdkill = rd;
      rd = rd->next;
    }
  /* remove after rdkill */
  return rdkill;
}

/**
 * Determine for a roledef that is instantiated, the uninteresting ends bits.
 *
 *@todo "What is interesting" relies on the fact that there are only secrecy, sychnr and agreement properties.
 */
Roledef
removeIrrelevant (const System sys, const int run, Roledef rd)
{
  if (untrustedAgent (sys, sys->runs[run].agents))
    {
      // untrusted, so also remove claims
      return removeDangling (rd, 1);
    }
  else
    {
      // trusted, so only remove reads
      return removeDangling (rd, 0);
    }
}


//! Unblock any waiting sends of my type.
/**
 * Note that the caller must ensure that rd->forbidden is restored afterwards.
 *\sa tryChoiceSend()
 */
void
unblock_synchronising_labels (const System sys, const int run,
			      const Roledef rd)
{
  if (rd->type != READ || rd->internal)
    return;
  if (!inTermlist (sys->synchronising_labels, rd->label))
    return;

  // This read possibly unblocks other sends
  int run_scan;

  for (run_scan = 0; run_scan < sys->maxruns; run_scan++)
    {
      if (run_scan != run)
	{
	  Roledef rd_scan;

	  rd_scan = sys->runs[run_scan].index;
	  if (rd_scan != NULL &&
	      rd_scan->type == SEND &&
	      rd_scan->forbidden != NULL &&
	      isTermEqual (rd_scan->label, rd->label) &&
	      isTermEqual (rd_scan->message, rd->message) &&
	      isTermEqual (rd_scan->from, rd->from) &&
	      isTermEqual (rd_scan->to, rd->to))
	    {
	      rd_scan->forbidden = NULL;
	    }
	}
    }
  return;
}

//! Explores the system state given by the next step of a run.
/** Grandiose naming scheme (c) sjors dubya.
 *
 * After an event was instantiated, this function is called to explore the
 * remainder of the system.
 *
 * Note that some additional pruning is done, so this function
 * also determines the enabledness of the event that was just instantiated.
 *
 *@returns 1 (true) if the event was enabled.
 *\sa match_basic(),executeTry()
 */

int
explorify (const System sys, const int run)
{
  Roledef rd;
  int flag;
  int myStep;
  Roledef roleCap, roleCapPart;
  Knowledge forbiddenBuffer;

  rd = runPointerGet (sys, run);
  myStep = sys->runs[run].step;
  roleCap = NULL;

  if (rd == NULL)
    {
      error ("Trying to progress completed run!\n");
    }

  flag = 0;

  /**
   * --------------------------------------------
   * Is the event really enabled?
   * Typically, a read event is only instantiated
   * at this point, so we can only now do some
   * instantiation related determinings.
   * --------------------------------------------
   */

  /*
   * Special checks after (implicit) choose events; always first in run reads.
   */
  if (myStep == 0 && rd->type == READ)
    {
      int rid;

      if (inTermlist (sys->untrusted, agentOfRun (sys, run)))
	{
	  /* this run is executed by an untrusted agent, do not explore */
	  return 0;
	}
      /* executed by trusted agent */

      /* Special check 1: if agents have been instantiated in such a way that no more claims in any run
       * need to be evaluated, then we can skip
       * further traversal.
       */
      //!@todo This implementation relies on the fact that there are only secrecy, synchr and agreement properties.
      if (switches.pruneNomoreClaims && sys->secrets == NULL)
	{			/* there are no remaining secrecy claims to be checked */
	  Roledef rdscan;
	  int validclaim;

	  rid = 0;
	  validclaim = 0;
	  /* check for each run */
	  while (rid < sys->maxruns)
	    {
	      /* are claims in this run evaluated anyway? */
	      if (!untrustedAgent (sys, sys->runs[rid].agents))
		{		/* possibly claims to be checked in this run */
		  rdscan = runPointerGet (sys, rid);
		  while (rdscan != NULL)
		    {
		      if (rdscan->type == CLAIM)
			{
			  /* force abort of loop */
			  validclaim = 1;
			  rdscan = NULL;
			  rid = sys->maxruns;
			}
		      else
			{
			  rdscan = rdscan->next;
			}
		    }
		}
	      rid++;
	    }
	  if (validclaim == 0)
	    {			/* no valid claims, abort */
	      return 0;
	    }
	}

      /* Special check 2: Symmetry reduction on chooses.
       * If the run we depend upon has already been activated (otherwise warn!) check for instance ordering
       */

      if (switches.agentSymmetries && sys->runs[run].prevSymmRun != -1)
	{
	  /* there is such a run on which we depend */
	  int ridSymm;

	  ridSymm = sys->runs[run].prevSymmRun;
	  if (sys->runs[ridSymm].step == 0)
	    {
	      /*
	       * dependency run was not chosen yet, so we can't do anything now
	       */
	      // warning ("Symmetrical run dependency #%i (for run #%i) has not chosen yet!", ridSymm, run);
	    }
	  else
	    {
	      /* dependent run has chosen, so we can compare */
	      int order;

	      order =
		termlistOrder (sys->runs[run].agents,
			       sys->runs[ridSymm].agents);
	      if (order < 0)
		{
		  /* we only explore the other half */
		  return 0;
		}
	      if (order == 0 && switches.reduceClaims)
		{
		  /* identical run; only the first would be checked for a claim */
		  /* so we cut off this run, including claims, turning it into a dummy run */
		  roleCap = removeDangling (rd, 1);
		}
	    }
	}

      /* Special check 3: if after choosing, this run is untrusted and ends on (read|skippedclaim)*, we can remove that part already.
       */

      if (switches.reduceEndgame && roleCap == NULL)
	roleCap = removeIrrelevant (sys, run, rd);

      /* Special check x: if all agents in each run send only encrypted stuff, and all agents are trusted,
       * there is no way for the intruder to learn anything else than encrypted terms, so secrecy claims will not
       * be violated anymore if they contain no terms that are encrypted with such keys */

      //!@todo For now, there is no check that the runs only send publicly encrypted stuff! Just an assumption to be made true using static analysis.

      /*
         rid = 0;
         while (rid < sys->maxruns)
         {
         if (!untrustedAgent (sys, sys->runs[rid].agents))
         {
         }
         rid++;
         }
       */
    }

  /* 
   * Special check b1: symmetry reduction part II on similar read events for equal roles.
   */

  if (switches.readSymmetries)
    {
      if (sys->runs[run].firstNonAgentRead == myStep)
	{
	  /* Apparently, we have a possible ordering with our symmetrical friend.
	   * Check if it has progressed enough, and has the same agents.
	   */
	  int ridSymm;

	  if (rd->type != READ)
	    {
	      error ("firstNonAgentRead is not a read?!");
	    }
	  ridSymm = sys->runs[run].prevSymmRun;
	  if (isTermlistEqual
	      (sys->runs[run].agents, sys->runs[ridSymm].agents))
	    {
	      /* same agents, so relevant */
	      if (myStep > 0 && sys->runs[ridSymm].step < myStep)
		{
		  // warning ("Symmetrical firstread dependency #%i (for run #%i) has not chosen yet!", ridSymm, run);
		}
	      else
		{
		  if (sys->runs[ridSymm].step <= myStep)
		    {
		      // warning ("Symmetrical firstread dependency #%i (for run #%i) has not read it's firstNonAgentRead %i yet, as it is only at %i!", ridSymm, run, myStep, sys->runs[ridSymm].step);
		    }
		  else
		    {
		      /* read was done, so we can compare them */
		      int i;
		      Roledef rdSymm;

		      rdSymm = sys->runs[ridSymm].start;
		      i = myStep;
		      while (i > 0)
			{
			  rdSymm = rdSymm->next;
			  i--;
			}
		      /* rdSymm now points to the instance of the symmetrical read */
		      i = termOrder (rdSymm->message, rd->message);
		      if (i < 0)
			{
			  /* only explore symmetrical variant */
			  return 0;
			}
		    }
		}
	    }
	}
    }

  /* Special check b2: symmetry order reduction.
   *
   * Concept: when there are two identical runs w.r.t. agents, we can make sure one goes before the other.
   * Depends on prevSymm, skipping chooses even.
   */

  if (switches.orderSymmetries && myStep == sys->runs[run].firstReal)
    {
      if (sys->runs[run].prevSymmRun != -1)
	{
	  /* there is such a run on which we depend */
	  int ridSymm;

	  ridSymm = sys->runs[run].prevSymmRun;
	  /* equal runs? */

	  if (isTermlistEqual
	      (sys->runs[run].agents, sys->runs[ridSymm].agents))
	    {
	      /* so, we have an identical partner */
	      /* is our partner there already? */
	      if (sys->runs[ridSymm].step <= myStep)
		{
		  /* not yet there, this is not a valid exploration */
		  /* verify !! */
		  return 0;
		}
	    }
	}
    }

  /**
   * Final special check; we must be sure that chooses have been done. Only
   * necessary for scenario != 0.
   *
   * Note: any choose selection after this would result in empty scenarios, so this
   * should be the last special check.
   */
  if (switches.scenario != 0)
    {
      /* two variants. If scenario size is 0, we operate on the old method involving chooses */
      if (switches.scenarioSize == 0)
	{
	  /* only after chooses */
	  if (myStep == 0 && rd->type == READ)
	    {
	      if (run == sys->lastChooseRun)
		{
		  /* We are just after the last choose instance */
		  /* count this instance */
		  if (sys->countScenario < INT_MAX)
		    {
		      sys->countScenario++;
		    }
		  /* If we are displaying scenarios, print it */
		  if (switches.output == SCENARIOS)
		    {
		      printf ("%i\t", sys->countScenario);
		      scenarioPrint (sys);
		      printf ("\n");
		    }
		  /* If it is not the selected one, abort */
		  if (switches.scenario != sys->countScenario)
		    {
		      /* this branch is not interesting */
		      /* unfortunately, it is also not drawn in the state graph because of this */
		      if (switches.output == STATESPACE)
			{
			  graphScenario (sys, run, rd);
			}
		      /* act as if executed, but don't really explore it. */
		      return 1;
		    }
		}
	    }
	}
      else
	{
	  /* scenario size is not zero */

	  //!@todo Optimization: if the good scenario is already traversed, other trace prefixes need not be explored any further.
	  if (sys->step + 1 == switches.scenarioSize)
	    {
	      /* Now, the prefix has been set. Count it */
	      if (sys->countScenario < INT_MAX)
		{
		  sys->countScenario++;
		}
	      if (switches.output == SCENARIOS)
		{
		  /* apparently we want the output */
		  int index;
		  eprintf ("%i\t", sys->countScenario);
		  index = 0;
		  while (index < switches.scenarioSize)
		    {
		      roledefPrint (sys->traceEvent[index]);
		      eprintf ("#%i; ", sys->traceRun[index]);
		      index++;
		    }
		  eprintf ("\n");
		}
	      /* Is this the selected one? */
	      if (switches.scenario != sys->countScenario)
		{
		  /* unfortunately, it is also not drawn in the state graph because of this */
		  if (switches.output == STATESPACE)
		    {
		      graphScenario (sys, run, rd);
		    }
		  /* act as if executed, but don't really explore it. */
		  return 1;
		}
	    }
	}
    }

  /**
   * --------------------------------------------
   * Now we assume the event is indeed enabled !
   * --------------------------------------------
   */

  /* (Possibly) do some local damage */
  // Unblock any sends
  forbiddenBuffer = rd->forbidden;
  if (sys->synchronising_labels != NULL)
    {
      unblock_synchronising_labels (sys, run, rd);
    }
  // Cap roles
  if (roleCap != NULL)
    {
      roleCapPart = roleCap->next;
      roleCap->next = NULL;
    }

  /* And explore the resulting system */
  if (executeStep (sys, run))
    {
      /* traverse the system after the step */
      flag = traverse (sys);
    }
  /* restore executeStep "damage" */
  runPointerSet (sys, run, rd);	// reset rd pointer
  sys->runs[run].step = myStep;	// reset local index
  sys->step--;
  indentSet (sys->step);

  /* restore local damage */
  rd->forbidden = forbiddenBuffer;
  if (roleCap != NULL)
    {
      roleCap->next = roleCapPart;
    }
  return 1;			// The event was indeed enabled (irrespective of traverse!)
}



//! Simple nondeterministic traversal.

__inline__ int
traverseSimple (const System sys)
{
  int run;
  int flag = 0;

  for (run = 0; run < (sys->maxruns); run++)
    {
      if (runPointerGet (sys, run) != NULL)
	{
	  flag = 1;
	  executeTry (sys, run);
	}
    }
  if (!flag)
    {
      /* trace was not succesful */
    }
  return flag;
}

/**
 * -----------------------------------------------------
 *
 * 		Traversal Methods
 *
 * -----------------------------------------------------
 */

/*
 * Some assistance macros
 */
#define predRead(sys,rd)	( rd->type == READ && !rd->internal )
#define isRead(sys,rd)		( rd != NULL && predRead(sys,rd) )
#define nonRead(sys,rd)		( rd != NULL && !predRead(sys,rd) )

/*
 * nonReads
 *
 * Do a certain type of action first, i.e. that which satisfies nonRead(System,
 * Roledef). Use the inverse of this predicate to detect the other type of
 * event.
 */

__inline__ int
nonReads (const System sys)
{
  /* all sends first, then simple nondeterministic traversal */

  int run;
  Roledef rd;

  /* check for existence of executable sends */
  for (run = 0; run < (sys->maxruns); run++)
    {
      rd = runPointerGet (sys, run);
      if (nonRead (sys, rd))
	{
	  return executeTry (sys, run);
	}
    }
  return 0;
}

/*
 * First traverse any non-reads, then non-deterministically the reads.
 */

__inline__ int
traverseNonReads (const System sys)
{
  if (nonReads (sys))
    return 1;
  else
    return traverseSimple (sys);
}

//! Execute a send
/**
 *\sa unblock_synchronising_labels()
 */

__inline__ int
tryChoiceSend (const System sys, const int run, const Roledef rd)
{
  int flag;

  flag = 0;
  if (rd->forbidden == NULL)
    {
      /* this is allowed. So we either try it, or we try it later (if blocking) */
      /* Note that a send in executetry will always succeed. */
      /* 1. Simply try */
      flag = executeTry (sys, run);
      /* 2. Postpone if synchonisable */
      if (flag && inTermlist (sys->synchronising_labels, rd->label))
	{
	  /* This is supposed to be blocked, so we do so */
	  /* It will possibly be unblocked by a corresponding read event,
	   * the actual code would be in explorify, post instantiation of the read event.
	   */
	  if (switches.clp)
	    {
	      block_clp (sys, run);
	    }
	  else
	    {
	      block_basic (sys, run);
	    }
	}
    }
  return flag;
}

//! Execute a read in the knowledge postponing way, on which the partial order reduction for secrecy depends.

__inline__ int
tryChoiceRead (const System sys, const int run, const Roledef rd)
{
  int flag;

  flag = 0;

  /* the sendsdone check only prevent
   * some unneccessary inKnowledge tests,
   * and branch tests, still improves
   * about 15% */
  if (sys->knowPhase > rd->knowPhase)
    {
      /* apparently there has been a new knowledge item since the
       * previous check */

      /* implicit check for enabledness */
      flag = executeTry (sys, run);

      /* if it was enabled (flag) we postpone it if it makes sense
       * to do so (hasVariable, non internal) */
      if (flag && hasTermVariable (rd->message) && !rd->internal)
	{
	  int stackKnowPhase = rd->knowPhase;

	  rd->knowPhase = sys->knowPhase;
	  if (switches.clp)
	    {
	      block_clp (sys, run);
	    }
	  else
	    {
	      block_basic (sys, run);
	    }
	  rd->knowPhase = stackKnowPhase;
	}
    }
  return flag;
}

//! Try to execute the event at the roledef. Returns true iff it was enabled, and thus explored.
/**
 * Note that rd should not be NULL
 */
__inline__ int
tryChoiceRoledef (const System sys, const int run, const Roledef rd)
{
  int flag;

#ifdef DEBUG
  if (rd == NULL)
    error ("tryChoiceRoledef should not be called with a NULL rd pointer");
#endif

  flag = 0;
  switch (rd->type)
    {
    case CLAIM:
      flag = executeTry (sys, run);
      break;

    case SEND:
      flag = tryChoiceSend (sys, run, rd);
      break;

    case READ:
      flag = tryChoiceRead (sys, run, rd);
      break;

    default:
      fprintf (stderr, "Encountered unknown event type %i.\n", rd->type);
      exit (1);
    }
  return flag;
}

//! Try to execute the event in a given run
__inline__ int
tryChoiceRun (const System sys, const int run)
{
  Roledef rd;

  rd = runPointerGet (sys, run);
  if (rd != NULL)
    return tryChoiceRoledef (sys, run, rd);
  else
    return 0;
}

//! Yield the last active run in the partial trace, or 0 if there is none.
__inline__ int
lastActiveRun (const System sys)
{
  if (sys->step == 0)
    {
      /* first step, start at 0 */
      return 0;
    }
  else
    {
      /* there was a previous action, start scan from there */
#ifdef DEBUG
      if (switches.switchP < 100)
	return sys->traceRun[sys->step - 1] + switches.switchP;
#endif
      return sys->traceRun[sys->step - 1];
    }
}

//! Determine whether a roleevent is a choose event
__inline__ int
isChooseRoledef (const System sys, const int run, const Roledef rd)
{
  return (rd == sys->runs[run].start && rd->type == READ && rd->internal);
}

//! Explore possible chooses first
__inline__ int
tryChoosesFirst (const System sys)
{
  int flag;
  int run;
  Roledef rd;

  flag = 0;
  for (run = 0; run < sys->maxruns && !flag; run++)
    {
      rd = runPointerGet (sys, run);
      if (isChooseRoledef (sys, run, rd))
	flag = tryChoiceRoledef (sys, run, rd);
    }
  return flag;
}

//! Explore left-to-right (from an offset)
__inline__ int
tryEventsOffset (const System sys, const int offset)
{
  int flag;
  int run;
  int i;

  flag = 0;
  for (i = 0; i < sys->maxruns && !flag; i++)
    {
      run = (i + offset) % sys->maxruns;
      flag = tryChoiceRun (sys, run);
    }
  return flag;
}

/*
 * POR4
 *
 * This is the simplified version of the algorithm, to be compared with
 * the -t7 version.
 *
 * Based on some new considerations.
 */

__inline__ int
traversePOR4 (const System sys)
{
  return tryEventsOffset (sys, lastActiveRun (sys));
}

/*
 * POR5
 *
 * POR4 but does chooses first.
 */

__inline__ int
traversePOR5 (const System sys)
{
  if (tryChoosesFirst (sys))
    return 1;
  return tryEventsOffset (sys, lastActiveRun (sys));
}

/*
 * POR6
 *
 * POR5 but has a left-oriented scan instead of working from the current run.
 */

__inline__ int
traversePOR6 (const System sys)
{
  return tryEventsOffset (sys, 0);
}

/*
 * POR7
 *
 * Left-oriented scan, to ensure reductions. However, first does all initial actions.
 */

__inline__ int
traversePOR7 (const System sys)
{
  if (tryChoosesFirst (sys))
    return 1;
  tryEventsOffset (sys, 0);
}

/*
 * POR8
 *
 * POR6, but tries to continue on the current run first. This turned out to be highly more efficient.
 */

__inline__ int
traversePOR8 (const System sys)
{
  int flag;
  int run;
  int last;

  last = lastActiveRun (sys);
  flag = tryChoiceRun (sys, last);
  for (run = 0; run < sys->maxruns && !flag; run++)
    {
      if (run != last)
	flag = tryChoiceRun (sys, run);
    }
  return flag;
}


//! Check for the properties that have lasting effects throughout the trace.
/**
 * Currently, only functions for secrecy.
 *@returns 1 (true) iff everything is okay, and no attack is found. 0 (false) if an attack is found.
 */

int
propertyCheck (const System sys)
{
  int flag = 1;			// default: properties are true, no attack 

  /* for now, we only check secrecy */
  if (sys->secrets != NULL)
    {
      Termlist scan;
      scan = sys->secrets;
      while (scan != NULL)
	{
	  if (!claimSecrecy (sys, scan->term))
	    {
	      /* apparently, secrecy of this term was violated */
	      /* find the violated claim event */

	      Termlist tl = NULL;
	      int claimev = -1;
	      int i = 0;

	      while (claimev == -1 && i <= sys->step)
		{
		  if (sys->traceEvent[i]->type == CLAIM &&
		      sys->traceEvent[i]->to == CLAIM_Secret)
		    {
		      Termlist tl = secrecyUnfolding (scan->term, sys->know);
		      if (tl != NULL)
			{
			  /* This was indeed a violated claim */
			  claimev = i;
			}
		    }
		  i++;
		}
	      /* do we have it? */
	      if (claimev == -1)
		{
		  /* weird, should not occur */
		  fprintf (stderr, "Violation, but cannot locate claim.\n");
		  printf
		    ("A secrecy claim was supposed to be violated on term ");
		  termPrint (scan->term);
		  printf (" but we couldn't find the corresponding claim.\n");
		  exit (1);
		}
	      else
		{
		  /* fine. so it's violated */
		  violateClaim (sys, sys->step, claimev, tl);
		  termlistDelete (tl);
		  flag = 0;
		}
	    }
	  scan = scan->next;
	}

    }
  return flag;
}

/*	true iff the term is secret */

int
isTermSecret (const System sys, const Term t)
{
  switch (switches.clp)
    {
    case 0:
      /* test for simple inclusion */
      if (inKnowledge (sys->know, t))
	return 0;
      if (isTermVariable (t))
	{
	  /* it's a variable! */

	  /* TODO that does not necessarily mean we can choose it, does
	   * it?  NO: the rule should be: there is at least one message
	   * in knowledge. We don't check it currently.*/

	  return 0;
	}
      return 1;
    case 1:
      /* CLP stuff */
      return secret_clp (sys, t);
    default:
      return 0;
    }
}

/*	true iff the claim is valid */

int
claimSecrecy (const System sys, const Term t)
{
  int csScan (Term t)
  {
    t = deVar (t);
    if (isTermTuple (t))
      return csScan (TermOp1 (t)) && csScan (TermOp2 (t));
    else
      return isTermSecret (sys, t);
  }

  if (csScan (t))
    return 1;
  else
    {
      /* Not reported anymore here, but only at the end */
      // reportSecrecy (sys, t);
      return 0;
    }
}

/*
 * Unfold the secrecy tuple and construct a list of terms that violate it.
 */

Termlist
secrecyUnfolding (Term t, const Knowledge know)
{
  t = deVar (t);
  if (isTermTuple (t))
    return termlistConcat (secrecyUnfolding (TermOp1 (t), know),
			   secrecyUnfolding (TermOp2 (t), know));
  else
    {
      if (inKnowledge (know, t))
	return termlistAdd (NULL, t);
      else
	return NULL;
    }
}

/*
 * for reporting we need a more detailed output of the claims.
 * Output is a termlist pointer, or -1.
 *
 * in: claim roledef, knowledge for which it is violated
 *
 * -1	: claim was ignored
 * NULL : claim is fulfilled (true)
 * Termlist: claim was violated, termlist terms are know to the intruder.
 */

Termlist
claimViolationDetails (const System sys, const int run, const Roledef rd,
		       const Knowledge know)
{
  if (rd->type != CLAIM)
    {
      fprintf (stderr,
	       "Trying to determine details of something other than a claim!\n");
      exit (-1);
    }

  /* cases */
  if (rd->to == CLAIM_Secret)
    {
      /* secrecy claim */

      if (untrustedAgent (sys, sys->runs[run].agents))
	{
	  /* claim was skipped */
	  return (Termlist) - 1;
	}
      else
	{
	  /* construct violating subterms list */
	  return secrecyUnfolding (rd->message, know);
	}
    }
  return NULL;
}

//! A claim was violated.
/**
 * This happens when we violate a claim.
 * Lots of administration.
 *@returns True iff explorify is in order.
 */
int
violateClaim (const System sys, int length, int claimev, Termlist reqt)
{
  int flag;
  Claimlist clinfo;

  /* default = no adaption of pruning, continue search */
  flag = 1;

  /* Count the violations */
  sys->attackid++;
  sys->failed = statesIncrease (sys->failed);
  clinfo = sys->traceEvent[claimev]->claiminfo;
  clinfo->failed = statesIncrease (clinfo->failed);	// note: for modelchecking secrecy, this can lead to more fails (at further events in branches of the tree) than claim encounters

  /* mark the path in the state graph? */
  if (switches.output == STATESPACE)
    {
      graphPath (sys, length);
    }

  /* Copy the current trace to the buffer, if the new one is shorter than the previous one. */
  if (sys->attack == NULL || length < sys->attack->reallength)
    {
      tracebufDone (sys->attack);
      sys->attack = tracebufSet (sys, length, claimev);
      attackMinimize (sys, sys->attack);
      sys->shortestattack = sys->attack->reallength;

      /* maybe there is some new pruning going on */
      flag = 0;
      switch (switches.prune)
	{
	case 0:
	  flag = 1;
	  break;
	case 1:
	  break;
	case 2:
	  sys->maxtracelength = sys->shortestattack - 1;
	  break;
	}
    }
  return flag;
}

//! Try to execute the next event in a run.
/**
 * One of the core functions of the system.
 *@returns 0 (false) if the event was not enabled. 1 (true) if there was an enabled instantiation of this event.
 */
int
executeTry (const System sys, int run)
{
  Roledef runPoint;
  int flag = 0;

  runPoint = runPointerGet (sys, run);
  sys->traceEvent[sys->step] = runPoint;	// store for later usage, problem: variables are substituted later...
  sys->traceRun[sys->step] = run;	// same

  if (runPoint == NULL)
    {
#ifdef DEBUG
      /* warning, ought not to occur */
      debug (2, "Trying to activate completed run");
#endif
    }
  else
    {
#ifdef DEBUG
      if (DEBUGL (4))
	{
	  indent ();
	  printf ("try: ");
	  roledefPrint (runPoint);
	  printf ("#%i\n", run);
	}
#endif
      if (runPoint->type == READ)
	{
	  if (switches.clp)
	    return matchRead_clp (sys, run, explorify);
	  else
	    return matchRead_basic (sys, run, explorify);
	}
      if (runPoint->type == SEND)
	{
	  if (switches.clp)
	    flag = send_clp (sys, run);
	  else
	    flag = send_basic (sys, run);
	  return flag;
	}

      /*
       * Execute claim event
       */
      if (runPoint->type == CLAIM)
	{
	  /* first we might dynamically determine whether the claim is valid */
	  if (untrustedAgent (sys, sys->runs[run].agents))
	    {
	      /* for untrusted agents we check no claim violations at all
	       * so: we know it's okay. */
	      /* TODO for CLP this doesn't work and call for branching, if the
	       * agent is a variable */
#ifdef DEBUG
	      if (DEBUGL (3))
		{
		  indent ();
		  printf ("Skipped claim in untrusted run with agents ");
		  termlistPrint (sys->runs[run].agents);
		  printf ("\n");
		}
#endif
	      explorify (sys, run);
	      return 1;
	    }

	  /* determine type of claim, and parameters */
#ifdef DEBUG
	  if (DEBUGL (2))
	    {
	      indent ();
	      printf ("claim: ");
	      roledefPrint (runPoint);
	      printf ("#%i\n", run);
	    }
#endif
	  /*
	   * update claim counters
	   */
	  sys->claims = statesIncrease (sys->claims);

	  /*
	   * distinguish claim types
	   */
	  if (runPoint->to == CLAIM_Secret)
	    {
	      /*
	       * SECRECY
	       */
	      /* TODO claims now have their own type, test for that */
	      /* TODO for now it is secrecy of the message */

	      Termlist oldsecrets = sys->secrets;
	      /* TODO this can be more efficient, by filtering out double occurrences */
	      sys->secrets =
		termlistAdd (termlistShallow (oldsecrets), runPoint->message);
	      flag = claimSecrecy (sys, runPoint->message);
	      runPoint->claiminfo->count++;

	      /* now check whether the claim failed for further actions */
	      if (!flag)
		{
		  /* violation */
		  Termlist tl;

		  tl = claimViolationDetails (sys, run, runPoint, sys->know);
		  if (violateClaim (sys, sys->step + 1, sys->step, tl))
		    flag = explorify (sys, run);
		  termlistDelete (tl);
		}
	      else
		{
		  /* no violation */
		  flag = explorify (sys, run);
		}

	      /* reset secrets list */
	      termlistDelete (sys->secrets);
	      sys->secrets = oldsecrets;
	    }
	  if (runPoint->to == CLAIM_Nisynch)
	    {
	      /*
	       * NISYNCH
	       */
	      flag = check_claim_nisynch (sys, sys->step);
	      if (!flag)
		{
		  /* violation */
		  if (violateClaim (sys, sys->step + 1, sys->step, NULL))
		    flag = explorify (sys, run);
		}
	      else
		{
		  /* no violation */
		  flag = explorify (sys, run);
		}
	    }
	  if (runPoint->to == CLAIM_Niagree)
	    {
	      /*
	       * NIAGREE
	       */
	      flag = check_claim_niagree (sys, sys->step);
	      if (!flag)
		{
		  /* violation */
		  if (violateClaim (sys, sys->step + 1, sys->step, NULL))
		    flag = explorify (sys, run);
		}
	      else
		{
		  /* no violation */
		  flag = explorify (sys, run);
		}
	    }
	}
      /* a claim always succeeds */
      flag = 1;
    }
  return flag;
}
