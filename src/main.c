/**
 *@file main.c
 * \brief The main file.
 *
 * Contains the main switch handling, and passes everything to the core logic.
 */

/**
 * \mainpage
 *
 * \section intro Introduction
 *
 * Scyther is a model checker for security protocols.
 *
 * \section install Installation
 *
 * How to install Scyther.
 *
 * \section exit Exit codes
 *
 * 0  Okay	No attack found, claims encountered
 *
 * 1  Error	Something went wrong (error) E.g. switch error, or scenario ran out.
 *
 * 2  Okay	No attack found (because) no claims encountered
 *
 * 3  Okay	Attack found
 *
 * However, if the --scenario=-1 switch is used, the exit code is used to return the number of scenarios.
 *
 * \section coding Coding conventions
 *
 * Usually, each source file except main.c has an myfileInit() and myfileDone() function
 * available. These allow any initialisation and destruction of required structures.
 *
 * GNU indent rules are used, but K&R derivatives are allowed as well. Conversion can
 * be done for any style using the GNU indent program.
 */

enum exittypes
{ EXIT_NOATTACK = 0, EXIT_ERROR = 1, EXIT_NOCLAIM = 2, EXIT_ATTACK = 3 };

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include "system.h"
#include "debug.h"
#include "modelchecker.h"
#include "memory.h"
#include "symbol.h"
#include "pheading.h"
#include "symbol.h"
#include "parser.h"
#include "tac.h"
#include "timer.h"
#include "compiler.h"
#include "latex.h"
#include "output.h"
#include "binding.h"
#include "switches.h"

#include "argtable2.h"

// The global system state
System sys;

extern struct tacnode *spdltac;
extern Term TERM_Claim;
extern int mgu_match;

void scanner_cleanup (void);
void strings_cleanup (void);
int yyparse (void);

void MC_incRuns (const System sys);
void MC_incTraces (const System sys);
void MC_single (const System sys);
int modelCheck (const System sys);

//! The main body, as called by the environment.
int
main (int argc, char **argv)
{
  int nerrors;
  int exitcode = EXIT_NOATTACK;

  /* Initialize memory routines */
  memInit ();

  /* initialize symbols */
  termsInit ();
  termmapsInit ();
  termlistsInit ();
  knowledgeInit ();
  symbolsInit ();
  tacInit ();

  /*
   * ------------------------------------------------
   *     generate system 
   * ------------------------------------------------
   */

  sys = systemInit ();
  sys->argc = argc;
  sys->argv = argv;

  process_switches(sys);
  // exit (0);	// TODO FIX weghalen [x][cc]

  /* init compiler for this system */
  compilerInit (sys);

  sys->know = emptyKnowledge ();


  /* parse input */

  yyparse ();
#ifdef DEBUG
  if (DEBUGL (1))
    tacPrint (spdltac);
#endif

  /* compile */

  if (sys->engine != ARACHNE_ENGINE)
    {
      // Compile as many runs as possible
      compile (spdltac, sys->switchRuns);
    }
  else
    {
      // Compile no runs for Arachne
      compile (spdltac, 0);
    }
  scanner_cleanup ();

  /* preprocess */
  preprocess (sys);

#ifdef DEBUG
  if (DEBUGL (1))
    {
      printf ("\nCompilation yields:\n\n");
      printf ("untrusted agents: ");
      termlistPrint (sys->untrusted);
      printf ("\n");
      knowledgePrint (sys->know);
      printf ("inverses: ");
      knowledgeInversesPrint (sys->know);
      printf ("\n");
      locVarPrint (sys->locals);
      protocolsPrint (sys->protocols);

      printf ("\nInstantiated runs:\n\n");
      runsPrint (sys);
    }
#endif

  /* allocate memory for traces, based on runs */
  systemStart (sys);
  sys->traceKnow[0] = sys->know;	// store initial knowledge

  /* add parameters to system */


  /*
   * ---------------------------------------
   *  Switches consistency checking.
   * ---------------------------------------
   */

  /* Latex only makes sense for attacks */
  if (sys->latex && sys->output != ATTACK)
    {
      error ("Scyther can only generate LaTeX output for attacks.");
    }
#ifdef DEBUG
  if (DEBUGL (4))
    {
      warning ("Selected output method is %i", sys->output);
    }
#endif

  if (sys->engine == ARACHNE_ENGINE)
    {
      arachneInit (sys);
    }
  /*
   * ---------------------------------------
   *  Start real stuff
   * ---------------------------------------
   */

  /* latex header? */
  if (sys->latex)
    latexInit (sys, argc, argv);

  /* model check system */
#ifdef DEBUG
  if (DEBUGL (1))
    warning ("Start modelchecking system.");
#endif
  MC_single (sys);

  /*
   * ---------------------------------------
   *  After checking the system, results
   * ---------------------------------------
   */

  /* Display shortest attack, if any */

  if (sys->attack != NULL && sys->attack->length != 0)
    {
      if (sys->output == ATTACK)
	{
	  attackDisplay (sys);
	}
      /* mark exit code */
      exitcode = EXIT_ATTACK;
    }
  else
    {
      /* check if there is a claim type that was never reached */
      Claimlist cl_scan;

      cl_scan = sys->claimlist;
      while (cl_scan != NULL)
	{
	  if (cl_scan->failed == STATES0)
	    {
	      /* mark exit code */
	      exitcode = EXIT_NOCLAIM;
	    }
	  cl_scan = cl_scan->next;
	}

    }

  /* latex closeup */
  if (sys->latex)
    latexDone (sys);

  /* Transfer any scenario counting to the exit code,
   * assuming that there is no error. */
  if (exitcode != EXIT_ERROR && sys->switchScenario < 0)
    {
      exitcode = sys->countScenario;
    }

  /*
   * Now we clean up any memory that was allocated.
   */

  if (sys->engine == ARACHNE_ENGINE)
    {
      arachneDone ();
      bindingDone ();
    }
  knowledgeDestroy (sys->know);
  systemDone (sys);
  compilerDone ();

  /* done symbols */
  tacDone ();
  symbolsDone ();
  knowledgeDone ();
  termlistsDone ();
  termmapsDone ();
  termsDone ();

  /* memory clean up? */
  strings_cleanup ();
  memDone ();

exit:
  /* deallocate each non-null entry in argtable[] */

  return exitcode;
}

//! Display time and state space size information using ASCII.
/**
 * Displays also whether an attack was found or not.
 */

void
timersPrint (const System sys)
{
  Claimlist cl_scan;
  int anyclaims;

// #define NOTIMERS

  /* display stats */
  if (sys->output != SUMMARY)
    {
      globalError++;
    }

  /* states traversed */

  eprintf ("states\t");
  statesPrintShort (sys);
  eprintf ("\n");

  /* scenario info */

  if (sys->switchScenario > 0)
    {
      eprintf ("scen_st\t");
      statesFormat (sys->statesScenario);
      eprintf ("\n");
    }

  /* flag
   *
   * L n          Attack of length <n>
   * None         failed claim
   * NoClaim      no claims
   */

  eprintf ("attack\t");
  if (sys->claims == STATES0)
    {
      eprintf ("NoClaim\n");
    }
  else
    {
      if (sys->failed != STATES0)
	eprintf ("L:%i\n", attackLength (sys->attack));
      else
	eprintf ("None\n");
    }

#ifndef NOTIMERS
  /* print time */

  double seconds;
  seconds = (double) clock () / CLOCKS_PER_SEC;
  eprintf ("time\t%.3e\n", seconds);

  /* states per second */

  eprintf ("st/sec\t");
  if (seconds > 0)
    {
      eprintf ("%.3e\n", statesDouble (sys->states) / seconds);
    }
  else
    {
      eprintf ("<inf>\n");
    }
#endif

  /* Print also individual claims */
  /* Note that if the output is set to empty, the claim output is redirected to stdout (for e.g. processing)
   */
  cl_scan = sys->claimlist;
  anyclaims = 0;
  while (cl_scan != NULL)
    {
      anyclaims = 1;

      eprintf ("claim\t");

      /* claim label is tuple */
      if (realTermTuple (cl_scan->label))
	{
	  /* modern version: claim label is tuple (protocname, label) */
	  /* first print protocol.role */
	  termPrint (TermOp1 (cl_scan->label));
	  eprintf ("\t");
	  termPrint (cl_scan->rolename);
	  eprintf ("\t");
	  /* second print event_label */
	  termPrint (cl_scan->type);
	  eprintf ("_");
	  termPrint (TermOp2 (cl_scan->label));
	  eprintf ("\t");
	}
      else
	{
	  /* old-fashioned output */
	  termPrint (cl_scan->type);
	  eprintf ("\t");
	  termPrint (cl_scan->rolename);
	  eprintf (" (");
	  termPrint (cl_scan->label);
	  eprintf (")\t");
	}
      /* print counts etc. */
      eprintf ("found:\t");
      statesFormat (cl_scan->count);
      if (cl_scan->count > 0)
	{
	  if (cl_scan->failed > 0)
	    {
	      eprintf ("\t");
	      eprintf ("failed:\t");
	      statesFormat (cl_scan->failed);
	    }
	  else
	    {
	      eprintf ("\tcorrect: ");
	      if (cl_scan->complete)
		{
		  eprintf ("complete_proof");
		}
	      else
		{
		  eprintf ("bounded_proof");
		  if (cl_scan->timebound)
		    eprintf ("\ttime=%i", get_time_limit());
		}
	    }
	}
      else
	{
	  eprintf ("\tcorrect: does_not_occur");
	}
      eprintf ("\n");
      cl_scan = cl_scan->next;
    }
  if (!anyclaims)
    {
      warning ("No claims in system.");
    }

  /* reset globalError */
  if (sys->output != SUMMARY)
    {
      globalError--;
    }
}

//! Analyse the model by incremental runs.
/*
 * This procedure considers mainly incremental searches, and settings
 * parameters for that. The real work is handled by modelCheck.
 */

void
MC_incRuns (const System sys)
{
  /*
   * incremental runs check
   *
   * note: we assume that at least one run needs to be checked.
   */
  int maxruns = sys->maxruns;
  int runs = 1;
  int flag = 1;
  int res;

  do
    {
      systemReset (sys);
      sys->maxruns = runs;
      systemRuns (sys);
      fprintf (stderr, "%i of %i runs in incremental runs search.\n",
	       runs, maxruns);
      res = modelCheck (sys);
      fprintf (stderr, "\n");
      if (res)
	{
	  /* Apparently a violation occurred. If we are searching
	   * the whole space, then we just continue.  However, if
	   * we're looking to prune, ``the buck stops here''. */

	  if (sys->prune != 0)
	    {
	      flag = 0;
	    }
	}
      runs++;
    }
  while (flag && runs <= maxruns);
  sys->maxruns = maxruns;
}

//! Analyse the model by incremental trace lengths.
/*
 * This procedure considers mainly incremental searches, and settings
 * parameters for that. The real work is handled by modelCheck.
 */

void
MC_incTraces (const System sys)
{
  /*
   * incremental traces check
   *
   * note: we assume that at least one run needs to be checked.
   */
  int maxtracelen;
  int tracelen;
  int tracestep;
  int flag;
  int res;

  tracestep = 3;		/* what is a sensible stepping size? */
  flag = 1;

  maxtracelen = getMaxTraceLength (sys);
  tracelen = maxtracelen - tracestep;
  while (tracelen > 6)		/* what is a reasonable minimum? */
    tracelen -= tracestep;

  flag = 1;

  do
    {
      systemReset (sys);
      sys->maxtracelength = tracelen;
      systemRuns (sys);
      fprintf (stderr,
	       "%i of %i trace length in incremental trace length search.\n",
	       tracelen, maxtracelen);
      res = modelCheck (sys);
      fprintf (stderr, "\n");
      if (res)
	{
	  /* Apparently a violation occurred. If we are searching
	   * the whole space, then we just continue.  However, if
	   * we're looking to prune, ``the buck stops here''. */

	  if (sys->prune != 0)
	    {
	      flag = 0;
	    }
	}
      tracelen += tracestep;
    }
  while (flag && tracelen <= maxtracelen);
}

//! Analyse the model with a fixed scenario.
/**
 * Traditional handywork.
 */

void
MC_single (const System sys)
{
  /*
   * simple one-time check
   */

  systemReset (sys);		// reset any globals
  systemRuns (sys);		// init runs data
  modelCheck (sys);
}

//! Model check the system, given all parameters.
/*
 * Precondition: the system was reset with the corresponding parameters.
 * Reports time and states traversed.
 * Note that the return values doubles as the number of failed claims.
 *@return True iff any claim failed, and thus an attack was found.
 */

int
modelCheck (const System sys)
{
  if (sys->output == STATESPACE)
    {
      graphInit (sys);
    }

  /* modelcheck the system */
  switch (sys->engine)
    {
    case POR_ENGINE:
      traverse (sys);
      break;
    case ARACHNE_ENGINE:
      arachne ();
      break;
    default:
      error ("Unknown engine type %i.", sys->engine);
    }

  /* clean up any states display */
  if (sys->switchS > 0)
    {
      //                States: 1.000e+06
      fprintf (stderr, "                  \r");
    }

  timersPrint (sys);
  if (sys->output == STATESPACE)
    {
      graphDone (sys);
    }
  if (sys->switchScenario > 0)
    {
      /* Traversing a scenario. Maybe we ran out. */
      if (sys->switchScenario > sys->countScenario)
	{
	  /* Signal as error */
	  exit (1);
	}
    }
  return (sys->failed != STATES0);
}
