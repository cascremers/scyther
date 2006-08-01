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
 * \section coding Coding conventions
 *
 * Usually, each source file except main.c has an myfileInit() and myfileDone() function
 * available. These allow any initialisation and destruction of required structures.
 *
 * GNU indent rules are used, but K&R derivatives are allowed as well. Conversion can
 * be done for any style using the GNU indent program.
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include "system.h"
#include "debug.h"
#include "symbol.h"
#include "pheading.h"
#include "symbol.h"
#include "parser.h"
#include "tac.h"
#include "timer.h"
#include "compiler.h"
#include "binding.h"
#include "switches.h"
#include "specialterm.h"
#include "color.h"
#include "error.h"
#include "claim.h"

//! The global system state pointer
System sys;

//! Pointer to the tac node container
extern struct tacnode *spdltac;
//! Match mode
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

  /* process any command-line switches */
  switchesInit (argc, argv);

  /* process colors */
  colorInit ();

  /* start system */
  sys = systemInit ();

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

  // Compile no runs for Arachne
  compile (spdltac, 0);
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

#ifdef DEBUG
  if (DEBUGL (4))
    {
      warning ("Selected output method is %i", switches.output);
    }
#endif

  arachneInit (sys);

  /*
   * ---------------------------------------
   *  Start real stuff
   * ---------------------------------------
   */

  /* xml init */
  if (switches.xml)
    xmlOutInit ();

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

  /* Exitcodes are *not* correct anymore */

  exitcode = EXIT_ATTACK;

  /* xml closeup */
  if (switches.xml)
    xmlOutDone ();

  /*
   * Now we clean up any memory that was allocated.
   */

  arachneDone ();
  knowledgeDestroy (sys->know);
  systemDone (sys);
  colorDone ();
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

exit:
  return exitcode;
}

//! Print something bad
void
printBad (char *s)
{
  eprintf ("%s%s%s", COLOR_Red, s, COLOR_Reset);
}

//! Print something good
void
printGood (char *s)
{
  eprintf ("%s%s%s", COLOR_Green, s, COLOR_Reset);
}

//! Print state (existState, isAttack)
/**
 * Fail == ( existState xor isAttack )
 */
void
printOkFail (int existState, int isAttack)
{
  if (existState != isAttack)
    {
      printGood ("Ok");
    }
  else
    {
      printBad ("Fail");
    }
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

  //**********************************************************************

  /* Print also individual claims */
  /* Note that if the output is set to empty, the claim output is redirected to stdout (for e.g. processing)
   */
  cl_scan = sys->claimlist;
  anyclaims = false;
  while (cl_scan != NULL)
    {
      if (claimStatusReport (sys, cl_scan))
	{
	  anyclaims = true;
	}
      cl_scan = cl_scan->next;
    }
  if (!anyclaims)
    {
      warning ("No claims in system.");
    }
}

//! Analyse the model
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
  /* modelcheck the system */
  arachne ();

  /* clean up any states display */
  if (switches.reportStates > 0)
    {
      //                States: 1.000e+06
      fprintf (stderr, "                  \r");
    }

  timersPrint (sys);
  return (sys->failed != STATES0);
}
