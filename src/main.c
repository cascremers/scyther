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
 * 1  Error	Something went wrong (error)
 * 2  Okay	No attack found (because) no claims encountered
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
#include "runs.h"
#include "debug.h"
#include "modelchecker.h"
#include "memory.h"
#include "symbols.h"
#include "pheading.h"
#include "symbols.h"
#include "parser.h"
#include "tac.h"
#include "compiler.h"
#include "latex.h"
#include "output.h"

#include "argtable2.h"

extern struct tacnode *spdltac;
void scanner_cleanup (void);
void strings_cleanup (void);
int yyparse (void);

void MC_incRuns (const System sys);
void MC_incTraces (const System sys);
void MC_single (const System sys);
int modelCheck (const System sys);

//! The name of this program.
const char *progname = "scyther";
//! Release tag name.
/**
 * Note that this is only referenced in the help output of the commandline program.
 * \todo Come up with a useful solution for release names.
 */
const char *releasetag = "alpha2-devel";

//! The main body, as called by the environment.
int
main (int argc, char **argv)
{
  System sys;

  struct arg_file *infile  = arg_file0(NULL,NULL,"FILE",    "input file ('-' for stdin)");
  struct arg_file *outfile = arg_file0("o","output","FILE", "output file (default is stdout)");
  struct arg_int *traversal = arg_int0 ("t", "traverse", NULL,
					"set traversal method, partial order reduction (default is 8)");
  struct arg_int *match =
    arg_int0 ("m", "match", NULL, "matching method (default is 0)");
  struct arg_lit *clp =
    arg_lit0 ("c", "cl", "use constraint logic, non-associative.");
  struct arg_int *prune = arg_int0 ("p", "prune", NULL,
				    "pruning method (default is 2)");
  struct arg_int *maxlength = arg_int0 ("l", "max-length", NULL,
					"prune traces longer than <int> events.");
  struct arg_lit *incTraces = arg_lit0 (NULL, "increment-traces",
					"incremental search using the length of the traces.");
  struct arg_int *maxruns =
    arg_int0 ("r", "max-runs", NULL, "create at most <int> runs.");
  struct arg_lit *incRuns = arg_lit0 (NULL, "increment-runs",
				      "incremental search using the number of runs.");
  struct arg_lit *latex = arg_lit0 (NULL, "latex", "output in LaTeX format.");
  struct arg_lit *noreport =
    arg_lit0 ("d", "disable-report", "don't report violations.");
  struct arg_lit *switchS = arg_lit0 (NULL, "no-progress", "suppress progress bar.");
  struct arg_lit *switchSS = arg_lit0 (NULL, "state-space", "output state space graph.");
  struct arg_lit *switchFC = arg_lit0 (NULL, "force-choose", "force only explicit choose events.");
  struct arg_lit *switchRS = arg_lit0 (NULL, "read-symm", "enable read symmetry reductions.");
  struct arg_lit *switchAS = arg_lit0 (NULL, "no-agent-symm", "disable agent symmetry reductions.");
  struct arg_lit *switchSO = arg_lit0 (NULL, "symm-order", "enable ordering symmetry reductions.");
#ifdef DEBUG
  struct arg_int *porparam = arg_int0 (NULL, "pp", NULL, "POR parameter.");
  struct arg_lit *switchI = arg_lit0 ("I", "debug-indent",
				      "indent the debug output using trace length.");
  struct arg_int *debugl =
    arg_int0 ("D", "debug", NULL, "set debug level (default is 0)");
#endif
  struct arg_lit *help = arg_lit0 (NULL, "help", "print this help and exit");
  struct arg_lit *version =
    arg_lit0 (NULL, "version", "print version information and exit");
  struct arg_end *end = arg_end (30);
  void *argtable[] = {
    infile, 
    outfile,
    traversal, 
    match, 
    clp,
    prune, 
    maxlength, incTraces,
    maxruns, incRuns,
    latex,
    noreport,
    switchS, 
    switchSS,
    switchFC,
    switchRS,
    switchAS,
    switchSO,
#ifdef DEBUG
    porparam,
    switchI,
    debugl,
#endif
    help, version,
    end
  };
  int nerrors;
  int exitcode = 0;

  /* verify the argtable[] entries were allocated sucessfully */
  if (arg_nullcheck (argtable) != 0)
    {
      /* NULL entries were detected, some allocations must have failed */
      fprintf (stderr, "%s: insufficient memory\n", progname);
      exitcode = 1;
      goto exit;
    }

  /* defaults
   * set any command line default values prior to parsing */
#ifdef DEBUG
  debugl->ival[0] = 0;
  porparam->ival[0] = 0;
#endif
  traversal->ival[0] = 8;
  match->ival[0] = 0;
  maxlength->ival[0] = -1;
  maxruns->ival[0] = INT_MAX;
  prune->ival[0] = 2;

  /* Parse the command line as defined by argtable[] */
  nerrors = arg_parse (argc, argv, argtable);

  /* special case: '--help' takes precedence over error reporting */
  if (help->count > 0)
    {
      printf ("Usage: %s ", progname);
      arg_print_syntax (stdout, argtable, "\n");
      printf
	("This program can model check security protocols for various\n");
      printf ("properties, given a finite scenario.\n\n");
      arg_print_glossary (stdout, argtable, "  %-25s %s\n");
      exitcode = 0;
      goto exit;
    }

  /* special case: '--version' takes precedence error reporting */
  if (version->count > 0)
    {
      printf ("'%s' model checker for security protocols.\n", progname);
      printf ("%s release.\n", releasetag);
      printf ("$Rev$ $Date$\n");
#ifdef DEBUG
      printf ("Compiled with debugging support.\n");
#endif
      printf ("December 2003--, Cas Cremers\n");
      exitcode = 0;
      goto exit;
    }

  /* If the parser returned any errors then display them and exit */
  if (nerrors > 0)
    {
      /* Display the error details contained in the arg_end struct. */
      arg_print_errors (stdout, end, progname);
      printf ("Try '%s --help' for more information.\n", progname);
      exitcode = 1;
      goto exit;
    }

  /* special case: uname with no command line options induces brief help */
  if (argc==1)
   {
     printf("Try '%s --help' for more information.\n",progname);
     exitcode=0;
     goto exit;
   }

  /*
   * Arguments have been parsed by argtable,
   * continue with main code.
   */

  /* Lutger-tries-to-test-with-broken-methods detector */
  if (clp->count > 0)
    {
      fprintf (stderr, "For the time being, this method is not supported, \n");
      fprintf (stderr, "as too many changes have been made to the normal \n");
      fprintf (stderr, "matching logic, and CL simply isn't reliable in \nmany ");
      fprintf (stderr, "ways. Try again in a few weeks.\n");
      exit(0);
    }

  /* redirect in- and output according to supplied filenames */
  /* output */
  if (outfile->count > 0)
    {
      /* try to open */
      if (!freopen (outfile->filename[0], "w", stdout))
        {
          fprintf(stderr, "Could not create output file '%s'.\n", outfile->filename[0]);
          exit(1);
        }
    }
  /* input */
  if (infile->count > 0)
    {
      /* check for the single dash */
      if (strcmp(infile->filename[0],"-"))
	{
          if (!freopen (infile->filename[0], "r", stdin))
	    {
	      fprintf(stderr, "Could not open input file '%s'.\n", infile->filename[0]);
	      exit(1);
	    }
	}
    }

  /* handle debug level */
#ifdef DEBUG
  debugSet (debugl->ival[0]);
  if (DEBUGL (1))
    {
      /* print command line */
      int i;
      printf ("$");
      for (i = 0; i < argc; i++)
	printf (" %s", argv[i]);
      printf ("\n");
    }
#else
  debugSet (0);
#endif
  /* Initialize memory routines */
  memInit ();

  /* initialize symbols */
  termsInit ();
  termmapsInit ();
  termlistsInit ();
  knowledgeInit ();
  symbolsInit ();
  tacInit ();

  /* generate system */
  sys = systemInit ();
  if (switchFC->count > 0)
      /* force explicit chooses */
      sys->switchForceChoose = 1;
  if (switchRS->count > 0)
    {
      if (switchSO->count > 0)
	  error ("--read-symm and --symm-order cannot be used at the same time.");
      sys->switchReadSymm = 1;
    }
  if (switchSO->count > 0)
      /* enable symmetry order */
      sys->switchSymmOrder = 1;
  if (switchAS->count > 0)
      /* disable agent symmetry order */
      sys->switchAgentSymm = 0;

#ifdef DEBUG
  sys->porparam = porparam->ival[0];
#endif
  sys->latex = latex->count;
  sys->know = emptyKnowledge ();

  /* parse input */

  yyparse ();
#ifdef DEBUG
  if (DEBUGL (1))
    tacPrint (spdltac);
#endif

  /* compile */

  compile (sys, spdltac, maxruns->ival[0]);
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

  sys->clp = (clp->count > 0 ? 1 : 0);

  sys->traverse = traversal->ival[0];
  sys->match = match->ival[0];
  sys->prune = prune->ival[0];
  if (switchS->count > 0)
      /* disable progress display */
      sys->switchS = 0;
  else
      /* enable progress display */
      sys->switchS = 50000;
  if (switchSS->count > 0)
    {
      /* enable state space graph output */
      sys->switchStatespace = 1;
    }

  /* TODO for now, warning for -m2 and non-clp */
  if (sys->match == 2 && !sys->clp)
    {
      printf
	("Warning: -m2 is only supported for constraint logic programming.\n");
    }
#ifdef DEBUG
  /* in debugging mode, some extra switches */
  if (switchI->count > 0)
    indentActivate ();
  if (DEBUGL (1))
    printf ("Using traversal method %i.\n", sys->traverse);
#else
  /* non-debug defaults */
  sys->switchM = 0;
#endif
  if (noreport->count > 0)
    sys->report = 0;
  if (maxlength->ival[0] >= 0)
    sys->switch_maxtracelength = maxlength->ival[0];

  /* latex header? */
  if (sys->latex)
    latexInit (sys, argc, argv);

  /* model check system */
#ifdef DEBUG
  if (DEBUGL (1))
    printf ("Start modelchecking system.\n");
#endif
  if (incRuns->count > 0)
    {
      MC_incRuns (sys);
    }
  else
    {
      if (incTraces->count > 0)
	{
	  MC_incTraces (sys);
	}
      else
	{
	  MC_single (sys);
	}
    }
  
  /* Display shortest attack, if any */

  if (sys->attack != NULL && sys->attack->length != 0)
    {
      attackDisplay(sys);
      /* mark exit code */
      exitcode = 3;
    }
  else
    {
      /* check for no claims */
      if (sys->failed == 0)
	{
          /* mark exit code */
	  exitcode = 2;
	}
    }

  /* latex closeup */
  if (sys->latex)
    latexDone (sys);

  /*
   * Now we clean up any memory that was allocated.
   */

  knowledgeDestroy (sys->know);
  systemDone (sys);

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
  arg_free (argtable);

  return exitcode;
}

//! Display time and state space size information using ASCII.
/**
 * Displays also whether an attack was found or not.
 */

void
timersPrint (const System sys)
{
// #define NOTIMERS

  /* display stats, header first */
#ifdef NOTIMERS
  fprintf (stderr, "States\t\tAttack\n");
#else
  fprintf (stderr, "Time\t\tStates\t\tAttack\t\tst/sec\n");

  /* print time */

  double seconds;
  seconds = (double) clock () / CLOCKS_PER_SEC;
  fprintf (stderr, "%.3e\t", seconds);
#endif

  /* states traversed */

  statesPrintShort (sys);
  fprintf (stderr, "\t");

  /* flag
   *
   * L n          Attack of length <n>
   * None         failed claim
   * NoClaim      no claims
   */

  if (sys->claims == 0)
    {
      fprintf (stderr, "NoClaim\t\t");
    }
  else
    {
      if (sys->failed > 0)
	fprintf (stderr, "L:%i\t\t", attackLength(sys->attack));
      else
	fprintf (stderr, "None\t\t");
    }

#ifdef NOTIMERS
  fprintf (stderr, "\n");
#else
  /* states per second */

  if (seconds > 0)
    {
      fprintf (stderr, "%.3e\t",
	      (double) (sys->statesLow +
			(sys->statesHigh * ULONG_MAX)) / seconds);
    }
  else
    {
      fprintf (stderr, "<inf>\t\t");
    }

  fprintf (stderr, "\n");
#endif
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
      fprintf (stderr, "%i of %i runs in incremental runs search.\n", runs, maxruns);
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
      fprintf (stderr, "%i of %i trace length in incremental trace length search.\n",
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
  if (sys->switchStatespace)
    {
      graphInit (sys);
    }
  traverse (sys);		// start model checking
  timersPrint (sys);
  if (sys->switchStatespace)
    {
      graphDone (sys);
    }
  return (sys->failed);
}


