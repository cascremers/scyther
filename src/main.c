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
#include "compiler.h"
#include "latex.h"
#include "output.h"
#include "binding.h"

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

//! The name of this program.
const char *progname = "scyther";
//! Release tag name.
/**
 * Note that this is only referenced in the help output of the commandline program.
 * \todo Come up with a useful solution for release names.
 */
#ifdef SVNCHANGED
const char *releasetag = SVNVERSION " [modified]";
#else
const char *releasetag = SVNVERSION;
#endif

//! The main body, as called by the environment.
int
main (int argc, char **argv)
{
  struct arg_file *infile =
    arg_file0 (NULL, NULL, "FILE", "input file ('-' for stdin)");
  struct arg_file *outfile = arg_file0 ("o", "output", "FILE",
					"output file (default is stdout)");
  struct arg_lit *switch_arachne =
    arg_lit0 ("a", "arachne", "use Arachne engine");
  struct arg_lit *switch_proof =
    arg_lit0 ("P", "proof", "generate proof output");
  struct arg_str *switch_check = arg_str0 (NULL, "check", "CLAIM",
					   "claim type to check (default is all)");
  struct arg_int *switch_scenario = arg_int0 ("s", "scenario", NULL,
					      "select a scenario instance 1-n (-1 to count)");
  struct arg_int *switch_scenario_size = arg_int0 ("S", "scenario-size", NULL,
						   "scenario size (fixed trace prefix length)");
  struct arg_int *switch_traversal_method = arg_int0 ("t", "traverse", NULL,
						      "set traversal method, partial order reduction (default is 12)");
  struct arg_int *switch_match_method =
    arg_int0 ("m", "match", NULL, "matching method (default is 0)");
  struct arg_lit *switch_clp =
    arg_lit0 ("c", "cl", "use constraint logic, non-associative");
  struct arg_int *switch_pruning_method = arg_int0 ("p", "prune", NULL,
						    "pruning method (default is 2)");
  struct arg_int *switch_prune_trace_length =
    arg_int0 ("l", "max-length", NULL,
	      "prune traces longer than <int> events.");
  struct arg_int *switch_prune_proof_depth =
    arg_int0 ("d", "max-depth", NULL,
	      "prune proof deeper than <int> splits.");
  struct arg_lit *switch_incremental_trace_length =
    arg_lit0 (NULL, "increment-traces",
	      "incremental search using the length of the traces.");
  struct arg_int *switch_maximum_runs =
    arg_int0 ("r", "max-runs", NULL, "create at most <int> runs");
  struct arg_lit *switch_incremental_runs = arg_lit0 (NULL, "increment-runs",
						      "incremental search using the number of runs");
  struct arg_int *switch_goal_select_method =
    arg_int0 (NULL, "goal-select", NULL, "use goal selection method <int> (default 3)");
  struct arg_lit *switch_latex_output =
    arg_lit0 (NULL, "latex", "output attacks in LaTeX format");
  struct arg_lit *switch_empty =
    arg_lit0 ("e", "empty", "do not generate output");
  struct arg_lit *switch_progress_bar =
    arg_lit0 ("b", "progress-bar", "show progress bar");
  struct arg_lit *switch_state_space_graph =
    arg_lit0 (NULL, "state-space", "output state space graph");
  struct arg_lit *switch_implicit_choose = arg_lit0 (NULL, "implicit-choose",
						     "allow implicit choose events (useful for few runs)");
  struct arg_lit *switch_choose_first =
    arg_lit0 (NULL, "choose-first", "priority to any choose events");
  struct arg_lit *switch_enable_read_symmetries =
    arg_lit0 (NULL, "read-symm", "enable read symmetry reductions");
  struct arg_lit *switch_disable_agent_symmetries =
    arg_lit0 (NULL, "no-agent-symm",
	      "disable agent symmetry reductions");
  struct arg_lit *switch_enable_symmetry_order = arg_lit0 (NULL, "symm-order",
							   "enable ordering symmetry reductions");
  struct arg_lit *switch_disable_noclaims_reductions =
    arg_lit0 (NULL, "no-noclaims-red",
	      "disable no more claims reductions");
  struct arg_lit *switch_disable_endgame_reductions =
    arg_lit0 (NULL, "no-endgame-red", "disable endgame reductions");
  struct arg_lit *switch_disable_claim_symmetry =
    arg_lit0 (NULL, "no-claimsymmetry-red",
	      "disable claim symmetry reductions");
  struct arg_lit *switch_summary = arg_lit0 (NULL, "summary",
					     "show summary on stdout instead of stderr");
  struct arg_lit *switch_echo =
    arg_lit0 ("E", "echo", "echo command line to stdout");
#ifdef DEBUG
  struct arg_int *switch_por_parameter =
    arg_int0 (NULL, "pp", NULL, "POR parameter");
  struct arg_lit *switch_debug_indent = arg_lit0 ("I", "debug-indent",
						  "indent the debug output using trace length");
  struct arg_int *switch_debug_level =
    arg_int0 ("D", "debug", NULL, "set debug level (default is 0)");
#endif
  struct arg_lit *help = arg_lit0 (NULL, "help", "print this help and exit");
  struct arg_lit *version =
    arg_lit0 (NULL, "version", "print version information and exit");
  struct arg_end *end = arg_end (30);
  void *argtable[] = {
    infile,
    outfile,
    switch_empty,
    switch_proof,
    switch_state_space_graph,
    switch_scenario,
    switch_scenario_size,
    switch_latex_output,
    switch_summary,
    switch_echo,
    switch_progress_bar,

    switch_arachne,
    switch_check,
    switch_traversal_method,
    switch_match_method,
    switch_clp,
    switch_pruning_method,
    switch_prune_proof_depth,
    switch_prune_trace_length, switch_incremental_trace_length,
    switch_maximum_runs, switch_incremental_runs,
    switch_goal_select_method,

    switch_implicit_choose,
    switch_choose_first,
    switch_enable_read_symmetries,
    switch_enable_symmetry_order,
    switch_disable_agent_symmetries,
    switch_disable_noclaims_reductions,
    switch_disable_endgame_reductions,
    switch_disable_claim_symmetry,
#ifdef DEBUG
    switch_por_parameter,
    switch_debug_indent,
    switch_debug_level,
#endif
    help, version,
    end
  };
  int nerrors;
  int exitcode = EXIT_NOATTACK;

  /* verify the argtable[] entries were allocated sucessfully */
  if (arg_nullcheck (argtable) != 0)
    {
      /* NULL entries were detected, some allocations must have failed */
      fprintf (stderr, "%s: insufficient memory\n", progname);
      exitcode = EXIT_ERROR;
      goto exit;
    }

  /* defaults
   * set any command line default values prior to parsing */
#ifdef DEBUG
  switch_debug_level->ival[0] = 0;
  switch_por_parameter->ival[0] = 0;
#endif
  switch_scenario->ival[0] = 0;
  switch_scenario_size->ival[0] = 0;
  switch_traversal_method->ival[0] = 12;
  switch_match_method->ival[0] = 0;
  switch_prune_trace_length->ival[0] = -1;
  switch_prune_proof_depth->ival[0] = -1;
  switch_maximum_runs->ival[0] = INT_MAX;
  switch_pruning_method->ival[0] = 2;
  switch_goal_select_method->ival[0] = -1;

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
#ifdef DEBUG
      printf ("%s, compiled with debugging support.\n", releasetag);
#else
      printf ("%s\n", releasetag);
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
      exitcode = EXIT_ERROR;
      goto exit;
    }

  /* special case: uname with no command line options induces brief help */
  if (argc == 1)
    {
      printf ("Try '%s --help' for more information.\n", progname);
      exitcode = 0;
      goto exit;
    }

  /*
   * Arguments have been parsed by argtable,
   * continue with main code.
   */

  /* Lutger-tries-to-test-with-broken-methods detector */
  if (switch_clp->count > 0)
    {
      fprintf (stderr,
	       "For the time being, this method is not supported, \n");
      fprintf (stderr, "as too many changes have been made to the normal \n");
      fprintf (stderr,
	       "matching logic, and CL simply isn't reliable in \nmany ");
      fprintf (stderr, "ways. Try again in a few weeks.\n");
      exit (0);
    }

  /* redirect in- and output according to supplied filenames */
  /* output */
  if (outfile->count > 0)
    {
      /* try to open */
      if (!freopen (outfile->filename[0], "w", stdout))
	{
	  fprintf (stderr, "Could not create output file '%s'.\n",
		   outfile->filename[0]);
	  exit (1);
	}
    }
  /* input */
  if (infile->count > 0)
    {
      /* check for the single dash */
      if (strcmp (infile->filename[0], "-"))
	{
	  if (!freopen (infile->filename[0], "r", stdin))
	    {
	      fprintf (stderr, "Could not open input file '%s'.\n",
		       infile->filename[0]);
	      exit (1);
	    }
	}
    }

  /* handle debug level */
#ifdef DEBUG
  debugSet (switch_debug_level->ival[0]);
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

  /*
   * ------------------------------------------------
   *     generate system 
   * ------------------------------------------------
   */

  sys = systemInit ();
  if (switch_arachne->count > 0)
    {
      sys->engine = ARACHNE_ENGINE;
      bindingInit (sys);
    }
  /* init compiler for this system */
  compilerInit (sys);

  /* transfer command line */
  sys->argc = argc;
  sys->argv = argv;

  if (switch_echo->count > 0)
    {
      /* print command line */
      fprintf (stdout, "command\t");
      commandlinePrint (stdout, sys);
      fprintf (stdout, "\n");
    }

  /* handle switches */

  sys->switchRuns = switch_maximum_runs->ival[0];	/* maximum number of runs */
  if (switch_implicit_choose->count > 0)
    /* allow implicit chooses */
    sys->switchForceChoose = 0;
  if (switch_choose_first->count > 0)
    sys->switchChooseFirst = 1;	/* priority to chooses */
  if (switch_enable_read_symmetries->count > 0)
    {
      if (switch_enable_symmetry_order->count > 0)
	error
	  ("--read-symm and --symm-order cannot be used at the same time.");
      sys->switchReadSymm = 1;
    }
  if (switch_enable_symmetry_order->count > 0)
    sys->switchSymmOrder = 1;	/* enable symmetry order */
  if (switch_disable_agent_symmetries->count > 0)
    sys->switchAgentSymm = 0;	/* disable agent symmetry order */
  if (switch_disable_noclaims_reductions->count > 0)
    sys->switchNomoreClaims = 0;	/* disable no more claims cutter */
  if (switch_disable_endgame_reductions->count > 0)
    sys->switchReduceEndgame = 0;	/* disable endgame cutter */
  if (switch_disable_claim_symmetry->count > 0)
    sys->switchReduceClaims = 0;	/* disable claim symmetry cutter */
  if (switch_summary->count > 0)
    sys->output = SUMMARY;	/* report summary on stdout */
  if (switch_proof->count > 0)
    sys->output = PROOF;	/* report proof on stdout (for arachne only) */

  /*
   * The scenario selector has an important side effect; when it is non-null,
   * any scenario traversing selects chooses first.
   */
  sys->switchScenario = switch_scenario->ival[0];	/* scenario selector */
  sys->switchScenarioSize = switch_scenario_size->ival[0];	/* scenario size */
  if (sys->switchScenario == 0 && sys->switchScenarioSize > 0)
    {
      /* no scenario, but a size is set. so override */
#ifdef DEBUG
      warning ("Scanning scenarios.");
#endif
      sys->switchScenario = -1;
    }
  if (sys->switchScenario < 0)
    {
      sys->output = SCENARIOS;
    }
  if (sys->switchScenario != 0 && sys->switchScenarioSize == 0)
    {
#ifdef DEBUG
      warning
	("Scenario selection without trace prefix length implies --choose-first.");
#endif
      sys->switchChooseFirst = 1;
    }
#ifdef DEBUG
  sys->porparam = switch_por_parameter->ival[0];
#endif
  sys->latex = switch_latex_output->count;
  sys->know = emptyKnowledge ();


  /* parse compiler-dependant switches */
  if (switch_check->count > 0)
    {
      Term claim;

#ifdef DEBUG
      if (lookup (switch_check->sval[0]) == NULL)
	{
	  globalError++;
	  warning ("Could not find this string at all in:");
	  symbolPrintAll ();
	  eprintf ("\n");
	  globalError--;
	}
#endif
      claim = findGlobalConstant (switch_check->sval[0]);
      if (claim == NULL)
	error ("Unknown claim type to check.");
      if (inTermlist (claim->stype, TERM_Claim))
	sys->switchClaimToCheck = claim;
      else
	error ("Claim type to check is not a claim.");
    }

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
      compile (spdltac, switch_maximum_runs->ival[0]);
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

  sys->clp = (switch_clp->count > 0 ? 1 : 0);

  sys->traverse = switch_traversal_method->ival[0];
  sys->match = switch_match_method->ival[0];
  mgu_match = sys->match;
  sys->prune = switch_pruning_method->ival[0];
  if (switch_progress_bar->count > 0)
    /* enable progress display */
    sys->switchS = 50000;
  else
    /* disable progress display */
    sys->switchS = 0;
  if (switch_state_space_graph->count > 0)
    {
      /* enable state space graph output */
      sys->output = STATESPACE;	//!< New method
    }
  if (switch_empty->count > 0)
    sys->output = EMPTY;
  if (switch_prune_proof_depth->ival[0] >= 0)
    sys->switch_maxproofdepth = switch_prune_proof_depth->ival[0];
  if (switch_prune_trace_length->ival[0] >= 0)
    sys->switch_maxtracelength = switch_prune_trace_length->ival[0];
  if (switch_goal_select_method->ival[0] >= 0)
    sys->switchGoalSelectMethod = switch_goal_select_method->ival[0];
#ifdef DEBUG
  /* in debugging mode, some extra switches */
  if (switch_debug_indent->count > 0)
    indentActivate ();
  if (DEBUGL (1))
    printf ("Using traversal method %i.\n", sys->traverse);
#else
  /* non-debug defaults */
  sys->switchM = 0;
#endif

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
  /* Incremental stuff only works for attack locating */
  if (switch_incremental_runs->count > 0 ||
      switch_incremental_trace_length->count > 0)
    {
      if (sys->output != ATTACK && sys->output != EMPTY)
	{
	  error ("Incremental traversal only for empty or attack output.");
	}
    }
  /* TODO for now, warning for -m2 and non-clp */
  if (sys->match == 2 && !sys->clp)
    {
      warning ("-m2 is only supported for constraint logic programming.");
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
  if (switch_incremental_runs->count > 0)
    {
      MC_incRuns (sys);
    }
  else
    {
      if (switch_incremental_trace_length->count > 0)
	{
	  MC_incTraces (sys);
	}
      else
	{
	  MC_single (sys);
	}
    }

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
		eprintf ("complete proof");
	      else
		eprintf ("bounded proof");
	    }
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
