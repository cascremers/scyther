/**
 *@file switches.c
 * \brief Handle command-line options
 *
 * Contains the main switch handling.
 */

#include "string.h"
#include "system.h"
#include "debug.h"
#include "version.h"
#include "timer.h"
#include "switches.h"
#include "specialterm.h"
#include <limits.h>

struct switchdata switches;

extern struct tacnode *spdltac;

const char *progname = "scyther";
const char *releasetag = SVNVERSION;

// Forward declarations
void process_switches ();

//! Init switches
/**
 * Set them all to the default settings.
 */
void
switchesInit (int argc, char **argv)
{
  // Command-line
  switches.argc = argc;
  switches.argv = argv;

  // Methods
  switches.engine = POR_ENGINE;	// default is partial ordering engine
  switches.match = 0;		// default matching
  switches.clp = 0;
  switches.tupling = 0;

  // Pruning and Bounding
  switches.prune = 2;		// default pruning method
  switches.maxproofdepth = INT_MAX;
  switches.maxtracelength = INT_MAX;
  switches.runs = INT_MAX;
  switches.filterClaim = NULL;	// default check all claims
  switches.maxAttacks = 0;	// no maximum default

  // Modelchecker
  switches.traverse = 12;	// default traversal method
  switches.forceChoose = 1;	// force explicit chooses by default
  switches.chooseFirst = 0;	// no priority to chooses by default
  switches.readSymmetries = 0;	// don't force read symmetries by default
  switches.agentSymmetries = 1;	// default enable agent symmetry
  switches.orderSymmetries = 0;	// don't force symmetry order reduction by default
  switches.pruneNomoreClaims = 1;	// default cutter when there are no more claims
  switches.reduceEndgame = 1;	// default cutter of last events in a trace
  switches.reduceClaims = 1;	// default remove claims from duplicate instance choosers
  // Parallellism
  switches.scenario = 0;
  switches.scenarioSize = 0;

  // Arachne
  switches.arachneSelector = 3;	// default goal selection method
  switches.maxIntruderActions = INT_MAX;	// max number of encrypt/decrypt events
  switches.agentTypecheck = 1;	// default do check agent types

  // Misc
  switches.switchP = 0;		// multi-purpose parameter
  switches.experimental = 0;	// experimental stuff defaults to 0, whatever that means.

  // Output
  switches.output = ATTACK;	// default is to show the attacks
  switches.report = 0;
  switches.reportClaims = 0;	// default don't report on claims
  switches.xml = 0;		// default no xml output
  switches.human = false;	// not human friendly by default
  switches.reportMemory = 0;
  switches.reportTime = 0;
  switches.reportStates = 0;
  switches.extendNonReads = 0;	// default off
  switches.extendTrivial = 0;	// default off

  // Obsolete
  switches.latex = 0;		// latex output?

  process_switches ();
}

//! Exit
void
switchesDone (void)
{
}

//! Process a single switch or generate help text
/**
 * When process is false, we just generate the help text.
 *
 * Yields new index, or -1 when an error occurred.
 * When the new index > argc, it should not be called anymore.
 * By convention, argc = the number of arguments + 1
 * The index steps through 1..argc-1.
 */
int
switcher (const int process, int index)
{
  char *this_arg;		// just a shortcut
  int this_arg_length;		// same here

  int argc;
  char **argv;

  char *arg_pointer;
  int arg_index;

  //! Check whether there are still n options left
  int enough_arguments_left (const int n, char shortopt, char *longopt)
  {
    if (index + n > argc)
      {
	error ("Option %c [%s] needs at least %i arguments.", shortopt,
	       longopt, n);
      }
    return 1;
  }

  // Skip over (processed) argument
  void arg_next (void)
  {
    index++;
    arg_pointer = argv[index];
  }

  //! Parse an argument into an integer
  int integer_argument (void)
  {
    int result;

    if (arg_pointer == NULL)
      {
	error ("(Integer) argument expected.");
      }
    result = 0;
    if (sscanf (arg_pointer, "%i", &result) != 1)
      {
	error ("Could not parse expected integer argument.");
      }
    arg_next ();
    return result;
  }

  //! Detect whether this confirms to this option.
  /**
   * set arg_pointer and index
   */
  int detect (char shortopt, char *longopt, int args)
  {
    arg_pointer = NULL;

    if (!process)
      {
	// If we are not processing, we always yield true.
	return 1;
      }
    // Is it this option anyway?
    if (this_arg_length < 2 || this_arg[0] != '-')
      {
	// No option
	return 0;
      }
    // Compare
    if (this_arg[1] == '-')
      {
	int optlength;

	// This seems to be a long switch, so we handle it accordingly

	optlength = strlen (longopt);
	if (strncmp (this_arg + 2, longopt, optlength))
	  return 0;
	if (optlength + 2 < this_arg_length)
	  {
	    // This has an additional thing!
	    if (args > 0 && this_arg[2 + optlength] == '=')
	      {
		// It's the right thing
		if (optlength + 3 < this_arg_length)
		  {
		    arg_pointer = this_arg + 2 + optlength + 1;
		  }
		else
		  {
		    // arg = next
		    index++;
		    arg_pointer = argv[index];
		  }
	      }
	    else
	      {
		// It's not this option
		return 0;
	      }
	  }
	else
	  {
	    // arg = next
	    index++;
	    arg_pointer = argv[index];
	  }
      }
    else
      {
	// Short variant
	if (this_arg_length < 2 || this_arg[1] != shortopt)
	  return 0;
	if (args > 0 && this_arg_length > 2)
	  {
	    // This has an additional thing!
	    // We assume the argument follows immediately (no appended '=')
	    arg_pointer = this_arg + 2;
	  }
	else
	  {
	    // arg = next
	    index++;
	    arg_pointer = argv[index];
	  }
      }
    // Allright, this is the right option
    // Enough arguments left?
    return enough_arguments_left (args, shortopt, longopt);
  }

  //! Align columns
  void helptext (const char *left, const char *right)
  {
    printf ("  %-25s %s\n", left, right);
  }

  if (process)
    {
      argc = switches.argc;
      argv = switches.argv;
#ifdef DEBUG
      // Check range for debug; we trust the non-debug version :)
      if (index < 1 || index >= argc)
	{
	  error ("Bad index number %i for argc %i", index, argc);
	}
#endif
      this_arg = argv[index];
      this_arg_length = strlen (this_arg);
    }
  else
    {
      // Just doing help
      this_arg = NULL;
      this_arg_length = 0;
    }

  /*
   * -------------------------------------------------------------
   *    Process the options, one by one
   * -------------------------------------------------------------
   */

  /* ==================
   *  Generic options
   */
  if (detect ('a', "arachne", 0))
    {
      if (!process)
	{
	  helptext ("-a,--arachne", "select Arachne engine [modelchecker]");
	}
      else
	{
	  // Select arachne engine
	  switches.engine = ARACHNE_ENGINE;
	  return index;
	}
    }

  if (detect ('x', "xml-output", 0))
    {
      if (!process)
	{
	  helptext ("-x,--xml-output", "show attack output in XML format");
	}
      else
	{
	  switches.xml = 1;
	  return index;
	}
    }

  if (detect ('m', "match", 1))
    {
      if (!process)
	{
	  helptext ("-m,--match=<int>", "matching method [0]");
	}
      else
	{
	  switches.match = integer_argument ();
	  return index;
	}
    }

  if (detect ('T', "timer", 1))
    {
      if (!process)
	{
	  /* Not shown in from help, as we don't want to encourage this
	     helptext ("-T,--timer=<int>", "maximum time in seconds [inf]");
	   */
	}
      else
	{
	  set_time_limit (integer_argument ());
	  return index;
	}
    }

  if (detect ('r', "max-runs", 1))
    {
      if (!process)
	{
	  helptext ("-r,--max-runs=<int>",
		    "maximum number of runs in the system [inf]");
	}
      else
	{
	  switches.runs = integer_argument ();
	  return index;
	}
    }

  if (detect ('l', "max-length", 1))
    {
      if (!process)
	{
	  helptext ("-l,--max-length=<int>",
		    "prune traces longer than <int> events [inf]");
	}
      else
	{
	  switches.maxtracelength = integer_argument ();
	  return index;
	}
    }

  if (detect (' ', "max-attacks", 1))
    {
      if (!process)
	{
	  /* not very important
	     helptext ("--max-attacks=<int>", "when not 0, maximum number of attacks [0]");
	   */
	}
      else
	{
	  switches.maxAttacks = integer_argument ();
	  return index;
	}
    }

  if (detect ('p', "prune", 1))
    {
      if (!process)
	{
	  /* not very important
	     helptext ("-p,--prune=<int>", "pruning method when an attack is found [0]");
	   */
	}
      else
	{
	  switches.prune = integer_argument ();
	  return index;
	}
    }

  if (detect ('H', "human-readable", 0))
    {
      if (!process)
	{
	  helptext ("-H,--human-readable",
		    "try to make the output human-friendly (e.g. in XML)");
	}
      else
	{
	  switches.human = true;
	  return index;
	}
    }

  if (detect (' ', "ra-tupling", 0))
    {
      if (!process)
	{
	  /* for experts only
	     helptext ("--ra-tupling", "compile using right-associative tupling");
	   */
	}
      else
	{
	  switches.tupling = 0;
	  return index;
	}
    }

  if (detect (' ', "la-tupling", 0))
    {
      if (!process)
	{
	  /* for experts only
	     helptext ("--la-tupling", "compile using left-associative tupling");
	   */
	}
      else
	{
	  switches.tupling = 1;
	  return index;
	}
    }

  if (detect (' ', "tupling", 1))
    {
      if (!process)
	{
	  /* for experts only
	     helptext ("--tupling", "tupling type to use");
	   */
	}
      else
	{
	  switches.tupling = integer_argument ();
	  return index;
	}
    }


  /* ==================
   *  Modelchecker only
   */
  if (!process)
    {
      printf ("Switches for modelchecking engine:\n");
    }

  if (detect ('L', "latex", 0))
    {
      if (!process)
	{
	  helptext ("-L,--latex", "output attacks in LaTeX format [ASCII]");
	}
      else
	{
	  switches.latex = 1;
	  return index;
	}
    }

  if (detect (' ', "state-space", 0))
    {
      if (!process)
	{
	  helptext ("--state-space",
		    "output state space graph (in DOT format)");
	}
      else
	{
	  switches.output = STATESPACE;
	  return index;
	}
    }

  /* ==================
   *  Arachne only
   */
  if (!process)
    {
      printf ("Switches for Arachne engine:\n");
      helptext ("(fixed)", "output attacks in DOT format");
    }

  if (detect ('G', "goal-select", 1))
    {
      if (!process)
	{
	  /* discourage: hide
	     helptext ("-G,--goal-select=<int>",
	     "use goal selection method <int> [3]");
	   */
	}
      else
	{
	  switches.arachneSelector = integer_argument ();
	  return index;
	}
    }

  if (detect ('P', "proof", 0))
    {
      if (!process)
	{
	  helptext ("-P,--proof", "show explicit proof");
	}
      else
	{
	  // Proof
	  switches.output = PROOF;
	  return index;
	}
    }

  if (detect (' ', "extend-nonreads", 0))
    {
      if (!process)
	{
	  /* discourage: hide
	   */
	}
      else
	{
	  switches.extendNonReads = 1;
	  return index;
	}
    }

  if (detect (' ', "extend-trivial", 0))
    {
      if (!process)
	{
	  /* discourage: hide
	   */
	}
      else
	{
	  switches.extendTrivial = 1;
	  return index;
	}
    }

  if (detect (' ', "intruder-actions", 1))
    {
      if (!process)
	{
	  /* fairly technical, untested pruning */
	}
      else
	{
	  switches.maxIntruderActions = integer_argument ();
	  return index;
	}
    }

  if (detect (' ', "disable-agenttypecheck", 0))
    {
      if (!process)
	{
	  /* maybe add after testing */
	}
      else
	{
	  switches.agentTypecheck = 0;
	  return index;
	}
    }

#ifdef DEBUG
  /* ==================
   *  Experimental options
   *
   *  Only with debugging version
   */

  if (detect (' ', "experimental", 1))
    {
      if (!process)
	{
	  /* unpredictable behaviour, can change throughout versions */
	}
      else
	{
	  switches.experimental = integer_argument ();
	  return index;
	}
    }
#endif

  /* ==================
   *  External options
   */
  if (!process)
    printf ("Misc. switches:\n");

  if (detect ('E', "echo", 0))
    {
      if (!process)
	{
	  /* not very important
	     helptext ("-E,--echo", "echo command line");
	   */
	}
      else
	{
	  /* print command line */
	  fprintf (stdout, "command\t");
	  commandlinePrint (stdout);
	  fprintf (stdout, "\n");
	  return index;
	}
    }

  if (detect (' ', "summary", 0))
    {
      if (!process)
	{
	  helptext ("--summary", "show summary only: omit attack details");
	}
      else
	{
	  switches.output = SUMMARY;
	  return index;
	}
    }

  if (detect ('b', "progress-bar", 0))
    {
      if (!process)
	{
	  /* discourage: do not show in help text 
	     helptext ("-b,--progress-bar", "show progress bar");
	   */
	}
      else
	{
	  switches.reportStates = 50000;
	  return index;
	}
    }

  if (detect ('e', "empty", 0))
    {
      if (!process)
	{
	  /* not very important
	     helptext ("-e,--empty", "do not generate output");
	   */
	}
      else
	{
	  switches.output = EMPTY;
	  return index;
	}
    }

  if (detect ('v', "version", 0))
    {
      if (!process)
	{
	  /* not very important: hide
	     helptext ("-v,--version", "version information");
	   */
	}
      else
	{
	  printf ("'%s' model checker for security protocols.\n", progname);
#ifdef DEBUG
	  printf ("Revision %s, compiled with debugging support.\n",
		  SVNVERSION);
#else
	  printf ("Revision %s\n", SVNVERSION);
#endif
	  printf ("Code by Cas Cremers\n");
	  exit (0);
	}
    }

  if (detect ('h', "help", 0))
    {
      if (!process)
	{
	  helptext ("-h,--help", "show this help");
	}
      else
	{
	  printf ("Usage:\n");
	  printf ("  %s [switches] [FILE]\nSwitches:\n", progname);
	  switcher (0, 0);
	  exit (0);
	}
    }

#ifdef DEBUG
  if (detect ('D', "debug", 1))
    {
      if (!process)
	{
	  helptext ("-D,--debug=<int>", "set debug (verbosity) level. [0]");
	}
      else
	{
	  debugSet (integer_argument ());
	  return index;
	}
    }
#endif

  if (detect ('o', "output", 1))
    {
      if (!process)
	{
	  helptext ("-o,--output=<FILE>", "output file [stdout]");
	}
      else
	{
	  // Set output file name
	  /* try to open */
	  if (!freopen (arg_pointer, "w", stdout))
	    {
	      fprintf (stderr, "Could not create output file '%s'.\n",
		       arg_pointer);
	      exit (1);
	    }
	  arg_next ();
	  return index;
	}
    }

  // If the option is not recognized, it means a file name.
  if (!process)
    {
      helptext ("FILE", "input file ('-' for stdin)");
    }
  else
    {
      if (!strcmp (this_arg, "-"))
	{
	  // '-' input: Leave input to stdin
	}
      else
	{
	  // not '-' input: change stdin to come from this file
	  if (!freopen (this_arg, "r", stdin))
	    {
	      // The file was not found. We have two options...
	      if (this_arg[0] == '-')
		{
		  fprintf (stderr, "Unknown switch '%s'.\n", this_arg);
		}
	      else
		{
		  fprintf (stderr, "Could not open input file '%s'.\n",
			   this_arg);
		}
	      exit (1);
	    }
	  return index + 1;
	}
    }
  return 0;
}

//! Process switches
void
process_switches ()
{
  int index;

  if (switches.argc == 1)
    {
      printf ("Try '%s --help' for more information, or visit:\n", progname);
      printf (" http://www.win.tue.nl/~ccremers/scyther/index.html\n");
      exit (0);
    }

  index = 1;
  while (index < switches.argc && index > 0)
    {
      index = switcher (1, index);
    }
}
