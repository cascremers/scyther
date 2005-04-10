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

extern System sys;

extern struct tacnode *spdltac;
extern Term TERM_Claim;
extern int mgu_match;

const char *progname = "scyther";
const char *releasetag = SVNVERSION;

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
switcher (const int process, const System sys, int index)
{
  char *this_arg;		// just a shortcut
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
    if (strlen (this_arg) < 2 || this_arg[0] != '-')
      {
	// No option
	return 0;
      }
    // Compare
    if (this_arg[1] == '-')
      {
	int optlength;

	// Long variant
	optlength = strlen (longopt);
	if (strncmp (this_arg + 2, longopt, optlength))
	  return 0;
	if ((optlength + 2 < strlen (this_arg)) &&
	    this_arg[2 + optlength] == '=')
	  {
	    // This has an additional thing!
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
	// Short variant
	if (strlen (this_arg) < 2 || this_arg[1] != shortopt)
	  return 0;
	if (strlen (this_arg) > 2)
	  {
	    // This has an additional thing!
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
      argc = sys->argc;
      argv = sys->argv;
#ifdef DEBUG
      // Check range for debug; we trust the non-debug version :)
      if (index < 1 || index >= argc)
	{
	  error ("Bad index number %i for argc %i", index, argc);
	}
#endif
      this_arg = argv[index];
    }
  else
    {
      // Just doing help
      this_arg = NULL;
    }

  /*
   * -------------------------------------------------------------
   *    Process the options, one by one
   * -------------------------------------------------------------
   */

  if (detect ('o', "output", 1))
    {
      if (!process)
	{
	  helptext ("-o,--output=<int>", "output file [stdout]");
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

  if (detect ('T', "timer", 1))
    {
      if (!process)
	{
	  helptext ("-T,--timer=<int>",
		    "maximum time in seconds");
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
		    "Maximum number of runs in the system");
	}
      else
	{
	  sys->switchRuns = integer_argument ();
	  return index;
	}
    }

  if (detect ('E', "echo", 0))
    {
      if (!process)
	{
	  helptext ("-E,--echo", "echo command line to stdout");
	}
      else
	{
	  /* print command line */
	  fprintf (stdout, "command\t");
	  commandlinePrint (stdout, sys);
	  fprintf (stdout, "\n");
	  return index;
	}
    }

  if (detect (' ', "summary", 0))
    {
      if (!process)
	{
	  helptext ("--summary", "show summary on stdout");
	}
      else
	{
	  sys->output = SUMMARY;
	  return index;
	}
    }

  if (detect (' ', "state-space", 0))
    {
      if (!process)
	{
	  helptext ("--state-space", "output state space graph (modelchecker)");
	}
      else
	{
	  sys->output = STATESPACE;
	  return index;
	}
    }

  if (detect ('b', "progress-bar", 0))
    {
      if (!process)
	{
	  helptext ("-b,--progress-bar", "show progress bar");
	}
      else
	{
	  sys->switchS = 50000;
	  return index;
	}
    }

  if (detect ('e', "empty", 0))
    {
      if (!process)
	{
	  helptext ("-e,--empty", "do not generate output");
	}
      else
	{
	  sys->output = EMPTY;
	  return index;
	}
    }

  if (detect ('L', "latex", 0))
    {
      if (!process)
	{
	  helptext ("-L,--latex", "output attacks in LaTeX format");
	}
      else
	{
	  sys->latex = 1;
	  return index;
	}
    }

  if (detect ('G', "goal-select", 1))
    {
      if (!process)
	{
	  helptext ("-G,--goal-select=<int>", "use goal selection method <int> (default is 3)");
	}
      else
	{
	  sys->switchGoalSelectMethod = integer_argument ();
	  return index;
	}
    }

  if (detect ('l', "max-length", 1))
    {
      if (!process)
	{
	  helptext ("-l,--max-length=<int>", "prune traces longer than <int> events.");
	}
      else
	{
	  sys->switch_maxtracelength = integer_argument ();
	  return index;
	}
    }

  if (detect ('p', "prune", 1))
    {
      if (!process)
	{
	  helptext ("-p,--prune", "pruning method");
	}
      else
	{
	  sys->prune = integer_argument ();
	  return index;
	}
    }

  if (detect ('m', "match", 1))
    {
      if (!process)
	{
	  helptext ("-m,--match", "matching method");
	}
      else
	{
	  sys->match = integer_argument ();
	  return index;
	}
    }

  if (detect ('P', "proof", 0))
    {
      if (!process)
	{
	  helptext ("-P,--proof", "construct explicit proof");
	}
      else
	{
	  // Proof
	  sys->output = PROOF;
	  return index;
	}
    }

  if (detect ('a', "arachne", 0))
    {
      if (!process)
	{
	  helptext ("-a,--arachne", "select Arachne engine");
	}
      else
	{
	  // Select arachne engine
	  sys->engine = ARACHNE_ENGINE;
	  bindingInit (sys);
	  return index;
	}
    }

  if (detect ('v', "version", 0))
    {
      if (!process)
	helptext ("-v,--version", "version information");
      else
	{
	  printf ("'%s' model checker for security protocols.\n", progname);
#ifdef DEBUG
	  printf ("Revision %s, compiled with debugging support.\n",
		  SVNVERSION);
#else
	  printf ("Revision %s\n", SVNVERSION);
#endif
	  printf ("December 2003--, Cas Cremers\n");
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
	  switcher (0, NULL, 0);
	  exit (0);
	}
    }

#ifdef DEBUG
  if (detect ('D', "debug", 1))
    {
      if (!process)
	{
	  helptext ("-D,--debug=<int>", "set debug (verbosity) level.");
	}
      else
	{
	  debugSet (integer_argument ());
	  return index;
	}
    }
#endif

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
	      fprintf (stderr, "Could not open input file '%s'.\n", this_arg);
	      exit (1);
	    }
	  return index + 1;
	}
    }
  return 0;
}

//! Process switches
void
process_switches (const System sys)
{
  int index;

  if (sys->argc == 1)
    {
      printf ("Try '%s --help' for more information.\n", progname);
      exit (0);
    }

  index = 1;
  while (index < sys->argc && index > 0)
    {
      index = switcher (1, sys, index);
    }
}
