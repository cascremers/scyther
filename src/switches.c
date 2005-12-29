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
#include "error.h"
#include "string.h"
#include "specialterm.h"
#include "memory.h"
#include <limits.h>
#include <stdlib.h>

struct switchdata switches;

extern struct tacnode *spdltac;

const char *progname = "scyther";
const char *releasetag = SVNVERSION;

// Forward declarations
void process_environment (void);
void process_switches (int commandline);

//! Init switches
/**
 * Set them all to the default settings.
 */
void
switchesInit (int argc, char **argv)
{
  // Methods
  switches.engine = ARACHNE_ENGINE;	// default is arachne engine
  switches.match = 0;		// default matching
  switches.clp = 0;
  switches.tupling = 0;

  // Pruning and Bounding
  switches.prune = 2;		// default pruning method (just output a single one)
  switches.maxproofdepth = INT_MAX;
  switches.maxtracelength = INT_MAX;
  switches.runs = 5;		// default is 5 for usability, but -r 0 or --maxruns=0 will set it back to INT_MAX
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
  switches.concrete = true;	// default removes symbols, and makes traces concrete
  switches.extravert = false;	// default allows also initiator Alice to talk to Alice
  switches.intruder = true;	// default allows an intruder

  // Misc
  switches.switchP = 0;		// multi-purpose parameter
  switches.experimental = 0;	// experimental stuff defaults to 0, whatever that means.
  switches.removeclaims = false;	// default: leave claims from spdl file
  switches.addreachableclaim = false;	// add 'reachable' claims
  switches.addallclaims = false;	// add all sorts of claims

  // Output
  switches.output = SUMMARY;	// default is to show a summary
  switches.report = 0;
  switches.reportClaims = 0;	// default don't report on claims
  switches.xml = 0;		// default no xml output (dot)
  switches.human = false;	// not human friendly by default
  switches.reportMemory = 0;
  switches.reportTime = 0;
  switches.reportStates = 0;
  switches.extendNonReads = 0;	// default off
  switches.extendTrivial = 0;	// default off
  switches.plain = false;	// default colors

  // Obsolete
  switches.latex = 0;		// latex output?

  // Process the environment variable SCYTHERFLAGS
  process_environment ();
  // Process the command-line switches
  switches.argc = argc;
  switches.argv = argv;
  process_switches (true);
}

//! Exit
void
switchesDone (void)
{
}

//! Open a (protocol) file instead of stdin
/**
 * Uses the environment variable SCYTHERDIR to also search for files
 */
int
openFileStdin (char *filename)
{
  const char *separators = ":;\n";
  char *dirs;

  //! try a filename and a prefix.
  int try (char *prefix)
  {
    char *buffer = NULL;
    int result = false;
    int buflen = 0;
    int prefixlen = 0;
    int namelen = 0;
    int addslash = false;
    int nameindex = 0;

    prefixlen = (int) strcspn (prefix, separators);
    namelen = strlen (filename);
    nameindex = prefixlen;

    buflen = prefixlen + namelen + 1;

    // Does the prefix end with a slash? (it should)
    if (nameindex > 0 && prefix[nameindex - 1] != '/')
      {
	addslash = true;
	buflen++;
	nameindex++;
      }

    buffer = (char *) memAlloc (buflen);
    memcpy (buffer, prefix, prefixlen);
    memcpy (buffer + nameindex, filename, namelen);
    buffer[buflen - 1] = '\0';

    // Add the slash in the center
    if (addslash)
      {
	buffer[nameindex - 1] = '/';
      }

    // Now try to open it
    if (freopen (buffer, "r", stdin) != NULL)
      {
	result = true;
      }

    memFree (buffer, buflen);
    return result;
  }

  // main code.

  if (try (""))
    {
      return true;
    }

  // Now try the environment variable
  dirs = getenv ("SCYTHERDIR");
  while (dirs != NULL)
    {
      if (strlen (dirs) > 0)
	{
	  // try this one
	  if (try (dirs))
	    {
	      return true;
	    }
	  // skip to next
	  dirs = strpbrk (dirs, separators);
	  if (dirs != NULL)
	    {
	      // skip over separator
	      dirs++;
	    }
	}
      else
	{
	  break;
	}
    }

  // Nope
  return false;
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
switcher (const int process, int index, int commandline)
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
  if (detect ('A', "arachne", 0))
    {
      if (!process)
	{
	  /*
	   * Obsolete switch, as it is now the default behaviour.
	   */
	}
      else
	{
	  // Select arachne engine
	  switches.engine = ARACHNE_ENGINE;
	  return index;
	}
    }

  if (detect ('M', "modelchecker", 0))
    {
      if (!process)
	{
	  /*
	   * Discourage
	   *
	   helptext ("-M,--modelchecker",
	   "select Model checking engine [Arachne]");
	   */
	}
      else
	{
	  // Select arachne engine
	  switches.engine = POR_ENGINE;
	  return index;
	}
    }

  if (detect ('d', "dot-output", 0))
    {
      if (!process)
	{
	  helptext ("-d,--dot-output", "show attack output in dot format");
	}
      else
	{
	  switches.output = ATTACK;
	  switches.xml = 0;
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
	  switches.output = ATTACK;
	  switches.xml = 1;
	  return index;
	}
    }

  if (detect ('p', "proof", 0))
    {
      if (!process)
	{
	  helptext ("-p,--proof", "show explicit proof");
	}
      else
	{
	  // Proof
	  switches.output = PROOF;
	  return index;
	}
    }

  if (detect ('c', "class", 0))
    {
      if (!process)
	{
	  helptext ("-c,--class",
		    "generate full class (show uninstantiated variables)");
	}
      else
	{
	  switches.concrete = false;
	  return index;
	}
    }

  if (detect (' ', "concrete", 0))
    {
      if (!process)
	{
	  /* this is now the default */
	}
      else
	{
	  switches.concrete = true;
	  return index;
	}
    }

  if (detect (' ', "remove-claims", 0))
    {
      if (!process)
	{
	  /* discourage:
	   *
	   * Causes all existing claims in the specification to be skipped.
	   */
	}
      else
	{
	  switches.removeclaims = true;
	  return index;
	}
    }

  if (detect ('C', "generate-claims", 0))
    {
      if (!process)
	{
	  helptext ("-C,--generate-claims",
		    "ignore any existing claims and automatically generate new claims");
	}
      else
	{
	  switches.removeclaims = true;
	  switches.addallclaims = true;
	  return index;
	}
    }

  if (detect ('G', "generate-semibundles", 0))
    {
      if (!process)
	{
	  helptext ("-G,--generate-statespace",
		    "ignore any existing claims and add 'reachable' claims to generate the full state space");
	}
      else
	{
	  switches.removeclaims = true;	// remove parsed claims
	  switches.addreachableclaim = true;	// add reachability claims
	  switches.prune = 0;	// do not prune anything
	  return index;
	}
    }

  /* ==================
   *  Bounding options
   */
  if (!process)
    {
      printf ("Switches that affect the state space:\n");
    }

  if (detect ('m', "match", 1))
    {
      if (!process)
	{
	  helptext ("-m,--match=<int>",
		    "matching method [0] (0:Typed,1:Basic,2:Typeless)");
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
		    "maximum number of runs in the system [5]. Set to 0 for unbounded search");
	}
      else
	{
	  int arg = integer_argument ();
	  if (arg == 0)
	    {
	      switches.runs = INT_MAX;
	    }
	  else
	    {
	      switches.runs = arg;
	    }
	  return index;
	}
    }

  if (detect ('l', "max-length", 1))
    {
      if (!process)
	{
	  /* not really needed if you prune runs
	     helptext ("-l,--max-length=<int>",
	     "prune traces longer than <int> events [inf]");
	   */
	}
      else
	{
	  switches.maxtracelength = integer_argument ();
	  return index;
	}
    }

  if (detect ('a', "all-attacks", 0))
    {
      if (!process)
	{
	  helptext ("-a,--all-attacks",
		    "generate all attacks instead of just one");
	}
      else
	{
	  switches.prune = 0;
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

  if (detect ('P', "prune", 1))
    {
      if (!process)
	{
	  /* not very important
	     helptext ("-P,--prune=<int>", "pruning method when an attack is found [2]");
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
	  /*
	   * Why?
	   *
	   helptext ("-H,--human-readable",
	   "try to make the output human-friendly (e.g. in XML).");
	   */
	}
      else
	{
	  switches.human = true;
	  switches.concrete = true;
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
  /*
     if (!process)
     {
     printf ("Switches for modelchecking engine:\n");
     }
   */

  if (detect ('L', "latex", 0))
    {
      if (!process)
	{
	  /*
	   * Obsolete
	   *
	   helptext ("-L,--latex", "output attacks in LaTeX format [ASCII]");
	   */
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
	  /*
	   * Obsolete
	   *
	   helptext ("--state-space",
	   "output state space graph (in DOT format)");
	   */
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
  /*
     if (!process)
     {
     printf ("Switches for Arachne engine:\n");
     }
   */

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

  if (detect (' ', "no-intruder", 0))
    {
      if (!process)
	{
	  /* for testing purposes: hide
	   *
	   * Disables the intruder
	   */
	}
      else
	{
	  switches.intruder = false;
	  return index;
	}
    }

  if (detect (' ', "extravert", 0))
    {
      if (!process)
	{
	  /* discourage: hide
	   *
	   * Finds only attacks which exclude initiator Alice talking to Alice
	   */
	}
      else
	{
	  switches.extravert = true;
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

  if (detect ('S', "summary", 0))
    {
      if (!process)
	{
	  /*
	   * This is now the default
	   *
	   helptext ("-S,--summary", "show summary only: omit attack details");
	   */
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
	  if (commandline)
	    {
	      printf ("Usage:\n");
	      printf ("  %s [switches] [FILE]\n\nSwitches:\n", progname);
	      switcher (0, 0, commandline);
	    }
	  exit (0);
	}
    }

  if (detect (' ', "plain", 0))
    {
      if (!process)
	{
	  helptext ("--plain", "disable color terminal output");
	}
      else
	{
	  switches.plain = true;
	  return index;
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
      if (!strcmp (this_arg, "-") && commandline)
	{
	  // '-' input: Leave input to stdin
	}
      else
	{
	  // not '-' input: change stdin to come from this file
	  if (!openFileStdin (this_arg))
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

  // Now show the environment variables
  if (!process)
    {
      printf
	("\nThere are two environment variables that influence the behaviour of Scyther.\n");
      printf
	("  SCYTHERFLAGS    Put any default command-line options here, syntax as on the command line.\n");
      printf
	("  SCYTHERDIR      Colon-separated path of directories to search for input files if a file\n");
      printf
	("                  is not found in the current directory. Note: use '$HOME' instead of '~'.\n");
    }

  return 0;
}

//! Process environment
void
process_environment (void)
{
  char *flags;

  flags = getenv ("SCYTHERFLAGS");
  if (flags != NULL)
    {
      int slen;

      slen = strlen (flags);
      if (slen > 0)
	{
	  /**
	   * We scan the flags here, but assume a stupid upper limit of 100 pieces, otherwise this all becomes fairly vague.
	   */
	  int max = 100;
	  char *argv[100];
	  int count;
	  char *args;
	  char *scanflag;
	  char *argn;

	  /* make a safe copy */
	  args = (char *) memAlloc (slen + 1);
	  memcpy (args, flags, slen + 1);

	  /* warning */
	  /*
	     globalError++;
	     eprintf ("warning: using environment variable SVNSCYTHER ('%s')\n",
	     args);
	     globalError--;
	   */

	  {
	    int i;

	    i = 0;
	    while (i < max)
	      {
		argv[i] = "";
		i++;
	      }
	  }

	  scanflag = args;
	  count = 0;
	  /* ugly use of assignment in condition */
	  while (count < max)
	    {
	      argn = strtok (scanflag, "\t ");
	      scanflag = NULL;
	      if (argn != NULL)
		{
		  count++;
		  argv[count] = argn;
		}
	      else
		{
		  break;
		}
	    }
	  /*
	     warning ("found %i arguments in SCYTHERFLAGS\n", count);
	   */

	  switches.argc = count + 1;
	  switches.argv = argv;
	  process_switches (false);
	}
    }
}

//! Process switches
void
process_switches (int commandline)
{
  int index;

  if (switches.argc == 1)
    {
      if (commandline)
	{
	  printf ("Try '%s --help' for more information, or visit:\n",
		  progname);
	  printf (" http://www.win.tue.nl/~ccremers/scyther/index.html\n");
	  exit (0);
	}
      else
	{
	  return;
	}
    }

  index = 1;
  while (index < switches.argc && index > 0)
    {
      index = switcher (1, index, commandline);
    }
}
