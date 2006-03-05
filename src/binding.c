/**
 * Handle bindings for Arache engine.
 */

#include "list.h"
#include "role.h"
#include "label.h"
#include "system.h"
#include "binding.h"
#include "warshall.h"
#include "memory.h"
#include "debug.h"
#include "term.h"
#include "termmap.h"
#include "arachne.h"
#include "switches.h"
#include "depend.h"
#include <malloc.h>

static System sys;		//!< local storage of system pointer

extern Protocol INTRUDER;	//!< The intruder protocol
extern Role I_M;		//!< special role; precedes all other events always

/*
 *
 * Assist stuff
 *
 */

//! Create mem for binding
Binding
binding_create (Term term, int run_to, int ev_to)
{
  Binding b;

  b = memAlloc (sizeof (struct binding));
  b->done = false;
  b->blocked = false;
  b->run_from = -1;
  b->ev_from = -1;
  b->run_to = run_to;
  b->ev_to = ev_to;
  b->term = term;
  b->level = 0;
  return b;
}

//! Remove mem for binding
void
binding_destroy (Binding b)
{
  if (b->done)
    {
      goal_unbind (b);
    }
  memFree (b, sizeof (struct binding));
}

/*
 *
 * Main
 *
 */

//! Init module
void
bindingInit (const System mysys)
{
  sys = mysys;
  sys->bindings = NULL;

  dependInit (sys);
}

//! Close up
void
bindingDone ()
{
  int delete (Binding b)
  {
    binding_destroy (b);
    return true;
  }
  list_iterate (sys->bindings, delete);
  list_destroy (sys->bindings);

  dependDone (sys);
}


/**
 *
 * Externally available functions
 *
 */


//! Print a binding (given a binding list pointer)
int
binding_print (const Binding b)
{
  if (b->done)
    eprintf ("Binding (%i,%i) --( ", b->run_from, b->ev_from);
  else
    eprintf ("Unbound --( ");
  termPrint (b->term);
  eprintf (" )->> (%i,%i)", b->run_to, b->ev_to);
  if (b->blocked)
    eprintf ("[blocked]");
  return true;
}

//! Bind a goal (true if success, false if it must be pruned)
int
goal_bind (const Binding b, const int run, const int ev)
{
  if (b->blocked)
    {
      error ("Trying to bind a blocked goal.");
    }
  if (!b->done)
    {
#ifdef DEBUG
      if (run >= sys->maxruns || sys->runs[run].step <= ev)
	{
	  globalError++;
	  eprintf ("For term: ");
	  termPrint (b->term);
	  eprintf (" needed for r%ii%i.\n", b->run_to, b->ev_to);
	  eprintf ("Current limits: %i runs, %i events for this run.\n",
		   sys->maxruns, sys->runs[run].step);
	  globalError--;
	  error
	    ("trying to bind to something not yet in the semistate: r%ii%i.",
	     run, ev);
	}
#endif
      b->run_from = run;
      b->ev_from = ev;
      if (dependPushEvent (run, ev, b->run_to, b->ev_to))
	{
	  b->done = true;
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      binding_print (b);
	      eprintf ("\n");
	    }
	  return true;
	}
    }
  else
    {
      globalError++;
      binding_print (b);
      error ("Trying to bind a bound goal again.");
    }
  return false;
}

//! Unbind a goal
void
goal_unbind (const Binding b)
{
  if (b->done)
    {
      dependPopEvent ();
      b->done = false;
    }
  else
    {
      error ("Trying to unbind an unbound goal again.");
    }
}

//! Bind a goal as a dummy (block)
/**
 * Especially made for tuple expansion
 */
int
binding_block (Binding b)
{
  if (!b->blocked)
    {
      b->blocked = true;
      return true;
    }
  else
    {
      error ("Trying to block a goal again.");
    }
}

//! Unblock a binding
int
binding_unblock (Binding b)
{
  if (b->blocked)
    {
      b->blocked = false;
      return true;
    }
  else
    {
      error ("Trying to unblock a non-blocked goal.");
    }
}


//! Add a goal
/**
 * The int parameter 'level' is just to store additional info. Here, it stores priorities for a goal.
 * Higher level goals will be selected first. Typically, a normal goal is level 0, a key is 1.
 *
 * Returns the number of added goals (sometimes unfolding tuples)
 */
int
goal_add (Term term, const int run, const int ev, const int level)
{
  term = deVar (term);
#ifdef DEBUG
  if (term == NULL)
    error ("Trying to add an emtpy goal term");
  if (run >= sys->maxruns)
    error ("Trying to add a goal for a run that does not exist.");
  if (ev >= sys->runs[run].step)
    error
      ("Trying to add a goal for an event that is not in the semistate yet.");
#endif
  if (realTermTuple (term))
    {
      return goal_add (TermOp1 (term), run, ev, level) +
	goal_add (TermOp2 (term), run, ev, level);
    }
  else
    {
      // Determine whether we already had it
      int createnew;

      int testSame (void *data)
      {
	Binding b;

	b = (Binding) data;
	if (isTermEqual (b->term, term))
	  {
	    // binding of same term
	    if (run == b->run_to && ev == b->ev_to)
	      {
		// identical binding 
		createnew = false;
	      }
	  }
	return true;
      }

      createnew = true;
      list_iterate (sys->bindings, testSame);
      if (createnew)
	{
	  // Add a new binding
	  Binding b;
	  b = binding_create (term, run, ev);
	  b->level = level;
	  sys->bindings = list_insert (sys->bindings, b);
#ifdef DEBUG
	  if (DEBUGL (3))
	    {
	      eprintf ("Adding new binding for ");
	      termPrint (term);
	      eprintf (" to run %i, ev %i.\n", run, ev);
	    }
#endif
	  return 1;
	}
    }
  return 0;
}

//! Remove a goal
void
goal_remove_last (int n)
{
  while (n > 0)
    {
      if (sys->bindings != NULL)
	{
	  Binding b;

	  b = (Binding) sys->bindings->data;
	  binding_destroy (b);
	  sys->bindings = list_delete (sys->bindings);
	  n--;
	}
      else
	{
	  error
	    ("goal_remove_last error: trying to remove %i too many bindings.",
	     n);
	}
    }
}

//! Determine whether some label set is ordered w.r.t. send/read order.
/**
 * Assumes all these labels exist in the system, within length etc, and that the run mappings are valid.
 */
int
labels_ordered (Termmap runs, Termlist labels)
{
  while (labels != NULL)
    {
      // Given this label, and the mapping of runs, we want to know if the order is okay. Thus, we need to know sendrole and readrole
      Labelinfo linfo;
      int send_run, send_ev, read_run, read_ev;

      int get_index (const int run)
      {
	Roledef rd;
	int i;

	i = 0;
	rd = sys->runs[run].start;
	while (rd != NULL && !isTermEqual (rd->label, labels->term))
	  {
	    rd = rd->next;
	    i++;
	  }
#ifdef DEBUG
	if (rd == NULL)
	  error
	    ("Could not locate send or read for label, after niagree holds, to test for order.");
#endif
	return i;
      }

      linfo = label_find (sys->labellist, labels->term);
      send_run = termmapGet (runs, linfo->sendrole);
      read_run = termmapGet (runs, linfo->readrole);
      send_ev = get_index (send_run);
      read_ev = get_index (read_run);
      if (!isDependEvent (send_run, send_ev, read_run, read_ev))
	{
	  // Not ordered; false
	  return false;
	}

      // Proceed
      labels = labels->next;
    }
  return true;
}

//! Check whether the binding denotes a sensible thing such that we can use run_from and ev_from
int
valid_binding (Binding b)
{
  if (b->done && (!b->blocked))
    return true;
  else
    return false;
}

//! Check for unique origination
/*
 * Contrary to a previous version, we simply check for unique origination.
 * This immediately takes care of any 'occurs before' things. Complexity is N
 * log N.
 *
 * Each term should originate only at one point (thus in one binding)
 *
 *@returns True, if it's okay. If false, it needs to be pruned.
 */
int
unique_origination ()
{
  List bl;

  bl = sys->bindings;

  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      // Check for a valid binding; it has to be 'done' and sensibly bound (not as in tuple expanded stuff)
      if (valid_binding (b))
	{
	  Termlist terms;

	  terms = tuple_to_termlist (b->term);
	  if (terms != NULL)
	    {
	      /* Apparently this is a good term.
	       * Now we check whether it occurs in any previous bindings as well.
	       */

	      List bl2;

	      bl2 = sys->bindings;
	      while (bl2 != bl)
		{
		  Binding b2;

		  b2 = (Binding) bl2->data;
		  if (valid_binding (b2))
		    {
		      Termlist terms2, sharedterms;

		      terms2 = tuple_to_termlist (b2->term);
		      sharedterms = termlistConjunct (terms, terms2);

		      // Compare terms
		      if (sharedterms != NULL)
			{
			  // Apparently, this binding shares a term.
			  // Equal terms should originate at the same point
			  if (b->run_from != b2->run_from ||
			      b->ev_from != b2->ev_from)
			    {
			      // Not equal: thus no unique origination.
			      return false;
			    }
			}
		      termlistDelete (terms2);
		      termlistDelete (sharedterms);
		    }
		  bl2 = bl2->next;
		}
	    }
	  termlistDelete (terms);
	}
      bl = bl->next;
    }
  return true;
}

//! Prune invalid state w.r.t. <=C minimal requirement
/**
 * Intuition says this can be done a lot more efficient. Luckily this is the prototype.
 *
 *@returns True, if it's okay. If false, it needs to be pruned.
 */
int
bindings_c_minimal ()
{
  if (!unique_origination ())
    {
      return false;
    }

  {
    List bl;

    // For all goals
    bl = sys->bindings;
    while (bl != NULL)
      {
	Binding b;

	b = (Binding) bl->data;
	// Check for a valid binding; it has to be 'done' and sensibly bound (not as in tuple expanded stuff)
	if (valid_binding (b))
	  {
	    int run;

	    // Find all preceding events
	    for (run = 0; run < sys->maxruns; run++)
	      {
		int ev;

		//!@todo hardcoded reference to step, should be length
		for (ev = 0; ev < sys->runs[run].step; ev++)
		  {
		    if (isDependEvent (run, ev, b->run_from, b->ev_from))
		      {
			// this node is *before* the from node
			Roledef rd;

			rd = roledef_shift (sys->runs[run].start, ev);
			if (termInTerm (rd->message, b->term))
			  {
			    // This term already occurs as interm in a previous node!
#ifdef DEBUG
			    if (DEBUGL (4))
			      {
				// Report this
				indentPrint ();
				eprintf ("Binding for ");
				termPrint (b->term);
				eprintf
				  (" at r%i i%i is not c-minimal because it occurred before at r%i i%i in ",
				   b->run_from, b->ev_from, run, ev);
				termPrint (rd->message);
				eprintf ("\n");
			      }
#endif
			    return false;
			  }
		      }
		    else
		      {
			// If this event is not before the target, then the
			// next in the run certainly is not either (because
			// that would imply that this one is before it)
			// Thus, we effectively exit the loop.
			break;
		      }
		  }
	      }
	  }
	bl = bl->next;
      }
  }
  return true;
}
