/**
 *
 *@file heuristic.c
 *
 * Heuristics code for Arachne method
 *
 */

#include <float.h>

#include "binding.h"
#include "system.h"
#include "specialterm.h"
#include "switches.h"
#include "hidelevel.h"

//! Check whether a binding (goal) is selectable
int
is_goal_selectable (const Binding b)
{
  if (b != NULL)
    {
      if (!b->blocked && !b->done)
	{
	  return 1;
	}
    }
  return 0;
}

//! Count selectable goals
int
count_selectable_goals (const System sys)
{
  List bl;
  int n;

  n = 0;
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;
      if (is_goal_selectable (b))
	{
	  n++;
	}
      bl = bl->next;
    }
  return n;
}

//! Return first selectable goal in the list
/**
 * The return list entry is either NULL, or a selectable goal.
 */
List
first_selectable_goal (List bl)
{
  while (bl != NULL && !is_goal_selectable ((Binding) bl->data))
    {
      bl = bl->next;
    }
  return bl;
}

//! Give an indication of the amount of consequences binding a term has
/**
 * Given a term, returns a float. 0: maximum consequences, 1: no consequences.
 */
float
termBindConsequences (const System sys, Term t)
{
  Termlist openVariables;

  openVariables = termlistAddVariables (NULL, t);
  if (openVariables == NULL)
    {
      // No variables, no consequences
      return 1;
    }
  else
    {
      // For each run event in the semitrace, check whether it contains any
      // of the open variables.
      int totalCount;
      int affectedCount;
      int run;

      totalCount = 0;
      affectedCount = 0;
      run = 0;
      while (run < sys->maxruns)
	{
	  Roledef rd;
	  int step;

	  rd = sys->runs[run].start;
	  step = 0;
	  while (step < sys->runs[run].height)
	    {
	      Termlist tl;

	      tl = openVariables;
	      while (tl != NULL)
		{
		  if ((rd->type == READ || rd->type == SEND)
		      && termSubTerm (rd->message, tl->term))
		    {
		      // This run event contains the open variable
		      affectedCount++;
		      tl = NULL;
		    }
		  else
		    {
		      tl = tl->next;
		    }
		}
	      totalCount++;
	      step++;
	      rd = rd->next;
	    }
	  run++;
	}

      termlistDelete (openVariables);
      if (totalCount > 0)
	{
	  // Valid computation
	  return (float) (totalCount - affectedCount) / totalCount;
	}
      else
	{
	  // No consequences, ensure no division by 0
	  return 1;
	}
    }
}

//! Determine whether a term is an open nonce variable
/**
 * Does not explore subterms
 */
int
isOpenNonceVar (Term t)
{
  t = deVar (t);
  if (realTermVariable (t))
    {
      return inTermlist (t->stype, TERM_Nonce);
    }
  else
    {
      return 0;
    }
}

//! Count unique open variables in term
/**
 */
int
count_open_variables (const Term t)
{
  Termlist tl;
  int n;

  tl = NULL;
  termlistAddVariables (tl, t);
  n = 0;
  while (tl != NULL)
    {
      if (!inTermlist (tl->next, t))
	{
	  if (isOpenNonceVar (t))
	    {
	      n = n + 1;
	    }
	}
      tl = tl->next;
    }
  termlistDelete (tl);
  return n;
}



//! Athena-like factor
/**
 * Lower is better (more nonce variables)
 */
float
term_noncevariables_level (const Term t)
{
  int onv;
  const int enough = 2;

  onv = count_open_variables (t);
  if (onv >= enough)
    {
      return 0;
    }
  else
    {
      return 1 - (onv / enough);
    }
}

//! Determine weight based on hidelevel
float
weighHidelevel (const System sys, const Term t)
{
  unsigned int hl;

  switch (hidelevelFlag (sys, t))
    {
    case HLFLAG_NONE:
      return 0;
    case HLFLAG_KNOW:
      return 0.3;
    case HLFLAG_PROT:
      return 0.6;
    }
  return 1;
}

//! newkeylevel (weighted)
int
newkeylevel (const int level)
{
  // keylevel is from { -1,0,1 } where -1 means delay
  if (level == 1)
    return 0;
  else
    return 1;
}

//! Goal selection
/**
 * Selects the most constrained goal.
 *
 * First selection is on level; thus, keys are selected first.
 *
 * Because the list starts with the newest terms, and we use <= (as opposed to <), we
 * ensure that for goals with equal constraint levels, we select the oldest one.
 *
 * --select-goal has two distint interpretations. If it is 0 or greater, it a
 * selection mask. If it is smaller than 0, it is some special tactic.
 *
 * selection masks for --select-goal
 *	1:	constrain level of term
 * 	2:	key or not
 * 	4:	consequences determination
 * 	8:	select also single variables (that are not role variables)
 * 	16:	single variables are better
 * 	32:	incorporate keylevel information
 *
 * special tactics for --select-goal
 *	-1:	random goal selection
 *
 */
Binding
select_goal_masked (const System sys)
{
  List bl;
  Binding best;
  float min_constrain;
  int mode;

  // mode bits local storage
  mode = switches.arachneSelector;

  // Find the most constrained goal
  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Listing open goals that might be chosen: ");
    }
  min_constrain = FLT_MAX;
  bl = sys->bindings;
  best = NULL;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;

      // Only if not done and not blocked
      if (is_goal_selectable (b))
	{
	  int allow;
	  Term gterm;

	  allow = 0;
	  gterm = deVar (b->term);
	  if (mode & 8)
	    {
	      // check for singular variable
	      if (realTermVariable (gterm))
		{
		  // singular variable only if it is not a role name variable
		  allow = !gterm->roleVar;
		}
	      else
		{
		  // not a singular variable, allow
		  allow = 1;
		}
	    }
	  else
	    {
	      // Normally (mode & 8 == 0) we ignore any singular variables
	      allow = !realTermVariable (gterm);
	    }

	  if (allow)
	    {
	      float buf_constrain;
	      int buf_weight;
	      int smode;

	      void adapt (const int w, const float fl)
	      {
		buf_constrain = buf_constrain + w * fl;
		buf_weight = buf_weight + w;
	      }

	      void erode (const int w, const float fl)
	      {
		if (smode & 1)
		  {
		    adapt (w, fl);
		  }
		smode = smode / 2;
	      }

	      // buf_constrain is the addition of the factors before division by weight
	      buf_constrain = 0;
	      buf_weight = 0;

	      if (switches.output == PROOF && best != NULL)
		eprintf (", ");

	      // We will shift this mode variable
	      smode = mode;

	      // Determine buf_constrain levels
	      // Bit 0: 1 constrain level
	      erode (1, term_constrain_level (b->term));
	      // Bit 1: 2 key level (inverted)
	      erode (1, 0.5 * (1 - b->level));
	      // Bit 2: 4 consequence level
	      erode (1, termBindConsequences (sys, b->term));
	      // Bit 3: 8 single variables first (crappy performance, counter-intuitive anyway)
	      erode (1, 1 - isTermVariable (b->term));
	      // Bit 4: 16 nonce variables level (Cf. what I think is in Athena)
	      erode (1, term_noncevariables_level (b->term));
	      // Bit 5: 32 use hidelevel information
	      erode (1, weighHidelevel (sys, b->term));
	      // Bit 5: 64 use hidelevel information
	      erode (1, 2 * weighHidelevel (sys, b->term));
	      // Bit 6: 128 use key level
	      erode (1, newkeylevel (b->level));

	      // Define legal range
	      if (smode > 0)
		error ("--heuristic mode %i is illegal", mode);

	      // Weigh result
	      if (buf_weight == 0 || buf_constrain <= min_constrain)
		{
		  min_constrain = buf_constrain;
		  best = b;
		  if (switches.output == PROOF)
		    eprintf ("*");
		}
	      if (switches.output == PROOF)
		{
		  termPrint (b->term);
		  if (mode & 2)
		    {
		      eprintf ("[%i]", b->level);
		    }
		  eprintf ("<%.2f>", buf_constrain);
		}
	    }
	}
      bl = bl->next;
    }
  if (switches.output == PROOF)
    {
      if (best == NULL)
	eprintf ("none");
      eprintf ("\n");
    }
  return best;
}

//! Goal selection special case -1: random
/**
 * Simply picks an open goal randomly. Has to be careful to skip singular stuff etc.
 */
Binding
select_goal_random (const System sys)
{
  int n;

  n = count_selectable_goals (sys);
  if (n > 0)
    {
      int choice;
      List bl;

      // Choose a random goal between 0 and n
      choice = rand () % n;

      // Fetch it
      bl = sys->bindings;
      while (choice >= 0)
	{
	  bl = first_selectable_goal (bl);
	  if (bl == NULL)
	    {
	      error ("Random chooser selected a NULL goal.");
	    }
	  choice--;
	}
      return (Binding) bl->data;
    }
  else
    {
      return (Binding) NULL;
    }
}

//! Goal selection function, generic
Binding
select_goal (const System sys)
{
  if (switches.arachneSelector >= 0)
    {
      // Masked
      return select_goal_masked (sys);
    }
  else
    {
      // Special cases
      switch (switches.arachneSelector)
	{
	case -1:
	  return select_goal_random (sys);
	}
      error ("Unknown value (<0) for --goal-select.");
    }
  return (Binding) NULL;
}
