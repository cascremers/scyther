/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2013 Cas Cremers
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 *
 *@file heuristic.c
 *
 * Heuristics code for Arachne method
 *
 */

#include <float.h>
#include <stdlib.h>

#include "binding.h"
#include "system.h"
#include "specialterm.h"
#include "switches.h"
#include "hidelevel.h"
#include "arachne.h"
#include "error.h"
#include "knowledge.h"

#define erode(deltaw) { \
    if (smode & 1) \
      { \
      	w = w + (deltaw); \
      } \
    smode = smode / 2; \
   }

//! Trivial goal detection
/**
 * Detect goals that we do not need to solve because they can be trivially solved.
 */
int
isTrivialGoal (const System sys, const Term t)
{
  if (isTermVariable (t))
    {
      return true;
    }
  else
    {
      Term f;

      f = getTermFunction (t);
      if (f != NULL)
	{
	  if (isKnowledgePublicFunction (sys->know, f))
	    {
	      return isTrivialGoal (sys, TermOp (t));
	    }
	}
    }
  return false;
}

//! Check whether a binding (goal) is selectable
int
is_goal_selectable (const System sys, const Binding b)
{
  if (b != NULL)
    {
      if ((!b->blocked) && (!b->done))
	{
	  if (!isTrivialGoal (sys, b->term))
	    {
	      return true;
	    }
	}
    }
  return false;
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
      if (is_goal_selectable (sys, b))
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
first_selectable_goal (const System sys, List bl)
{
  while (bl != NULL && !is_goal_selectable (sys, (Binding) bl->data))
    {
      bl = bl->next;
    }
  return bl;
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
weighHidelevel (const System sys, const Term t, const float massknow,
		const float massprot)
{
  switch (hidelevelFlag (sys, t))
    {
    case HLFLAG_NONE:
      return 0;
    case HLFLAG_KNOW:
      return massknow;
    case HLFLAG_PROT:
      return massprot;
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

struct state_tcc
{
  int leaves;
  int nonvariables;
};

//! Simple helper for below
int
countMe (Term t, struct state_tcc *stcc)
{
  if (TermRunid (t) >= 0)
    {
      (stcc->leaves)++;
      if (!isTermVariable (t))
	{
	  (stcc->nonvariables)++;
	}
    }
  return 1;
}

//! count local constants
float
term_constcount (const System sys, Term t)
{
  float ratio;
  struct state_tcc Stcc;

  Stcc.nonvariables = 0;
  Stcc.leaves = 0;
  term_iterate_state_deVar (t, countMe, NULL, NULL, NULL, &Stcc);
  if (Stcc.leaves == 0)
    {
      ratio = 1;
    }
  else
    {
      ratio = ((Stcc.leaves - Stcc.nonvariables) / Stcc.leaves);
    }
  return ratio;
}

//! determine lowest level at which sk/sk occurs, or -1 otherwise.
int
lowest_skk_level (Term t)
{
  t = deVar (t);
  if (t == NULL)
    {
      return -1;
    }
  if (isTermEqual (t, TERM_SK) || isTermEqual (t, TERM_K))
    {
      return 0;
    }
  if (realTermLeaf (t))
    {
      return -1;
    }
  if (realTermTuple (t))
    {
      int x, y;
      x = lowest_skk_level (TermOp1 (t));
      y = lowest_skk_level (TermOp2 (t));
      if (x < 0)
	return y;
      if (y < 0)
	return x;
      if (y < x)
	return y;
      else
	return x;
    }
  else
    {
      int x, y;
      x = lowest_skk_level (TermOp (t));
      y = lowest_skk_level (TermKey (t));
      if (x < 0)
	return y + 1;
      if (y < 0)
	return x + 1;
      if (y < x)
	return y + 1;
      else
	return x + 1;
    }
}

//! count sk/k level depth
float
term_skk_level (const System sys, Term t)
{
  int l;

  l = lowest_skk_level (t);
  if (l < 0)
    {
      return 1.0;
    }
  else
    {
      float res;

      res = l / 4;
      if (res > 1)
	return 1;
      else
	return res;
    }
}

//! Determine the weight of a given goal
/**
 * 0 to ... (lower is better)
 *
 * --heuristic has two distint interpretations. If it is 0 or greater, it a
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
float
computeGoalWeight (const System sys, const Binding b)
{
  float w;
  int smode;
  Term t;

  // Total weight
  w = 0;
  // We will shift this mode variable
  smode = switches.heuristic;
  t = b->term;

  // Determine buf_constrain levels
  // Bit 0: 1 use hidelevel
  erode (2 * weighHidelevel (sys, t, 0.5, 0.5));
  // Bit 1: 2 key level (inverted)
  erode (0.5 * (1 - b->level));
  // Bit 2: 4 constrain level
  erode (term_constrain_level (t));
  // Bit 3: 8 nonce variables level (Cf. what I think is in Athena)
  erode (term_noncevariables_level (t));

  // Bit 4: 16 use hidelevel (normal)
  erode (1 * weighHidelevel (sys, t, 0.5, 0.5));
  // Bit 5: 32 use known nonces (Athena try 2)
  erode (term_constcount (sys, t));

  // Bit 6: 64 use hidelevel (but only single-weight)
  erode (weighHidelevel (sys, t, 0.5, 0.5));
  // Bit 7: 128 use hidelevel (quadruple-weight)
  erode (4 * weighHidelevel (sys, t, 0.5, 0.5));

  // Bit 8: 256 use known nonces (Athena try 2), half weight
  erode (0.5 * term_constcount (sys, t));

  // Bit 9: 512 do sk first (first sk, then sk occurrence level 1, etc)
  erode (16 * term_skk_level (sys, t));

  // Define legal range
  if (smode > 0)
    error ("--heuristic mode %i is illegal", switches.heuristic);

  // Return
  return w;
}

//! Goal selection
/**
 * Selects the most constrained goal.
 *
 * Because the list starts with the newest terms, and we use <= (as opposed to <), we
 * ensure that for goals with equal constraint levels, we select the oldest one.
 *
 */
Binding
select_goal_masked (const System sys)
{
  List bl;
  Binding best;
  float best_weight;

  // Find the most constrained goal
  if (switches.output == PROOF)
    {
      indentPrint ();
      eprintf ("Listing open goals that might be chosen: ");
    }
  best_weight = FLT_MAX;
  best = NULL;
  bl = sys->bindings;
  while (bl != NULL)
    {
      Binding b;

      b = (Binding) bl->data;

      // Only if not done and not blocked
      if (is_goal_selectable (sys, b))
	{
	  float w;

	  w = computeGoalWeight (sys, b);

	  // Spacing between output
	  if (switches.output == PROOF && best != NULL)
	    eprintf (", ");

	  // Better alternative?
	  if (w <= best_weight)
	    {
	      best_weight = w;
	      best = b;
	      if (switches.output == PROOF)
		eprintf ("*");
	    }
	  if (switches.output == PROOF)
	    {
	      termPrint (b->term);
	      eprintf ("<%.2f>", w);
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
	  bl = first_selectable_goal (sys, bl);
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
  if (switches.heuristic >= 0)
    {
      // Masked
      return select_goal_masked (sys);
    }
  else
    {
      // Special cases
      switch (switches.heuristic)
	{
	case -1:
	  return select_goal_random (sys);
	}
      error ("Unknown value (<0) for --goal-select.");
    }
  return (Binding) NULL;
}
