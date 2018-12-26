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
 *@file trusted.c
 * \brief Prune for trusted assumptions
 *
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "system.h"
#include "debug.h"
#include "timer.h"
#include "switches.h"
#include "error.h"
#include "specialterm.h"
#include "arachne.h"
#include "binding.h"
#include "depend.h"
#include "compromise.h"
#include "type.h"
#include "mgu.h"

extern Protocol INTRUDER;	// from arachne.c


//! Is compromise of agent a allowed?
int
isCompromiseAllowed (const System sys, int *partners, Binding b, Term a)
{
  if (switches.LKRothers)
    {
      // Is any of the agents outside the group of main actors?
      if (!inTermlist (sys->runs[0].rho, a))
	{
	  return true;
	}
    }
  if (switches.LKRactor)
    {
      if (b->LKRactor == 1)
	{
	  /**
	   * LKRactor of sk(a) is enabled if a is the actor of the claim run, but
	   * does not occur in any other role.
	   * 
	   * A naive implementation would return true (possibly okay) for
	   * isTermVariable(a). However, even if it is a variable, we can already
	   * exclude that it is justified by LKRactor if the variable occurs more
	   * than once in rho. In such cases, even later instantiations will not
	   * make the premise of LKRactor true. This allows for correct pruning,
	   * because only now will any (disjoint) instantiation of the variables
	   * lead to a correct solution.
	   */
	  int count;

	  count = termlistCount (sys->runs[0].rho, a);
	  if (count <= 1)
	    {
	      // Does not occur in another role
	      return true;
	    }
	}
    }


  {
    // Is any of the agents outside the group of main actors?
    if (!inTermlist (sys->runs[0].rho, a))
      {
	return true;
      }
  }

  // This block has to be the last since it can return both false and true directly
  if (switches.LKRafter || switches.LKRafterours || switches.LKRaftercorrect)
    {
      // After the claim?
      //
      // Clearly only relevant for secrecy (as we would not even
      // construct events after the claim for authentication
      // properties).
      // 
      // Bindings always have a 'to' destination
      int r1, e1, r2, e2;

      // Check first if we must require it is one of ours
      if (switches.LKRafterours
	  && !(switches.LKRafter || switches.LKRaftercorrect))
	{
	  // Yes: agent must be one of the insiders for this to be a good justification
	  if (!inTermlist (sys->runs[0].rho, a))
	    {
	      return false;
	    }
	}

      // Where is the key used?
      r1 = b->run_to;
      e1 = b->ev_to;
      // End of the claim run/test thread
      r2 = 0;
      e2 = sys->runs[0].step - 1;

      if (e2 < 0)
	{
	  // This does not make sense if the claim run is empty. Hence we
	  // prune.
	  return false;
	}
      if (((r1 != r2) || (e1 != e2)))
	{
	  // If they were the same, not allowed (by this rule)
	  if (isDependEvent (r2, e2, r1, e1))
	    {
	      // Key is needed strictly after the claim run end. Good.

	      if (switches.LKRafter)
		{
		  return true;
		}
	      if (switches.markFullSession)
		{
		  if (switches.LKRaftercorrect)
		    {
		      return true;
		    }
		}
	    }
	  else
	    {
		  /**
		   * Claim may be before the long-term key reveal. That's fine
		   * but we want to enforce it.
		   *
		   * Trick: we add the binding, iterate. Because we already
		   * iterate, we can prune this particular state then later on.
		   */
	      if (dependPushEvent (r2, e2, r1, e1))
		{
		  iterate ();
		  dependPopEvent ();
		}
	      return false;
	    }
	}
    }
  return false;
}


//! Check LKRs okay for key inner tuple term
/**
 * It's currently a bit inefficient, because tuple_to_termlist is not needed
 * and we could directly descend into the tree ourselves. But this is easier
 * for now.
 *
 * The key in binding b is sk(a1) or k (a1,...,an), one of the ai is the agent
 * which has been long-term key revealed. There are a number of cases in which
 * this is allowed, as defined in the paper.
 *
 * Note that if compromise of b is allowed, then if b occurs in the
 * list, that would work.
 */
int
goodBindingKeyAgents (const System sys, int *partners, Binding b,
		      Term keyagents)
{
  int isFine;
  Termlist alist;
  Termlist tl;

  isFine = false;
  alist = tuple_to_termlist (keyagents);
  for (tl = alist; tl != NULL; tl = tl->next)
    {
      Term agentt;

      agentt = deVar (tl->term);
      if (agentCompatible (agentt->stype))
	{
	  if (isCompromiseAllowed (sys, partners, b, agentt))
	    {
	      isFine = true;
	      break;
	    }
	}
    }
  termlistDelete (alist);
  return isFine;
}


//! Check whether the LKR's required for a binding b are allowed.
int
goodBindingLKR (const System sys, int *partners, Binding b)
{
  int isFine;
  Termlist tlstore, tl;

  isFine = true;
  tlstore = getPrivateKeyAgents (b, NULL);
  for (tl = tlstore; tl != NULL; tl = tl->next)
    {
      if (!goodBindingKeyAgents (sys, partners, b, tl->term))
	{
	  isFine = false;
	  break;
	}
    }
  termlistDelete (tlstore);
  return isFine;
}


//! prune a state if it does not conform to the trusted mode
/**
 * Currently, only the LKR mode.
 *
 * Returns true if pruned.
 */
int
pruneTrusted (const System sys, int *partners)
{
  List bl;

  // Scan all bindings to find the private keys
  for (bl = sys->bindings; bl != NULL; bl = bl->next)
    {
      if (!goodBindingLKR (sys, partners, (Binding) bl->data))
	{
	  /*
	   * One is not good, then prune
	   */
	  return true;
	}
    }
  // All fine, don't prune.
  return false;
}

//! Helper for splitLKRactorCandidate
int
calliter (Termlist tl)
{
  iterate ();
  return true;
}

//! Find Unsplit LKRactor candidate
/**
 * Return true if we found (and explored) one
 */
int
splitLKRactorCandidate (const System sys)
{
  List bl;

  // Scan all bindings to find the private keys
  for (bl = sys->bindings; bl != NULL; bl = bl->next)
    {
      Binding b;

      b = (Binding) bl->data;
      if (b->LKRactor == 0)
	{
	  // Not assigned yet
	  Termlist tl;		// Termlists need deletion later on (if not NULL)

	  tl = getPrivateKeyAgents (b, NULL);
	  if (tl != NULL)
	    {
	      // Okay, it is a candidate
	      // But it may be a pair too; all of them can be the actor
	      Termlist tl2;
	      Termlist tls;
	      Term actor;

	      actor = agentOfRun (sys, 0);	// retrieve actor of test run for later iteration

	      // Branch 1: consider all options in the binding as actor, i.e., LKRactor caused the LKR reveal.
	      tl2 = tuple_to_termlist (tl->term);
	      b->LKRactor = 1;	// Mark that we are considering this as the actor now
	      for (tls = tl2; tls != NULL; tls = tls->next)
		{
		  unify (tls->term, actor, NULL, calliter, NULL);
		}
	      // Branch 2: LKRactor did not cause this LKR reveal
	      b->LKRactor = 2;	// Mark that we are considering this as a non-actor
	      iterate ();

	      b->LKRactor = 0;	// Restore state precisely to previous state

	      termlistDelete (tl2);	// cleanup
	      termlistDelete (tl);	// cleanup
	      return true;
	    }
	}
    }
  return false;
}


//! Rewrite a state if needed
/**
 * This is essentially a constraint system rewrite rule (a la Tamarin) that
 * performs a case distinction in case long-term keys are revealed and the
 * LKRactor rule is enabled.
 *
 * This is called directly from the body of the iterate() call, before any
 * pruning is performed.
 *
 * Return true if the state been rewritten and iterated already. In this case, the calling iterate() instance will not continue and instead return.
 * Return false if nothing happened. The calling iterate() instance will proceed as usual.
 */
int
iterateTrusted (const System sys)
{
  if (switches.LKRactor)
    {
      // Currently only splitting for LKRactor
      return splitLKRactorCandidate (sys);
    }
  return false;
}
