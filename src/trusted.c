/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007 Cas Cremers
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

extern Protocol INTRUDER;	// from arachne.c

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
      Binding b;
      Termlist tl;
      Termlist tlstore;

      b = (Binding) bl->data;
      tlstore = getPrivateKeyAgents (b, NULL);
      for (tl = tlstore; tl != NULL; tl = tl->next)
	{
	  Term a;

	  a = tl->term;

	  /* The key in binding b is sk(a) or k (..,a,..), a is the agent which
	   * has been long-term key revealed. There are a number of cases in
	   * which this is allowed, as defined in the paper.
	   */
	  if (switches.LKRnotgroup)
	    {
	      // Is the agent outside the group of main actors?
	      if (!inTermlist (sys->runs[0].rho, a))
		{
		  continue;
		}
	    }
	  if (switches.LKRactor || switches.LKRactorrnsafe)
	    {
	      // Is it the agent the actor of run 0,...
	      if (isTermEqual (a, agentOfRun (sys, 0)))
		{
		  // ... but not of the other roles 
		  Termlist agents;
		  Term claimrole;
		  int allgood;

		  claimrole = sys->runs[0].role->nameterm;
		  allgood = true;
		  for (agents = sys->runs[0].rho; agents != NULL;
		       agents = agents->next)
		    {
		      if (TermSymb (claimrole) != TermSymb (agents->term))
			{
			  if (isTermEqual (a, agents->term))
			    {
			      allgood = false;
			      break;
			    }
			}
		    }
		  if (allgood)
		    {
		      // It was the actor, but not assigned to any of the other roles
		      if (switches.LKRactor)
			{
			  continue;
			}
		      if (switches.LKRactorrnsafe)
			{
			  if (!compromiseRNRpartner (partners,a))
			    {
			      continue;
			    }
			}
		    }
		}
	    }
	  if (switches.LKRafter || switches.LKRaftercorrect
	      || switches.LKRrnsafe)
	    {
	      // After the claim?
	      //
	      // Clearly only relevant for secrecy (as we would not even
	      // construct events after the claim for authentication
	      // properties).
	      // 
	      // Bindings always have a 'to' destination
	      int r1, e1, r2, e2;

	      r1 = b->run_to;
	      e1 = b->ev_to;
	      r2 = 0;
	      e2 = sys->runs[0].step - 1;	// assumption that it contains at least an event.
	      if (((r1 != r2) || (e1 != e2)))
		{
		  // If they were the same, not allowed (by this rule)
		  if (!isDependEvent (r1, e1, r2, e2))
		    {
		      // Claim may be before the long-term key reveal. That's fine.
		      if (switches.LKRafter)
			{
			  continue;
			}
		      if (switches.markFullSession)
			{
			  if (switches.LKRaftercorrect)
			    {
			      continue;
			    }
			  if (switches.LKRrnsafe)
			    {
			      if (!compromiseRNRpartner (partners,a))
				{
				  continue;
				}
			    }
			}
		    }
		}
	    }
	  /*
	   * There was no valid reason to allow LKR: hence we prune.
	   */
	  return true;
	}
      termlistDelete (tlstore);
    }
  return false;
}
