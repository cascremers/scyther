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

extern Protocol INTRUDER;	// from arachne.c

int
untrustedActorRun (const System sys, const int run)
{
  if (!isAgentTrusted (sys, agentOfRun (sys, run)))
    {
      return true;
    }
  return false;
}

int
untrustedAgentsRun (const System sys, const int run)
{
  if (!isAgentlistTrusted (sys, sys->runs[run].rho))
    {
      return true;
    }
  return false;
}

int
pruneTrustedRun (const System sys, const int run)
{
  switch (switches.trustedMode)
    {
    case 0:
      return untrustedActorRun (sys, run);
    case 1:
      if (run == 0)
	{
	  // Claim run status is evaluated by pruneClaimRunTrusted in claim.c
	  return false;
	}
      else
	{
	  return untrustedActorRun (sys, run);
	}
    case 2:
      if (run == 0)
	{
	  // Stronger (possibly) than claim
	  return untrustedAgentsRun (sys, run);
	}
      else
	{
	  return untrustedActorRun (sys, run);
	}
    case 3:
      return untrustedAgentsRun (sys, run);
    }
  return false;
}

//! prune a state if it does not conform to the trusted mode
int
pruneTrusted (const System sys)
{
  // Check if the actors of all other runs are not untrusted
  if (sys->untrusted != NULL)
    {
      int run;

      for (run = 0; run < sys->maxruns; run++)
	{
	  if (sys->runs[run].protocol != INTRUDER)
	    {
	      if (sys->runs[run].rho != NULL)
		{
		  if (pruneTrustedRun (sys, run))
		    {
		      return true;
		    }
		}
	      else
		{
		  Protocol p;

		  globalError++;
		  eprintf ("error: Run %i: ", run);
		  role_name_print (run);
		  eprintf (" has an empty agents list.\n");
		  eprintf ("protocol->rolenames: ");
		  p = (Protocol) sys->runs[run].protocol;
		  termlistPrint (p->rolenames);
		  eprintf ("\n");
		  error ("Aborting.");
		  globalError--;
		  return true;
		}
	    }
	}
    }
  return false;
}
