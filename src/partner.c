/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2009 Cas Cremers
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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include "term.h"
#include "termlist.h"
#include "label.h"
#include "system.h"
#include "knowledge.h"
#include "symbol.h"
#include "compiler.h"
#include "switches.h"
#include "specialterm.h"
#include "warshall.h"
#include "hidelevel.h"
#include "debug.h"
#include "intruderknowledge.h"
#include "error.h"
#include "mgu.h"
#include "compromise.h"
#include "termmap.h"
#include "depend.h"

/*
   Simple sys pointer as a global. Yields cleaner code although it's against programming standards.
   It is declared as static to hide it from the outside world, and to indicate its status.
   Other modules will just see a nicely implemented sys parameter of compile, so we can always change
   it later if somebody complains. Which they won't.
*/

static System sys;

/*
 * Declaration from system.c
 */
extern int protocolCount;

/*
 * Forward declarations
 */

//! When none of the runs match
#define MATCH_NONE 0
//! When the order matches
#define MATCH_ORDER 1
//! When the order is reversed
#define MATCH_REVERSE 2
//! When the content matches
#define MATCH_CONTENT 3

/*
 * Code init / done
 */
void
partnerInit (const System mysys)
{
  sys = mysys;
}

void
partnerDone (void)
{
}


/*
 * Main code
 */

//! Label compare (should be considered equal for two different protocols so as to cater for different protocols.)
/**
 * TODO this must be made more precise.
 */
int
isLabelComprEqual (Term l1, Term l2)
{
  if (isTermEqual (l1, l2))
    {
      return true;
    }
  if (isTermTuple (l1) && isTermTuple (l2))
    {
      // Protocol prefixes.
      Termlist tl1, tl2;
      int result;

      tl1 = tuple_to_termlist (l1);
      tl2 = tuple_to_termlist (l2);

      // First element is protocol, skip
      // Second element is remainder
      result = isTermlistEqual (tl1->next, tl2->next);

      termlistDelete (tl1);
      termlistDelete (tl2);
      return result;
    }
  return false;
}

//! Check complete message match
/**
 * Roledef based.
 *@returns MATCH_NONE or MATCH_CONTENT
 */
__inline__ int
events_hist_match_rd (const Roledef rdi, const Roledef rdj)
{
  if (isTermEqual (rdi->message, rdj->message) &&
      isTermEqual (rdi->from, rdj->from) && isTermEqual (rdi->to, rdj->to) &&
      isLabelComprEqual (rdi->label, rdj->label) &&
      !(rdi->internal || rdj->internal))
    {
      return MATCH_CONTENT;
    }
  else
    {
      return MATCH_NONE;
    }
}

//! Check generic agree claim for a given set of runs, arachne style
int
arachne_runs_hist_match (const System sys, const Claimlist cl,
			 const Termmap runs)
{
  Termlist labels;

#ifdef DEBUG
  if (DEBUGL (5))
    {
      eprintf ("Checking runs agreement for Arachne.\n");
      termmapPrint (runs);
      eprintf ("\n");
    }
#endif

  for (labels = cl->prec; labels != NULL; labels = labels->next)
    {
      // For each label, check whether it matches. Maybe a bit too strict (what about variables?)
      // Locate roledefs for read & send, and check whether they are before step
      Labelinfo linfo;

      Roledef get_label_event (const Term role, const Term label)
      {
	int run;
	Roledef rd;
	int i;

	run = termmapGet (runs, role);
	if (run == -1)
	  {
	    return NULL;
	  }
#ifdef DEBUG
	if (run < 0 || run >= sys->maxruns)
	  {
	    globalError++;
	    eprintf ("Run mapping %i out of bounds for role ", run);
	    termPrint (role);
	    eprintf (" and label ");
	    termPrint (label);
	    eprintf ("\n");
	    eprintf ("This label has sendrole ");
	    termPrint (linfo->sendrole);
	    eprintf (" and readrole ");
	    termPrint (linfo->readrole);
	    eprintf ("\n");
	    globalError--;
	    error ("Run mapping is out of bounds.");
	  }
#endif
	rd = sys->runs[run].start;
	for (i = 0; i < sys->runs[run].step; i++)
	  {
	    if (isLabelComprEqual (rd->label, label))
	      {
		return rd;
	      }
	    rd = rd->next;
	  }
	return NULL;
      }

      // Main
      linfo = label_find (sys->labellist, labels->term);
      if (!linfo->ignore)
	{
	  Roledef rd_send, rd_read;

	  rd_read = get_label_event (linfo->readrole, labels->term);
	  if (rd_read == NULL)
	    {
	      // False!
	      return 0;
	    }
	  rd_send = get_label_event (linfo->sendrole, labels->term);
	  if (rd_send == NULL)
	    {
	      // False!
	      return 0;
	    }
	  // Compare
	  if (events_hist_match_rd (rd_send, rd_read) != MATCH_CONTENT)
	    {
	      // False!
	      return 0;
	    }
	}
    }
  return 1;
}

//! Iterate over all termmap for runs_involved
int
iterateInvolvedRuns (int (*f) (Termmap runs_involved))
{
  Claimlist cl;
  Termmap runs_involved;
  int flag;

  int fill_roles (Termlist roles_tofill)
  {
    if (roles_tofill == NULL)
      {
	return f (runs_involved);
      }
    else
      {
	// Choose a run for this role, if possible
	// Note that any will do
	int run, flag;

	flag = true;
	for (run = 0; run < sys->maxruns; run++)
	  {
	    // Choose, iterate
	    runs_involved =
	      termmapSet (runs_involved, roles_tofill->term, run);
	    flag = fill_roles (roles_tofill->next);
	    if (!flag)
	      {
		return false;
	      }
	  }
	return true;
      }
  }

  cl = sys->current_claim;

  runs_involved = termmapSet (NULL, cl->roles->term, 0);	// 0 is the claim run
  flag = fill_roles (cl->roles->next);

  termmapDelete (runs_involved);
  return flag;
}

//! Check whether histories match for a given runmap.
int
doHistoriesMatch (Termmap runs_involved)
{
  return arachne_runs_hist_match (sys, sys->current_claim, runs_involved);
}

//! Mark everybody as true with the same history
/**
 * This is actually a weird definition but hey, that's what we get.
 */
void
matchingHistories (int *partners)
{
  int checkHistories (Termmap runs_involved)
  {
    if (doHistoriesMatch (runs_involved))
      {
	Termmap tmi;

	for (tmi = runs_involved; tmi != NULL; tmi = tmi->next)
	  {
	    partners[tmi->result] = true;
	  }
      }
    return true;		// always proceed
  }
  iterateInvolvedRuns (checkHistories);
}

// Propagate the overlaps (true entries) over overlapping entries
void
propagateOverlap (int *greens)
{
  int proceed;

  proceed = true;
  while (proceed)
    {
      int i;

      proceed = false;
      for (i = 0; i < sys->maxruns; i++)
	{
	  if (!greens[i])
	    {
	      // this one is part of it, let's see if any others overlap in any direction
	      int j;
	      int beforeany;
	      int afterany;

	      beforeany = false;
	      afterany = false;
	      for (j = 0; j < sys->maxruns; j++)
		{
		  if (greens[j])
		    {
		      if (isDependEvent (i, 0, j, sys->runs[j].step - 1))
			{
			  beforeany = true;
			}
		      if (isDependEvent (j, 0, i, sys->runs[i].step - 1))
			{
			  afterany = true;
			}
		    }
		}
	      if (beforeany && afterany)
		{
		  greens[i] = true;
		  proceed = true;
		}
	    }
	}
    }
}

void
debugPrintArray (int *greens)
{
  int i;

  for (i = 0; i < sys->maxruns; i++)
    {
      if (greens[i])
	{
	  eprintf ("1");
	}
      else
	{
	  eprintf ("0");
	}
    }
  eprintf ("\n");
}

//! Return the SID of a run, or NULL if none found.
Term
getSID (int run)
{
  if ((run >= 0) && (run < sys->maxruns))
    {
      Roledef rd;

      for (rd = sys->runs[run].start; rd != NULL; rd = rd->next)
	{
	  if (rd->type == CLAIM)
	    {
	      if (isTermEqual (rd->to, CLAIM_SID))
		{
		  return (rd->message);
		}
	    }
	}
    }
  return NULL;
}

//! Fix partners on the basis of SIDs
void
matchingSIDs (int *partners)
{
  int run;
  Term SID;

  SID = getSID (0);
  if (SID == NULL)
    {
      error
	("Claim run needs to have a Session ID (SID) for this partner definition.");
    }
  for (run = 1; run < sys->maxruns; run++)
    {
      Term xsid;

      xsid = getSID (run);
      if (isTermEqual (SID, xsid))
	{
	  partners[run] = true;
	}
    }
}

//! Compute mlist for a run for type = READ || SEND
/**
 * Result needs to be deleted afterwards.
 */
Termlist
getMList (int run, int type)
{
  int step;
  Termlist mlist;
  Roledef rd;
  int first;

  mlist = NULL;
  first = true;
  rd = sys->runs[run].start;
  for (step = 0; step < sys->runs[run].step; step++)
    {
      if (rd->type == type)
	{
	  if (rd->compromisetype == COMPR_NONE)
	    {
	      if (inTermlist (sys->current_claim->prec, rd->label))
		{
		  if (first == true)
		    {
		      Term from, to;

		      from = rd->from;
		      to = rd->to;

		      mlist = termlistAppend (mlist, from);
		      mlist = termlistAppend (mlist, to);
		      first = false;
		    }
		  mlist = termlistAppend (mlist, rd->message);
		}
	    }
	}
      rd = rd->next;
    }
  return mlist;
}

//! Matching mlist to claim?
int
isMListMatching (Termlist sendlist, Termlist recvlist, int run)
{
  Termlist sent, received;
  int result;

  if (sys->current_claim->protocol != sys->runs[run].protocol)
    {
      return false;
    }
  sent = getMList (run, SEND);
  result = isTermlistEqual (recvlist, sent);
  if (result)
    {
      received = getMList (run, READ);
      result = isTermlistEqual (sendlist, received);
      termlistDelete (received);
    }

  termlistDelete (sent);

  return result;
}

//! Fix partners on the basis of CK_HMQV message list
void
matchingMList (int *partners)
{
  int run;
  Termlist sendlist, recvlist;

  // Hardcoded to claim run
  sendlist = getMList (0, SEND);
  recvlist = getMList (0, READ);

  for (run = 1; run < sys->maxruns; run++)
    {
      if (isMListMatching (sendlist, recvlist, run))
	{
	  partners[run] = true;
	}
    }
  termlistDelete (sendlist);
  termlistDelete (recvlist);
}

//! get array of partners
/**
 * Depending on the settings in switches, returns the partner array. This is a
 * mapping from runs to booleans, where true means it is a partner of the claim
 * run (0).
 *
 * Note: should be free'd afterwards!
 */
int *
getPartnerArray (void)
{
  int run;
  int *partners;

  partners = (int *) malloc (sizeof (int) * sys->maxruns);
  partners[0] = true;
  for (run = 1; run < sys->maxruns; run++)
    {
      partners[run] = false;
    }

  switch (switches.partnerDefinition)
    {
    case 0:
      propagateOverlap (partners);
      break;
    case 1:
      matchingHistories (partners);
      break;
    case 2:
      matchingSIDs (partners);
      break;
    case 3:
      matchingMList (partners);
      break;
    }

  // propagate partners into runs
  for (run = 1; run < sys->maxruns; run++)
    {
      sys->runs[run].partner = partners[run];
    }

  return partners;
}
