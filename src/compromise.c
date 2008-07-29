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
#include "partner.h"

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
Protocol compromiseProtocol (Protocol sourceprot);

//! For the compromise attacks, all protocols are cloned and special new protocols are added.
/**
 * For now, they're all active attacks.
 * 0: none
 * 1: key
 * 2: all
 *
 * The main idea is that local things may get compromised. Of course, if one
 * manages this during the session (say with your partner), all bets are off.
 * The idea is to find the strongest possible attack class that may be
 * countered.
 *
 * We distinguish between long-term secrets (sk(A), unhash) and short-term stuff.
 *
 * I can see two types of compromise attack: one is a 'network' attack which
 * performs e.g. cryptanalysis. This type may take some time. It only gets the
 * short term keys and everything it can decrypt from that. Hence from {h(na)}k
 * we get k,h(na) but not na.
 *
 * The second type is a local attack, which assumes somehow the memory of a
 * computer is hacked. This yields everything local and hence we get (in the
 * previous case) na and k.
 *
 * To prove: is the second type strictly stronger than the first one?
 *
 * For the first one it is clear that one can consider active versus passive:
 * was the intruder already manipulating messages before the key was
 * compromised? A realistic assumption seems to have a split between both
 * phases: before the split, compromise may occur, but after the split (when
 * the run starts with the claim) no more compromised stuff. No run overlaps
 * the split.
 *
 * For the second class it seems natural that the intruder is already active,
 * and it is also not so clear that there may be a 'split' in time between both
 * actions. Hence here we may require that the agent that is compromised is not
 * in the set of agents you think you're talking to.
 *
 * Observations:
 *
 * Further investigation and testing have revealed that the 'active' variant
 * may be equally strong as the complete local compromise attack. This is
 * because the intruder can learn any locals, which is about as good as
 * inserting his own, and ultimately these attacks are a form of message replay
 * attack it seems. Hence the form of the message is more or less the same.
 */

//! Check SID based partner definition requirements.
void
checkSIDrequirements (void)
{
  Protocol p;

  for (p = sys->protocols; p != NULL; p = p->next)
    {
      Role r;

      for (r = p->roles; r != NULL; r = r->next)
	{
	  Roledef rd;
	  int SIDfound;

	  SIDfound = false;
	  for (rd = r->roledef; rd != NULL; rd = rd->next)
	    {
	      if (rd->type == CLAIM)
		{
		  if (rd->to == CLAIM_SID)
		    {
		      SIDfound = true;
		      break;
		    }
		}
	    }
	  if (!SIDfound)
	    {
	      error
		("For a partner definition based on session identifiers, all roles need to have explicit SID claims.");
	    }
	}
    }
}

//! Check compromise requirements
void
checkCompromiseRequirements (void)
{
  if (switches.partnerDefinition == 2)
    {
      /**
       * SID based partner definition requires that it is defined for all partners.
       */
      checkSIDrequirements ();
    }
}

void
compromisePrepare (const System mysys)
{
  sys = mysys;

  if (switches.compromiseType > 0)
    {
      /*
       * Check for requirements
       */
      checkCompromiseRequirements ();

      // Duplication needed.
      Protocol newprots, oldprots, lastprot;

      oldprots = sys->protocols;
      newprots = NULL;
      lastprot = NULL;
      while (oldprots != NULL)
	{
	  Protocol newprot;

	  if (oldprots->compromiseProtocol == false)
	    {
	      // Duplicate this non-compromise protocol
	      newprot = compromiseProtocol (oldprots);
	      newprot->next = newprots;
	      newprots = newprot;
	      // Count the new protocol
	      protocolCount++;
	    }
	  // Store the last protocol and move on
	  lastprot = oldprots;
	  oldprots = oldprots->next;
	}
      // We've duplicated all, so we can append them
      if (lastprot != NULL)
	{
	  lastprot->next = newprots;
	}
      // DEBUG TODO
#ifdef DEBUG
      if (DEBUGL (1))
	{
	  Protocol prot;

	  eprintf ("Role list after duplication for compromise");
	  for (prot = sys->protocols; prot != NULL; prot = prot->next)
	    {
	      eprintf ("---------------------\n");
	      eprintf ("Protocol ");
	      termPrint (prot->nameterm);
	      eprintf ("\n");
	      rolesPrint (prot->roles);
	    }
	}
#endif
    }
}

//! Is the run compromised?
int
isRunCompromised (const int run)
{
  return (sys->runs[run].protocol->compromiseProtocol);
}

// Count the number of compromised runs
int
countCompromisedRuns (void)
{
  int run;
  int count;

  count = 0;
  for (run = 0; run < sys->maxruns; run++)
    {
      if (isRunCompromised (run))
	{
	  count++;
	}
    }
  return count;
}

//! Invent a new name for this protocol
Term
makeNewName (const Term oldname)
{
  Term newname;
  Term firstleaf;

  if (oldname == NULL)
    {
      return NULL;
    }
  newname = termDuplicateDeep (oldname);
  firstleaf = newname;
  while (!isTermLeaf (firstleaf))
    {
      firstleaf = deVar (firstleaf);
      if (isTermEncrypt (firstleaf))
	{
	  firstleaf = TermOp (firstleaf);
	}
      else
	{
	  if (isTermTuple (firstleaf))
	    {
	      firstleaf = TermOp1 (firstleaf);
	    }
	  else
	    {
	      error ("Protocol name term of unknown compound type.");
	    }
	}
    }
  firstleaf = deVar (firstleaf);
  TermSymb (firstleaf) = symbolNextFree (TermSymb (firstleaf));
  return newname;
}

//! Check for locals
int
containsLocal (Role r, Term t)
{
  int res;

  int checkT (Term t)
  {
    if (inTermlist (r->locals, t))
      {
	return 0;
      }
    else
      {
	return 1;
      }
  }

  res = term_iterate_leaves (t, checkT);
  if (res == 0)
    {
      return true;
    }
  else
    {
      return false;
    }
}

//! Compromise data from a message
/**
 * Append to the existing list.
 * Depends on the compromise test.
 */
Termlist
learnFromMessage (Role r, Termlist tl, Term t)
{
  t = deVar (t);
  if (realTermLeaf (t))
    {
      if (switches.compromiseType == 1)
	{
	  // Key compromise: scan for SessionKey type
	  if (inTermlist (t->stype, TERM_SessionKey))
	    {
	      tl = termlistAddNew (tl, t);
	    }
	}
      if (switches.compromiseType == 2)
	{
	  if (inTermlist (r->locals, t))
	    {
	      tl = termlistAddNew (tl, t);
	    }
	}
    }
  else
    {
      if (realTermTuple (t))
	{
	  tl = learnFromMessage (r, tl, TermOp1 (t));
	  tl = learnFromMessage (r, tl, TermOp2 (t));
	}
      else if (realTermEncrypt (t))
	{
	  // We learn the whole encryption if it contains a local
	  if (switches.compromiseType == 2)
	    {
	      if (containsLocal (r, t))
		{
		  tl = termlistAddNew (tl, t);
		}
	    }

	  // Iterate for more information
	  tl = learnFromMessage (r, tl, TermOp (t));
	  tl = learnFromMessage (r, tl, TermKey (t));

	  // We learn the key if it contains a local
	  if (containsLocal (r, TermKey (t)))
	    {
	      tl = termlistAddNew (tl, TermKey (t));
	    }
	}
    }
  return tl;
}

//! Create a rodedef node for a compromised send.
Roledef
createCompromiseSend (Role role, Term compromised)
{
  Roledef rd;

  rd = roledefAdd (NULL, SEND, TERM_Compromise, role->nameterm,
		   role->nameterm, compromised, NULL);
  return rd;
}

//! RoleDef constuction
/**
 * Given the head, appends rdnew to the end. Returns the new head.
 */
Roledef
roledefAppend (Roledef rdhead, Roledef rdnew)
{
  Roledef rdtail;

  rdtail = roledefTail (rdhead);
  if (rdtail == NULL)
    {
      return rdnew;
    }
  else
    {
      rdtail->next = rdnew;
      return rdhead;
    }
}

//! Duplicate an old protocol into a new (compromise) protocol
/**
 * We need to duplicate any subparts we modify. This includes all roles and
 * events, as we will be relabeling them.
 *
 * We will get rid of e.g. claims in the process, as they contain pointers to
 * the protocol again.
 *
 * @TODO In general this is a hairy situation, as we'd want to replace protocol
 * pointers and protocol nameterms throughout all children. A more complete
 * check is advisable.
 */
Protocol
compromiseProtocol (Protocol sourceprot)
{
  Protocol destprot;
  Role oldrole, newroles;
  Term newname, oldname;

  destprot = protocolDuplicate (sourceprot);
  destprot->compromiseProtocol = true;

  // Give it a new name
  oldname = destprot->nameterm;
  newname = makeNewName (oldname);
  destprot->nameterm = newname;

  // Propagate the name through to the roles
  newroles = NULL;
  for (oldrole = destprot->roles; oldrole != NULL; oldrole = oldrole->next)
    {
      int interesting;
      Role newrole;
      Roledef rd, rdhead, rdtail;
      Termlist compTerms, compKnown;

      interesting = false;	// Only of interest when something is leaked.
      compTerms = NULL;		// What should be sent out at some point
      compKnown = NULL;		// What we have sent out already
      newrole = roleDuplicate (oldrole);

      rdhead = NULL;
      rd = newrole->roledef;
      while (rd != NULL)
	{
	  int includeevent;

	  includeevent = false;

	  if (rd->type != CLAIM)
	    {
	      includeevent = true;
	    }
	  else
	    {
	      // It is a claim
	      if (rd->to == CLAIM_Secret)
		{
		  /* Secrecy claims are explicitly included: they in fact store
		   * 'intermediate' products like the generated keys.
		   * TODO this is not really what we want. Rather we want an action like "internal compute" or
		   * something like that.
		   */
		  includeevent = true;
		}
	      else
		{
		  if (rd->to == CLAIM_SID)
		    {
		      /* We include the SID events for two reasons:
		       * 1. They are part of the intermediate products.
		       * 2. They need to be in compromised runs for the partner check.
		       */
		      includeevent = true;
		    }
		}

	    }
	  if (includeevent)
	    {
	      Roledef newrd;
	      Labelinfo linfo;
	      Termlist tlsend;

	      newrd = roledefDuplicate1 (rd);

	      // Scan what is new here to be sent etc. later
	      // The algorithm depends on the type of compromise
	      compTerms =
		learnFromMessage (newrole, compTerms, newrd->message);

	      // If it is a send, we already do stuff.
	      // Note that plain received/sent is already in the
	      // intruder knowledge for sure.
	      if ((rd->type == SEND) || (rd->type == READ))
		{
		  compKnown = termlistAppend (compKnown, rd->message);
		}

	      // Each role event must be scanned and tags modified.
	      newrd->label = termSubstitute (newrd->label, oldname, newname);
	      linfo = label_find (sys->labellist, newrd->label);
	      if (linfo == NULL)
		{
		  linfo = label_create (newrd->label, destprot);
		  linfo->ignore = true;
		  sys->labellist = list_append (sys->labellist, linfo);
		}

	      // Compute termlist of things to send now.
	      // Note tlsend is not delete, but concatenated to compKnown
	      // further on.
	      tlsend = termlistNotIn (compTerms, compKnown);
	      if (tlsend != NULL)
		{
		  Roledef rdcompr;
		  // Add another node for the compromise.
		  // Here we assume rdtail is not NULL by construction.
		  interesting = true;

		  rdcompr = createCompromiseSend (newrole,
						  termlist_to_tuple (tlsend));
		  // If it is a recv, we add it at the end
		  // but if it is a send, we insert it before
		  if (rd->type == READ)
		    {
		      // Read, append
		      rdhead = roledefAppend (rdhead, newrd);
		      rdhead = roledefAppend (rdhead, rdcompr);
		    }
		  else
		    {
		      // Non-read, prepend
		      rdhead = roledefAppend (rdhead, rdcompr);
		      rdhead = roledefAppend (rdhead, newrd);
		    }
		}
	      else
		{
		  //
		  rdhead = roledefAppend (rdhead, newrd);
		}
	      compKnown = termlistConcat (compKnown, tlsend);
	    }
	  rd = rd->next;
	}

      // Cleanup
      termlistDelete (compTerms);
      termlistDelete (compKnown);

      newrole->roledef = rdhead;
      if (interesting)
	{
	  // Append, move on
	  newrole->next = newroles;
	  newroles = newrole;
	}
    }
  destprot->roles = newroles;

  return destprot;
}

//! Check whether actor of a run is one of the claim agents.
/**
 * Hardcoded: claim run is 0
 */
int
actorInClaim (const System sys, const int run)
{
  if (inTermlist (sys->runs[0].rho, agentOfRun (sys, run)))
    {
      return true;
    }
  else
    {
      return false;
    }
}

//! Check for invalid states
int
compromisePrune (void)
{
  if (switches.compromiseType > 0)
    {
      /*
       * The idea is that compromised runs must be separated in time somehow
       * from the claim run, with no overlapping runs forcing them to be
       * 'close' somehow.
       */
      int run;
      int *partners;
      int result;

      partners = getPartnerArray ();
      result = false;
      for (run = 0; run < sys->maxruns; run++)
	{
	  if (partners[run])
	    {
	      if (isRunCompromised (run))
		{
		  // One of the partners is compromised, prune
		  result = true;
		  break;
		}
	    }
	}
      free (partners);
      return result;
    }
  return false;
}
