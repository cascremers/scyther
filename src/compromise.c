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
Protocol compromiseProtocol (Protocol sourceprot, int type);

//! Check SID based partner definition requirements.
void
checkSIDrequirements (void)
{
  Protocol p;

  for (p = sys->protocols; p != NULL; p = p->next)
    {
      if (!isHelperProtocol (p))
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
		      if (isTermEqual (rd->to, CLAIM_SID))
			{
			  SIDfound = true;
			  break;
			}
		    }
		}
	      if (!SIDfound)
		{
		  globalError++;
		  error_pre ();
		  eprintf ("Protocol ");
		  termPrint (p->nameterm);
		  eprintf (", role ");
		  termPrint (r->nameterm);
		  eprintf ("\n");
		  globalError--;
		  error
		    ("For a partner definition based on session identifiers, all roles need to have explicit SID claims.");
		}
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

//! Check whether we should compromise this protocol
/**
 * We don't compromise special helper protocols. These start with an '@'
 * conform the usage in Gijs Hollestelle's work.
 */
int
shouldCompromiseProtocol (Protocol prot)
{
  if (isHelperProtocol (prot))
    {
      return false;
    }
  return true;
}

//! Check whether a given event (roledef) is a compromise event
int
isCompromiseEvent (Roledef rd)
{
  if (rd != NULL)
    {
      if (rd->type == SEND)
	{
	  if (isTermEqual (rd->label, TERM_Compromise))
	    {
	      return true;
	    }
	}
    }
  return false;
}

//! Check whether role has a compromise event
int
hasRoleCompromiseEvent (Role r)
{
  Roledef rd;

  for (rd = r->roledef; rd != NULL; rd = rd->next)
    {
      if (isCompromiseEvent (rd))
	{
	  return true;
	}
    }
  return false;
}

//! Check protocol for role compromise events
int
hasProtocolCompromiseEvent (Protocol p)
{
  Role r;

  for (r = p->roles; r != NULL; r = r->next)
    {
      if (hasRoleCompromiseEvent (r))
	{
	  return true;
	}
    }
  return false;
}

//! Remove compromise events from a role
void
removeRoleCompromiseEvents (Role role)
{
  Roledef rd, prev;

  // Scan for first non-compromise and store this new start
  rd = role->roledef;
  while ((rd != NULL) && (isCompromiseEvent (rd)))
    {
      rd = rd->next;
    }
  role->roledef = rd;

  // Filter the remainder
  prev = NULL;
  while (rd != NULL)
    {
      if (isCompromiseEvent (rd))
	{
	  /* Note that the above condition is never true for the first event
	   * (by the postcondition of the first loop) and therefore we can be
	   * sure prev != NULL by the else case.
	   */
	  prev->next = rd->next;
	}
      else
	{
	  prev = rd;
	}
      rd = rd->next;
    }
}

//! Remove compromise events from a protocol
void
removeProtocolCompromiseEvents (Protocol prot)
{
  Role role;

  for (role = prot->roles; role != NULL; role = role->next)
    {
      removeRoleCompromiseEvents (role);
    }
}

//! Remove all compromise events
void
removeCompromiseEvents (void)
{
  Protocol prot;

  for (prot = sys->protocols; prot != NULL; prot = prot->next)
    {
      if (prot->compromiseProtocol == 0)
	{
	  removeProtocolCompromiseEvents (prot);
	}
    }
}

void
compromisePrepare (const System mysys)
{
  sys = mysys;

  if (switches.SSRinfer)
    {
      /* If we are not using any self-defined compromised events, remove them.
       * */
      removeCompromiseEvents ();
    }
  if (switches.SSR || switches.SKR || switches.RNR)
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

	  if (oldprots->compromiseProtocol == 0)
	    {
	      if (shouldCompromiseProtocol (oldprots))
		{
		  /**
		   * Type cases: first the SSR/SKR type and then the RNR type.
		   * We need both for the LKR conditions later.
		   */
		  int type;
		  int created;

		  created = false;
		  for (type = 1; type <= 2; type++)
		    {
		      int create;

		      create = false;
		      if (type == 1)
			{
			  if (switches.SSR || switches.SKR)
			    {
			      create = true;
			    }
			}
		      if (type == 2)
			{
			  if (switches.RNR)
			    {
			      create = true;
			    }
			}

		      if (create)
			{
			  // Duplicate this non-compromise protocol
			  newprot = compromiseProtocol (oldprots, type);
			  created = true;
			  newprot->next = newprots;
			  newprots = newprot;
			  // Count the new protocol
			  protocolCount++;
			}
		    }
		}
	      // Remove any compromise events from the duplicated one
	      removeProtocolCompromiseEvents (oldprots);
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

    }

  // Cleanup any remaining stuff
  removeCompromiseEvents ();

  // Report (if needed)
  if (switches.reportCompromise)
    {
      Protocol prot;

      for (prot = sys->protocols; prot != NULL; prot = prot->next)
	{
	  eprintf ("---------------------\n");
	  eprintf ("Protocol ");
	  termPrint (prot->nameterm);
	  if (prot->compromiseProtocol == 1)
	    {
	      eprintf (", compromise SSR/SKR");
	    }
	  else
	    {
	      if (prot->compromiseProtocol == 2)
		{
		  eprintf (", compromise RNR");
		}
	      else
		{
		  if (prot->compromiseProtocol != 0)
		    {
		      eprintf (", compromise type %i",
			       prot->compromiseProtocol);
		    }
		}
	    }
	  eprintf ("\n");
	  rolesPrint (prot->roles);
	}
      exit (0);
    }
}

//! Is the run compromised?
/**
 * Returns value:
 * 0: nope
 * 1: SSR and SKR
 * 2: RNR
 */
int
isRunCompromised (const int run)
{
  return (sys->runs[run].protocol->compromiseProtocol);
}

// Weigh the number of compromised runs
/** 
 * If a run compromises the attacked agent or supposed partners, we count it as more
 */
int
weighCompromisedRuns (void)
{
  int run;
  int count, countCompr, countAgent, countActor;

  countCompr = 0;
  countAgent = 0;
  countActor = 0;
  // We start at run 1, because run 0 is the claim run which should not be
  // compromised at all.
  for (run = 1; run < sys->maxruns; run++)
    {
      if (isRunCompromised (run))
	{
	  Term cagent;

	  cagent = agentOfRun (sys, run);
	  if (isTermEqual (cagent, agentOfRun (sys, 0)))
	    {
	      countActor++;
	    }
	  else
	    {
	      if (inTermlist (sys->runs[0].rho, cagent))
		{
		  countAgent++;
		}
	      else
		{
		  countCompr++;
		}
	    }
	}
    }
  /*
   * The final computation translates into:
   */
  count = countCompr + (4 * countAgent) + (16 * countActor);
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

  res = term_iterate_open_leaves (t, checkT);
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
 *
 * Type: 1: SSR/SKR
 * 	 2: RNR
 */
Termlist
learnFromMessage (Role r, Termlist tl, Term t, int type)
{
  int takelocal;

  takelocal = false;
  t = deVar (t);
  if (realTermLeaf (t))
    {
      if (type == 1)
	{
	  if (switches.SKR)
	    {
	      // Key compromise: scan for SessionKey type
	      if (inTermlist (t->stype, TERM_SessionKey))
		{
		  tl = termlistAddNew (tl, t);
		}
	    }
	  if (switches.SSR)
	    {
	      if (switches.SSRinfer)
		{
		  takelocal = true;
		}
	    }
	}
      if (type == 2)
	{
	  if (switches.RNR)
	    {
	      takelocal = true;
	    }
	}
      if (takelocal)
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
	  tl = learnFromMessage (r, tl, TermOp1 (t), type);
	  tl = learnFromMessage (r, tl, TermOp2 (t), type);
	}
      else if (realTermEncrypt (t))
	{
	  if (switches.SSRinfer && (!switches.SSRfilter))
	    {
	      /* If SSRinfer is true, and not filtered, we may consider the
	       * full state (and not just from infer commands)
	       */
	      int takeall;

	      takeall = false;

	      // Case 1: SSR (if not restricted to filtering)
	      if (type == 1)
		{
		  if (switches.SSR)
		    {
		      takeall = true;
		    }
		}
	      if (type == 2)
		{
		  if (switches.RNR && switches.RNRinfer)
		    {
		      takeall = true;
		    }
		}
	      if (takeall)
		{
		  // We learn the whole encryption if it contains a local
		  if (containsLocal (r, t))
		    {
		      tl = termlistAddNew (tl, t);
		    }
		}
	    }
	  /* Otherwise we may learn any key terms anyway (automatically
	   * inferred, needs documentation for user!)
	   */
	  if (type == 1)
	    {
	      if (switches.SKR)
		{
		  // We learn the key if it contains a local
		  if (containsLocal (r, TermKey (t)))
		    {
		      tl = termlistAddNew (tl, TermKey (t));
		    }
		}
	    }

	  // Iterate for more information
	  tl = learnFromMessage (r, tl, TermOp (t), type);
	  tl = learnFromMessage (r, tl, TermKey (t), type);
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

//! Create a sequence of roledefs of compromised sends from a list.
Roledef
createCompromiseSends (Role role, Termlist comprlist)
{
  Roledef rd;

  rd = NULL;
  while (comprlist != NULL)
    {
      rd = roledefAdd (rd, SEND, TERM_Compromise, role->nameterm,
		       role->nameterm, comprlist->term, NULL);
      comprlist = comprlist->next;
    }
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

//! Infer session key if needed, from explicit marker
Termlist
learnSessionKey (Termlist compterms, Roledef rd)
{
  if (switches.SKR)
    {
      if (rd->type == CLAIM)
	{
	  if (isTermEqual (rd->to, CLAIM_SKR))
	    {
	      return termlistAppend (compterms, rd->message);
	    }
	}
    }
  return compterms;
}

//! Duplicate an old protocol into a new (compromise) protocol
/**
 * We need to duplicate any subparts we modify. This includes all roles and
 * events, as we will be relabeling them.
 *
 * We will get rid of e.g. claims in the process, as they contain pointers to
 * the protocol again.
 *
 * Type:
 *
 * 1: SSR & SKR variant
 * 2: RNR
 *
 * We assume the caller decides whether we need SSR/SKR/RNR and do not double check.
 *
 * @TODO In general this is a hairy situation, as we'd want to replace protocol
 * pointers and protocol nameterms throughout all children. A more complete
 * check is advisable.
 */
Protocol
compromiseProtocol (Protocol sourceprot, int type)
{
  Protocol destprot;
  Role oldrole, newroles;
  Term newname, oldname;

  destprot = protocolDuplicate (sourceprot);
  destprot->compromiseProtocol = type;
  destprot->parentProtocol = sourceprot;

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
      Roledef rd, rdhead;
      Termlist compTerms, compKnown;

      interesting = false;	// Only of interest when something is leaked.
      compTerms = NULL;		// What should be sent out at some point
      compKnown = NULL;		// What we have sent out already
      newrole = roleDuplicate (oldrole);

      rdhead = NULL;
      rd = newrole->roledef;
      while (rd != NULL)
	{
	  Roledef newrd;
	  Labelinfo linfo;
	  Termlist tlsend;

	  newrd = roledefDuplicate1 (rd);

	  if (isCompromiseEvent (rd))
	    {
	      // If it is a compromise event, it's interesting by definition.
	      interesting = true;
	    }
	  // Scan what is new here to be sent etc. later
	  // The algorithm depends on the type of compromise
	  compTerms =
	    learnFromMessage (newrole, compTerms, newrd->message, type);
	  if (type == 1)
	    {
	      // Special (additional) case for type 1: explicit session key marker
	      compTerms = learnSessionKey (compTerms, newrd);
	    }

	  if (rd->type != READ)
	    {
	      // We reverse the list for prettier printing
	      Termlist tlrev;

	      tlrev = termlistReverse (compTerms);
	      termlistDelete (compTerms);
	      compTerms = tlrev;
	    }
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
	      interesting = true;

	      // Unfold list elements to a list of compromise events.  This
	      // makes for easier interpretation of the output, and is
	      // equivalent in terms of complexity to having a single
	      // (tuple) send.
	      rdcompr = createCompromiseSends (newrole, tlsend);

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
		      /**
		       * For a non-recv, we also append. This has the effect of
		       * making the action atomic, i.e. we assume that
		       * computing the local state for a non-blocking event
		       * also executes the event. This interacts in a more
		       * sensible way with the matching histories definition,
		       * but requires some insight.
		       */
		  rdhead = roledefAppend (rdhead, newrd);
		  rdhead = roledefAppend (rdhead, rdcompr);
		  // Non-read, prepend
		  //rdhead = roledefAppend (rdhead, rdcompr);
		  //rdhead = roledefAppend (rdhead, newrd);
		}
	    }
	  else
	    {
	      // No additional events to be added
	      rdhead = roledefAppend (rdhead, newrd);
	    }
	  compKnown = termlistConcat (compKnown, tlsend);

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
compromisePrune (int *partners)
{
  if (switches.SSR || switches.SKR || switches.RNR)
    {
      /*
       * These effectively encode the preconditions for SSR/SKR:
       * should not be part of the state.
       */
      int run;
      int result;

      result = false;
      for (run = 0; run < sys->maxruns; run++)
	{
	  if (partners[run])
	    {
	      int type;

	      type = isRunCompromised (run);
	      if (type == 1)
		{
		  // One of the partners is compromised with type SKR/SSR, prune
		  result = true;
		  break;
		}
	      if (type == 2)
		{
		  /*
		   * For RNR we do allow compromise of the partners, but
		   * then there should not be a long term compromise then.
		   */
		  if (!isAgentTrusted (sys, agentOfRun (sys, run)))
		    {
		      // There was a long-term compromise at some point.
		      // Hence we prune. Otherwise it's allowed.
		      result = true;
		      break;
		    }
		}
	    }
	}
      free (partners);
      return result;
    }
  return false;
}

//! Check whether a compromise RNR occurs in a partner run.
int
compromiseRNRpartner (int *partners, Term a)
{
  // Check for RNR compromise type
  int r2;

  for (r2 = 0; r2 < sys->maxruns; r2++)
    {
      if (partners[r2])
	{
	  if (isTermEqual(agentOfRun(sys,r2), a))
	    {
	      if (sys->runs[r2].protocol->compromiseProtocol == 2)
		{
		  return true;
		}
	    }
	}
    }
  return false;
}
