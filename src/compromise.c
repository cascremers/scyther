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
#include "binding.h"
#include "heuristic.h"

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
  if ((switches.partnerDefinition == 2) || (switches.partnerDefinition == 5))
    {
	/**
	 * SID based partner definitions requires that it is defined for all partners.
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
      removeProtocolCompromiseEvents (prot);
    }
}

//! Is the run compromised?
/**
 * Returns value with OR'ed value of things.
 */
int
isRunCompromised (const int run)
{
  List bl;
  int stacked;

  stacked = 0;
  for (bl = sys->bindings; bl != NULL; bl = bl->next)
    {
      Binding b;

      b = (Binding) bl->data;
      if (b->done)
	{
	  if (b->run_from == run)
	    {
	      // This comes from this run
	      Roledef rd;

	      rd = eventRoledef (sys, run, b->ev_from);
	      stacked = stacked | rd->compromisetype;
	    }
	}
    }
  return stacked;
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
  for (run = 0; run < sys->maxruns; run++)
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
 */
Termlist
learnFromMessage (Role r, Termlist tl, Term t, int type)
{
  t = deVar (t);
  if (realTermLeaf (t))
    {
      if (type == COMPR_SKR)
	{
	  // Key compromise: scan for SessionKey type
	  /**
	   * Still badly documented: defining a variable or constant with the
	   * SessionKey type makes it available through session-key reveal
	   * queries.
	   */
	  if (inTermlist (t->stype, TERM_SessionKey))
	    {
	      tl = termlistAddNew (tl, t);
	    }
	}
      else
	{
	  if (((type == COMPR_RNR) && (!isTermVariable (t)))
	      || (type == COMPR_SSR))
	    {
	      if (inTermlist (r->locals, t))
		{
		  tl = termlistAddNew (tl, t);
		}
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
      else
	{
	  if (realTermEncrypt (t))
	    {
	      if ((type == COMPR_SSR) && (!switches.SSRfilter))
		{
		  // We learn the whole encryption if it contains a local
		  if (containsLocal (r, t))
		    {
		      tl = termlistAddNew (tl, t);
		    }
		}
	      if (switches.SKRinfer)
		{
		  /* If --SKRinfer then automatically infer session keys.
		   */
		  if (type == COMPR_SKR)
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
/**
 * Return true if state needs to be pruned.
 */
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
	      if (type & (COMPR_SKR | COMPR_SSR))
		{
		  // One of the partners is compromised with type SKR/SSR, prune
		  result = true;
		  break;
		}
	    }
	}
      return result;
    }
  return false;
}

//! Check whether a compromise RNR occurs in a partner run.
int
compromiseRNRpartner (int *partners, Term a)
{
  // Check for RNR compromise type
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      if (partners[run])
	{
	  if (isTermEqual (agentOfRun (sys, run), a))
	    {
	      int type;

	      type = isRunCompromised (run);
	      if (type & COMPR_RNR)
		{
		  return true;
		}
	    }
	}
    }
  return false;
}

//! Insert compromise send for message list
/**
 * The head pointer of r->roledef is automatically updated.
 * Return pointer to inserted message or tail (if rdlast when none)
 */
Roledef
addComprSend (Role r, Roledef rdlast, Termlist tl, int type)
{
  if (tl != NULL)
    {
      Term tlm;

      tlm = termlist_to_tuple (tl);
      r->roledef =
	roledefInsert (r->roledef, rdlast, SEND, TERM_Compromise, r->nameterm,
		       r->nameterm, tlm, NULL);
      if (rdlast == NULL)
	{
	  r->roledef->compromisetype = type;
	  return r->roledef;
	}
      else
	{
	  rdlast->next->compromisetype = type;
	  return rdlast->next;
	}
    }
  else
    {
      return rdlast;
    }
}

//! Insert Compromise events into role
/**
 * Special case for SSRinfer = 1: If so, we scan the role for such things first.
 * If compromise event, we just leave it, and add no further SSR reveals.
 * If no compromise event, we may add them.
 */
void
adaptRoleCompromised (Protocol p, Role r)
{
  Roledef rd;
  Termlist SKRseen;
  Termlist SSRseen;
  Termlist RNRseen;
  int addSSR;

  /*
   * Phase 1: Scan for manual compromise events if relevant.
   */
  addSSR = false;
  if (switches.SSR && (switches.SSRinfer > 0))
    {
      addSSR = true;
      if (switches.SSRinfer == 1)
	{
	  for (rd = r->roledef; rd != NULL; rd = rd->next)
	    {
	      if (isCompromiseEvent (rd))
		{
		  addSSR = false;
		  break;
		}
	    }
	}
    }

  /*
   * Phase 2: Deduce and add
   */
  SKRseen = NULL;
  SSRseen = NULL;
  RNRseen = NULL;
  for (rd = r->roledef; rd != NULL; rd = rd->next)
    {
      //********************************************************
      // Add seen stuff
      if (rd->type == SEND || rd->type == RECV)
	{
	  SKRseen = termlistConcat (SKRseen, tuple_to_termlist (rd->message));
	  SSRseen = termlistConcat (SSRseen, tuple_to_termlist (rd->message));
	  RNRseen = termlistConcat (RNRseen, tuple_to_termlist (rd->message));
	}
      if (!isCompromiseEvent (rd))
	{
	  Roledef rdlast;

	  rdlast = rd;

	  //********************************************************
	  // Scan for SKR
	  if (switches.SKR)
	    {
	      Termlist SKRnew;
	      Termlist SKRsend;

	      SKRnew = NULL;
	      if (rd->type == CLAIM)
		{
		  if (isTermEqual (rd->to, CLAIM_SKR))
		    {
		      SKRnew = termlistAppend (SKRnew, rd->message);
		    }
		}
	      if (rd->type == SEND || rd->type == RECV)
		{
		  // Here we actually do inference of keys. 
		  SKRnew =
		    learnFromMessage (r, SKRnew, rd->message, COMPR_SKR);
		}
	      // Add stuff
	      SKRsend = termlistNotIn (SKRnew, SKRseen);
	      rdlast = addComprSend (r, rdlast, SKRsend, COMPR_SKR);
	      // Continue
	      termlistDelete (SKRnew);
	      SKRseen = termlistConcat (SKRseen, SKRsend);
	    }
	  //********************************************************
	  // Scan for SSR
	  if (addSSR)
	    {
	      Termlist SSRnew;
	      Termlist SSRsend;

	      SSRnew = learnFromMessage (r, NULL, rd->message, COMPR_SSR);
	      // Add stuff
	      SSRsend = termlistNotIn (SSRnew, SSRseen);
	      rdlast = addComprSend (r, rdlast, SSRsend, COMPR_SSR);
	      // Continue
	      termlistDelete (SSRnew);
	      SSRseen = termlistConcat (SSRseen, SSRsend);
	    }
	  //********************************************************
	  // Scan for RNR
	  if (switches.RNR)
	    {
	      Termlist RNRnew;
	      Termlist RNRsend;

	      RNRnew = learnFromMessage (r, NULL, rd->message, COMPR_RNR);
	      // Add stuff
	      RNRsend = termlistNotIn (RNRnew, RNRseen);
	      rdlast = addComprSend (r, rdlast, RNRsend, COMPR_RNR);
	      // Continue
	      termlistDelete (RNRnew);
	      RNRseen = termlistConcat (RNRseen, RNRsend);
	    }
	  //********************************************************
	  // Jump
	  rd = rdlast;
	}
    }
  termlistDelete (SKRseen);
  termlistDelete (SSRseen);
  termlistDelete (RNRseen);
}

//! Delay all compromise events in an atomic section to the end of the atomic section
/**
 * This mimics cryptographic models which don't allow any compromise between a
 * receive and a send as 'send' queries are considered atomic.
 */
void
delayCompromiseAtomic (const Protocol p, const Role r)
{
  Roledef delayed;
  Roledef rdold;
  Roledef rdnew;
  int empty;

  delayed = NULL;
  rdnew = NULL;

  rdold = r->roledef;
  empty = true;
  while (rdold != NULL)
    {
      Roledef rdnext;
      int flush;

      // Isolate event
      rdnext = rdold->next;
      rdold->next = NULL;

      // See where to put it
      if (isCompromiseEvent (rdold))
	{
	  // Delay this event
	  delayed = roledefAppend (delayed, rdold);
	}
      else
	{
	  // Append this event here
	  rdnew = roledefAppend (rdnew, rdold);
	  empty = false;
	}

      // Do we need to flush?
      flush = false;
      if (rdnext == NULL)
	{
	  // Always at the end
	  flush = true;
	}
      else
	{
	  if ((rdnext->type == RECV) || (rdnext->type == CLAIM))
	    {
	      if (!empty)
		{
		  // Don't flush in initial segment, otherwise fine
		  flush = true;
		}
	    }
	}
      if (flush)
	{
	  rdnew = roledefAppend (rdnew, delayed);
	  delayed = NULL;
	}

      // Continue
      rdold = rdnext;
    }

  // Store new event order
  r->roledef = rdnew;
}

//! Unfold compromise events consisting of tuples
/**
 * This does not make a difference for the algorithm,
 * but it makes displaying things a bit easier.
 */
void
unfoldCompromise (Protocol p, Role r)
{
  Roledef rdnew;
  Roledef rdold;
  Roledef rd;

  rdnew = NULL;
  rdold = r->roledef;
  for (rd = rdold; rd != NULL; rd = rd->next)
    {
      if (isCompromiseEvent (rd) && isTermTuple (rd->message))
	{
	  Termlist tl, tltup;

	  tltup = tuple_to_termlist (rd->message);
	  for (tl = tltup; tl != NULL; tl = tl->next)
	    {
	      Roledef rd2;

	      rd2 = roledefDuplicate1 (rd);
	      rd2->message = tl->term;
	      rdnew = roledefAppend (rdnew, rd2);
	    }
	  termlistDelete (tltup);
	}
      else
	{
	  Roledef rd2;

	  rd2 = roledefDuplicate1 (rd);
	  rdnew = roledefAppend (rdnew, rd2);
	}
    }
  r->roledef = rdnew;
  roledefDelete (rdold);
}

//! Insert Compromise events into all protocols
void
adaptProtocolsCompromised (void)
{
  Protocol p;

  if ((switches.SSR && (switches.SSRinfer > 0)) || switches.SKR
      || switches.RNR)
    {
      for (p = sys->protocols; p != NULL; p = p->next)
	{
	  if (!isHelperProtocol (p))
	    {
	      Role r;

	      for (r = p->roles; r != NULL; r = r->next)
		{
		  adaptRoleCompromised (p, r);
		  if (switches.delayCompromiseAtomic)
		    {
		      delayCompromiseAtomic (p, r);
		    }
		  unfoldCompromise (p, r);
		}
	    }
	}
    }
}

//! Prepare the system with respect to compromises.
void
compromisePrepare (const System mysys)
{
  sys = mysys;

  if ((switches.SSRinfer == 2) || (!switches.SSR))
    {
      /* If we are surely not using any self-defined compromised events, remove them.
       * */
      removeCompromiseEvents ();
    }
  if (switches.SSR || switches.SKR || switches.RNR)
    {
      /*
       * Check for requirements
       */
      checkCompromiseRequirements ();
      /* Fix protocol
       */
      adaptProtocolsCompromised ();
    }

  // Report (if needed)
  if (switches.reportCompromise)
    {
      Protocol prot;

      for (prot = sys->protocols; prot != NULL; prot = prot->next)
	{
	  eprintf ("---------------------\n");
	  eprintf ("Protocol ");
	  termPrint (prot->nameterm);
	  eprintf ("\n");
	  rolesPrint (prot->roles);
	}
      exit (0);
    }
}

//! Check preconditions of a particular compromise event in a realizable pattern
/**
 * One remaining problem is the tension between the 'first binding' enforcement 
 * and the compromise enablement that's only valid after a certain point.
 *
 * The rationale here is to check the prefix-bound nature of the OS (where it
 * differs from the future-inspection in the crypto models). It therefore only
 * applies to SKR and SSR where the partnering definition is used.
 */
int
checkCompromiseSanityEvent (const int run, const int ev, const int comprtype)
{
  if ((comprtype == COMPR_SKR) || (comprtype == COMPR_SSR))
    {
      if (isCompromisePartner (run, ev))
	{
	  // It is a partner based on the preceding events, so that is bad.
	  return false;
	}
    }
  return true;
}

//! Check realizability
int
isRealizable ()
{
  return (count_selectable_goals (sys) == 0);
}

//! Check preconditions of compromise events in a realizable pattern
/**
 * @TODO: This only makes sense for partnering definition 1, I guess.
 *
 * One remaining problem is the tension between the 'first binding' enforcement 
 * and the compromise enablement that's only valid after a certain point.
 */
int
checkCompromiseSanity ()
{
  List bl;

  /*
   * First some big preconditions to this test
   */
  if (switches.partnerDefinition != 1)
    {
      // For the other partner definitions no final check is needed.
      return true;
    }
  if ((switches.SKR == 0) && (switches.SSR == 0))
    {
      // No SKR, no SSR: irrelevant
      return true;
    }

  /*
   * Only done for realizable patterns
   */
  if (!isRealizable ())
    {
      // This check only makes sense for realizable patterns.
      // Not realizable? Nothing to see here, please continue.
      return true;
    }

  /*
   * Now we actually scan for the conditions
   */
  for (bl = sys->bindings; bl != NULL; bl = bl->next)
    {
      Binding b;

      b = (Binding) bl->data;
      if (b->done)
	{
	  // This comes from this event
	  int ct;
	  Roledef rd;

	  rd = eventRoledef (sys, b->run_from, b->ev_from);
	  ct = rd->compromisetype;
	  if (ct != 0)
	    {
	      // It is actually a compromise
	      if (!checkCompromiseSanityEvent (b->run_from, b->ev_from, ct))
		{
		  return false;
		}
	    }
	}
    }
  return true;
}
