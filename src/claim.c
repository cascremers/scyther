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
 *@file claim.c
 *
 * Claim handling for the Arachne engine.
 *
 */

#include <stdlib.h>

#include "termmap.h"
#include "system.h"
#include "label.h"
#include "error.h"
#include "debug.h"
#include "binding.h"
#include "arachne.h"
#include "specialterm.h"
#include "switches.h"
#include "color.h"
#include "cost.h"
#include "timer.h"
#include "compiler.h"
#include "depend.h"

//! When none of the runs match
#define MATCH_NONE 0
//! When the order matches
#define MATCH_ORDER 1
//! When the order is reversed
#define MATCH_REVERSE 2
//! When the content matches
#define MATCH_CONTENT 3

//! This label is fixed
#define LABEL_GOOD -3
//! This label still needs to be done
#define LABEL_TODO -2

extern int globalError;
extern int attack_leastcost;

// Debugging the NI-SYNCH checks
//#define OKIDEBUG

// Forward declaration
int oki_nisynch (const System sys, const int trace_index,
		 const Termmap role_to_run, const Termmap label_to_index);

/*
 * Validity checks for claims
 *
 * Note that the first few operate on claims, and that the tests for e.g. the Arachne engine are seperate.
 */


#ifdef OKIDEBUG
int indac = 0;

void
indact ()
{
  int i;

  i = indac;
  while (i > 0)
    {
      eprintf ("|   ");
      i--;
    }
}
#endif

//! Check complete message match
/**
 * Roledef based.
 *@returns MATCH_NONE or MATCH_CONTENT
 */
int
events_match_rd (const Roledef rdi, const Roledef rdj)
{
  if (isTermEqual (rdi->message, rdj->message) &&
      isTermEqual (rdi->from, rdj->from) &&
      isTermEqual (rdi->to, rdj->to) &&
      isTermEqual (rdi->label, rdj->label) &&
      !(rdi->internal || rdj->internal))
    {
      return MATCH_CONTENT;
    }
  else
    {
      return MATCH_NONE;
    }
}


//! Check complete message match
/**
 *@returns any of the MATCH_ signals
 */
int
events_match (const System sys, const int i, const int j)
{
  Roledef rdi, rdj;

  rdi = sys->traceEvent[i];
  rdj = sys->traceEvent[j];
  if (isTermEqual (rdi->message, rdj->message) &&
      isTermEqual (rdi->from, rdj->from) &&
      isTermEqual (rdi->to, rdj->to) &&
      isTermEqual (rdi->label, rdj->label) &&
      !(rdi->internal || rdj->internal))
    {
      if (rdi->type == SEND && rdj->type == RECV)
	{
	  if (i < j)
	    return MATCH_ORDER;
	  else
	    return MATCH_REVERSE;
	}
      if (rdi->type == RECV && rdj->type == SEND)
	{
	  if (i > j)
	    return MATCH_ORDER;
	  else
	    return MATCH_REVERSE;
	}
    }
  return MATCH_NONE;
}


//! Check nisynch from label_to_index.
int
oki_nisynch_full (const System sys, const Termmap label_to_index)
{
  // Are all labels well linked?
  Termmap label_to_index_scan;

  label_to_index_scan = label_to_index;
  while (label_to_index_scan != NULL)
    {
      if (label_to_index_scan->result != LABEL_GOOD)
	{
#ifdef OKIDEBUG
	  indact ();
	  eprintf ("Incorrectly linked label at the end,");
	  eprintf ("label: ");
	  termPrint (label_to_index_scan->term);
	  eprintf ("\n");
#endif
	  return 0;
	}
      label_to_index_scan = label_to_index_scan->next;
    }
  // Apparently they are all well linked
  return 1;
}

//! Evaluate claims or internal recvs (chooses)
int
oki_nisynch_other (const System sys, const int trace_index,
		   const Termmap role_to_run, const Termmap label_to_index)
{
  int result;

#ifdef OKIDEBUG
  indact ();
  eprintf ("Exploring further assuming this (claim) run is not involved.\n");
  indac++;
#endif
  result = oki_nisynch (sys, trace_index - 1, role_to_run, label_to_index);
#ifdef OKIDEBUG
  indact ();
  eprintf (">%i<\n", result);
  indac--;
#endif
  return result;
}

//! Evaluate recvs
int
oki_nisynch_recv (const System sys, const int trace_index,
		  const Termmap role_to_run, const Termmap label_to_index)
{
  /*
   * Recv is only relevant for already involved runs, and labels in prec
   */
  Termmap role_to_run_scan;
  int result = 7;
  Roledef rd;
  int rid;

  rd = sys->traceEvent[trace_index];
  rid = sys->traceRun[trace_index];

  role_to_run_scan = role_to_run;
  while (role_to_run_scan != NULL)
    {
      if (role_to_run_scan->result == rid)
	{
	  // Involved, but is it a prec label?
	  if (termmapGet (label_to_index, rd->label) == LABEL_TODO)
	    {
	      Termmap label_to_index_buf;
	      int result;

	      label_to_index_buf = termmapDuplicate (label_to_index);
	      label_to_index_buf =
		termmapSet (label_to_index_buf, rd->label, trace_index);
#ifdef OKIDEBUG
	      indact ();
	      eprintf ("Exploring because this (recv) run is involved.\n");
	      indac++;
#endif
	      result =
		oki_nisynch (sys, trace_index - 1, role_to_run,
			     label_to_index_buf);
#ifdef OKIDEBUG
	      indact ();
	      eprintf (">%i<\n", result);
	      indac--;
#endif
	      termmapDelete (label_to_index_buf);
	      return result;
	    }
	}
      role_to_run_scan = role_to_run_scan->next;
    }
  // Apparently not involved
#ifdef OKIDEBUG
  indact ();
  eprintf ("Exploring further assuming this (recv) run is not involved.\n");
  indac++;
#endif
  result = oki_nisynch (sys, trace_index - 1, role_to_run, label_to_index);
#ifdef OKIDEBUG
  indac--;
#endif
  return result;
}


//! Evaluate sends
int
oki_nisynch_send (const System sys, const int trace_index,
		  const Termmap role_to_run, const Termmap label_to_index)
{
  Roledef rd;
  int rid;
  int result = 8;
  int old_run;
  Term rolename;

  rd = sys->traceEvent[trace_index];
  rid = sys->traceRun[trace_index];
  /*
   * Two options: it is either involved or not
   */
  // 1. Assume that this run is not yet involved 
#ifdef OKIDEBUG
  indact ();
  eprintf ("Exploring further assuming (send) run %i is not involved.\n",
	   rid);
  indac++;
#endif
  result = oki_nisynch (sys, trace_index - 1, role_to_run, label_to_index);
#ifdef OKIDEBUG
  indact ();
  eprintf (">%i<\n", result);
  indac--;
#endif
  if (result)
    return 1;

#ifdef OKIDEBUG
  indact ();
  eprintf ("Exploring when %i is involved.\n", rid);
#endif
  // 2. It is involved. Then either already used for this role, or will be now.
  rolename = sys->runs[rid].role->nameterm;
  old_run = termmapGet (role_to_run, rolename);	// what was already stored for this role as the runid
  if (old_run == -1 || old_run == rid)
    {
      int partner_index;

      // Was not involved yet in a registerd way, or was the correct rid
      partner_index = termmapGet (label_to_index, rd->label);
      // Ordered match needed for this label
      // So it already needs to be filled by a recv
      if (partner_index >= 0)
	{
	  // There is already a recv for it
	  if (events_match (sys, partner_index, trace_index) == MATCH_ORDER)
	    {
	      // They match in the right order
	      Termmap role_to_run_buf, label_to_index_buf;

#ifdef OKIDEBUG
	      indact ();
	      eprintf ("Matching messages found for label ");
	      termPrint (rd->label);
	      eprintf ("\n");
#endif
	      /**
	       *@todo Optimization can be done when old_run == rid, no copy of role_to_run needs to be made.
	       */
	      role_to_run_buf = termmapDuplicate (role_to_run);
	      role_to_run_buf = termmapSet (role_to_run_buf, rolename, rid);
	      label_to_index_buf = termmapDuplicate (label_to_index);
	      label_to_index_buf =
		termmapSet (label_to_index_buf, rd->label, LABEL_GOOD);
#ifdef OKIDEBUG
	      indact ();
	      eprintf ("In NI-Synch scan, assuming %i run is involved.\n",
		       rid);
	      indact ();
	      eprintf
		("Exploring further assuming this matching, which worked.\n");
	      indac++;
#endif
	      result =
		oki_nisynch (sys, trace_index - 1, role_to_run_buf,
			     label_to_index_buf);
#ifdef OKIDEBUG
	      indact ();
	      eprintf (">%i<\n", result);
	      indac--;
#endif
	      termmapDelete (label_to_index_buf);
	      termmapDelete (role_to_run_buf);
	      return result;
	    }
	}
    }
  return 0;
}


//! nisynch generalization
/**
 * role_to_run maps the involved roles to run identifiers.
 * label_to_index maps all labels in prec to the event indices for things already found,
 * or to LABEL_TODO for things not found yet but in prec, and LABEL_GOOD for well linked messages (and that have thus defined a runid for the corresponding role).
 * All values not in prec map to -1.
 *@returns 1 iff the claim is allright, 0 iff it is violated.
 */
int
oki_nisynch (const System sys, const int trace_index,
	     const Termmap role_to_run, const Termmap label_to_index)
{
  int type;

  // Check for completed trace
  if (trace_index < 0)
    return oki_nisynch_full (sys, label_to_index);

#ifdef OKIDEBUG
  indact ();
  eprintf ("Checking event %i", trace_index);
  eprintf (" = #%i : ", sys->traceRun[trace_index]);
  roledefPrint (sys->traceEvent[trace_index]);
  eprintf ("\n");
#endif

  type = sys->traceEvent[trace_index]->type;

  if (type == CLAIM || sys->traceEvent[trace_index]->internal)
    return oki_nisynch_other (sys, trace_index, role_to_run, label_to_index);
  if (type == RECV)
    return oki_nisynch_recv (sys, trace_index, role_to_run, label_to_index);
  if (type == SEND)
    return oki_nisynch_send (sys, trace_index, role_to_run, label_to_index);
  /*
   * Exception: no claim, no send, no recv, what is it?
   */
  error ("Unrecognized event type in claim scanner at %i.", trace_index);
  return 0;
}

/*
 * Real checks
 */

//! Check validity of ni-synch claim at event i.
/**
 *@returns 1 iff claim is true.
 */
int
check_claim_nisynch (const System sys, const int i)
{
  Roledef rd;
  int result;
  int rid;
  Termmap f, g;
  Claimlist cl;
  Termlist tl;

  rid = sys->traceRun[i];
  rd = sys->traceEvent[i];
  cl = rd->claiminfo;
  cl->count = statesIncrease (cl->count);
  f = termmapSet (NULL, sys->runs[rid].role->nameterm, rid);

  // map all labels in prec to LABEL_TODO
  g = NULL;

  tl = cl->prec;
  while (tl != NULL)
    {
      g = termmapSet (g, tl->term, LABEL_TODO);
      tl = tl->next;
    }
  /*
   * Check claim
   */
  result = oki_nisynch (sys, i, f, g);
  if (!result)
    {
#ifdef DEBUG
      globalError++;
      warning ("Claim has failed!");
      eprintf ("To be exact, claim label ");
      termPrint (cl->label);
      eprintf (" with prec set ");
      termlistPrint (cl->prec);
      eprintf ("\n");
      eprintf ("i: %i\nf: ", i);
      termmapPrint (f);
      eprintf ("\ng: ");
      termmapPrint (g);
      eprintf ("\n");
      globalError--;
#endif

    }
  termmapDelete (f);
  termmapDelete (g);
  return result;
}

//! Check validity of ni-agree claim at event i.
/**
 *@returns 1 iff claim is true.
 *@todo This is now just a copy of ni-synch, should be fixed asap.
 */
int
check_claim_niagree (const System sys, const int i)
{
  Roledef rd;
  int result;
  int rid;
  Termmap f, g;
  Claimlist cl;
  Termlist tl;

  rid = sys->traceRun[i];
  rd = sys->traceEvent[i];
  cl = rd->claiminfo;
  cl->count = statesIncrease (cl->count);
  f = termmapSet (NULL, sys->runs[rid].role->nameterm, rid);

  // map all labels in prec to LABEL_TODO
  g = NULL;

  tl = cl->prec;
  while (tl != NULL)
    {
      g = termmapSet (g, tl->term, LABEL_TODO);
      tl = tl->next;
    }
  /*
   * Check claim
   */
  result = oki_nisynch (sys, i, f, g);
  if (!result)
    {
#ifdef DEBUG
      warning ("Claim has failed!");
      eprintf ("To be exact, claim label ");
      termPrint (cl->label);
      eprintf (" with prec set ");
      termlistPrint (cl->prec);
      eprintf ("\n");
      eprintf ("i: %i\nf: ", i);
      termmapPrint (f);
      eprintf ("\ng: ");
      termmapPrint (g);
      eprintf ("\n");
#endif

    }
  termmapDelete (f);
  termmapDelete (g);
  return result;
}

//! Get label event
Roledef
get_label_event (const System sys, const Labelinfo linfo, const Term role,
		 const Term label, const Termmap runs)
{
  Roledef rd, rd_res;
  int i;
  int run;

  run = termmapGet (runs, role);
  if (run != -1)
    {
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
	  eprintf (" and recvrole ");
	  termPrint (linfo->recvrole);
	  eprintf ("\n");
	  globalError--;
	  error ("Run mapping is out of bounds.");
	}
#endif
      rd = sys->runs[run].start;
      rd_res = NULL;
      i = 0;
      while (i < sys->runs[run].step && rd != NULL)
	{
	  if (isTermEqual (rd->label, label))
	    {
	      rd_res = rd;
	      rd = NULL;
	    }
	  else
	    {
	      rd = rd->next;
	    }
	  i++;
	}
      return rd_res;
    }
  else
    {
      return NULL;
    }
}

//! Check generic agree claim for a given set of runs, arachne style
int
arachne_runs_agree (const System sys, const Claimlist cl, const Termmap runs)
{
  Termlist labels;
  int flag;

#ifdef DEBUG
  if (DEBUGL (5))
    {
      eprintf ("Checking runs agreement for Arachne.\n");
      termmapPrint (runs);
      eprintf ("\n");
    }
#endif

  flag = 1;
  labels = cl->prec;
  while (flag && labels != NULL)
    {
      // For each label, check whether it matches. Maybe a bit too strict (what about variables?)
      // Locate roledefs for recv & send, and check whether they are before step
      Roledef rd_send, rd_recv;
      Labelinfo linfo;

      // Main
      linfo = label_find (sys->labellist, labels->term);
      if (!linfo->ignore)
	{
	  rd_send =
	    get_label_event (sys, linfo, linfo->sendrole, labels->term, runs);
	  rd_recv =
	    get_label_event (sys, linfo, linfo->recvrole, labels->term, runs);

	  if (rd_send == NULL || rd_recv == NULL)
	    {
	      // False!
	      flag = 0;
	    }
	  else
	    {
	      // Compare
	      if (events_match_rd (rd_send, rd_recv) != MATCH_CONTENT)
		{
		  // False!
		  flag = 0;
		}
	    }
	}

      labels = labels->next;
    }
  return flag;
}

// Result structure
struct flag_and_termmap
{
  int flag;
  Termmap termmap;
};

struct flag_and_termmap
fill_roles (const System sys, const Claimlist cl, const Termmap runs_involved,
	    const int require_order, Termlist roles_tofill)
{
  struct flag_and_termmap ftres;

  ftres.flag = true;
  ftres.termmap = runs_involved;

  if (roles_tofill == NULL)
    {
      // All roles have been chosen
      if (arachne_runs_agree (sys, cl, runs_involved))
	{
	  // niagree holds
	  if (require_order)
	    {
	      // Stronger claim: nisynch. Test for ordering as well.
	      ftres.flag = labels_ordered (runs_involved, cl->prec);
	    }
	  return ftres;
	}
      else
	{
	  // niagree does not hold
	  ftres.flag = false;
	  return ftres;
	}
    }
  else
    {
      // Choose a run for this role, if possible
      // Note that any will do
      int run;

      ftres.flag = false;
      for (run = 0; run < sys->maxruns; run++)
	{
	  // Has to be from the right protocol
	  if (sys->runs[run].protocol == cl->protocol)
	    {
	      // Has to be the right name
	      if (isTermEqual
		  (sys->runs[run].role->nameterm, roles_tofill->term))
		{
		  // Choose, iterate
		  // Mimic lazy evaluation of earlier code
		  ftres.termmap =
		    termmapSet (ftres.termmap, roles_tofill->term, run);

		  if (!ftres.flag)
		    {
		      struct flag_and_termmap ftres2;
		      ftres2 =
			fill_roles (sys, cl, ftres.termmap,
				    require_order, roles_tofill->next);
		      if (ftres2.flag)
			{
			  ftres.flag = ftres2.flag;
			  ftres.termmap = ftres2.termmap;
			}
		    }
		}
	    }
	}
    }
  return ftres;
}

//! Check arachne authentications claim
/**
 * Per default, occurs in run 0, but for generality we have left the run parameter in.
 *@returns 1 if the claim is true, 0 if it is not.
 */
int
arachne_claim_authentications (const System sys, const int claim_run,
			       const int claim_index, const int require_order)
{
  Claimlist cl;
  Roledef rd;
  Termmap runs_involved;
  struct flag_and_termmap ftres;

#ifdef DEBUG
  if (DEBUGL (5))
    {
      eprintf ("Testing for Niagree claim with any sort of runs.\n");
    }
#endif

  rd = roledef_shift (sys->runs[claim_run].start, claim_index);
#ifdef DEBUG
  if (rd == NULL)
    error ("Retrieving claim info for NULL node??");
#endif
  cl = rd->claiminfo;

  runs_involved = termmapSet (NULL, cl->roles->term, claim_run);
  ftres = fill_roles (sys, cl, runs_involved, require_order, cl->roles->next);

  termmapDelete (ftres.termmap);
  return ftres.flag;
}

//! Test niagree
int
arachne_claim_niagree (const System sys, const int claim_run,
		       const int claim_index)
{
  return arachne_claim_authentications (sys, claim_run, claim_index, 0);
}

//! Test nisynch
int
arachne_claim_nisynch (const System sys, const int claim_run,
		       const int claim_index)
{
  return arachne_claim_authentications (sys, claim_run, claim_index, 1);
}

//! Test weak agreement with a single agent
int
has_weakagree_agent (const System sys, const int claim_run, const Term agent)
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      if (!isHelperProtocol (sys->runs[run].protocol))
	{
	  if (isTermEqual (agent, agentOfRun (sys, run)))
	    {
	      if (isTermlistSetEqual
		  (sys->runs[run].rho, sys->runs[claim_run].rho))
		{
		  return true;
		}
	    }
	}
    }
  return false;
}

//! Test weak agreement
int
arachne_claim_weakagree (const System sys, const int claim_run,
			 const int claim_index)
{
  /*
   * Runs for each supposed agent, with matching *sets* for rho.
   * (so we can skip the actor)
   */
  if (sys->current_claim->parameter == NULL)
    {
      // No parameter: need agents for all roles
      Termlist tl;

      for (tl = sys->runs[claim_run].rho; tl != NULL; tl = tl->next)
	{
	  Term agent;

	  agent = tl->term;
	  if (!has_weakagree_agent (sys, claim_run, agent))
	    {
	      return false;
	    }
	}
      return true;
    }
  else
    {
      // Parameter for role
      Term agent;

      agent = agentOfRunRole (sys, claim_run, sys->current_claim->parameter);
      return has_weakagree_agent (sys, claim_run, agent);
    }
}

//! Test commit(X) => running(X)
/**
 * To be precise:
 *
 * for all claim(a,Commit,b,data) => 
 *    claim(b,Running,a,data)#rid and role(rid) == ROLE(b in claim role spec)
 *
 * For now we assume data is non-empty
 */
int
arachne_claim_commit (const System sys, const int claim_run,
		      const int claim_index)
{
  /* Check whether preceded by a running with equal parameters */

  int run;
  Roledef rd_claim;
  Term actor_a;
  Term actor_b;
  Term partner_role;
  Termlist params_a;

  rd_claim = roledef_shift (sys->runs[claim_run].start, claim_index);
  params_a = tuple_to_termlist (rd_claim->message);
  actor_a = rd_claim->from;
  actor_b = params_a->term;
  partner_role = termLeft (rd_claim->claiminfo->parameter);

  /*
   * Iterate over all preceding events (include claim run for consistency with formal definition)
   */
  for (run = 0; run < sys->maxruns; run++)
    {
      int ev;
      Roledef rd;

      rd = sys->runs[run].start;
      for (ev = 0; ev < sys->runs[run].step; ev++)
	{
	  if (!isDependEvent (run, ev, claim_run, claim_index))
	    {
	      break;
	    }
	  /* so this event precedes */
	  if (rd->type == CLAIM)
	    {
	      // Check for running signal/claim
	      // (Check: maybe below can also be rd->to)
	      if (isTermEqual (rd->claiminfo->type, CLAIM_Running))
		{
		  // Now check whether they match up nicely
		  // protocols should be the same
		  if (sys->current_claim->protocol == rd->claiminfo->protocol)
		    {
		      Termlist params_b;

		      params_b = tuple_to_termlist (rd->message);
		      // check agent requirements
		      if (isTermEqual (rd->from, actor_b)
			  && isTermEqual (params_b->term, actor_a))
			{
			  // check role (also same protocol)
			  if (isTermEqual
			      (partner_role, rd->claiminfo->rolename))
			    {
			      // check parameters
			      if (isTermlistEqual
				  (params_a->next, params_b->next))
				{
				  // Claim holds
				  termlistDelete (params_b);
				  termlistDelete (params_a);
				  return true;
				}
			    }
			}
		      termlistDelete (params_b);
		    }
		}
	    }
	  /* next */
	  rd = rd->next;
	}
    }
  termlistDelete (params_a);
  return false;
}

//! Test aliveness of agent
int
is_agent_alive (const System sys, const Term agent)
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      if (!isHelperProtocol (sys->runs[run].protocol))
	{
	  if (isTermEqual (agent, agentOfRun (sys, run)))
	    {
	      return true;
	    }
	}
    }
  return false;
}

//! Test aliveness
int
arachne_claim_alive (const System sys, const int claim_run,
		     const int claim_index)
{
  /*
   * Fairly simple claim: there must exist runs for each agent involved.
   * We don't even consider the roles.
   */
  if (sys->current_claim->parameter == NULL)
    {
      // No parameter: check for all roles
      Termlist tl;

      for (tl = sys->runs[claim_run].rho; tl != NULL; tl = tl->next)
	{
	  if (!is_agent_alive (sys, tl->term))
	    {
	      return false;
	    }
	}
      return true;
    }
  else
    {
      // Parameter: check for agent in that role
      Term agent;

      agent = agentOfRunRole (sys, claim_run, sys->current_claim->parameter);
      return is_agent_alive (sys, agent);
    }
}

//! Determine good height for full session
/**
 * For a role, assume in context of claim role
 */
int
pruneClaimRunTrusted (const System sys)
{
  if (sys->trustedRoles == NULL)
    {
      // all agents need to be trusted
      if (!isRunTrusted (sys, 0))
	{
	  return true;
	}
    }
  else
    {
      // a subset is trusted
      if (!isAgentlistTrusted (sys, sys->trustedRoles))
	{
	  return true;
	}
    }
  return false;
}

//! Prune determination for specific properties
/**
 * Sometimes, a property holds in part of the tree. Thus, we don't need to explore that part further if we want to find an attack.
 *
 *@returns true iff this state is invalid for some reason
 */
int
prune_claim_specifics (const System sys)
{
  // generic status of (all) roles trusted or not
  if (pruneClaimRunTrusted (sys))
    {
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf
	    ("Pruned because all agents of the claim run must be trusted.\n");
	}
      return true;
    }

  // specific claims
  if (sys->current_claim->type == CLAIM_Niagree)
    {
      if (arachne_claim_niagree (sys, 0, sys->current_claim->ev))
	{
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: niagree holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  if (sys->current_claim->type == CLAIM_Nisynch)
    {
      if (arachne_claim_nisynch (sys, 0, sys->current_claim->ev))
	{
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: nisynch holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  if (sys->current_claim->type == CLAIM_Weakagree)
    {
      if (arachne_claim_weakagree (sys, 0, sys->current_claim->ev))
	{
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: Weak agreement holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  if (sys->current_claim->type == CLAIM_Alive)
    {
      if (arachne_claim_alive (sys, 0, sys->current_claim->ev))
	{
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: alive holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  if (sys->current_claim->type == CLAIM_Commit)
    {
      if (arachne_claim_commit (sys, 0, sys->current_claim->ev))
	{
	  sys->current_claim->count =
	    statesIncrease (sys->current_claim->count);
	  if (switches.output == PROOF)
	    {
	      indentPrint ();
	      eprintf
		("Pruned: 'commit => running' holds in this part of the proof tree.\n");
	    }
	  return 1;
	}
    }
  return 0;
}

//! Setup system for specific claim test and iterate
int
add_claim_specifics (const System sys, const Claimlist cl, const Roledef rd,
		     int (*callback) (void))
{
  /*
   * different cases
   */

  // per default, all agents are trusted
  sys->trustedRoles = NULL;

  if (cl->type == CLAIM_Secret || cl->type == CLAIM_SKR)
    {
      int newgoals;
      int flag;

      /**
       * Secrecy claim
       */
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("* To verify the secrecy claim, we add the term ");
	  termPrint (rd->message);
	  eprintf (" as a goal.\n");
	  indentPrint ();
	  eprintf
	    ("* If all goals can be bound, this constitutes an attack.\n");
	}

      /**
       * We say that a state exists for secrecy, but we don't really test wheter the claim can
       * be reached (without reaching the attack).
       */
      cl->count = statesIncrease (cl->count);
      newgoals = goal_add (rd->message, 0, cl->ev, 0);	// Assumption that all claims are in run 0

      flag = callback ();

      goal_remove_last (newgoals);
      return flag;
    }

  if (cl->type == CLAIM_Reachable)
    {
      int flag;

      if (switches.check)
	{
	  // For reachability claims in check mode, we restrict the number of runs to the number of roles of this protocol
	  Protocol protocol;
	  int rolecount;

	  protocol = (Protocol) cl->protocol;
	  rolecount = termlistLength (protocol->rolenames);
	  switches.runs = rolecount;
	}
      if (rd->message != NULL)
	{
	  sys->trustedRoles = tuple_to_termlist (rd->message);

#ifdef DEBUG
	  if (DEBUGL (2))
	    {
	      eprintf ("Trusted roles : ");
	      termlistPrint (sys->trustedRoles);
	      eprintf ("\n");
	    }
#endif
	}

      flag = callback ();

      if (rd->message != NULL)
	{
	  termlistDelete (sys->trustedRoles);
	  sys->trustedRoles = NULL;
	}
      return flag;
    }

  return callback ();
}

//! Count a false claim
/**
 * Counts global attacks as well as claim instances.
 */
void
count_false_claim (const System sys)
{
  sys->attackid++;
  sys->current_claim->failed = statesIncrease (sys->current_claim->failed);
}


//! Check properties
int
property_check (const System sys)
{
  int flag;
  int cost;

  flag = 1;

  /**
   * By the way the claim is handled, this automatically means a flaw.
   */
  count_false_claim (sys);
  if (switches.output == ATTACK)
    {
      arachneOutputAttack ();
    }
  // Store attack cost if cheaper
  cost = attackCost (sys);
  if (cost < attack_leastcost)
    {
      // Cheapest attack
      attack_leastcost = cost;
      if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("New cheaper attack found with cost %i.\n", cost);
	}
    }

  return flag;
}

/* claim status reporting */

//! Print something bad
void
printBad (char *s)
{
  eprintf ("%s%s%s", COLOR_Red, s, COLOR_Reset);
}

//! Print something good
void
printGood (char *s)
{
  eprintf ("%s%s%s", COLOR_Green, s, COLOR_Reset);
}

//! Print state (existState, isAttack)
/**
 * Fail == ( existState xor isAttack )
 */
void
printOkFail (int existState, int isAttack)
{
  if (existState != isAttack)
    {
      printGood ("Ok");
    }
  else
    {
      printBad ("Fail");
    }
}


//! Report claim status
int
claimStatusReport (const System sys, Claimlist cl)
{
  if (isTermEqual (cl->type, CLAIM_Empty))
    {
      return false;
    }
  else
    {
      Protocol protocol;
      Term pname;
      Term rname;
      Termlist labellist;
      int isAttack;		// stores whether this claim failure constitutes an attack or not

      if (switches.output != SUMMARY)
	{
	  globalError++;
	}
      if (isTermEqual (cl->type, CLAIM_Reachable))
	{
	  // An attack on reachable is not really an attack, we're just generating the state space
	  isAttack = false;
	}
      else
	{
	  isAttack = true;
	}

      eprintf ("claim\t");

      protocol = (Protocol) cl->protocol;
      pname = protocol->nameterm;
      rname = cl->rolename;

      labellist = tuple_to_termlist (cl->label);

      /* maybe the label contains duplicate info: if so, we remove it here */
      {
	Termlist tl;
	tl = labellist;
	while (tl != NULL)
	  {
	    if (isTermEqual (tl->term, pname)
		|| isTermEqual (tl->term, rname))
	      {
		tl = termlistDelTerm (tl);
		labellist = tl;
	      }
	    else
	      {
		tl = tl->next;
	      }
	  }
      }

      termPrint (pname);
      eprintf (",");
      termPrint (rname);
      eprintf ("\t");
      /* second print event_label */
      termPrint (cl->type);

      eprintf ("_");
      if (labellist != NULL)
	{
	  Termlist tl;

	  tl = labellist;
	  while (tl != NULL)
	    {
	      termPrint (tl->term);
	      tl = tl->next;
	      if (tl != NULL)
		{
		  eprintf (",");
		}
	    }
	  /* clean up */
	  termlistDelete (labellist);
	  labellist = NULL;
	}
      else
	{
	  eprintf ("?");
	}
      /* add parameter */
      eprintf ("\t");
      if (cl->parameter != NULL)
	{
	  termPrint (cl->parameter);
	}
      else
	{
	  eprintf ("-");
	}

      /* now report the status */
      eprintf ("\t");
      if (cl->count > 0 && cl->failed > 0)
	{
	  /* there is a state */
	  printOkFail (true, isAttack);

	  eprintf ("\t");
	  /* are these all attacks? */
	  eprintf ("[");
	  if (cl->complete)
	    {
	      eprintf ("exactly");
	    }
	  else
	    {
	      eprintf ("at least");
	    }
	  eprintf (" %i ", cl->failed);
	  if (isAttack)
	    {
	      eprintf ("attack");
	    }
	  else
	    {
	      eprintf ("variant");
	    }
	  if (cl->failed != 1)
	    {
	      eprintf ("s");
	    }
	  eprintf ("]");
	}
      else
	{
	  /* no state */
	  printOkFail (false, isAttack);
	  eprintf ("\t");

	  /* subcases */
	  if (cl->count == 0)
	    {
	      /* not encountered */
	      eprintf ("[does not occur]");
	    }
	  else
	    {
	      /* does occur */
	      if (cl->complete)
		{
		  /* complete proof */
		  eprintf ("[proof of correctness]");
		}
	      else
		{
		  /* only due to bounds */
		  eprintf ("[no attack within bounds]");
		}
	    }
	  if (cl->timebound)
	    eprintf ("\ttime=%i", get_time_limit ());
	}

      /* states (if asked) */
      if (switches.countStates)
	{
	  eprintf ("\tstates=");
	  statesFormat (cl->states);
	}

      /* any warnings */
      if (cl->warnings)
	{
	  eprintf ("\t[read the warnings for more information]");
	}

      /* new line */
      eprintf ("\n");

      if (switches.output != SUMMARY)
	{
	  globalError--;
	}

      return true;
    }
}

//! Check whether this claim needs to be verified according to filter settings
int
isClaimRelevant (const Claimlist cl)
{
  // Is there something to filter?
  if (switches.filterProtocol == NULL)
    {
      // No: consider all claims
      return true;
    }
  else
    {
      // only this protocol
      if (!isStringEqual
	  (switches.filterProtocol,
	   TermSymb (((Protocol) cl->protocol)->nameterm)->text))
	{
	  // not this protocol; return
	  return false;
	}
      // and maybe also a specific cl->label?
      if (switches.filterLabel != NULL)
	{
	  if (cl->label == NULL)
	    {
	      return false;
	    }
	  else
	    {
	      Term t;

	      t = cl->label;
	      while (isTermTuple (t))
		{
		  t = TermOp2 (t);
		}
	      if (!isStringEqual (switches.filterLabel, TermSymb (t)->text))
		{
		  // not this label; return
		  return false;
		}
	    }
	}
    }
  return true;
}

//! Check whether a claim is really just a signal, and not a claim
/**
 * This piece of code effectively decides what is a signal and what not
 */
int
isClaimSignal (const Claimlist cl)
{
  if (isTermEqual (cl->type, CLAIM_Empty))
    {
      return true;
    }
  if (isTermEqual (cl->type, CLAIM_SID))
    {
      return true;
    }
  if (isTermEqual (cl->type, CLAIM_Running))
    {
      return true;
    }
  if (isTermEqual (cl->type, CLAIM_Notequal))
    {
      return true;
    }
  return false;
}
