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

/*
 * type.c
 *
 * Code to check the consistency of types, in the presence of type flaw stuff etc.
 */

#include <stdlib.h>
#include <stdio.h>
#include "term.h"
#include "termlist.h"
#include "system.h"
#include "debug.h"
#include "switches.h"
#include "specialterm.h"

extern Protocol INTRUDER;
extern Termlist TERMLISTERROR;

//! Report a bad substitution, if needed
void
reportBadSubst (const Term tvar, const Term tsubst)
{
#ifdef DEBUG
  if (DEBUGL (5))
    {
      Term tbuf;

      tbuf = tvar->subst;
      tvar->subst = NULL;

      eprintf ("Substitution fails on ");
      termPrint (tvar);
      eprintf (" -/-> ");
      termPrint (tsubst);
      eprintf (", maybe because type: \n");
      termlistPrint (tvar->stype);
      eprintf (" does not contain ");
      termlistPrint (tsubst->stype);
      eprintf ("\n");

      tvar->subst = tbuf;
    }
#endif
}

//! Say whether a typelist is 'generic' or should be taken per item.
int
isTypelistGeneric (const Termlist typelist)
{
  if (typelist == NULL)
    {
      return 1;
    }
  else
    {
      return inTermlist (typelist, TERM_Ticket);
    }
}

//! Say whether this variable can contain tuples and/or encryptions
/**
 * Precondition: tvar should be a variable.
 *
 * This function is specifically used for detecting the problematic Athena case.
 */
int
isOpenVariable (const Term tvar)
{
  return isTypelistGeneric (tvar->stype);
}

//! Check whether a single variable term is instantiated correctly.
/**
 * Check whether a single variable term is instantiated correctly in this
 * system. This takes the matching parameter into account, and is aware of the
 * 'ticket' type.
 *
 * Non-variables etc. imply true.
 */
int
checkTypeTerm (const Term tvar)
{
  // Checks are only needed for match < 2 etc.
  if (switches.match < 2 && tvar != NULL && realTermVariable (tvar))
    {
      // Non-instantiated terms are fine.
      if (tvar->subst != NULL)
	{
	  if (!isTypelistGeneric (tvar->stype))
	    {
	      // So there is a specific (non-ticket) type, and the var is instantiated, match mode 0 or 1
	      // Is it really a leaf?
	      Term tsubst;

	      tsubst = deVar (tvar);
	      if (!realTermLeaf (tsubst))
		{
		  // Then it's definitively false
		  reportBadSubst (tvar, tsubst);
		  return false;
		}
	      else
		{
		  // It is a leaf
		  if (switches.match == 0)
		    {
		      /* Types must match exactly. Thus, one of the variable type should match a type of the constant.
		       */
		      Termlist tl;

		      tl = tvar->stype;
		      while (tl != NULL)
			{
			  if (inTermlist (tsubst->stype, tl->term))
			    {
			      // One type matches
			      return true;
			    }
			  tl = tl->next;
			}
		      // No type matches.
		      reportBadSubst (tvar, tsubst);
		      return false;
		    }
		}
	    }
	}
    }
  return true;
}

//! Check whether a typelist is a strict agent type list
int
isAgentType (Termlist typelist)
{
  return (termlistLength (typelist) == 1 &&
	  inTermlist (typelist, TERM_Agent));
}

//! Helper function to determine whether a list is compatible with an agent var.
int
agentCompatible (Termlist tl)
{
  if (isTypelistGeneric (tl))
    {
      return 1;
    }
  else
    {
      return inTermlist (tl, TERM_Agent);
    }
}

//! Check whether two type lists are compatible for variables
/**
 * Depends on some input:
 *
 * agentcheck	true if agent type is always restrictive
 *
 * returns the new type list (needs to be deleted!) or TERMLISTERROR (should
 * not be deleted!)
 */
Termlist
typelistConjunct (Termlist typelist1, Termlist typelist2,
		  const int agentcheck)
{
  if (typelist1 != TERMLISTERROR && typelist2 != TERMLISTERROR)
    {

      /* In the restricted agent case, we check whether agent list occurs in
       * either set. If so, the result can only be an agent-restrictive list.
       */

      if (agentcheck)
	{
	  if (isAgentType (typelist1) || isAgentType (typelist2))
	    {
	      /* Now, the result must surely accept agents. Thus, it must be
	       * NULL or accept agents.
	       */
	      if (switches.match == 0)
		{
		  // only if we are doing matching, otherwise it is always agent-compatible
		  if (!
		      (agentCompatible (typelist1)
		       && agentCompatible (typelist2)))
		    {
		      // Not good: one of them cannot
		      return TERMLISTERROR;
		    }
		}
	      // Good: but because an agent is involved, the type reduces to the simple Agent type only.
	      return termlistAdd (NULL, TERM_Agent);
	    }
	  else
	    {
	      /* Not the simple agent variable case. Now other things come in to play.
	       */
	      if (switches.match == 0)
		{
		  /*
		   * Strict match: (-m0) conjunct of the types must be non-empty.
		   */

		  // Generic exceptions
		  if (isTypelistGeneric (typelist1))
		    {
		      // Copy for later deletion
		      return termlistShallow (typelist2);
		    }
		  else
		    {
		      if (isTypelistGeneric (typelist2))
			{
			  // Copy for later deletion
			  return termlistShallow (typelist1);
			}
		      else
			{
			  /* Apparently neither is generic, and we can take the real conjunct.
			   * However, this conjunct must not be empty (because that implies that the types cannot match).
			   */
			  Termlist conjunct;

			  conjunct = termlistConjunct (typelist1, typelist2);
			  if (conjunct == NULL)
			    {
			      // Empty, and thus the variables cannot be instantiated without causing a type flaw.
			      return TERMLISTERROR;
			    }
			  else
			    {
			      // Non-empty, which is good in this case.
			      return conjunct;
			    }
			}
		    }
		}
	      else
		{
		  /*
		   * Not so strict: (-m1 or -m2)
		   *
		   * Because the variable is not bound, there is certainly no
		   * binding yet to tuples or crypted terms, and thus any
		   * typing will do.
		   */
		  return NULL;
		}
	    }
	}
    }
  return TERMLISTERROR;
}

//! Check a single ground variable
/**
 * Check whether all variables that map to this one have a possible valid substitution
 */
int
checkGroundVariable (const System sys, const Term groundvar)
{
  int allvalid;

  allvalid = 1;
  if (switches.match < 2)
    {
      if (realTermVariable (groundvar))
	{
	  Termlist tl;
	  Termlist typelist;

	  // Check
	  typelist = termlistShallow (groundvar->stype);
	  tl = sys->variables;
	  while (allvalid == 1 && tl != NULL)
	    {
	      Term term;

	      term = tl->term;

	      // Not actually the same, of course
	      if (term != groundvar)
		{
		  // Does this term map to the same variable?
		  if (isTermEqual (term, groundvar))
		    {
		      Termlist tlprev;

		      // Maps to same ground term
		      // Take conjunct
		      tlprev = typelist;
		      typelist =
			typelistConjunct (tlprev, term->stype,
					  switches.agentTypecheck);
		      termlistDelete (tlprev);

		      if (typelist == TERMLISTERROR)
			{
			  // And this is not valid...
			  allvalid = 0;
			}
		    }
		}
	      tl = tl->next;
	    }
	  if (typelist != TERMLISTERROR)
	    {
	      termlistDelete (typelist);
	    }
	}
    }
  return allvalid;
}


//! Global check of the system, for all variables.
/**
 * Returns true if all variables are okay.
 *
 * This version checks all substitutions, and thus takes over all the functions
 * that are now in mgu.c. However, we have left them in for speed purposes,
 * because pruning early is good.
 */
int
checkAllSubstitutions (const System sys)
{
  int allvalid;
  Termlist groundvars;
  Termlist tl;

  /* We scan all unbound variables for so called 'ground variables', which are
   * the root of a substitution tree. Such variables are checked for
   * satisfyability, i.e. the conjunction of their type lists must not be
   * empty.
   *
   * At the same time, we check also bound variables for their mappings.
   */
  groundvars = NULL;
  allvalid = 1;
  tl = sys->variables;
  while ((allvalid == 1) && (tl != NULL))
    {
      Term tvar;

      tvar = tl->term;
      if (realTermVariable (tvar))
	{
	  Term tsubst;

	  tsubst = deVar (tvar);

	  if (tvar != tsubst)
	    {
	      // Substitution going on, check

	      if (realTermVariable (tsubst))
		{
		  /* Variable -> Variable (unbound)
		   *
		   * Check whether we already scanned for this one, because we
		   * don't want to scan for this ground variable more than once.
		   */
		  if (!inTermlist (groundvars, tsubst))
		    {
		      /* Not done before, add now.
		       */
		      groundvars = termlistAdd (groundvars, tsubst);

		      /* Check whether there exists a valid substitution for
		       * everything mapping to this ground variable.
		       */
		      allvalid = allvalid
			&& checkGroundVariable (sys, tsubst);
		    }
		}
	      else
		{
		  /* Variable -> term (bound)
		   */

		  if (switches.agentTypecheck && isAgentType (tvar->stype))
		    {
		      // *Must* include agent type, regardless of match
		      allvalid = allvalid && agentCompatible (tsubst->stype);
		    }
		  else
		    {
		      // Consider match
		      allvalid = allvalid && checkTypeTerm (tvar);
		    }
		}
	    }
	}
      tl = tl->next;
    }

  termlistDelete (groundvars);
  return allvalid;
}

//! Check this variables whether it is a good agent type
/**
 * Checks for leaf/etc and correct agent type
 */
int
goodAgentType (Term agent)
{
  agent = deVar (agent);

  if (!realTermLeaf (agent))
    {				// not a leaf
      return false;
    }
  else
    {				// real leaf
      if (isTermVariable (agent))
	{
	  // Variable: check type consistency (should have a solution)
	  // Not yet: depends on matching mode also
	}
      else
	{
	  // Constant: allow only exact type
	  if (!inTermlist (agent->stype, TERM_Agent))
	    {
	      return false;
	    }
	}
    }

  return true;
}
