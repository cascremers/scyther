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
 * @file role.c 
 * \brief role related logic.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "term.h"
#include "termlist.h"
#include "knowledge.h"
#include "system.h"
#include "debug.h"
#include "error.h"
#include "role.h"

extern int protocolCount;	// from system.c

//! Allocate memory the size of a roledef struct.
Roledef
makeRoledef ()
{
  return (Roledef) malloc (sizeof (struct roledef));
}

//! Print a role event.
/**
 * If print_actor is true, the actor is included (OS version), otherwise it is left out (short stuff)
 */
void
roledefPrintGeneric (Roledef rd, int print_actor)
{
  if (rd == NULL)
    {
      eprintf ("[Empty roledef]");
      return;
    }
  if (rd->type == RECV && rd->internal)
    {
      /* special case: internal recv == choose ! */
      eprintf ("CHOOSE(");
      termPrint (rd->message);
      eprintf (")");
      return;
    }
  if (rd->type == RECV)
    eprintf ("RECV");
  if (rd->type == SEND)
    eprintf ("SEND");
  if (rd->type == CLAIM)
    eprintf ("CLAIM");
  if (rd->label != NULL)
    {
      //! Print label
      Term label;

      /* Old version: sometimes prints protocol stuff (really unique labels)
         label = deVar (rd->label);
         if (protocolCount < 2 && realTermTuple (label))
         {
         // Only one protocol, so we don't need to show the extra label info
         label = TermOp2 (label);
         }
       */
      label = deVar (rd->label);
      if (realTermTuple (label))
	{
	  label = TermOp2 (label);
	}

      eprintf ("_");
      termPrint (label);
    }
  eprintf ("(");
  if (!(rd->from == NULL && rd->to == NULL))
    {
      if (print_actor || rd->type == RECV)
	{
	  termPrint (rd->from);
	  eprintf (",");
	}
      if (rd->type == CLAIM)
	eprintf (" ");
      if (print_actor || rd->type != RECV)
	{
	  termPrint (rd->to);
	  eprintf (", ");
	}
    }
  termPrint (rd->message);
  eprintf (" )");
}

//! Print a roledef
void
roledefPrint (Roledef rd)
{
  roledefPrintGeneric (rd, 1);
}

//! Print a roledef, but shorten it
void
roledefPrintShort (Roledef rd)
{
  roledefPrintGeneric (rd, 0);
}


//! Duplicate a single role event node.
/**
 *\sa roledefDelete()
 */
Roledef
roledefDuplicate1 (const Roledef rd)
{
  Roledef newrd;

  if (rd == NULL)
    return NULL;
  newrd = makeRoledef ();
  memcpy (newrd, rd, sizeof (struct roledef));
  newrd->next = NULL;
  return newrd;
}

//! Duplicate a role event list.
/**
 *\sa roledefDelete()
 */
Roledef
roledefDuplicate (Roledef rd)
{
  Roledef newrd;

  if (rd == NULL)
    return NULL;
  newrd = roledefDuplicate1 (rd);
  newrd->next = roledefDuplicate (rd->next);
  return newrd;
}

//! Delete a role event or event list.
/**
 *\sa roledefDuplicate()
 */
void
roledefDelete (Roledef rd)
{
  if (rd == NULL)
    return;
  roledefDelete (rd->next);
  free (rd);
  return;
}

//! Destroy a role event or event list.
void
roledefDestroy (Roledef rd)
{
  if (rd == NULL)
    return;
  roledefDestroy (rd->next);
  termDelete (rd->from);
  termDelete (rd->to);
  termDelete (rd->message);
  free (rd);
  return;
}

//! Make a new role event with the specified parameters.
/**
 *@return A pointer to a new role event with the given parameters.
 */
Roledef
roledefInit (int type, Term label, Term from, Term to, Term msg, Claimlist cl)
{
  Roledef newEvent;

  newEvent = makeRoledef ();
  newEvent->internal = 0;
  newEvent->type = type;
  newEvent->label = label;
  newEvent->from = from;
  newEvent->to = to;
  newEvent->message = msg;
  newEvent->forbidden = NULL;	// no forbidden stuff
  newEvent->knowPhase = -1;	// we haven't explored any knowledge yet
  newEvent->claiminfo = cl;	// only for claims
  if (type == RECV)
    newEvent->bound = 0;	// bound goal (Used for arachne only). Technically involves choose events as well.
  else
    newEvent->bound = 1;	// other stuff does not need to be bound
  newEvent->next = NULL;
  newEvent->lineno = 0;
  return newEvent;
}

//! Add a role event to an existing list, with the given parameters.
/**
 *\sa roledefInit()
 */
Roledef
roledefAdd (Roledef rd, int type, Term label, Term from, Term to, Term msg,
	    Claimlist cl)
{
  Roledef scan;

  if (rd == NULL)
    return roledefInit (type, label, from, to, msg, cl);

  scan = rd;
  while (scan->next != NULL)
    scan = scan->next;
  scan->next = roledefInit (type, label, from, to, msg, cl);
  return rd;
}

//! Create an empty role structure with a name.
Role
roleCreate (Term name)
{
  Role r;

  r = malloc (sizeof (struct role));
  r->nameterm = name;
  r->roledef = NULL;
  r->locals = NULL;
  r->variables = NULL;
  r->declaredvars = NULL;
  r->declaredconsts = NULL;
  r->initiator = 1;		//! Will be determined later, if a recv is the first action (in compiler.c)
  r->singular = false;		// by default, a role is not singular
  r->next = NULL;
  r->knows = NULL;
  r->lineno = 0;
  return r;
}

//! Print a role.
void
rolePrint (Role r)
{
  Roledef rd;

  if (r == NULL)
    return;

  indent ();
  eprintf ("[[Role : ");
  termPrint (r->nameterm);
  eprintf ("]]\n");
  locVarPrint (r->locals);

  rd = r->roledef;
  while (rd != NULL)
    {
      roledefPrint (rd);
      eprintf ("\n");
      rd = rd->next;
    }
}

//! Print a list of roles.
void
rolesPrint (Role r)
{
  if (r == NULL)
    {
      eprintf ("Empty role.");
    }
  else
    {
      while (r != NULL)
	{
	  rolePrint (r);
	  r = r->next;
	}
    }
}

//! Iterate over the events in a roledef list
/**
 * Function gets roledef pointer
 */
int
roledef_iterate_events (Roledef rd, int (*func) ())
{
  while (rd != NULL)
    {
      if (!func (rd))
	return 0;
      rd = rd->next;
    }
  return 1;
}

//! Roledef length
/**
 * Would be faster hard-coded,
 * but this just shows the use of the iteration.
 */
int
roledef_length (Roledef rd)
{
  int count = 0;

  while (rd != NULL)
    {
      count++;
      rd = rd->next;
    }
  return count;
}

//! Yield roledef pointer for a given index
Roledef
roledef_shift (Roledef rd, int i)
{
  while (i > 0 && rd != NULL)
    {
      rd = rd->next;
      i--;
    }
  return rd;
}

//! Check whether a term is a subterm of a roledef
int
roledefSubTerm (Roledef rd, Term tsub)
{
  if (rd == NULL)
    {
      return false;
    }
  else
    {
      return (termSubTerm (rd->from, tsub) ||
	      termSubTerm (rd->to, tsub) || termSubTerm (rd->message, tsub));
    }
}

/*
 * Some stuff directly from the semantics
 */

//! Is a term readable (from some knowledge set)
/**
 * Returns value of predicate
 */
int
Readable (Knowledge know, Term t)
{
  if (isTermVariable (t))
    {
      // Variable pattern
      return true;
    }
  if (!isTermLeaf (t))
    {
      if (isTermTuple (t))
	{
	  // Tuple pattern
	  Knowledge knowalt;
	  int both;

	  both = false;
	  knowalt = knowledgeDuplicate (know);
	  knowledgeAddTerm (knowalt, TermOp2 (t));
	  if (Readable (knowalt, TermOp1 (t)))
	    {
	      // Yes, left half works
	      knowledgeDelete (knowalt);
	      knowalt = knowledgeDuplicate (know);
	      knowledgeAddTerm (knowalt, TermOp1 (t));
	      if (Readable (knowalt, TermOp2 (t)))
		{
		  both = true;
		}
	    }
	  knowledgeDelete (knowalt);
	  return both;
	}
      else
	{
	  // Encryption pattern
	  // But we exclude functions
	  if (getTermFunction (t) == NULL)
	    {
	      // Real encryption pattern
	      Term inv;
	      int either;

	      // Left disjunct
	      if (inKnowledge (know, t))
		{
		  return true;
		}
	      // Right disjunct
	      inv = inverseKey (know, TermKey (t));
	      either = false;
	      if (inKnowledge (know, inv))
		{
		  if (Readable (know, TermOp (t)))
		    {
		      either = true;
		    }
		}
	      termDelete (inv);
	      return either;
	    }
	}
    }
  return inKnowledge (know, t);
}

//! Well-formed error reporting.
void
wfeError (Knowledge know, Roledef rd, char *errorstring, Term was,
	  Term shouldbe)
{
  globalError++;
  eprintf ("Well-formedness error.\n");
  roledefPrint (rd);
  eprintf ("\nKnowing ");
  knowledgePrintShort (know);
  eprintf ("\n");
  if (was != NULL || shouldbe != NULL)
    {
      eprintf ("while parsing ");
      termPrint (was);
      if (shouldbe != NULL)
	{
	  eprintf (" which should have been ");
	  termPrint (shouldbe);
	}
      eprintf ("\n");
    }
  globalError--;
  error (errorstring);
}


//! Return the first event (or NULL) in which a term occurs
Roledef
firstEventWithTerm (Roledef rd, Term t)
{
  while (rd != NULL)
    {
      if (termSubTerm (rd->message, t))
	{
	  return rd;
	}
      rd = rd->next;
    }
  return NULL;
}
