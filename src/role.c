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
  int printlabel;

  printlabel = true;
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
    {
      if (rd->compromisetype != COMPR_NONE)
	{
	  eprintf ("COMPR_");
	  printlabel = false;
	  switch (rd->compromisetype)
	    {
	    case COMPR_NONE:
	      eprintf ("None");
	      break;
	    case COMPR_SSR:
	      eprintf ("SSR");
	      break;
	    case COMPR_SKR:
	      eprintf ("SKR");
	      break;
	    case COMPR_RNR:
	      eprintf ("RNR");
	      break;
	    }
	}
      else
	{
	  eprintf ("SEND");
	}
    }
  if (rd->type == CLAIM)
    eprintf ("CLAIM");
  if (printlabel && (rd->label != NULL))
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
  newEvent->forbidden = NULL;	// no forbidden stuff, only for recvs
  newEvent->knowPhase = -1;	// we haven't explored any knowledge yet, only for recvs
  newEvent->claiminfo = cl;	// only for claims
  newEvent->compromisetype = COMPR_NONE;	// compromisetype
  if (type == RECV)
    newEvent->bound = 0;	// bound goal (Used for arachne only). Technically involves choose events as well.
  else
    newEvent->bound = 1;	// other stuff does not need to be bound
  newEvent->next = NULL;
  newEvent->lineno = 0;
  return newEvent;
}

//! Yield the tail node of a roledef list
/**
 * Returns NULL only if given NULL
 */
Roledef
roledefTail (Roledef rd)
{
  if (rd == NULL)
    {
      return NULL;
    }
  else
    {
      while (rd->next != NULL)
	{
	  rd = rd->next;
	}
      return rd;
    }
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

//! Append a role event to an existing list, with the given parameters.
/**
 *\sa roledefInit()
 * Returns the new head (if given NULL) or the rd it was given as input.
 */
Roledef
roledefAdd (Roledef rd, int type, Term label, Term from, Term to, Term msg,
	    Claimlist cl)
{
  Roledef scan;

  if (rd == NULL)
    return roledefInit (type, label, from, to, msg, cl);

  scan = roledefTail (rd);
  scan->next = roledefInit (type, label, from, to, msg, cl);
  return rd;
}

//! Add a role event to a list, at a particular point.
/**
 * Head = head of list. 
 * Insert after rd.
 *
 * Returns new head
 */
Roledef
roledefInsert (Roledef head, Roledef rd, int type, Term label, Term from,
	       Term to, Term msg, Claimlist cl)
{
  Roledef oldnext;
  Roledef newhead;

  if (rd == NULL)
    {
      return roledefAdd (head, type, label, from, to, msg, cl);
    }
  oldnext = rd->next;
  rd->next = NULL;

  newhead = roledefAdd (head, type, label, from, to, msg, cl);
  rd = roledefTail (newhead);
  rd->next = oldnext;
  return newhead;
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

//! Duplicate role
Role
roleDuplicate (Role source)
{
  Role dest;

  if (source == NULL)
    {
      return NULL;
    }

  dest = (Role) malloc (sizeof (struct role));
  memcpy (dest, source, sizeof (struct role));
  return dest;
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
roledef_length (const Roledef rd)
{
  int count = 0;
  int countplus (Roledef rd)
  {
    count++;
    return 1;
  }
  roledef_iterate_events (rd, countplus);
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
