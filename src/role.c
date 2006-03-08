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
  if (rd->type == READ && rd->internal)
    {
      /* special case: internal read == choose ! */
      eprintf ("CHOOSE(");
      termPrint (rd->message);
      eprintf (")");
      return;
    }
  if (rd->type == READ)
    eprintf ("READ");
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
      if (print_actor || rd->type == READ)
	{
	  termPrint (rd->from);
	  eprintf (",");
	}
      if (rd->type == CLAIM)
	eprintf (" ");
      if (print_actor || rd->type != READ)
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
  if (type == READ)
    newEvent->bound = 0;	// bound goal (Used for arachne only). Technically involves choose events as well.
  else
    newEvent->bound = 1;	// other stuff does not need to be bound
  newEvent->next = NULL;
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
  r->initiator = 1;		//! Will be determined later, if a read is the first action (in compiler.c)
  r->singular = false;		// by default, a role is not singular
  r->next = NULL;
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

// Check whether a term is a subterm of a roledef
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
