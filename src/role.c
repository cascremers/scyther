/**
 * @file roles.c 
 * \brief role related logic.
 */
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "term.h"
#include "termlist.h"
#include "knowledge.h"
#include "system.h"
#include "memory.h"
#include "constraint.h"
#include "debug.h"
#include "output.h"
#include "tracebuf.h"
#include "role.h"

extern int globalLatex;		// from system.c

//! Allocate memory the size of a roledef struct.
Roledef
makeRoledef ()
{
  return (Roledef) memAlloc (sizeof (struct roledef));
}

//! Print a role event list.
void
roledefPrint (Roledef rd)
{
  if (rd == NULL)
    {
      printf ("[Empty roledef]\n");
      return;
    }
  if (rd->type == READ && rd->internal)
    {
      /* special case: internal read == choose ! */
      printf ("CHOOSE(");
      termPrint (rd->message);
      printf (")");
      return;
    }
  if (rd->type == READ)
    printf ("READ");
  if (rd->type == SEND)
    printf ("SEND");
  if (rd->type == CLAIM)
    printf ("CLAIM");
  if (rd->label != NULL)
    {
      if (globalLatex)
	{
	  printf ("$_{");
	  termPrint (rd->label);
	  printf ("}$");
	}
      else
	{
	  printf ("_");
	  termPrint (rd->label);
	}
    }
  if (globalLatex)
    printf ("$");
  printf ("(");
  termPrint (rd->from);
  printf (",");
  if (rd->type == CLAIM)
    printf (" ");
  termPrint (rd->to);
  printf (", ");
  termPrint (rd->message);
  printf (" )");
  if (globalLatex)
    printf ("$");
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
  memFree (rd, sizeof (struct roledef));
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
  memFree (rd, sizeof (struct roledef));
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
  newEvent->next = NULL;
  return newEvent;
}

//! Add a role event to an existing list, with the given parameters.
/**
 *\sa roledefInit()
 */
Roledef
roledefAdd (Roledef rd, int type, Term label, Term from, Term to, Term msg, Claimlist cl)
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

  r = memAlloc (sizeof (struct role));
  r->nameterm = name;
  r->next = NULL;
  r->locals = NULL;
  r->roledef = NULL;
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
  printf ("[[Role : ");
  termPrint (r->nameterm);
  printf ("]]\n");
  locVarPrint (r->locals);

  rd = r->roledef;
  while (rd != NULL)
    {
      roledefPrint (rd);
      printf ("\n");
      rd = rd->next;
    }
}

//! Print a list of roles.
void
rolesPrint (Role r)
{
  if (r == NULL)
    {
      printf ("Empty role.");
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


