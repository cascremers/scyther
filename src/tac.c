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

#include <stdio.h>
#include <stdlib.h>
#include "tac.h"
#include "memory.h"
#include "switches.h"
#include "error.h"

extern int yylineno;

static Tac allocatedTacs;

//! Init segment
void
tacInit (void)
{
  allocatedTacs = NULL;
}

//! Closing segment
void
tacDone (void)
{
  Tac ts;

  ts = allocatedTacs;
  while (ts != NULL)
    {
      Tac tf;

      tf = ts;
      ts = ts->allnext;
      free (tf);
    }
}

//! Copy a tac
Tac
tacCopy (Tac c)
{
  Tac newTac;

  newTac = (Tac) malloc (sizeof (struct tacnode));
  memcpy (newTac, c, sizeof (struct tacnode));

  // Store in taclist
  newTac->allnext = allocatedTacs;
  allocatedTacs = newTac;

  return newTac;
}

//! Create a tac node of some type
Tac
tacCreate (int op)
{
  /* maybe even store in scrapping list, so we could delete them
   * all later */
  Tac t = malloc (sizeof (struct tacnode));
  t->allnext = allocatedTacs;
  allocatedTacs = t;
  t->lineno = yylineno;
  t->op = op;
  t->next = NULL;
  t->prev = NULL;
  t->t1.tac = NULL;
  t->t2.tac = NULL;
  t->t3.tac = NULL;
  return t;
}

Tac
tacJoin (int op, Tac t1, Tac t2, Tac t3)
{
  Tac t;
  t = tacCreate (op);
  t->t1.tac = t1;
  t->t2.tac = t2;
  t->t3.tac = t3;
  return t;
}

Tac
tacCat (Tac t1, Tac t2)
{
  Tac t1e;

  if (t1 == NULL)
    {
      if (t2 == NULL)
	return NULL;
      else
	return t2;
    }
  else
    {
      t1e = t1;
      while (t1e->next != NULL)
	t1e = t1e->next;
      t1e->next = t2;
      if (t2 != NULL)
	{
	  t2->prev = t1e;
	}
      return t1;
    }
}

//! List to right-associative tuple
Tac
tacTupleRa (Tac taclist)
{
  Tac tc;

  /* check for single node */
  if (taclist->next == NULL)
    {
      /* just return */
      tc = taclist;
    }
  else
    {
      /* otherwise, write as (x,(y,(z,..))) */
      tc = tacCreate (TAC_TUPLE);
      tc->t1.tac = taclist;
      tc->t2.tac = tacTuple (taclist->next);

      /* unlink list */
      tc->t1.tac->next = NULL;
      tc->t2.tac->prev = NULL;
    }
  return tc;
}

//! List to left-associative tuple
Tac
tacTupleLa (Tac taclist)
{
  Tac tc;

  /* initial node is simple the first item */
  tc = taclist;
  tc->prev = NULL;

  /* add any other nodes (one is ensured) */
  do
    {
      Tac tcnew;

      taclist = taclist->next;
      /* add a new node (taclist) to the existing thing by first making the old one into the left-hand side of a tuple */
      tcnew = tacCreate (TAC_TUPLE);
      tcnew->t1.tac = tc;
      tcnew->t2.tac = taclist;
      tc = tcnew;
      /* unlink */
      tc->t1.tac->next = NULL;
      tc->t2.tac->prev = NULL;
    }
  while (taclist->next != NULL);

  return tc;
}

//! Compile a list into a tuple
/* in: a list. out: a tuple (for e.g. associativity)
 * Effectively, this defines how we interpret tuples with
 * more than two components.
 */
Tac
tacTuple (Tac taclist)
{
  if (taclist == NULL || taclist->next == NULL)
    {
      /* just return */
      return taclist;
    }
  else
    {
      switch (switches.tupling)
	{
	case 0:
	  /* case 0: as well as */
	  /* DEFAULT behaviour */
	  /* right-associative */
	  return tacTupleRa (taclist);
	case 1:
	  /* switch --la-tupling */
	  /* left-associative */
	  return tacTupleLa (taclist);
	default:
	  error ("Unknown tupling mode (--tupling=%i)", switches.tupling);
	}
    }
  // @TODO this should be considered an error
  return NULL;
}

/*
 * tacPrint
 * Print the tac. Only for debugging purposes.
 */

void
tacPrint (Tac t)
{
  if (t == NULL)
    return;
  switch (t->op)
    {
    case TAC_PROTOCOL:
      printf ("protocol %s (", t->t1.sym->text);
      tacPrint (t->t3.tac);
      printf (")\n{\n");
      tacPrint (t->t2.tac);
      printf ("};\n");
      break;
    case TAC_ROLE:
      printf ("role %s\n{\n", t->t1.sym->text);
      tacPrint (t->t2.tac);
      printf ("};\n");
      break;
    case TAC_RECV:
      printf ("recv");
      if (t->t1.sym != NULL)
	{
	  printf ("_%s", t->t1.sym->text);
	}
      printf ("(");
      tacPrint (t->t2.tac);
      printf (");\n");
      break;
    case TAC_SEND:
      printf ("send");
      if (t->t1.sym != NULL)
	{
	  printf ("_%s", t->t1.sym->text);
	}
      printf ("(");
      tacPrint (t->t2.tac);
      printf (");\n");
      break;
    case TAC_CLAIM:
      printf ("claim");
      if (t->t1.sym != NULL)
	{
	  printf ("_%s", t->t1.sym->text);
	}
      printf ("(");
      tacPrint (t->t2.tac);
      printf (");\n");
      break;
    case TAC_CONST:
      printf ("const ");
      tacPrint (t->t1.tac);
      if (t->t2.tac != NULL)
	{
	  printf (" : ");
	  tacPrint (t->t2.tac);
	}
      printf (";\n");
      break;
    case TAC_VAR:
      printf ("var ");
      tacPrint (t->t1.tac);
      if (t->t2.tac != NULL)
	{
	  printf (" : ");
	  tacPrint (t->t2.tac);
	}
      printf (";\n");
      break;
    case TAC_UNDEF:
      printf ("undefined");
      if (t->next != NULL)
	printf (",");
      break;
    case TAC_STRING:
      printf ("%s", t->t1.sym->text);
      if (t->next != NULL)
	printf (",");
      break;
    case TAC_TUPLE:
      printf ("(");
      tacPrint (t->t1.tac);
      printf (",");
      tacPrint (t->t2.tac);
      printf (")");
      break;
    case TAC_ENCRYPT:
      printf ("{");
      tacPrint (t->t1.tac);
      printf ("}");
      tacPrint (t->t2.tac);
      if (t->next != NULL)
	{
	  printf (",");
	  t = t->next;
	  tacPrint (t);
	}
      break;
    case TAC_RUN:
      printf ("run ");
      tacPrint (t->t1.tac);
      printf ("(");
      tacPrint (t->t2.tac);
      printf (");\n");
      break;
    case TAC_ROLEREF:
      symbolPrint (t->t1.sym);
      printf (".");
      symbolPrint (t->t2.sym);
      break;
    case TAC_COMPROMISED:
      printf ("compromised ");
      tacPrint (t->t1.tac);
      printf (";\n");
      break;
    case TAC_SECRET:
      printf ("secret ");
      tacPrint (t->t1.tac);
      printf (";\n");
      break;
    case TAC_INVERSEKEYS:
      printf ("inversekeys (");
      tacPrint (t->t1.tac);
      printf (",");
      tacPrint (t->t2.tac);
      printf (");\n");
      break;
    case TAC_HASHFUNCTION:
      printf ("hashfunction ");
      tacPrint (t->t1.tac);
      printf (";\n");
      break;
    case TAC_UNTRUSTED:
      printf ("untrusted ");
      tacPrint (t->t1.tac);
      printf (";\n");
      break;
    default:
      printf ("[??]");
    }

  /* and any other stuff */
  if (t->next != NULL)
    {
      tacPrint (t->next);
    }
}
