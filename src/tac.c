#include <stdio.h>
#include "tac.h"
#include "memory.h"

extern int yylineno;

static Tac allocatedTacs;

void
tacInit (void)
{
  allocatedTacs = NULL;
}

void
tacDone (void)
{
  Tac ts, tf;

  ts = allocatedTacs;
  while (ts != NULL)
    {
      tf = ts;
      ts = ts->allnext;
      memFree (tf, sizeof (struct tacnode));
    }
}

Tac
tacCreate (int op)
{
  /* maybe even store in scrapping list, so we could delete them
   * all later */
  Tac t = memAlloc (sizeof (struct tacnode));
  t->allnext = allocatedTacs;
  allocatedTacs = t;
  t->lineno = yylineno;
  t->op = op;
  t->next = NULL;
  t->prev = NULL;
  t->tac1 = NULL;
  t->tac2 = NULL;
  t->tac3 = NULL;
  return t;
}

Tac
tacString (char *s)
{
  Tac t;
  t = tacCreate (TAC_STRING);
  t->str1 = s;
  return t;
}

Tac
tacJoin (int op, Tac t1, Tac t2, Tac t3)
{
  Tac t;
  t = tacCreate (op);
  t->tac1 = t1;
  t->tac2 = t2;
  t->tac3 = t3;
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

/* in: a list. out: a tuple (for e.g. associativity)
 * Effectively, this defines how we interpret tuples with
 * more than two components.
 */

Tac
tacTuple (Tac taclist)
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
      tc->tac1 = taclist;
      tc->tac2 = tacTuple (taclist->next);

      /* unlink list */
      tc->tac1->next = NULL;
      tc->tac2->prev = NULL;
    }
  return tc;
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
      printf ("protocol %s (", t->sym1->text);
      tacPrint (t->tac3);
      printf (")\n{\n");
      tacPrint (t->tac2);
      printf ("};\n");
      break;
    case TAC_ROLE:
      printf ("role %s\n{\n", t->sym1->text);
      tacPrint (t->tac2);
      printf ("};\n");
      break;
    case TAC_READ:
      printf ("read");
      if (t->sym1 != NULL)
	{
	  printf ("_%s", t->sym1->text);
	}
      printf ("(");
      tacPrint (t->tac2);
      printf (");\n");
      break;
    case TAC_SEND:
      printf ("send");
      if (t->sym1 != NULL)
	{
	  printf ("_%s", t->sym1->text);
	}
      printf ("(");
      tacPrint (t->tac2);
      printf (");\n");
      break;
    case TAC_CLAIM:
      printf ("claim");
      if (t->sym1 != NULL)
	{
	  printf ("_%s", t->sym1->text);
	}
      printf ("(");
      tacPrint (t->tac2);
      printf (");\n");
      break;
    case TAC_CONST:
      printf ("const ");
      tacPrint (t->tac1);
      if (t->tac2 != NULL)
	{
	  printf (" : ");
	  tacPrint (t->tac2);
	}
      printf (";\n");
      break;
    case TAC_VAR:
      printf ("var ");
      tacPrint (t->tac1);
      if (t->tac2 != NULL)
	{
	  printf (" : ");
	  tacPrint (t->tac2);
	}
      printf (";\n");
      break;
    case TAC_UNDEF:
      printf ("undefined");
      if (t->next != NULL)
	printf (",");
      break;
    case TAC_STRING:
      printf ("%s", t->sym1->text);
      if (t->next != NULL)
	printf (",");
      break;
    case TAC_TUPLE:
      printf ("(");
      tacPrint (t->tac1);
      printf (",");
      tacPrint (t->tac2);
      printf (")");
      break;
    case TAC_ENCRYPT:
      printf ("{");
      tacPrint (t->tac1);
      printf ("}");
      tacPrint (t->tac2);
      if (t->next != NULL)
	{
	  printf (",");
	  t = t->next;
	  tacPrint (t);
	}
      break;
    case TAC_RUN:
      printf ("run ");
      tacPrint (t->tac1);
      printf ("(");
      tacPrint (t->tac2);
      printf (");\n");
      break;
    case TAC_ROLEREF:
      symbolPrint (t->sym1);
      printf (".");
      symbolPrint (t->sym2);
      break;
    case TAC_COMPROMISED:
      printf ("compromised ");
      tacPrint (t->tac1);
      printf (";\n");
      break;
    case TAC_SECRET:
      printf ("secret ");
      tacPrint (t->tac1);
      printf (";\n");
      break;
    case TAC_INVERSEKEYS:
      printf ("inversekeys (");
      tacPrint (t->tac1);
      printf (",");
      tacPrint (t->tac2);
      printf (");\n");
      break;
    case TAC_UNTRUSTED:
      printf ("untrusted ");
      tacPrint (t->tac1);
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
