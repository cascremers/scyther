#include <stdio.h>
#include <stdlib.h>

#include "symbols.h"
#include "memory.h"

/*
   Symbol processor.

   Stores symbols for the lexical scanner. Can later print them.
   Implementation uses a hashtable, the size of which is defined in
   symbols.h.
*/

extern int yylineno;

/* global declarations */

Symbol symbtab[HASHSIZE];
Symbol symb_list;
Symbol symb_alloc;

/* main code */

void
symbolsInit (void)
{
  int i;

  for (i = 0; i < HASHSIZE; i++)
    symbtab[i] = NULL;
  symb_list = NULL;
  symb_alloc = NULL;
}

void
symbolsDone (void)
{
  Symbol s;

  while (symb_alloc != NULL)
    {
      s = symb_alloc;
      symb_alloc = s->allocnext;
      memFree (s, sizeof (struct symbol));
    }
}

Symbol
get_symb (void)
{
  Symbol t;
  if (symb_list != NULL)
    {
      t = symb_list;
      symb_list = symb_list->next;
    }
  else
    {
      t = (Symbol) memAlloc (sizeof (struct symbol));
      t->allocnext = symb_alloc;
      symb_alloc = t;
    }
  return t;
}

void
free_symb (Symbol s)
{
  if (s == NULL)
    return;
  s->next = symb_list;
  symb_list = s;
}

int
hash (char *s)
{
  int hv = 0;
  int i;

  for (i = 0; s[i] != EOS; i++)
    {
      int v = (hv >> 28) ^ (s[i] & 0xf);
      hv = (hv << 4) | v;
    }
  hv = hv & 0x7fffffff;
  return hv % HASHSIZE;
}

void
insert (Symbol s)
{
  if (s == NULL)
    return;			/* illegal insertion of empty stuff */

  int hv = hash (s->text);
  s->next = symbtab[hv];
  symbtab[hv] = s;
}

Symbol
lookup (char *s)
{
  if (s == NULL)
    return NULL;

  int hv = hash (s);
  Symbol t = symbtab[hv];

  while (t != NULL)
    {
      if (strcmp (t->text, s) == 0)
	break;
      else
	t = t->next;
    }
  return t;
}

void
symbolPrint (Symbol s)
{
  if (s == NULL)
    return;

  /* TODO maybe action depending on type? */
  printf ("%s", s->text);
}

Symbol
symbolSysConst (char *str)
{
  Symbol symb;

  symb = lookup (str);
  if (symb == NULL)
    {
      symb = get_symb ();
      symb->lineno = yylineno;
      symb->type = T_SYSCONST;
      symb->text = str;
    }
  return symb;
}
