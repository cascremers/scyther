#include <stdio.h>
#include <stdlib.h>

#include "symbol.h"
#include "memory.h"

/*
   Symbol processor.

   Stores symbols for the lexical scanner. Can later print them.
   Implementation uses a hashtable, the size of which is defined in
   symbols.h.
*/

extern int yylineno;

/* global declarations */

//! Symbol hash table.
Symbol symbtab[HASHSIZE];
//! List of available (freed) symbol blocks.
Symbol symb_list;
//! List of all allocated symbol blocks.
Symbol symb_alloc;

/* main code */

//! Open symbols code.
void
symbolsInit (void)
{
  int i;

  for (i = 0; i < HASHSIZE; i++)
    symbtab[i] = NULL;
  symb_list = NULL;
  symb_alloc = NULL;
}

//! Close symbols code.
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

//! Create a memory block for a symbol.
/**
 * Internal memory management is used.
 *@return A pointer to a memory block of size struct.
 */
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

//! Declare a symbol to be freed.
void
free_symb (Symbol s)
{
  if (s == NULL)
    return;
  s->next = symb_list;
  symb_list = s;
}

//! Return the index in the hash table for the string.
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

//! Insert a string into the hash table.
void
insert (Symbol s)
{
  int hv;

  if (s == NULL)
    return;			/* illegal insertion of empty stuff */

  hv = hash (s->text);
  s->next = symbtab[hv];
  symbtab[hv] = s;
}

//! Find a string in the hash table.
Symbol
lookup (char *s)
{
  int hv;
  Symbol t;

  if (s == NULL)
    return NULL;

  hv = hash (s);
  t = symbtab[hv];

  while (t != NULL)
    {
      if (strcmp (t->text, s) == 0)
	break;
      else
	t = t->next;
    }
  return t;
}

//! Print a symbol.
void
symbolPrint (Symbol s)
{
  if (s == NULL)
    return;

  /* TODO maybe action depending on type? */
  printf ("%s", s->text);
}

//! Insert a string into the symbol table, if it wasn't there yet.
/**
 * Also sets line numbers and type.
 *\sa T_SYSCONST
 */
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
