#include <stdlib.h>
#include <stdio.h>
#include "termlists.h"
#include "debug.h"
#include "memory.h"

/* system constants.
 * declared in compiler.c
 */

extern Term TERM_Function;
extern Term TERM_Hidden;

void
termlistsInit (void)
{
  return;
}

void
termlistsDone (void)
{
  return;
}

/* inline candidate */

Termlist
makeTermlist ()
{
  return (Termlist) memAlloc (sizeof (struct termlist));
}

/*

termlistDuplicate

A deep copy.

*/

Termlist
termlistDuplicate (Termlist tl)
{
  Termlist newtl;

  if (tl == NULL)
    return NULL;
  newtl = makeTermlist ();
  newtl->term = termDuplicate (tl->term);
  newtl->prev = NULL;
  newtl->next = termlistDuplicate (tl->next);
  if (newtl->next != NULL)
    (newtl->next)->prev = newtl;
  return newtl;
}

/*

termlistShallow

A shallow copy, because I gather we won't be modifying any terms, only
termlists. Oh, and it reverses the order :) Don't forget!

*/

Termlist
termlistShallow (Termlist tl)
{
  Termlist newtl;

  newtl = NULL;
  while (tl != NULL)
    {
      newtl = termlistAdd (newtl, tl->term);
      tl = tl->next;
    }
  return newtl;
}

/*

termlistDelete

(shallow)

*/

void
termlistDelete (Termlist tl)
{
  if (tl == NULL)
    return;
  termlistDelete (tl->next);
  memFree (tl, sizeof (struct termlist));
}


/*

termlistDestroy

(deep)

*/

void
termlistDestroy (Termlist tl)
{
  if (tl == NULL)
    return;
  termlistDestroy (tl->next);
  termDelete (tl->term);
  memFree (tl, sizeof (struct termlist));
}

/*

inTermlist

check whether a term occurs in a termlist

*/

int
inTermlist (Termlist tl, Term term)
{
  if (tl == NULL)
    {
      if (term == NULL)
	return 1;
      else
	return 0;
    }
  else
    {
      if (isTermEqual (tl->term, term))
	return 1;
      else
	return inTermlist (tl->next, term);
    }
}

/* are all elements of list 1 in list 2, and vice versa? 
 Note that we assume unique elements !
 */

int
isTermlistEqual (Termlist tl1, Termlist tl2)
{
  if (termlistLength (tl1) != termlistLength (tl2))
    return 0;
  while (tl2 != NULL)
    {
      if (!inTermlist (tl1, tl2->term))
	return 0;
      tl2 = tl2->next;
    }
  return 1;
}

/*

termlistAdd

Adds a term. Duplicates are allowed.
A new list pointer is returned.

*/

Termlist
termlistAdd (Termlist tl, Term term)
{
  Termlist newtl;

  newtl = makeTermlist ();
  newtl->term = term;
  newtl->next = tl;

  if (tl == NULL)
    {
      newtl->prev = NULL;
    }
  else
    {
      newtl->prev = tl->prev;
      if (newtl->prev != NULL)
	(newtl->prev)->next = newtl;
      tl->prev = newtl;
    }
  return newtl;
}

/*

termlistAppend

Appends a term to the end of the list. Duplicates are allowed.
A new list pointer is returned.

*/

Termlist
termlistAppend (const Termlist tl, const Term term)
{
  Termlist newtl;
  Termlist scantl;

  newtl = makeTermlist ();
  newtl->term = term;
  newtl->next = NULL;

  if (tl == NULL)
    {
      newtl->prev = NULL;
      return newtl;
    }
  else
    {
      scantl = tl;
      while (scantl->next != NULL)
	scantl = scantl->next;
      scantl->next = newtl;
      newtl->prev = scantl;
    }
  return tl;
}

Termlist
termlistConcat (Termlist tl1, Termlist tl2)
{
  if (tl1 == NULL)
    return tl2;
  if (tl2 == NULL)
    return tl1;

  Termlist scan = tl1;
  while (scan->next != NULL)
    scan = scan->next;
  scan->next = tl2;
  return tl1;
}

/*

termlistDelTerm

remove the current element from the termlist. Easier because of the
double linked list.

*/
Termlist
termlistDelTerm (Termlist tl)
{
  Termlist newhead;

  if (tl == NULL)
    return NULL;
  if (tl->prev != NULL)
    {
      (tl->prev)->next = tl->next;
      newhead = tl->prev;
      while (newhead->prev != NULL)
	newhead = newhead->prev;
    }
  else
    {
      newhead = tl->next;
    }
  if (tl->next != NULL)
    (tl->next)->prev = tl->prev;
  memFree (tl, sizeof (struct termlist));
  return newhead;
}

Termlist
termlistConjunct (Termlist tl1, Termlist tl2)
{
  Termlist newtl;
  Termlist scan;

  scan = tl1;
  newtl = NULL;
  while (scan != NULL)
    {
      if (inTermlist (tl2, scan->term))
	newtl = termlistAdd (newtl, scan->term);
      scan = scan->next;
    }
  return newtl;
}

Termlist
termlistConjunctType (Termlist tl1, Termlist tl2, int termtype)
{
  Termlist newtl;
  Termlist scan;

  scan = tl1;
  newtl = NULL;
  while (scan != NULL)
    {
      if (((scan->term)->type == termtype) && (inTermlist (tl2, scan->term)))
	newtl = termlistAdd (newtl, scan->term);
      scan = scan->next;
    }
  return newtl;
}

Termlist
termlistType (Termlist tl, int termtype)
{
  Termlist newtl;
  Termlist scan;

  scan = tl;
  newtl = NULL;
  while (scan != NULL)
    {
      if ((scan->term)->type == termtype)
	newtl = termlistAdd (newtl, scan->term);
      scan = scan->next;
    }
  return newtl;
}

void
termlistPrint (Termlist tl)
{
  if (tl == NULL)
    {
      printf ("[Empty]");
      return;
    }
  printf ("[");
  while (tl != NULL)
    {
      termPrint (tl->term);
      tl = tl->next;
      if (tl != NULL)
	  printf(", ");
    }
  printf ("]");
}

Termlist
termlistAddVariables (Termlist tl, Term t)
{
  if (t == NULL)
    return tl;

  t = deVar (t);
  if (isTermLeaf (t))
    {
      if (isTermVariable (t) && !inTermlist (tl, t))
	return termlistAdd (tl, t);
      else
	return tl;
    }
  else
    {
      if (isTermEncrypt (t))
	return termlistAddVariables (termlistAddVariables (tl, t->op),
				     t->key);
      else
	return
	  termlistAddVariables (termlistAddVariables (tl, t->op1), t->op2);
    }
}
    
Termlist
termlistAddRealVariables (Termlist tl, Term t)
{
  if (t == NULL)
    return tl;

  if (realTermLeaf (t))
    {
      if (realTermVariable (t))
	{
	  Term tbuf = t->subst;
	  t->subst = NULL;
	  if (!inTermlist (tl,t))
	    {
	      tl = termlistAdd (tl,t);
	    }
	  t->subst = tbuf;
	  return termlistAddRealVariables (tl,t->subst);
	}
      else
	{
	  return tl;
	}
    }
  else
    {
      if (realTermEncrypt (t))
	return termlistAddVariables (termlistAddVariables (tl, t->op),
				     t->key);
      else
	return
	  termlistAddVariables (termlistAddVariables (tl, t->op1), t->op2);
    }
}

Termlist
termlistAddBasic (Termlist tl, Term t)
{
  if (t == NULL)
    return tl;
  if (!isTermLeaf (t))
    {
      if (isTermEncrypt (t))
	return termlistAddBasic (termlistAddBasic (tl, t->op), t->key);
      else
	return termlistAddBasic (termlistAddBasic (tl, t->op1), t->op2);
    }
  else
    {
      if (!inTermlist (tl, t))
	{
	  return termlistAdd (tl, t);
	}

    }
  return tl;
}

Termlist
termlistAddBasics (Termlist tl, Termlist scan)
{
  while (scan != NULL)
    {
      tl = termlistAddBasic (tl, scan->term);
      scan = scan->next;
    }
  return tl;
}

/*
 * termlistMinusTerm
 *
 * Remove a term from a termlist, and yield a new termlist pointer.
 * Semantics: remove the first occurrence of the term.
 */

Termlist
termlistMinusTerm (Termlist tl, Term t)
{
  Termlist scan;

  scan = tl;
  while (scan != NULL)
    {
      if (isTermEqual (scan->term, t))
	return termlistDelTerm (scan);
      else
	scan = scan->next;
    }
  return tl;
}

int
termlistLength (Termlist tl)
{
  int i = 0;

  while (tl != NULL)
    {
      tl = tl->next;
      i++;
    }
  return i;
}

/*

inverseKey

Gives the inverse Key of some term (which is used to encrypt something), as is defined
by the termlist, which is a list of key1,key1inv, key2, key2inv, etc...

*/


Term
inverseKey (Termlist inverses, Term key)
{
  key = deVar (key);

  /* is this a function application? i.e. hash? */
  if (isTermLeaf (key) && inTermlist (key->stype, TERM_Function))
    {
      /* functions cannot be inverted by default */
      return termDuplicate (TERM_Hidden);
    }
  /* check for the special case first: when it is effectively a function application  */
  if (isTermEncrypt (key) && isTermLeaf (key->key)
      && inTermlist (deVar (key->key)->stype, TERM_Function))
    {
      /* we are scanning for functions */
      /* scan the list */
      /* key is function application kk(op), or {op}kk */
      Term funKey (Term orig, Term newk)
      {
	/* in: {op}kk, nk
	 * out: {op'}nk */
	return makeTermEncrypt (termDuplicate (orig->op),
				termDuplicate (newk));
      }
      while (inverses != NULL && inverses->next != NULL)
	{

	  if (isTermEqual (key->key, inverses->term))
	    return funKey (key, inverses->next->term);
	  if (isTermEqual (key->key, inverses->next->term))
	    return funKey (key, inverses->term);
	  inverses = inverses->next->next;
	}
    }
  else
    {
      /* scanning for a direct inverse */

      /* scan the list */
      while (inverses != NULL && inverses->next != NULL)
	{
	  if (isTermEqual (key, inverses->term))
	    return termDuplicate (inverses->next->term);
	  if (isTermEqual (key, inverses->next->term))
	    return termDuplicate (inverses->term);
	  inverses = inverses->next->next;
	}
    }
  return termDuplicate (key);	/* defaults to symmetrical */
}

/*
 * localTerm
 *
 * Creates a term local to a run.
 * We assume that at this point, no variables have been instantiated yet that occur in this term.
 * We also assume that fromlist, tolist and locals only hold real leaves.
 */

Term
termLocal (const Term t, Termlist fromlist, Termlist tolist,
	   const Termlist locals, const int runid)
{
  if (t == NULL)
    return NULL;

  if (realTermLeaf (t))
    {
      while (fromlist != NULL && tolist != NULL)
	{
	  if (isTermEqual (fromlist->term, t))
	    {
	      // matches!
	      return tolist->term;
	    }
	  fromlist = fromlist->next;
	  tolist = tolist->next;
	}
      if (inTermlist (locals, t))
	{
	  // return termRunid(t,runid);
	}
      return t;
    }
  else
    {
      Term newt = termDuplicate (t);
      if (realTermTuple (t))
	{
	  newt->op1 = termLocal (t->op1, fromlist, tolist, locals, runid);
	  newt->op2 = termLocal (t->op2, fromlist, tolist, locals, runid);
	}
      else
	{
	  newt->op = termLocal (t->op, fromlist, tolist, locals, runid);
	  newt->key = termLocal (t->key, fromlist, tolist, locals, runid);
	}
      return newt;
    }
}

/*
 * termlistLocal
 *
 * We expand the previous concept to termlists.
 */

Termlist
termlistLocal (Termlist tl, const Termlist fromlist, const Termlist tolist,
	       const Termlist locals, int runid)
{
  Termlist newtl = NULL;

  while (tl != NULL)
    {
      newtl =
	termlistAdd (newtl,
		     termLocal (tl->term, fromlist, tolist, locals, runid));
      tl = tl->next;
    }
  return newtl;
}

/*
 * Check whether tl2 is contained in tl1.
 */

int
termlistContained (const Termlist tlbig, Termlist tlsmall)
{
  while (tlsmall != NULL)
    {
      if (!inTermlist (tlbig, tlsmall->term))
	return 0;
      tlsmall = tlsmall->next;
    }
  return 1;
}

/*
 * Determine whether a variable has been substituted with something with
 * the right type.
 */

int
validSubst (const int matchmode, const Term term)
{
  if (!realTermVariable (term) || term->subst == NULL)
    return 1;
  else
    {
      switch (matchmode)
	{
	case 0:		/* real type match */
	  return realTermLeaf (term->subst)
	    && termlistContained (term->stype, term->subst->stype);
	case 1:		/* basic type match */
	  /* subst must be a leaf */
	  /* TODO: what about functions? */
	  return realTermLeaf (term->subst);
	case 2:		/* no type match */
	  /* anything goes */
	  return 1;
	default:
	  return 0;
	}
    }
}

/*
 * termFunction
 *
 * An assist function that helps to simulate Term->Term functions, using
 * termlists. One termlist functions as the domain, and the other as the
 * range.
 *
 * Extending a function with a value y = f(x) amounts to extending the
 * domain with x, and the range with y.
 */

Term
termFunction (Termlist fromlist, Termlist tolist, Term tx)
{
  while (fromlist != NULL && tolist != NULL)
    {
      if (isTermEqual (fromlist->term, tx))
	{
	  return tolist->term;
	}
      fromlist = fromlist->next;
      tolist = tolist->next;
    }
  return NULL;
}

/*
 * Forward the termlist pointer to the last item
 */

Termlist
termlistForward (Termlist tl)
{
  if (tl == NULL)
    {
      return NULL;
    }
  else
    {
      while (tl->next != NULL)
	{
	  tl = tl->next;
	}
      return tl;
    }
}

