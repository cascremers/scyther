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

#include <stdlib.h>
#include <stdio.h>
#include "termlist.h"
#include "specialterm.h"
#include "debug.h"
#include "error.h"
#include "switches.h"
#include "knowledge.h"

/*
 * Shared stuff
 */

//! Termlist error thing (for global use)
Termlist TERMLISTERROR;

/*
 * Forward declarations
 */

Termlist makeTermlist ();

//! Open termlists code.
void
termlistsInit (void)
{
  TERMLISTERROR = makeTermlist ();
  TERMLISTERROR->term = NULL;
  TERMLISTERROR->prev = NULL;
  TERMLISTERROR->next = NULL;
  return;
}

//! Close termlists code.
void
termlistsDone (void)
{
  termlistDelete (TERMLISTERROR);
  return;
}

//! Allocate memory for a termlist node.
/**
 *@return A pointer to uninitialised memory of the size of a termlist node.
 */
Termlist
makeTermlist ()
{
  /* inline candidate */
  return (Termlist) malloc (sizeof (struct termlist));
}

//! Duplicate a termlist.
/**
 * Uses termDuplicate to copy the elements, and allocated new memory for the list nodes.
 *\sa termDuplicate(), termlistShallow()
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

//! Shallow reverse copy of a termlist.
/**
 * Just copies the element pointers. Allocates new memory for the list nodes.
 * Note that it reverses the order of the list.
 *\sa termlistDuplicate()
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

//! Shallow deletion of a termlist.
/**
 * Deletes the termlist nodes only. Elements are intact after exit.
 *\sa termlistShallow()
 */
void
termlistDelete (Termlist tl)
{
  if (tl == NULL)
    return;
#ifdef DEBUG
  if (tl == TERMLISTERROR)
    {
      static int count = 0;

      count++;
      if (count > 1)
	{
	  // TERMLISTERROR should only be destroyed once (by the done function)
	  error ("Trying to delete TERMLISTERROR a second time, whazzup?");
	}
    }
#endif
  termlistDelete (tl->next);
  free (tl);
}


//! Deep deletion of a termlist.
/**
 * Deletes the termlist nodes as well as the elements.
 *\sa termlistDuplicate(), termDuplicate(), termDelete()
 */
void
termlistDestroy (Termlist tl)
{
  if (tl == NULL)
    return;
  termlistDestroy (tl->next);
  termDelete (tl->term);
  free (tl);
}

//! Determine whether a term is an element of a termlist.
/**
 * The NULL term is not an element of any list. (Not even of the NULL list)
 *
 *@return True iff the term is an element of the termlist.
 */
int
inTermlist (Termlist tl, const Term term)
{
  if (term == NULL)
    {
      return 0;
    }
  while (tl != NULL)
    {
      if (isTermEqual (tl->term, term))
	{
	  return 1;
	}
      tl = tl->next;
    }
  return 0;
}

//! Determine whether a term is an element of a termlist: yield pointer
Termlist
termlistFind (Termlist tl, const Term term)
{
#ifdef DEBUG
  if (term == NULL)
    {
      error ("Trying to do inTermlist for a NULL term.");
    }
#endif
  while (tl != NULL)
    {
      if (isTermEqual (tl->term, term))
	{
	  return tl;
	}
      tl = tl->next;
    }
  return NULL;
}


//! Equality of two term lists.
/**
 * Are all elements of list 1 in list 2, and vice versa? 
 * Note that we assume unique elements!
 *@return True iff every element of the list is in the other list.
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

//! Adds a term to the front of a termlist.
/**
 * Duplicates are allowed.
 *@return A new list pointer.
 *\sa termlistAppend()
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

//! Adds a term to the end of a termlist.
/**
 * Duplicates are allowed.
 *@return A new list pointer if the termlist was NULL.
 *\sa termlistAdd()
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

//! Add a term only to a list if it wasn't in it before.
/**
 * Mimics a basic set type behaviour.
 */
Termlist
termlistAddNew (const Termlist tl, const Term t)
{
  if (t == NULL || inTermlist (tl, t))
    return tl;
  else
    return termlistAdd (tl, t);
}

//! Concatenates two termlists.
/**
 * The last pointer of the first list is made to point to the second list.
 *@return The pointer to the concatenated list.
 */
Termlist
termlistConcat (Termlist tl1, Termlist tl2)
{
  Termlist scan;

  if (tl1 == NULL)
    return tl2;
  if (tl2 == NULL)
    return tl1;

  scan = tl1;
  while (scan->next != NULL)
    scan = scan->next;
  scan->next = tl2;
  return tl1;
}

//! Concatenates two termlists.
/**
 * Creates a completely new list that can be deleted.
 *
 * Note that the order is not preserved currently.
 */
Termlist
termlistConcatStatic (Termlist tl1, Termlist tl2)
{
  Termlist tl, tls;

  tl = NULL;
  for (tls = tl1; tls != NULL; tls = tls->next)
    {
      tl = termlistAdd (tl, tls->term);
    }
  for (tls = tl2; tls != NULL; tls = tls->next)
    {
      tl = termlistAdd (tl, tls->term);
    }
  return tl;
}

//! Remove the pointed at element from the termlist.
/**
 * Easier because of the double linked list. Note: does not do termDelete on the term.
 *
 *@param tl The pointer to the termlist node to be deleted from the list.
 *@return The possibly new head pointer to the termlist.
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
  free (tl);
  return newhead;
}

//! Construct the conjunction of two termlists.
/**
 *@return A new termlist containing the elements in both lists.
 */
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

//! Construct the conjunction of two termlists, and a certain type.
/**
 *@return A new termlist containing the elements in both lists, that are also of the desired type.
 */
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

//! Construct the conjunction of a termlist and a certain type.
/**
 *@return A new termlist containing the elements in the list that are of the desired type.
 */
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

//! Display a termlist.
/**
 * Lists of terms are displayed between square brackets, and seperated by commas.
 */
void
termlistPrint (Termlist tl)
{
  if (tl == NULL)
    {
      eprintf ("[Empty]");
      return;
    }
  eprintf ("[");
  while (tl != NULL)
    {
      termPrint (tl->term);
      tl = tl->next;
      if (tl != NULL)
	eprintf (", ");
    }
  eprintf ("]");
}

//! Append all open variables in a term to a list.
/**
 *@param tl The list to which to append to.
 *@param t The term possibly containing open variables.
 *@return The pointer to the extended list.
 *\sa termlistAddRealVariables()
 */
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
	return termlistAddVariables (termlistAddVariables (tl, TermOp (t)),
				     TermKey (t));
      else
	return
	  termlistAddVariables (termlistAddVariables (tl, TermOp1 (t)),
				TermOp2 (t));
    }
}

//! Append all variables in a term to a list.
/**
 *@param tl The list to which to append to.
 *@param t The term possibly containing open and closed variables.
 *@return The pointer to the extended list.
 *\sa termlistAddVariables()
 */
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
	  if (!inTermlist (tl, t))
	    {
	      tl = termlistAdd (tl, t);
	    }
	  t->subst = tbuf;
	  return termlistAddRealVariables (tl, t->subst);
	}
      else
	{
	  return tl;
	}
    }
  else
    {
      if (realTermEncrypt (t))
	return termlistAddVariables (termlistAddVariables (tl, TermOp (t)),
				     TermKey (t));
      else
	return
	  termlistAddVariables (termlistAddVariables (tl, TermOp1 (t)),
				TermOp2 (t));
    }
}

//! Append all basic terms in a term to a list.
/**
 *@param tl The list to which to append to.
 *@param t The term containing basic terms.
 *@return The pointer to the extended list.
 *\sa termlistAddBasics()
 */
Termlist
termlistAddBasic (Termlist tl, Term t)
{
  t = deVar (t);

  if (t == NULL)
    return tl;
  if (!realTermLeaf (t))
    {
      if (realTermEncrypt (t))
	return termlistAddBasic (termlistAddBasic (tl, TermOp (t)),
				 TermKey (t));
      else
	return termlistAddBasic (termlistAddBasic (tl, TermOp1 (t)),
				 TermOp2 (t));
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

//! Append all basic terms in a termlist to another list.
/**
 *@param tl The list to which to append to.
 *@param scan The termlist with terms containing basic terms.
 *@return The pointer to the extended list.
 *\sa termlistAddBasic()
 */
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

//! Remove a term from a termlist.
/**
 * Removes the first occurrence of the term.
 *@return A new termlist pointer.
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

//! Determine the length of a termlist.
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

//! Create a term local to a run.
/*
 * We assume that at this point, no variables have been instantiated yet that occur in this term.
 * We also assume that fromlist, tolist only hold real leaves.
 *
 * variable instantiations are not followed through.
 *
 *\sa termlistLocal()
 */
Term
termLocal (const Term tPre, Termlist fromlist, Termlist tolist)
{
  Term t;

  if (tPre == NULL)
    return NULL;

  t = deVar (tPre);

  if (realTermLeaf (t))
    {
      while ((fromlist != NULL) && (tolist != NULL))
	{
	  if (isTermEqual (fromlist->term, t))
	    {
	      // matches!
	      return tolist->term;
	    }
	  fromlist = fromlist->next;
	  tolist = tolist->next;
	}
      return t;
    }
  else
    {
      Term newt;

      newt = termNodeDuplicate (t);
      if (realTermTuple (t))
	{
	  TermOp1 (newt) = termLocal (TermOp1 (t), fromlist, tolist);
	  TermOp2 (newt) = termLocal (TermOp2 (t), fromlist, tolist);
	}
      else
	{
	  if (realTermEncrypt (t))
	    {
	      TermOp (newt) = termLocal (TermOp (t), fromlist, tolist);
	      TermKey (newt) = termLocal (TermKey (t), fromlist, tolist);
	    }
	}
      return newt;
    }
}

//! Create a list of instance terms.
/**
 * We expand the termlocal concept to termlists.
 *\sa termLocal()
 */
Termlist
termlistLocal (Termlist tl, const Termlist fromlist, const Termlist tolist)
{
  Termlist newtl = NULL;

  while (tl != NULL)
    {
      newtl = termlistAdd (newtl, termLocal (tl->term, fromlist, tolist));
      tl = tl->next;
    }
  return newtl;
}

//! Check whether a termlist is contained in another.
/**
 *@param tlbig The big list.
 *@param tlsmall The list that is possibly contained in the big one.
 *@return True iff tlsmall is contained in tlbig.
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

//! Check whether the element sets corresponding to two termlist are equal
/**
 * Currently this is a classical two-way containment test, but probably it can be done smarter.
 */
int
isTermlistSetEqual (const Termlist tl1, const Termlist tl2)
{
  if (termlistContained (tl1, tl2))
    {
      if (termlistContained (tl2, tl1))
	{
	  return true;
	}
    }
  return false;
}

//! Yield the result of f(x)
/**
 * This function interpretes two termlists as the domain and range of a function,
 * and if the term occurs in the domain, returns the matching value from the range.
 * Note that these functions cannot have NULL in the domain or the range.
 *@param fromlist The domain list.
 *@param tolist The range list, in a one-to-one correspondence with the fromlist.
 *@param tx The point on which the function is to be evaluated.
 *@return The result of the function application or NULL if the point is not within the domain.
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

//! Yield the last node of a termlist.
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

/**
 * Compare two termlists containing only basic terms, and yield ordering.
 */
int
termlistOrder (Termlist tl1, Termlist tl2)
{
  int order;

  order = 0;
  while (order == 0 && tl1 != NULL && tl2 != NULL)
    {
      order = termOrder (tl1->term, tl2->term);
      tl1 = tl1->next;
      tl2 = tl2->next;
    }
  if (order != 0)
    return order;
  if (tl1 == NULL && tl2 == NULL)
    return order;
  if (tl1 == NULL)
    return -1;
  else
    return 1;
}

//! Iterate over terms in termlist
/**
 * Function gets terms
 */
int
termlist_iterate (Termlist tl, int (*func) ())
{
  while (tl != NULL)
    {
      if (!func (tl->term))
	return 0;
      tl = tl->next;
    }
  return 1;
}

//! Create a tuple term from a termlist
Term
termlist_to_tuple (Termlist tl)
{
  int width;

  width = termlistLength (tl);
  if (width > 1)
    {
      // 2 parts
      // Make two termlists for each side.
      Term tresult;
      Termlist tl1, tl2;
      int split, i;

      /**
       * This can be done much more efficiently by cutting
       * the list temporarily, and reconnecting it afterwards.
       */
      tl1 = NULL;
      tl2 = NULL;
      split = width / 2;
      i = 0;
      while (tl != NULL)
	{
	  if (i < split)
	    tl1 = termlistAdd (tl1, tl->term);
	  else
	    tl2 = termlistAdd (tl2, tl->term);
	  tl = tl->next;
	  i++;
	}
      tresult =
	makeTermTuple (termlist_to_tuple (tl1), termlist_to_tuple (tl2));
      termlistDelete (tl1);
      termlistDelete (tl2);
      return tresult;
    }
  else
    {
      if (tl == NULL)
	{
	  // W00t! Wtf?
	  error ("termlist_to_tuple called (internally?) with NULL");
	}
      else
	{
	  // Single node, simple
	  return termDuplicate (tl->term);
	}
    }
  // @TODO Should be considered an error
  return NULL;
}

//! Split a tuple term into termlist components.
Termlist
tuple_to_termlist (Term t)
{
  t = deVar (t);
  if (t == NULL)
    {
      return NULL;
    }
  else
    {
      if (realTermTuple (t))
	{
	  return termlistConcat (tuple_to_termlist (TermOp1 (t)),
				 tuple_to_termlist (TermOp2 (t)));
	}
      else
	{
	  return termlistAdd (NULL, t);
	}
    }
}

//! Get the leftmost term of a tuple (e.g. a non-tuple)
Term
termLeft (Term t)
{
  t = deVar (t);
  if (realTermTuple (t))
    {
      return termLeft (TermOp1 (t));
    }
  return t;
}

//! Remove all items from tlbig that occur in tlsmall, and return the pointer to the new tlbig.
Termlist
termlistMinusTermlist (const Termlist tlbig, const Termlist tlsmall)
{
  Termlist tl;
  Termlist tlnewstart;

  tl = tlbig;
  tlnewstart = tlbig;
  while (tl != NULL)
    {
      if (inTermlist (tlsmall, tl->term))
	{
	  Termlist tlnext;

	  // Remember next node.
	  tlnext = tl->next;
	  // This node should be removed.
	  tlnewstart = termlistDelTerm (tl);
	  // Skip to next.
	  tl = tlnext;
	}
      else
	{
	  // This item will remain in the list.
	  tl = tl->next;
	}
    }
  return tlnewstart;
}
