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

//! Open termlists code.
void
termlistsInit (void)
{
  return;
}

//! Close termlists code.
void
termlistsDone (void)
{
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
  return (Termlist) memAlloc (sizeof (struct termlist));
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
  termlistDelete (tl->next);
  memFree (tl, sizeof (struct termlist));
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
  memFree (tl, sizeof (struct termlist));
}

//! Determine whether a term is an element of a termlist.
/**
 *@return True iff the term is an element of the termlist.
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

//! Concatenates two termlists.
/**
 * The last pointer of the first list is made to point to the second list.
 *@return The pointer to the concatenated list.
 */
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

//! Remove the pointed at element from the termlist.
/**
 * Easier because of the double linked list.
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
  memFree (tl, sizeof (struct termlist));
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
	return termlistAddVariables (termlistAddVariables (tl, t->left.op),
				     t->right.key);
      else
	return
	  termlistAddVariables (termlistAddVariables (tl, t->left.op1), t->right.op2);
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
	return termlistAddVariables (termlistAddVariables (tl, t->left.op),
				     t->right.key);
      else
	return
	  termlistAddVariables (termlistAddVariables (tl, t->left.op1), t->right.op2);
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
  if (t == NULL)
    return tl;
  if (!isTermLeaf (t))
    {
      if (isTermEncrypt (t))
	return termlistAddBasic (termlistAddBasic (tl, t->left.op), t->right.key);
      else
	return termlistAddBasic (termlistAddBasic (tl, t->left.op1), t->right.op2);
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

//! Give the inverse key term of a term.
/**
 * Gives a duplicate of the inverse Key of some term (which is used to encrypt something), as is defined
 * by the termlist, which is a list of key1,key1inv, key2, key2inv, etc...
 *@param inverses The list of inverses, typically from the knowledge.
 *@param key Any term of which the inverse will be determined.
 *@return A pointer to a duplicate of the inverse key term.
 *\sa termDuplicate(), knowledge::inverses
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
  if (isTermEncrypt (key) && isTermLeaf (key->right.key)
      && inTermlist (deVar (key->right.key)->stype, TERM_Function))
    {
      /* we are scanning for functions */
      /* scan the list */
      /* key is function application kk(op), or {op}kk */
      Term funKey (Term orig, Term newk)
      {
	/* in: {op}kk, nk
	 * out: {op'}nk */
	return makeTermEncrypt (termDuplicate (orig->left.op),
				termDuplicate (newk));
      }
      while (inverses != NULL && inverses->next != NULL)
	{

	  if (isTermEqual (key->right.key, inverses->term))
	    return funKey (key, inverses->next->term);
	  if (isTermEqual (key->right.key, inverses->next->term))
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

//! Create a term local to a run.
/*
 * We assume that at this point, no variables have been instantiated yet that occur in this term.
 * We also assume that fromlist, tolist and locals only hold real leaves.
 *\sa termlistLocal()
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
	  newt->left.op1 = termLocal (t->left.op1, fromlist, tolist, locals, runid);
	  newt->right.op2 = termLocal (t->right.op2, fromlist, tolist, locals, runid);
	}
      else
	{
	  newt->left.op = termLocal (t->left.op, fromlist, tolist, locals, runid);
	  newt->right.key = termLocal (t->right.key, fromlist, tolist, locals, runid);
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

//! Check substitution validity
/**
 * Determine whether a variable has been substituted with something with
 * the right type.
 *@param matchmode The system matching mode, typically system::match
 *@param term The closed variable term.
 *@return True iff the substitution is valid in the current mode.
 *\sa system::match
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

