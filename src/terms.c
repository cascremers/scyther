/**
 * @file terms.c 
 * \brief Term related base functions.
 *
 * Intended to be a standalone file, however during development it turned out that a termlist structure was needed
 * to define term types, so there is now a dependency loop with termlists.c.
 */
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "terms.h"
#include "debug.h"
#include "memory.h"
#include "ctype.h"


/* external definitions */

extern Term TERM_Function;
extern int inTermlist ();	// suppresses a warning, but at what cost?
extern int globalLatex;

/* forward declarations */

void indent (void);

/* useful macros */

#define RID_UNDEF MIN_INT
/* main code */

/* Two types of terms: general, and normalized. Normalized rewrites all
   tuples to (x,(y,z))..NULL form, making list traversal easy. */

//! Initialization of terms code.
void
termsInit (void)
{
  return;
}

//! Cleanup of terms code.
void
termsDone (void)
{
  return;
}

//! Allocate memory for a term.
/**
 *@return A pointer to the new term memory, which is not yet initialised.
 */
Term
makeTerm ()
{
  return (Term) memAlloc (sizeof (struct term));
}

//! Create a fresh encrypted term from two existing terms.
/**
 *@return A pointer to the new term.
 */
Term
makeTermEncrypt (Term t1, Term t2)
{
  Term term = makeTerm ();
  term->type = ENCRYPT;
  term->stype = NULL;
  term->op = t1;
  term->key = t2;
  return term;
}

//! Create a fresh term tuple from two existing terms.
/**
 *@return A pointer to the new term.
 */
Term
makeTermTuple (Term t1, Term t2)
{
  if (t1 == NULL)
    {
      if (t2 == NULL)
	{
#ifdef DEBUG
	  debug (5, "Trying to make a tuple node with an empty term.");
#endif
	  return NULL;
	}
      else
	return t2;
    }
  if (t2 == NULL)
    {
      return t1;
    }

  Term tt = makeTerm ();
  tt->type = TUPLE;
  tt->stype = NULL;
  tt->op1 = t1;
  tt->op2 = t2;
  return tt;
}

//! Make a term of the given type with run identifier and symbol.
/**
 *@return A pointer to the new term.
 *\sa GLOBAL, VARIABLE, LEAF, ENCRYPT, TUPLE
 */
Term
makeTermType (const int type, const Symbol symb, const int runid)
{
  Term term = makeTerm ();
  term->type = type;
  term->stype = NULL;
  term->subst = NULL;
  term->symb = symb;
  term->runid = runid;
  return term;
}

//! Unwrap any substitutions.
/**
 * For speed, it is also a macro. Sometimes it will call
 * deVarScan to do the actual unwinding.
 *@return A term that is either not a variable, or has a NULL substitution.
 *\sa deVar()
 */
Term
deVarScan (Term t)
{
  while (realTermVariable (t) && t->subst != NULL)
    t = t->subst;
  return t;
}

//! Determine whether a term contains an unsubstituted variable as subterm.
/**
 *@return True iff there is an open variable as subterm.
 */
int
hasTermVariable (Term term)
{
  if (term == NULL)
    return 0;
  term = deVar (term);
  if (realTermLeaf (term))
    return realTermVariable (term);
  else
    {
      if (realTermTuple (term))
	return (hasTermVariable (term->op1) || hasTermVariable (term->op2));
      else
	return (hasTermVariable (term->op) || hasTermVariable (term->key));
    }
}


//!Tests whether two terms are completely identical.
/**
 * This also includes
 * variables. This is the recursive function.
 * We assume the term is normalized, e.g. no tupling has direct
 * subtupling.
 *@return True iff the terms are equal.
 *\sa isTermEqual()
 */

int
isTermEqualFn (Term term1, Term term2)
{
  term1 = deVar (term1);
  term2 = deVar (term2);

  if (term1 == term2)
    return 1;
  if ((term1 == NULL) || (term2 == NULL))
    return 0;

  if (term1->type != term2->type)
    {
      return 0;
    }
  if (realTermLeaf (term1))
    {
      return (term1->symb == term2->symb && term1->runid == term2->runid);
    }
  else
    {
      /* ENCRYPT or TUPLE */

      if (realTermEncrypt (term1))
	{
	  /* for optimization of encryption equality, we compare
	     operator 2 first (we expect it to be a smaller term)
	   */
	  return (isTermEqualFn (term1->key, term2->key) &&
		  isTermEqualFn (term1->op, term2->op));
	}
      else
	{
	  /* tuple */

	  return (isTermEqualFn (term1->op1, term2->op1) &&
		  isTermEqualFn (term1->op2, term2->op2));
	}
    }
}

//! See if a term is a subterm of another.
/**
 *@param t Term to be checked for a subterm.
 *@param tsub Subterm.
 *@return True iff tsub is a subterm of t.
 */
int
termOccurs (Term t, Term tsub)
{
  t = deVar (t);
  tsub = deVar (tsub);

  if (isTermEqual (t, tsub))
    return 1;
  if (realTermLeaf (t))
    return 0;
  if (realTermTuple (t))
    return (termOccurs (t->op1, tsub) || termOccurs (t->op2, tsub));
  else
    return (termOccurs (t->op, tsub) || termOccurs (t->key, tsub));
}

//! Print a term to stdout.
void
termPrint (Term term)
{
  if (term == NULL)
    {
      printf ("Empty term");
      return;
    }
#ifdef DEBUG
  if (!DEBUGL (1))
    {
      term = deVar (term);
    }
#else
  term = deVar (term);
#endif
  if (realTermLeaf (term))
    {
      symbolPrint (term->symb);
      if (realTermVariable (term))
	printf ("V");
      if (term->runid >= 0)
	{
	  if (globalLatex)
	    printf ("\\sharp%i", term->runid);
	  else
	    printf ("#%i", term->runid);
	}
      if (term->subst != NULL)
	{
	  if (globalLatex)
	    printf ("\\rightarrow");
	  else
	    printf ("->");
	  termPrint (term->subst);
	}
    }
  if (realTermTuple (term))
    {
      printf ("(");
      while (realTermTuple (term))
	{
	  termPrint (term->op1);
	  printf (",");
	  term = term->op2;
	  if (!realTermTuple (term))
	    termPrint (term);

	}
      printf (")");
      return;
    }
  if (realTermEncrypt (term))
    {
      if (isTermLeaf (term->key)
	  && inTermlist (term->key->stype, TERM_Function))
	{
	  /* function application */
	  termPrint (term->key);
	  printf ("(");
	  termPrint (term->op);
	  printf (")");
	}
      else
	{
	  /* normal encryption */
	  if (globalLatex)
	    {
	      printf ("\\{");
	      termPrint (term->op);
	      printf ("\\}_{");
	      termPrint (term->key);
	      printf ("}");
	    }
	  else
	    {
	      printf ("{");
	      termPrint (term->op);
	      printf ("}");
	      termPrint (term->key);
	    }
	}
    }
}


//! Make a deep copy of a term.
/**
 * Leaves are not copied.
 *@return If the original was a leaf, then the pointer is simply returned. Otherwise, new memory is allocated and the node is copied recursively.
 *\sa termDuplicateDeep()
 */

Term
termDuplicate (const Term term)
{
  Term newterm;

  if (term == NULL)
    return NULL;
  if (realTermLeaf (term))
    return term;

  newterm = (Term) memAlloc (sizeof (struct term));
  newterm->type = term->type;
  if (realTermEncrypt (term))
    {
      newterm->op = termDuplicate (term->op);
      newterm->key = termDuplicate (term->key);
    }
  else
    {
      newterm->op1 = termDuplicate (term->op1);
      newterm->op2 = termDuplicate (term->op2);
    }
  return newterm;
}

//! Make a true deep copy of a term.
/**
 * Currently, it this function is not to be used, so we can be sure leaf nodes occur only once in the system.
 *@return New memory is allocated and the node is copied recursively.
 *\sa termDuplicate()
 */


Term
termDuplicateDeep (const Term term)
{
  Term newterm;

  if (term == NULL)
    return NULL;

  newterm = (Term) memAlloc (sizeof (struct term));
  if (realTermLeaf (term))
    {
      memcpy (newterm, term, sizeof (struct term));
    }
  else
    {
      newterm->type = term->type;
      if (realTermEncrypt (term))
	{
	  newterm->op = termDuplicateDeep (term->op);
	  newterm->key = termDuplicateDeep (term->key);
	}
      else
	{
	  newterm->op1 = termDuplicateDeep (term->op1);
	  newterm->op2 = termDuplicateDeep (term->op2);
	}
    }
  return newterm;
}

//! Make a copy of a term, but remove substituted variable nodes.
/**
 * Remove all instantiated variables on the way down.
 *\sa termDuplicate()
 */

Term
termDuplicateUV (Term term)
{
  Term newterm;

  if (term == NULL)
    return NULL;
  term = deVar (term);
  if (realTermLeaf (term))
    return term;

  newterm = (Term) memAlloc (sizeof (struct term));
  newterm->type = term->type;
  if (realTermEncrypt (term))
    {
      newterm->op = termDuplicateUV (term->op);
      newterm->key = termDuplicateUV (term->key);
    }
  else
    {
      newterm->op1 = termDuplicateUV (term->op1);
      newterm->op2 = termDuplicateUV (term->op2);
    }
  return newterm;
}

/*

realTermDuplicate

make a deep copy of a term, also of leaves.

*/

Term
realTermDuplicate (const Term term)
{
  Term newterm;

  if (term == NULL)
    return NULL;

  newterm = (Term) memAlloc (sizeof (struct term));
  if (realTermLeaf (term))
    {
      memcpy (newterm, term, sizeof (struct term));
    }
  else
    {
      newterm->type = term->type;
      if (realTermEncrypt (term))
	{
	  newterm->op = realTermDuplicate (term->op);
	  newterm->key = realTermDuplicate (term->key);
	}
      else
	{
	  newterm->op1 = realTermDuplicate (term->op1);
	  newterm->op2 = realTermDuplicate (term->op2);
	}
    }
  return newterm;
}

//!Removes a term and deallocates memory.
/**
 * Is meant to remove terms make with termDuplicate. Only deallocates memory
 * of nodes, not of leaves.
 *\sa termDuplicate(), termDuplicateUV()
 */

void
termDelete (const Term term)
{
  if (term != NULL && !realTermLeaf (term))
    {
      if (realTermEncrypt (term))
	{
	  termDelete (term->op);
	  termDelete (term->key);
	}
      else
	{
	  termDelete (term->op1);
	  termDelete (term->op2);
	}
      memFree (term, sizeof (struct term));
    }
}

//! Normalize a term with respect to tupling.
/**
 * Avoids problems with associativity by rewriting every ((x,y),z) to
 * (x,(y,z)), i.e. a normal form for terms, after which equality is
 * okay. No memory was allocated or deallocated, as only pointers are swapped.
 *
 *@return After execution, the term pointed at has been normalized. */

void
termNormalize (Term term)
{
  term = deVar (term);
  if (term == NULL || realTermLeaf (term))
    return;

  if (realTermEncrypt (term))
    {
      termNormalize (term->op);
      termNormalize (term->key);
    }
  else
    {
      /* normalize left hand first,both for tupling and for
         encryption */
      termNormalize (term->op1);
      /* check for ((x,y),z) construct */
      if (realTermTuple (term->op1))
	{
	  /* temporarily store the old terms */
	  Term tx = (term->op1)->op1;
	  Term ty = (term->op1)->op2;
	  Term tz = term->op2;
	  /* move node */
	  term->op2 = term->op1;
	  /* construct (x,(y,z)) version */
	  term->op1 = tx;
	  (term->op2)->op1 = ty;
	  (term->op2)->op2 = tz;
	}
      termNormalize (term->op2);
    }
}

//! Copy a term, and ensure all run identifiers are set to the new value.
/**
 * Strange code. Only to be used on locals, as is stupidly replaces all run identifiers.
 *@return The new term.
 *\sa termDuplicate()
 */
Term
termRunid (Term term, int runid)
{
  if (term == NULL)
    return NULL;
  if (realTermLeaf (term))
    {
      /* leaf */
      if (term->runid == runid)
	return term;
      else
	{
	  Term newt = termDuplicate (term);
	  newt->runid = runid;
	  return newt;
	}
    }
  else
    {
      /* anything else, recurse */
      if (realTermEncrypt (term))
	{
	  return makeTermEncrypt (termRunid (term->op, runid),
				  termRunid (term->key, runid));
	}
      else
	{
	  return makeTermTuple (termRunid (term->op1, runid),
				termRunid (term->op2, runid));
	}
    }
}

//! Determine tuple width of a given term.
/**
 *\sa tupleProject()
 */
int
tupleCount (Term tt)
{
  if (tt == NULL)
    {
      return 0;
    }
  else
    {
      deVar (tt);
      if (!realTermTuple (tt))
	{
	  return 1;
	}
      else
	{
	  return (tupleCount (tt->op1) + tupleCount (tt->op2));
	}
    }
}

//! Yield the projection Pi(n) of a term.
/**
 *@param tt Term
 *@param n The index in the tuple.
 *@return Returns either a pointer to a term, or NULL if the index is out of range.
 *\sa tupleCount()
 */
Term
tupleProject (Term tt, int n)
{
  if (tt == NULL)
    {
      return NULL;
    }
  deVar (tt);
  if (!realTermTuple (tt))
    {
      if (n > 0)
	{
	  /* no tuple, adressing error */
	  return NULL;
	}
      else
	{
	  /* no tuple */
	  return tt;
	}
    }
  else
    {
      /* there is a tuple to traverse */
      int left = tupleCount (tt->op1);
      if (n >= left)
	{
	  /* it's in the right hand side */
	  return tupleProject (tt->op2, n - left);
	}
      else
	{
	  /* left hand side */
	  return tupleProject (tt->op1, n);
	}
    }
}

//! Determine size of term.
/**
 * Determines the size of a term according to some heuristic.
 * Currently, the encryption operator is weighed as well.
 *@return Returns a nonnegative integer.
 *\sa termDistance()
 */

int
termSize(Term t)
{
  if (t == NULL)
    {
      return 0;
    }

  t = deVar(t);
  if (realTermLeaf(t))
    {
      return 1;
    }
  else
    {
      if (realTermEncrypt(t))
	{
	  return 1 + termSize(t->op) + termSize(t->key);
	}
      else
	{
	  return termSize(t->op1) + termSize(t->op2);
	}
    }
}

//! Determine distance between two terms.
/**
 *@return A float value between 0, completely dissimilar, and 1, equal.
 *\sa termSize()
 */

float
termDistance(Term t1, Term t2)
{
  /* First the special cases: no equal subterms, completely equal */
  if (isTermEqual(t1,t2))
      return 1;

  t1 = deVar(t1);
  t2 = deVar(t2);

  int t1s = termSize(t1);
  int t2s = termSize(t2);

  if (t1 == NULL || t2 == NULL)
    {
      return 0;
    }
  if (t1->type != t2->type)
    {
      /* unequal type, maybe one is a subterm of the other? */
      if (t1s > t2s && termOccurs(t1,t2))
	{
	  return (float) t2s / t1s;
	}
      if (t2s > t1s && termOccurs(t2,t1))
	{
	  return (float) t1s / t2s;
	}
      return 0;
    }
  else
    {
      /* equal types */
      if (isTermLeaf(t1))
	{
	  /* we had established before that they are not equal */
	  return 0;
	}
      else
	{
	  /* non-leaf recurse */
	  if (isTermEncrypt(t1))
	    {
	      /* encryption */
	      return (termDistance(t1->op, t2->op) + termDistance(t1->key, t2->key)) / 2;
	    }
	  else
	    {
	      return (termDistance(t1->op1, t2->op1) + termDistance(t1->op2, t2->op2)) / 2;
	    }
	}
    }
}
