/** @file terms.c \brief Term related base functions.
 *
 * Intended to be a standalone file, however during development it turned out
 * that a termlist structure was needed to define term types, so there is now a
 * dependency loop with termlists.c.
 *
 * Until now, symbols were unique and never deleted.  The same holds for basic
 * terms; leaves are equal when their pointers are equal.  We are looking to
 * extend this to whole terms. At that point, term equality is be reduced to
 * pointer comparison, which is what we want. However, for comparison of terms
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "term.h"
#include "debug.h"
#include "memory.h"
#include "ctype.h"
#include "specialterm.h"

/* public flag */
int rolelocal_variable;

/* external definitions */

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
  rolelocal_variable = 0;
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
  TermOp (term) = t1;
  TermKey (term) = t2;
  return term;
}

//! Create a fresh term tuple from two existing terms.
/**
 *@return A pointer to the new term.
 */
Term
makeTermTuple (Term t1, Term t2)
{
  Term tt;

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
	{
	  return t2;
	}
    }
  if (t2 == NULL)
    {
      return t1;
    }

  tt = makeTerm ();
  tt->type = TUPLE;
  tt->stype = NULL;
  tt->roleVar = 0;
  TermOp1 (tt) = t1;
  TermOp2 (tt) = t2;
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
  term->roleVar = 0;
  term->subst = NULL;
  TermSymb (term) = symb;
  TermRunid (term) = runid;
  return term;
}

//! Unwrap any substitutions.
/**
 * For speed, it is also a macro. Sometimes it will call
 * deVarScan to do the actual unwinding.
 *@return A term that is either not a variable, or has a NULL substitution.
 *\sa deVar()
 */
__inline__ Term
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
	return (hasTermVariable (TermOp1 (term))
		|| hasTermVariable (TermOp2 (term)));
      else
	return (hasTermVariable (TermOp (term))
		|| hasTermVariable (TermKey (term)));
    }
}

//! Safe wrapper for isTermEqual

int
isTermEqualDebug (Term t1, Term t2)
{
  return isTermEqualFn (t1, t2);
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
      return (TermSymb (term1) == TermSymb (term2)
	      && TermRunid (term1) == TermRunid (term2));
    }
  else
    {
      /* ENCRYPT or TUPLE */

      if (realTermEncrypt (term1))
	{
	  /* for optimization of encryption equality, we compare
	     operator 2 first (we expect it to be a smaller term)
	   */
	  return (isTermEqualFn (TermKey (term1), TermKey (term2)) &&
		  isTermEqualFn (TermOp (term1), TermOp (term2)));
	}
      else
	{
	  /* tuple */

	  return (isTermEqualFn (TermOp1 (term1), TermOp1 (term2)) &&
		  isTermEqualFn (TermOp2 (term1), TermOp2 (term2)));
	}
    }
}

//! See if a term is a subterm of another.
/**
 *@param t Term to be checked for a subterm.
 *@param tsub Subterm.
 *	Note that if t is non-null and tsub is null, it is a valid subterm.
 *@return True iff tsub is a subterm of t.
 */
int
termSubTerm (Term t, Term tsub)
{
  t = deVar (t);
  tsub = deVar (tsub);

  if (isTermEqual (t, tsub))
    {
      return 1;
    }
  else
    {
      if (t == NULL)
	{
	  return 0;
	}
      else
	{
	  if (tsub == NULL)
	    {
	      return 1;
	    }
	  else
	    {
	      if (realTermLeaf (t))
		{
		  return 0;
		}
	      else
		{
		  if (realTermTuple (t))
		    return (termSubTerm (TermOp1 (t), tsub)
			    || termSubTerm (TermOp2 (t), tsub));
		  else
		    return (termSubTerm (TermOp (t), tsub)
			    || termSubTerm (TermKey (t), tsub));
		}
	    }
	}
    }
}

//! See if a term is an interm of another.
/**
 *@param t Term to be checked for a subterm.
 *@param tsub interm.
 *@return True iff tsub is an interm of t.
 */
int
termInTerm (Term t, Term tsub)
{
  t = deVar (t);
  tsub = deVar (tsub);

  if (isTermEqual (t, tsub))
    return 1;
  if (realTermLeaf (t))
    return 0;
  if (realTermTuple (t))
    return (termInTerm (TermOp1 (t), tsub) || termInTerm (TermOp2 (t), tsub));
  else
    return 0;
}

//! Print a term to stdout.
/**
 * The tuple printing only works correctly for normalized terms.
 * If not, they might are displayed as "((x,y),z)". Maybe that is even
 * desirable to distinguish them.
 *\sa termTuplePrint()
 */
void
termPrint (Term term)
{
  if (term == NULL)
    {
      eprintf ("*");
      return;
    }
#ifdef DEBUG
  if (!DEBUGL (4))
    {
      term = deVar (term);
    }
#else
  term = deVar (term);
#endif
  if (realTermLeaf (term))
    {
      symbolPrint (TermSymb (term));
      if (term->type == VARIABLE)
	eprintf ("V");
      if (TermRunid (term) >= 0)
	{
	  if (globalLatex && globalError == 0)
	    eprintf ("\\sharp%i", TermRunid (term));
	  else
	    eprintf ("#%i", TermRunid (term));
	}
      if (term->subst != NULL)
	{
	  if (globalLatex)
	    eprintf ("\\rightarrow");
	  else
	    eprintf ("->");
	  termPrint (term->subst);
	}
    }
  if (realTermTuple (term))
    {
      eprintf ("(");
      termTuplePrint (term);
      eprintf (")");
      return;
    }
  if (realTermEncrypt (term))
    {
      if (isTermLeaf (TermKey (term))
	  && inTermlist (TermKey (term)->stype, TERM_Function))
	{
	  /* function application */
	  termPrint (TermKey (term));
	  eprintf ("(");
	  termTuplePrint (TermOp (term));
	  eprintf (")");
	}
      else
	{
	  /* normal encryption */
	  if (globalLatex)
	    {
	      eprintf ("\\{");
	      termTuplePrint (TermOp (term));
	      eprintf ("\\}_{");
	      termPrint (TermKey (term));
	      eprintf ("}");
	    }
	  else
	    {
	      eprintf ("{");
	      termTuplePrint (TermOp (term));
	      eprintf ("}");
	      termPrint (TermKey (term));
	    }
	}
    }
}

//! Print an inner (tuple) term to stdout, without brackets.
/**
 * The tuple printing only works correctly for normalized terms.
 * If not, they might are displayed as "((x,y),z)". Maybe that is even
 * desirable to distinguish them.
 */
void
termTuplePrint (Term term)
{
  if (term == NULL)
    {
      eprintf ("Empty term");
      return;
    }
  term = deVar (term);
  while (realTermTuple (term))
    {
      // To remove any brackets, change this into termTuplePrint.
      termPrint (TermOp1 (term));
      eprintf (",");
      term = deVar (TermOp2 (term));
    }
  termPrint (term);
  return;
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
  memcpy (newterm, term, sizeof (struct term));
  if (realTermEncrypt (term))
    {
      TermOp (newterm) = termDuplicate (TermOp (term));
      TermKey (newterm) = termDuplicate (TermKey (term));
    }
  else
    {
      TermOp1 (newterm) = termDuplicate (TermOp1 (term));
      TermOp2 (newterm) = termDuplicate (TermOp2 (term));
    }
  return newterm;
}

//! Make a deep copy of a term node (one-level)
/**
 * Leaves are not copied.
 *@return If the original was a leaf, then the pointer is simply returned. Otherwise, new memory is allocated and the node is copied recursively.
 *\sa termDuplicateDeep()
 */

Term
termNodeDuplicate (const Term term)
{
  Term newterm;

  if (term == NULL)
    return NULL;
  if (realTermLeaf (term))
    return term;

  newterm = (Term) memAlloc (sizeof (struct term));
  memcpy (newterm, term, sizeof (struct term));
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
  memcpy (newterm, term, sizeof (struct term));
  if (!realTermLeaf (term))
    {
      if (realTermEncrypt (term))
	{
	  TermOp (newterm) = termDuplicateDeep (TermOp (term));
	  TermKey (newterm) = termDuplicateDeep (TermKey (term));
	}
      else
	{
	  TermOp1 (newterm) = termDuplicateDeep (TermOp1 (term));
	  TermOp2 (newterm) = termDuplicateDeep (TermOp2 (term));
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

  term = deVar (term);
  if (term == NULL)
    return NULL;
  if (realTermLeaf (term))
    return term;

  newterm = (Term) memAlloc (sizeof (struct term));
  memcpy (newterm, term, sizeof (struct term));
  if (realTermEncrypt (term))
    {
      TermOp (newterm) = termDuplicateUV (TermOp (term));
      TermKey (newterm) = termDuplicateUV (TermKey (term));
    }
  else
    {
      TermOp1 (newterm) = termDuplicateUV (TermOp1 (term));
      TermOp2 (newterm) = termDuplicateUV (TermOp2 (term));
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
	  TermOp (newterm) = realTermDuplicate (TermOp (term));
	  TermKey (newterm) = realTermDuplicate (TermKey (term));
	}
      else
	{
	  TermOp1 (newterm) = realTermDuplicate (TermOp1 (term));
	  TermOp2 (newterm) = realTermDuplicate (TermOp2 (term));
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
	  termDelete (TermOp (term));
	  termDelete (TermKey (term));
	}
      else
	{
	  termDelete (TermOp1 (term));
	  termDelete (TermOp2 (term));
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
      termNormalize (TermOp (term));
      termNormalize (TermKey (term));
    }
  else
    {
      /* normalize left hand first,both for tupling and for
         encryption */
      termNormalize (TermOp1 (term));
      /* check for ((x,y),z) construct */
      if (realTermTuple (TermOp1 (term)))
	{
	  /* temporarily store the old terms */
	  Term tx = TermOp1 (TermOp1 (term));
	  Term ty = TermOp2 (TermOp1 (term));
	  Term tz = TermOp2 (term);
	  /* move node */
	  TermOp2 (term) = TermOp1 (term);
	  /* construct (x,(y,z)) version */
	  TermOp1 (term) = tx;
	  TermOp1 (TermOp2 (term)) = ty;
	  TermOp2 (TermOp2 (term)) = tz;
	}
      termNormalize (TermOp2 (term));
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
      if (TermRunid (term) == runid)
	return term;
      else
	{
	  Term newt = termDuplicate (term);
	  TermRunid (newt) = runid;
	  return newt;
	}
    }
  else
    {
      /* anything else, recurse */
      if (realTermEncrypt (term))
	{
	  return makeTermEncrypt (termRunid (TermOp (term), runid),
				  termRunid (TermKey (term), runid));
	}
      else
	{
	  return makeTermTuple (termRunid (TermOp1 (term), runid),
				termRunid (TermOp2 (term), runid));
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
      tt = deVar (tt);
      if (!realTermTuple (tt))
	{
	  return 1;
	}
      else
	{
	  return (tupleCount (TermOp1 (tt)) + tupleCount (TermOp2 (tt)));
	}
    }
}

//! Yield the projection Pi(n) of a term.
/**
 *@param tt Term
 *@param n The index in the tuple [0..tupleCount-1]
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
  tt = deVar (tt);
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
      int left = tupleCount (TermOp1 (tt));
      if (n >= left)
	{
	  /* it's in the right hand side */
	  return tupleProject (TermOp2 (tt), n - left);
	}
      else
	{
	  /* left hand side */
	  return tupleProject (TermOp1 (tt), n);
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
termSize (Term t)
{
  if (t == NULL)
    {
      return 0;
    }

  t = deVar (t);
  if (realTermLeaf (t))
    {
      return 1;
    }
  else
    {
      if (realTermEncrypt (t))
	{
	  return 1 + termSize (TermOp (t)) + termSize (TermKey (t));
	}
      else
	{
	  return termSize (TermOp1 (t)) + termSize (TermOp2 (t));
	}
    }
}

//! Determine distance between two terms.
/**
 *@return A float value between 0, completely dissimilar, and 1, equal.
 *\sa termSize()
 */

float
termDistance (Term t1, Term t2)
{
  int t1s;
  int t2s;

  /* First the special cases: no equal subterms, completely equal */
  if (isTermEqual (t1, t2))
    return 1;

  t1 = deVar (t1);
  t2 = deVar (t2);

  t1s = termSize (t1);
  t2s = termSize (t2);

  if (t1 == NULL || t2 == NULL)
    {
      return 0;
    }
  if (t1->type != t2->type)
    {
      /* unequal type, maybe one is a subterm of the other? */
      if (t1s > t2s && termSubTerm (t1, t2))
	{
	  return (float) t2s / t1s;
	}
      if (t2s > t1s && termSubTerm (t2, t1))
	{
	  return (float) t1s / t2s;
	}
      return 0;
    }
  else
    {
      /* equal types */
      if (isTermLeaf (t1))
	{
	  /* we had established before that they are not equal */
	  return 0;
	}
      else
	{
	  /* non-leaf recurse */
	  if (isTermEncrypt (t1))
	    {
	      /* encryption */
	      return (termDistance (TermOp (t1), TermOp (t2)) +
		      termDistance (TermKey (t1), TermKey (t2))) / 2;
	    }
	  else
	    {
	      return (termDistance (TermOp1 (t1), TermOp1 (t2)) +
		      termDistance (TermOp2 (t1), TermOp2 (t2))) / 2;
	    }
	}
    }
}

/**
 * Enforce a (arbitrary) ordering on terms
 * <0 means a<b, 0 means a=b, >0 means a>b.
 */
int
termOrder (Term t1, Term t2)
{
  char *name1;
  char *name2;

  t1 = deVar (t1);
  t2 = deVar (t2);
  if (isTermEqual (t1, t2))
    {
      /* equal terms */
      return 0;
    }

  /* differ */
  if (t1->type != t2->type)
    {
      /* different types, so ordering on types first */
      if (t1->type < t2->type)
	return -1;
      else
	return 1;
    }

  /* same type
   * distinguish cases
   */
  if (realTermLeaf (t1))
    {
      /* compare names */
      int comp;

      comp = strcmp (TermSymb (t1)->text, TermSymb (t2)->text);
      if (comp != 0)
	{
	  /* names differ */
	  return comp;
	}
      else
	{
	  /* equal names, compare run identifiers */
	  if (TermRunid (t1) == TermRunid (t2))
	    {
	      error
		("termOrder: two terms seem to be identical although local precondition says they aren't.");
	    }
	  else
	    {
	      if (TermRunid (t1) < TermRunid (t2))
		return -1;
	      else
		return 1;
	    }
	}
    }
  else
    {
      /* non-leaf */
      int compL, compR;

      if (isTermEncrypt (t1))
	{
	  compL = termOrder (TermOp (t1), TermOp (t2));
	  compR = termOrder (TermKey (t1), TermKey (t2));
	}
      else
	{
	  compL = termOrder (TermOp1 (t1), TermOp1 (t2));
	  compR = termOrder (TermOp2 (t1), TermOp2 (t2));
	}
      if (compL != 0)
	return compL;
      else
	return compR;
    }
}

//! Generic term iteration
int
term_iterate (const Term term, int (*leaf) (), int (*nodel) (),
	      int (*nodem) (), int (*noder) ())
{
  if (term != NULL)
    {
      if (realTermLeaf (term))
	{
	  // Leaf
	  if (leaf != NULL)
	    {
	      return leaf (term);
	    }
	}
      else
	{
	  int flag;

	  flag = 1;

	  if (nodel != NULL)
	    flag = flag && nodel (term);

	  // Left part
	  if (realTermTuple (term))
	    flag = flag
	      && (term_iterate (TermOp1 (term), leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      && (term_iterate (TermOp (term), leaf, nodel, nodem, noder));

	  if (nodem != NULL)
	    flag = flag && nodem (term);

	  // Right part
	  if (realTermTuple (term))
	    flag = flag
	      && (term_iterate (TermOp2 (term), leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      && (term_iterate (TermKey (term), leaf, nodel, nodem, noder));

	  if (noder != NULL)
	    flag = flag && noder (term);

	  return flag;
	}
    }
  return 1;
}

//! Generic term iteration
int
term_iterate_deVar (Term term, int (*leaf) (), int (*nodel) (),
		    int (*nodem) (), int (*noder) ())
{
  term = deVar (term);
  if (term != NULL)
    {
      if (realTermLeaf (term))
	{
	  // Leaf
	  if (leaf != NULL)
	    {
	      return leaf (term);
	    }
	  else
	    {
	      return 1;
	    }
	}
      else
	{
	  int flag;

	  flag = 1;

	  if (nodel != NULL)
	    flag = flag && nodel (term);

	  // Left part
	  if (realTermTuple (term))
	    flag = flag
	      &&
	      (term_iterate_deVar
	       (TermOp1 (term), leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      &&
	      (term_iterate_deVar (TermOp (term), leaf, nodel, nodem, noder));

	  if (nodem != NULL)
	    flag = flag && nodem (term);

	  // right part
	  if (realTermTuple (term))
	    flag = flag
	      &&
	      (term_iterate_deVar
	       (TermOp2 (term), leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      &&
	      (term_iterate_deVar
	       (TermKey (term), leaf, nodel, nodem, noder));

	  if (noder != NULL)
	    flag = flag && noder (term);

	  return flag;
	}
    }
  return 1;
}

//! Iterate over the leaves in a term
/**
 * Note that this function iterates over real leaves; thus closed variables can occur as
 * well. It is up to func to decide wether or not to recurse.
 */
int
term_iterate_leaves (const Term term, int (*func) ())
{
  if (term != NULL)
    {
      if (realTermLeaf (term))
	{
	  if (!func (term))
	    return 0;
	}
      else
	{
	  if (realTermTuple (term))
	    return (term_iterate_leaves (TermOp1 (term), func)
		    && term_iterate_leaves (TermOp2 (term), func));
	  else
	    return (term_iterate_leaves (TermOp (term), func)
		    && term_iterate_leaves (TermKey (term), func));
	}
    }
  return 1;
}

//! Iterate over open leaves (i.e. respect variable closure)
int
term_iterate_open_leaves (const Term term, int (*func) ())
{
  int testleaf (const Term t)
  {
    if (substVar (t))
      {
	return term_iterate_open_leaves (t, func);
      }
    else
      {
	return func (t);
      }
  }

  return term_iterate_leaves (term, testleaf);
}

//! Turn all rolelocals into variables
void
term_rolelocals_are_variables ()
{
  rolelocal_variable = 1;
}

//! Count the encryption level of a term
int
term_encryption_level (const Term term)
{
  int iter_maxencrypt (Term t)
  {
    t = deVar (t);
    if (t == NULL)
      {
#ifdef DEBUG
	if (DEBUGL (2))
	  {
	    eprintf ("Warning: Term encryption level finds a NULL for term ");
	    termPrint (term);
	    eprintf ("\n");
	  }
#endif
	return 0;
      }
    if (realTermLeaf (t))
      {
	return 0;
      }
    else
      {
	if (realTermTuple (t))
	  {
	    int l, r;

	    l = iter_maxencrypt (TermOp1 (t));
	    r = iter_maxencrypt (TermOp2 (t));
	    if (l > r)
	      return l;
	    else
	      return r;
	  }
	else
	  {
	    // encrypt
	    return 1 + iter_maxencrypt (TermOp (t));
	  }
      }
  }

  return iter_maxencrypt (term);
}

//! Determine 'constrained factor' of a term
/**
 * Actually this is (#vars/structure).
 * Thus, 0 means very constrained, no variables.
 * Everything else has higher float, but always <=1. In fact, only a single variable has a level 1.
 */
float
term_constrain_level (const Term term)
{
  int vars;
  int structure;
  int flag;

  void tcl_iterate (Term t)
  {
    t = deVar (t);
    structure++;
    if (realTermLeaf (t))
      {
	if (realTermVariable (t))
	  vars++;
      }
    else
      {
	if (realTermTuple (t))
	  {
	    tcl_iterate (TermOp1 (t));
	    tcl_iterate (TermOp2 (t));
	  }
	else
	  {
	    tcl_iterate (TermOp (t));
	    tcl_iterate (TermKey (t));
	  }
      }
  }

  if (term == NULL)
    error ("Cannot determine constrain level of empty term.");

  vars = 0;
  structure = 0;
  tcl_iterate (term);
  return ((float) vars / (float) structure);
}

//! Adjust the keylevels of the symbols in a term.
/**
 * This is used to scan the roles. For each symbol, this function does the bookkeeping of the keylevels at which they occur.
 */
void
term_set_keylevels (const Term term)
{
  void scan_levels (int level, Term t)
  {
#ifdef DEBUG
    if (DEBUGL (5))
      {
	int c;

	c = 0;
	while (c < level)
	  {
	    eprintf ("  ");
	    c++;
	  }
	eprintf ("Scanning keylevel %i for term ", level);
	termPrint (t);
	eprintf ("\n");
      }
#endif
    if (realTermLeaf (t))
      {
	Symbol sym;

	// So, it occurs at 'level' as key. If that is less than known, store.
	sym = TermSymb (t);
	if (level < sym->keylevel)
	  {
	    // New minimum level
	    sym->keylevel = level;
	  }
      }
    else
      {
	if (realTermTuple (t))
	  {
	    scan_levels (level, TermOp1 (t));
	    scan_levels (level, TermOp2 (t));
	  }
	else
	  {
	    scan_levels (level, TermOp (t));
	    scan_levels ((level + 1), TermKey (t));
	  }
      }
  }

  scan_levels (0, term);
}

//! Print the term diff of two terms
/**
 * This is not correct yet. We need to add function application and correct tuple handing.
 */
void
termPrintDiff (Term t1, Term t2)
{
  t1 = deVar (t1);
  t2 = deVar (t2);

  void termFromTo (Term t1, Term t2)
  {
    t1 = deVar (t1);
    t2 = deVar (t2);

    eprintf (" [");
    termPrint (t1);
    eprintf ("]->[");
    termPrint (t2);
    eprintf ("] ");
  }

  if (isTermEqual (t1, t2))
    {
      // Equal, simply print
      termPrint (t1);
    }
  else
    {
      if (t1->type != t2->type)
	{
	  // Different types
	  termFromTo (t1, t2);
	}
      else
	{
	  // Equal types, but not the same
	  // If component type, but both components different, we simply do moveto at the node level.
	  if (realTermLeaf (t1))
	    {
	      // Different constants
	      termFromTo (t1, t2);
	    }
	  else
	    {
	      if (realTermEncrypt (t1))
		{
		  // Encryption
		  if (isTermEqual (TermOp (t1), TermOp (t2))
		      || isTermEqual (TermKey (t1), TermKey (t2)))
		    {
		      eprintf ("{");
		      termPrintDiff (TermOp (t1), TermOp (t2));
		      eprintf ("}");
		      termPrintDiff (TermKey (t1), TermKey (t2));
		    }
		  else
		    {
		      termFromTo (t1, t2);
		    }
		}
	      else
		{
		  // Tupling
		  if (isTermEqual (TermOp1 (t1), TermOp1 (t2))
		      || isTermEqual (TermOp2 (t1), TermOp2 (t2)))
		    {
		      eprintf ("(");
		      termPrintDiff (TermOp1 (t1), TermOp1 (t2));
		      eprintf (")");
		      termPrintDiff (TermOp2 (t1), TermOp2 (t2));
		    }
		  else
		    {
		      termFromTo (t1, t2);
		    }
		}
	    }
	}
    }
}
