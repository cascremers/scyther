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

/* public flag */
int rolelocal_variable;

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
  term->left.op = t1;
  term->right.key = t2;
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
  tt->left.op1 = t1;
  tt->right.op2 = t2;
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
  term->left.symb = symb;
  term->right.runid = runid;
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
	return (hasTermVariable (term->left.op1)
		|| hasTermVariable (term->right.op2));
      else
	return (hasTermVariable (term->left.op)
		|| hasTermVariable (term->right.key));
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
      return (term1->left.symb == term2->left.symb
	      && term1->right.runid == term2->right.runid);
    }
  else
    {
      /* ENCRYPT or TUPLE */

      if (realTermEncrypt (term1))
	{
	  /* for optimization of encryption equality, we compare
	     operator 2 first (we expect it to be a smaller term)
	   */
	  return (isTermEqualFn (term1->right.key, term2->right.key) &&
		  isTermEqualFn (term1->left.op, term2->left.op));
	}
      else
	{
	  /* tuple */

	  return (isTermEqualFn (term1->left.op1, term2->left.op1) &&
		  isTermEqualFn (term1->right.op2, term2->right.op2));
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
termSubTerm (Term t, Term tsub)
{
  t = deVar (t);
  tsub = deVar (tsub);

  if (isTermEqual (t, tsub))
    return 1;
  if (realTermLeaf (t))
    return 0;
  if (realTermTuple (t))
    return (termSubTerm (t->left.op1, tsub)
	    || termSubTerm (t->right.op2, tsub));
  else
    return (termSubTerm (t->left.op, tsub)
	    || termSubTerm (t->right.key, tsub));
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
    return (termInTerm (t->left.op1, tsub)
	    || termInTerm (t->right.op2, tsub));
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
      symbolPrint (term->left.symb);
      if (term->type == VARIABLE)
	eprintf ("V");
      if (term->right.runid >= 0)
	{
	  if (globalLatex && globalError == 0)
	    eprintf ("\\sharp%i", term->right.runid);
	  else
	    eprintf ("#%i", term->right.runid);
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
      if (isTermLeaf (term->right.key)
	  && inTermlist (term->right.key->stype, TERM_Function))
	{
	  /* function application */
	  termPrint (term->right.key);
	  eprintf ("(");
	  termTuplePrint (term->left.op);
	  eprintf (")");
	}
      else
	{
	  /* normal encryption */
	  if (globalLatex)
	    {
	      eprintf ("\\{");
	      termTuplePrint (term->left.op);
	      eprintf ("\\}_{");
	      termPrint (term->right.key);
	      eprintf ("}");
	    }
	  else
	    {
	      eprintf ("{");
	      termTuplePrint (term->left.op);
	      eprintf ("}");
	      termPrint (term->right.key);
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
      termPrint (term->left.op1);
      eprintf (",");
      term = deVar (term->right.op2);
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
      newterm->left.op = termDuplicate (term->left.op);
      newterm->right.key = termDuplicate (term->right.key);
    }
  else
    {
      newterm->left.op1 = termDuplicate (term->left.op1);
      newterm->right.op2 = termDuplicate (term->right.op2);
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
	  newterm->left.op = termDuplicateDeep (term->left.op);
	  newterm->right.key = termDuplicateDeep (term->right.key);
	}
      else
	{
	  newterm->left.op1 = termDuplicateDeep (term->left.op1);
	  newterm->right.op2 = termDuplicateDeep (term->right.op2);
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
      newterm->left.op = termDuplicateUV (term->left.op);
      newterm->right.key = termDuplicateUV (term->right.key);
    }
  else
    {
      newterm->left.op1 = termDuplicateUV (term->left.op1);
      newterm->right.op2 = termDuplicateUV (term->right.op2);
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
	  newterm->left.op = realTermDuplicate (term->left.op);
	  newterm->right.key = realTermDuplicate (term->right.key);
	}
      else
	{
	  newterm->left.op1 = realTermDuplicate (term->left.op1);
	  newterm->right.op2 = realTermDuplicate (term->right.op2);
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
	  termDelete (term->left.op);
	  termDelete (term->right.key);
	}
      else
	{
	  termDelete (term->left.op1);
	  termDelete (term->right.op2);
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
      termNormalize (term->left.op);
      termNormalize (term->right.key);
    }
  else
    {
      /* normalize left hand first,both for tupling and for
         encryption */
      termNormalize (term->left.op1);
      /* check for ((x,y),z) construct */
      if (realTermTuple (term->left.op1))
	{
	  /* temporarily store the old terms */
	  Term tx = (term->left.op1)->left.op1;
	  Term ty = (term->left.op1)->right.op2;
	  Term tz = term->right.op2;
	  /* move node */
	  term->right.op2 = term->left.op1;
	  /* construct (x,(y,z)) version */
	  term->left.op1 = tx;
	  (term->right.op2)->left.op1 = ty;
	  (term->right.op2)->right.op2 = tz;
	}
      termNormalize (term->right.op2);
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
      if (term->right.runid == runid)
	return term;
      else
	{
	  Term newt = termDuplicate (term);
	  newt->right.runid = runid;
	  return newt;
	}
    }
  else
    {
      /* anything else, recurse */
      if (realTermEncrypt (term))
	{
	  return makeTermEncrypt (termRunid (term->left.op, runid),
				  termRunid (term->right.key, runid));
	}
      else
	{
	  return makeTermTuple (termRunid (term->left.op1, runid),
				termRunid (term->right.op2, runid));
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
	  return (tupleCount (tt->left.op1) + tupleCount (tt->right.op2));
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
      int left = tupleCount (tt->left.op1);
      if (n >= left)
	{
	  /* it's in the right hand side */
	  return tupleProject (tt->right.op2, n - left);
	}
      else
	{
	  /* left hand side */
	  return tupleProject (tt->left.op1, n);
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
	  return 1 + termSize (t->left.op) + termSize (t->right.key);
	}
      else
	{
	  return termSize (t->left.op1) + termSize (t->right.op2);
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
	      return (termDistance (t1->left.op, t2->left.op) +
		      termDistance (t1->right.key, t2->right.key)) / 2;
	    }
	  else
	    {
	      return (termDistance (t1->left.op1, t2->left.op1) +
		      termDistance (t1->right.op2, t2->right.op2)) / 2;
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

      comp = strcmp (t1->left.symb->text, t2->left.symb->text);
      if (comp != 0)
	{
	  /* names differ */
	  return comp;
	}
      else
	{
	  /* equal names, compare run identifiers */
	  if (t1->right.runid == t2->right.runid)
	    {
	      error
		("termOrder: two terms seem to be identical although local precondition says they aren't.");
	    }
	  else
	    {
	      if (t1->right.runid < t2->right.runid)
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
	  compL = termOrder (t1->left.op, t2->left.op);
	  compR = termOrder (t1->right.key, t2->right.key);
	}
      else
	{
	  compL = termOrder (t1->left.op1, t2->left.op1);
	  compR = termOrder (t1->right.op2, t2->right.op2);
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
	      && (term_iterate (term->left.op1, leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      && (term_iterate (term->left.op, leaf, nodel, nodem, noder));

	  if (nodem != NULL)
	    flag = flag && nodem (term);

	  // Right part
	  if (realTermTuple (term))
	    flag = flag
	      && (term_iterate (term->right.op2, leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      && (term_iterate (term->right.key, leaf, nodel, nodem, noder));

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
	       (term->left.op1, leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      &&
	      (term_iterate_deVar (term->left.op, leaf, nodel, nodem, noder));

	  if (nodem != NULL)
	    flag = flag && nodem (term);

	  // right part
	  if (realTermTuple (term))
	    flag = flag
	      &&
	      (term_iterate_deVar
	       (term->right.op2, leaf, nodel, nodem, noder));
	  else
	    flag = flag
	      &&
	      (term_iterate_deVar (term->right.key, leaf, nodel, nodem, noder));

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
	    return (term_iterate_leaves (term->left.op1, func)
		    && term_iterate_leaves (term->right.op2, func));
	  else
	    return (term_iterate_leaves (term->left.op, func)
		    && term_iterate_leaves (term->right.key, func));
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
  int iter_maxencrypt (Term term)
    {
      term = deVar (term);
      if (realTermLeaf (term))
	{
	  return 0;
	}
      else
	{
	  if (realTermTuple (term))
	    {
	      int l,r;

	      l = iter_maxencrypt (term->left.op1);
	      r = iter_maxencrypt (term->right.op2);
	      if (l>r)
		  return l;
	      else
		  return r;
	    }
	  else
	    {
	      // encrypt
	      return 1+iter_maxencrypt (term->left.op);
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
	    tcl_iterate (t->left.op1);
	    tcl_iterate (t->right.op2);
	  }
	else
	  {
	    tcl_iterate (t->left.op);
	    tcl_iterate (t->right.key);
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
	sym = t->left.symb;
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
	    scan_levels (level, t->left.op1);
	    scan_levels (level, t->right.op2);
	  }
	else
	  {
	    scan_levels (level, t->left.op);
	    scan_levels ((level + 1), t->right.key);
	  }
      }
  }

  scan_levels (0, term);
}
