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

void
termsInit (void)
{
  return;
}

void
termsDone (void)
{
  return;
}

Term
makeTerm ()
{
  return (Term) memAlloc (sizeof (struct term));
}

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

/* deVar unwraps any substitutions.
 *
 * For speed, it is a macro. Sometimes it will call
 * deVarScan to do the actual unwinding.
 */

Term
deVarScan (Term t)
{
  while (realTermVariable (t) && t->subst != NULL)
    t = t->subst;
  return t;
}

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

/*

isTermEqualFn(term,term)

Tests whether two terms are completely identical. This also includes
variables. This is the recursive function.

We assume the term is normalized, e.g. no tupling has direct
subtupling.

Out: 0 unequal, 1 equal
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


/*

Duplicate

make a deep copy of a term, but not of leaves.

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

/*

DuplicateDeep

make a deep copy of a term, and also of leaves.

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

/*
 * DuplicateUV
 *
 * Remove all instantiated variables on the way down.
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

/*

termDelete

Removes a term and deallocates memory

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

/*
   termNormalize

   avoids problems with associativity by rewriting every ((x,y),z) to
   (x,y,z)), i.e. a normal form for terms, after which equality is
   okay.
*/

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

/* tupleCount yields the size of the top tuple in the term */

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

/* tupleProject yields the projection pi (0 .. n-1) on a top tuple. Returns
 * NULL if the range is incorrect. */

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

/* number of elements in a term.
 *
 * Currently, the encryption operator is weighed as well.
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

/* Yield some sort of distance between two terms, as a float between 0 and 1.
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
