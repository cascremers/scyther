#ifndef TERMS
#define TERMS

#include "symbols.h"

#define	GLOBAL	 1
#define VARIABLE 2
#define LEAF	 3		// type <= LEAF means it's a leaf, nkay?
#define	ENCRYPT  4
#define	TUPLE	 5

struct term
{
  /* basic  : name,runid
     encrypt: op,key
     tuple  : op,next
   */
  int type;
  void *stype;			// only for leaf, termlist pointer
  struct term *subst;		// only for variable/leaf, substitution term

  union
  {
    Symbol symb;
    struct term *op;
    struct term *op1;
    struct term *next;		// for alternative memory management
  };
  union
  {
    int runid;
    struct term *key;
    struct term *op2;
  };
};

typedef struct term *Term;

void termsInit (void);
void termsDone (void);
Term makeTermEncrypt (Term t1, Term t2);
Term makeTermTuple (Term t1, Term t2);
Term makeTermType (const int type, const Symbol symb, const int runid);
Term deVarScan (Term t);
#define substVar(t)		((t != NULL && t->type == VARIABLE && t->subst != NULL) ? 1 : 0)
#define deVar(t)		( substVar(t) ? deVarScan(t->subst) : t)
#define realTermLeaf(t)		(t != NULL && t->type <= LEAF)
#define realTermTuple(t)	(t != NULL && t->type == TUPLE)
#define realTermEncrypt(t)	(t != NULL && t->type == ENCRYPT)
#define realTermVariable(t)	(t != NULL && t->type == VARIABLE)
#define isTermLeaf(t)		realTermLeaf(deVar(t))
#define isTermTuple(t)		realTermTuple(deVar(t))
#define isTermEncrypt(t)	realTermEncrypt(deVar(t))
#define isTermVariable(t)	realTermVariable(deVar(t))
#define isTermEqual(t1,t2)	((substVar(t1) || substVar(t2)) \
				?	isTermEqualFn(t1,t2) \
				:	( \
					(t1 == t2) \
					?	1 \
					:	( \
						(t1 == NULL || t2 == NULL || t1->type != t2->type) \
						?	0 \
						:	( \
							realTermLeaf(t1) \
							?	(t1->symb == t2->symb && t1->runid == t2->runid) \
							:	( \
								realTermEncrypt(t2) \
								?	(isTermEqualFn(t1->key, t2->key) && \
									 isTermEqualFn(t1->op,  t2->op)) \
								:	(isTermEqualFn(t1->op1, t2->op1) && \
									 isTermEqualFn(t1->op2, t2->op2)) \
								) \
							) \
						 )  \
					) \
				)

int hasTermVariable (Term term);
int isTermEqualFn (Term term1, Term term2);
int termOccurs (Term t, Term tsub);
void termPrint (Term term);
Term termDuplicate (const Term term);
Term termDuplicateDeep (const Term term);
Term termDuplicateUV (Term term);
void termDelete (const Term term);
void termNormalize (Term term);
Term termRunid (Term term, int runid);
int tupleCount (Term tt);
Term tupleProject (Term tt, int n);
int termSize(Term t);
float termDistance(Term t1, Term t2);

#endif
