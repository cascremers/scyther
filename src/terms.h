#ifndef TERMS
#define TERMS

#include "symbols.h"

#define	GLOBAL	 1
#define VARIABLE 2
#define LEAF	 3		// type <= LEAF means it's a leaf, nkay?
#define	ENCRYPT  4
#define	TUPLE	 5

//! The most basic datatype in the modelchecker.
/**
 * Describes a single term.
 */

struct term
{
  /* basic  : name,runid
     encrypt: op,key
     tuple  : op,next
   */

  //! The type of term.
  /**
   * \sa GLOBAL, VARIABLE, LEAF, ENCRYPT, TUPLE
   */
  int type;
  //! Data Type termlist (e.g. agent or nonce)
  /** Only for leaves. */
  void *stype;			
  //! Substitution term.
  /**
   * If this is non-NULL, this leaf term is apparently substituted by
   * this term.
   */
  struct term *subst;		// only for variable/leaf, substitution term

  union 
  {
    Symbol symb;
    //! Encrypted subterm.
    struct term *op;
    //! Left-hand side of tuple pair.
    struct term *op1;
    struct term *next;		// for alternative memory management
  } left;
  union
  {
    int runid;
    //! Key used to encrypt subterm.
    struct term *key;
    //! Right-hand side of tuple pair.
    struct term *op2;
  } right;
};

//! Pointer shorthand.
typedef struct term *Term;

void termsInit (void);
void termsDone (void);
Term makeTermEncrypt (Term t1, Term t2);
Term makeTermTuple (Term t1, Term t2);
Term makeTermType (const int type, const Symbol symb, const int runid);
__inline__ Term deVarScan (Term t);
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
#ifdef DEBUG
#define isTermEqual(t1,t2)      isTermEqualDebug(t1,t2)
int isTermEqualDebug (Term t1, Term t2);
#else
#define isTermEqual1(t1,t2)	((substVar(t1) || substVar(t2)) \
				?	isTermEqualFn(t1,t2) \
				:	( \
					(t1 == t2) \
					?	1 \
					:	( \
						(t1 == NULL || t2 == NULL || t1->type != t2->type) \
						?	0 \
						:	( \
							realTermLeaf(t1) \
							?	0 \
							:	( \
								realTermEncrypt(t2) \
								?	(isTermEqualFn(t1->right.key, t2->right.key) && \
									 isTermEqualFn(t1->left.op,  t2->left.op)) \
								:	(isTermEqualFn(t1->left.op1, t2->left.op1) && \
									 isTermEqualFn(t1->right.op2, t2->right.op2)) \
								) \
							) \
						 )  \
					) \
				)

#define isTermEqual2(t1,t2)	((substVar(t1) || substVar(t2)) \
				?	isTermEqualFn(t1,t2) \
				:	( \
					(t1 == t2) \
					?	1 \
					:	( \
						(t1 == NULL || t2 == NULL || t1->type != t2->type) \
						?	0 \
						:	( \
							realTermLeaf(t1) \
							?	0 \
							:	( \
								realTermEncrypt(t2) \
								?	(isTermEqual1(t1->right.key, t2->right.key) && \
									 isTermEqual1(t1->left.op,  t2->left.op)) \
								:	(isTermEqual1(t1->left.op1, t2->left.op1) && \
									 isTermEqual1(t1->right.op2, t2->right.op2)) \
								) \
							) \
						 )  \
					) \
				)

#define isTermEqual3(t1,t2)	((substVar(t1) || substVar(t2)) \
				?	isTermEqualFn(t1,t2) \
				:	( \
					(t1 == t2) \
					?	1 \
					:	( \
						(t1 == NULL || t2 == NULL || t1->type != t2->type) \
						?	0 \
						:	( \
							realTermLeaf(t1) \
							?	0 \
							:	( \
								realTermEncrypt(t2) \
								?	(isTermEqual2(t1->right.key, t2->right.key) && \
									 isTermEqual2(t1->left.op,  t2->left.op)) \
								:	(isTermEqual2(t1->left.op1, t2->left.op1) && \
									 isTermEqual2(t1->right.op2, t2->right.op2)) \
								) \
							) \
						 )  \
					) \
				)

#define isTermEqual(t1,t2) isTermEqual2(t1,t2)
#endif

int hasTermVariable (Term term);
int isTermEqualFn (Term term1, Term term2);
int termOccurs (Term t, Term tsub);
void termPrint (Term term);
void termTuplePrint (Term term);
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
int termOrder (Term t1, Term t2);

#endif
