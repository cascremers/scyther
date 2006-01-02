#ifndef TERMS
#define TERMS

#include "symbol.h"

#define false 0
#define true 1

// type <= LEAF means it's a leaf, nkay?
enum termtypes
{ GLOBAL, VARIABLE, LEAF, ENCRYPT, TUPLE };

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
  void *stype;			// list of types
  int roleVar;			// only for leaf, arachne engine: role variable flag

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

//! Component macros (left)
#define TermSymb(t)		(t->left.symb)
#define TermOp1(t)		(t->left.op1)
#define TermOp(t)		(t->left.op)

//! Component macros (right)
#define TermRunid(t)		(t->right.runid)
#define TermOp2(t)		(t->right.op2)
#define TermKey(t)		(t->right.key)

//! Flag for term status
extern int rolelocal_variable;

//! Pointer shorthand.
typedef struct term *Term;

void termsInit (void);
void termsDone (void);
Term makeTermEncrypt (Term t1, Term t2);
Term makeTermTuple (Term t1, Term t2);
Term makeTermType (const int type, const Symbol symb, const int runid);
__inline__ Term deVarScan (Term t);
#define realTermLeaf(t)		(t != NULL && t->type <= LEAF)
#define realTermTuple(t)	(t != NULL && t->type == TUPLE)
#define realTermEncrypt(t)	(t != NULL && t->type == ENCRYPT)
#define realTermVariable(t)	(t != NULL && (t->type == VARIABLE || (t->type <= LEAF && rolelocal_variable && TermRunid(t) == -3)))
#define substVar(t)		((realTermVariable (t) && t->subst != NULL) ? 1 : 0)
#define deVar(t)		( substVar(t) ? deVarScan(t->subst) : t)
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
							?	isTermEqualFn(t1,t2) \
							:	( \
								realTermEncrypt(t2) \
								?	(isTermEqualFn(TermKey(t1), TermKey(t2)) && \
									 isTermEqualFn(TermOp(t1),  TermOp(t2))) \
								:	(isTermEqualFn(TermOp1(t1), TermOp1(t2)) && \
									 isTermEqualFn(TermOp2(t1), TermOp2(t2))) \
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
							?	isTermEqualFn(t1,t2) \
							:	( \
								realTermEncrypt(t2) \
								?	(isTermEqual1(TermKey(t1), TermKey(t2)) && \
									 isTermEqual1(TermOp(t1),  TermOp(t2))) \
								:	(isTermEqual1(TermOp1(t1), TermOp1(t2)) && \
									 isTermEqual1(TermOp2(t1), TermOp2(t2))) \
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
							?	isTermEqualFn(t1,t2) \
							:	( \
								realTermEncrypt(t2) \
								?	(isTermEqual2(TermKey(t1), TermKey(t2)) && \
									 isTermEqual2(TermOp(t1),  TermOp(t2))) \
								:	(isTermEqual2(TermOp1(t1), TermOp1(t2)) && \
									 isTermEqual2(TermOp2(t1), TermOp2(t2))) \
								) \
							) \
						 )  \
					) \
				)

#define isTermEqual(t1,t2) isTermEqual2(t1,t2)
#endif

int hasTermVariable (Term term);
int isTermEqualFn (Term term1, Term term2);
int termSubTerm (Term t, Term tsub);
int termInTerm (Term t, Term tsub);
void termPrint (Term term);
void termTuplePrint (Term term);
Term termDuplicate (const Term term);
Term termNodeDuplicate (const Term term);
Term termDuplicateDeep (const Term term);
Term termDuplicateUV (Term term);
void termDelete (const Term term);
void termNormalize (Term term);
Term termRunid (Term term, int runid);
int tupleCount (Term tt);
Term tupleProject (Term tt, int n);
int termSize (Term t);
float termDistance (Term t1, Term t2);
int termOrder (Term t1, Term t2);
int term_iterate (const Term term, int (*leaf) (), int (*nodel) (),
		  int (*nodem) (), int (*noder) ());
int term_iterate_deVar (Term term, int (*leaf) (), int (*nodel) (),
			int (*nodem) (), int (*noder) ());
int term_iterate_leaves (const Term t, int (*func) ());
int term_iterate_open_leaves (const Term term, int (*func) ());
void term_rolelocals_are_variables ();
int term_encryption_level (const Term term);
float term_constrain_level (const Term term);
void term_set_keylevels (const Term term);
void termPrintDiff (Term t1, Term t2);
int isLeafNameEqual (Term t1, Term t2);
Term freshTermPrefix (Term prefixterm);
int isTermFunctionName (Term t);
Term getTermFunction (Term t);


#endif
