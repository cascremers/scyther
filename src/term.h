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

#ifndef TERMS
#define TERMS

#include "symbol.h"
#include "bool.h"

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
  union
  {
    int roleVar;		//!< only for leaf, arachne engine: role variable flag
    int fcall;			//!< only for 'encryption' to mark actual function call f(t)
  } helper;

  //! Substitution term.
  /**
   * If this is non-NULL, this leaf term is apparently substituted by
   * this term.
   */
  struct term *subst;		// only for variable/leaf, substitution term

  union
  {
    //! Pointer to the symbol for leaves
    Symbol symb;
    //! Encrypted subterm.
    struct term *op;
    //! Left-hand side of tuple pair.
    struct term *op1;
    struct term *next;		//!< for alternative memory management
  } left;
  union
  {
    //! run identifier for leaves
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
Term makeTermFcall (Term t1, Term t2);
Term makeTermTuple (Term t1, Term t2);
Term makeTermType (const int type, const Symbol symb, const int runid);
Term deVarScan (Term t);
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

#define isTermEqual(t1,t2) isTermEqual2(t1,t2)
#endif

int hasTermVariable (Term term);
int isTermEqualFn (Term term1, Term term2);
int termSubTerm (Term t, Term tsub);
int termInTerm (Term t, Term tsub);
void termPrintCustom (Term term, char *leftvar, char *rightvar, char *lefttup,
		      char *righttup, char *leftenc, char *rightenc,
		      void (*callback) (const Term t));
void termPrint (Term term);
void termTuplePrintCustom (Term term, char *leftvar, char *rightvar,
			   char *lefttup, char *righttup, char *leftenc,
			   char *rightenc, void (*callback) (const Term t));
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
int term_iterate (const Term term, int (*leaf) (Term t),
		  int (*nodel) (Term t), int (*nodem) (Term t),
		  int (*noder) (Term t));
int term_iterate_state_deVar (Term term, int (*leaf) (),
			      int (*nodel) (),
			      int (*nodem) (), int (*noder) (), void *state);
int term_iterate_state_leaves (const Term term, int (*func) (), void *state);
int term_iterate_state_open_leaves (const Term term, int (*func) (),
				    void *state);
void term_rolelocals_are_variables ();
int term_encryption_level (const Term term);
float term_constrain_level (const Term term);
void term_set_keylevels (const Term term);
void termPrintDiff (Term t1, Term t2);
int isLeafNameEqual (Term t1, Term t2);
Term freshTermPrefix (Term prefixterm);
Term intTermPrefix (const int n, Term prefixterm);
int isTermFunctionName (Term t);
Term getTermFunction (Term t);
unsigned int termHidelevel (const Term tsmall, Term tbig);
void termSubstPrint (Term t);

int iterateTermOther (const int myrun, Term t, int (*callback) (), void *s);

extern char *RUNSEP;		// by default, set to "#"

#endif
