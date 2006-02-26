#ifndef TERMLISTS
#define TERMLISTS

#include "term.h"

//! The list container for the term type.
/**
 * Implemented as a double linked list to allow for element deletion.
 *\sa term
 */
struct termlist
{
  //! The term element for this node.
  Term term;
  //! Next node pointer or NULL for the tail of the list.
  struct termlist *next;
  //! Previous node pointer or NULL for the head of the list.
  struct termlist *prev;
};

//! Shorthand for termlist pointers.
typedef struct termlist *Termlist;

void termlistsInit (void);
void termlistsDone (void);
Termlist termlistDuplicate (Termlist tl);
Termlist termlistShallow (Termlist tl);
void termlistDelete (Termlist tl);
void termlistDestroy (Termlist tl);
void termlistPrint (Termlist tl);
__inline__ int inTermlist (Termlist tl, const Term term);
__inline__ Termlist termlistFind (Termlist tl, const Term term);
int isTermlistEqual (Termlist tl1, Termlist tl2);
Termlist termlistAdd (Termlist tl, Term term);
#define termlistPrepend(tl,t) termlistAdd(tl,t)
Termlist termlistAppend (const Termlist tl, const Term term);
Termlist termlistAddNew (const Termlist tl, const Term t);
Termlist termlistConcat (Termlist tl1, Termlist tl2);
Termlist termlistConcatStatic (Termlist tl1, Termlist tl2);
Termlist termlistDelTerm (Termlist tl);
Termlist termlistConjunct (Termlist tl1, Termlist tl2);
Termlist termlistConjunctType (Termlist tl1, Termlist tl2, int termtype);
Termlist termlistType (Termlist tl, int termtype);
Termlist termlistAddVariables (Termlist tl, Term t);
Termlist termlistAddRealVariables (Termlist tl, Term t);
Termlist termlistAddBasic (Termlist tl, Term t);
Termlist termlistAddBasics (Termlist tl, Termlist scan);
Termlist termlistMinusTerm (Termlist tl, Term t);
int termlistLength (Termlist tl);
Term inverseKey (Termlist inverses, Term key);
Term termLocal (const Term t, Termlist fromlist, Termlist tolist);
Termlist termlistLocal (Termlist tl, const Termlist fromlist,
			const Termlist tolist);
int termlistContained (const Termlist tlbig, Termlist tlsmall);
int validSubst (const int matchmode, const Term term);
Term termFunction (Termlist fromlist, Termlist tolist, Term tx);
Termlist termlistForward (Termlist tl);
int termlistOrder (Termlist tl1, Termlist tl2);
int termlist_iterate (Termlist tl, int (*func) ());
Term termlist_to_tuple (Termlist tl);
Termlist tuple_to_termlist (Term t);
Termlist termlistMinusTermlist (const Termlist tlbig, const Termlist tlsmall);

#endif
