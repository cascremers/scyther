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
int inTermlist (Termlist tl, const Term term);
Termlist termlistFind (Termlist tl, const Term term);
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
Term termLocal (const Term t, Termlist fromlist, Termlist tolist);
Termlist termlistLocal (Termlist tl, const Termlist fromlist,
			const Termlist tolist);
int termlistContained (const Termlist tlbig, Termlist tlsmall);
int isTermlistSetEqual (const Termlist tl1, const Termlist tl2);
Term termFunction (Termlist fromlist, Termlist tolist, Term tx);
Termlist termlistForward (Termlist tl);
int termlistOrder (Termlist tl1, Termlist tl2);
int termlist_iterate (Termlist tl, int (*func) ());
Term termlist_to_tuple (Termlist tl);
Termlist tuple_to_termlist (Term t);
Term termLeft (Term t);
Termlist termlistMinusTermlist (const Termlist tlbig, const Termlist tlsmall);

#define TERMLISTADD(l,t)	l = termlistAdd (l,t)
#define TERMLISTAPPEND(l,t)	l = termlistAppend (l,t)
#define TERMLISTPREPEND(l,t)	l = termlistPrepend (l,t)

#endif
