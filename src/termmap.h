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

#ifndef TERMMAPS
#define TERMMAPS

#include "term.h"

//! The function container for the term to integer function type.
/**
 *\sa term
 */
struct termmap
{
  //! The term element for this node.
  Term term;
  //! Next node pointer or NULL for the last element of the function.
  struct termmap *next;
  //! Function result
  int result;
};

//! Shorthand for termmap pointers.
typedef struct termmap *Termmap;

void termmapsInit (void);
void termmapsDone (void);
int termmapGet (Termmap f, const Term x);
Termmap termmapSet (const Termmap f, const Term x, const int y);
Termmap termmapDuplicate (const Termmap f);
void termmapDelete (const Termmap f);
void termmapPrint (Termmap f);

#endif
