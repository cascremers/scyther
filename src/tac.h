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

#ifndef TAC_H
#define TAC_H

#include "symbol.h"

/*
 * TAC instructions
 */

enum tactypes
{
  TAC_UNDEF,
  TAC_SYM,
  TAC_TUPLE,
  TAC_ENCRYPT,
  TAC_FCALL,
  TAC_VAR,
  TAC_CONST,
  TAC_FRESH,
  TAC_RECV,
  TAC_SEND,
  TAC_CLAIM,
  TAC_FUNC,
  TAC_STRING,
  TAC_ROLE,

  TAC_PROTOCOL,
  TAC_KNOWS,
  TAC_RUN,
  TAC_ROLEREF,
  TAC_SECRET,
  TAC_INVERSEKEYS,
  TAC_INVERSEKEYFUNCTIONS,
  TAC_HASHFUNCTION,
  TAC_UNTRUSTED,
  TAC_COMPROMISED,
  TAC_USERTYPE,
  TAC_MATCH,
  TAC_MACRO
};

//! Structure to hold the compilation tree nodes
struct tacnode
{
  struct tacnode *next;		//!< pointer to previous node
  struct tacnode *prev;		//!< pointer to next node
  struct tacnode *allnext;
  int op;			//!< operator for this node
  int lineno;			//!< line number of parser location in the input file
  union
  {
    Symbol sym;
    struct tacnode *tac;
    char *str;
    int value;
  } t1;
  union
  {
    Symbol sym;
    struct tacnode *tac;
    char *str;
    int value;
  } t2;
  union
  {
    Symbol sym;
    struct tacnode *tac;
    char *str;
    int value;
  } t3;
};

typedef struct tacnode *Tac;

void tacInit (void);
void tacDone (void);
Tac tacCopy (Tac c);
Tac tacCreate (int op);
Tac tacSymb (char *s);
Tac tacJoin (int op, Tac t1, Tac t2, Tac t3);
Tac tacTuple (Tac taclist);
Tac tacCat (Tac t1, Tac t2);
void tacPrint (Tac t);

#endif
