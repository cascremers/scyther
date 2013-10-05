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

#ifndef SYMBOLS
#define SYMBOLS

#include <stdarg.h>

//! Size of symbol hashtable.
/** Optimistically large. Should be a prime, says theory.
 */
#define HASHSIZE 997

enum symboltypes
{ T_UNDEF = -1, T_PROTOCOL, T_CONST, T_VAR, T_SYSCONST };

#define EOS 0

//! Symbol structure
struct symbol
{
  //! Type of symbol.
  /**
   *\sa T_UNDEF, T_PROTOCOL, T_CONST, T_VAR, T_SYSCONST
   */
  int type;
  //! Line number at which it occurred.
  int lineno;
  //! Level of occurrence in role nodes. 0 for as non-key, 1 for key only, 2 for key of key only, etc..
  int keylevel;
  //! Ascii string with name of the symbol.
  const char *text;
  //! Possible next pointer.
  struct symbol *next;
  //! Used for linking all symbol blocks, freed or in use.
  struct symbol *allocnext;
};

typedef struct symbol *Symbol;	//!< pointer to symbol structure

void symbolsInit (void);
void symbolsDone (void);

Symbol get_symb (void);
void free_symb (const Symbol s);

void insert (const Symbol s);
Symbol lookup (const char *s);
void symbolPrint (const Symbol s);
void symbolPrintAll (void);
Symbol symbolSysConst (const char *str);
void symbol_fix_keylevels (void);
Symbol symbolNextFree (Symbol prefixsymbol);
Symbol symbolFromInt (int n, Symbol prefixsymbol);

void eprintf (char *fmt, ...);
void veprintf (const char *fmt, va_list args);

extern int globalError;
extern char *globalStream;

#endif
