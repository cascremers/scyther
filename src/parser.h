/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     ID = 258,
     PROTOCOL = 259,
     ROLE = 260,
     READT = 261,
     SENDT = 262,
     CLAIMT = 263,
     VAR = 264,
     CONST = 265,
     RUN = 266,
     SECRET = 267,
     COMPROMISED = 268,
     INVERSEKEYS = 269,
     UNTRUSTED = 270,
     USERTYPE = 271,
     SINGULAR = 272,
     FUNCTION = 273,
     HASHFUNCTION = 274,
     KNOWS = 275,
     TRUSTED = 276
   };
#endif
/* Tokens.  */
#define ID 258
#define PROTOCOL 259
#define ROLE 260
#define READT 261
#define SENDT 262
#define CLAIMT 263
#define VAR 264
#define CONST 265
#define RUN 266
#define SECRET 267
#define COMPROMISED 268
#define INVERSEKEYS 269
#define UNTRUSTED 270
#define USERTYPE 271
#define SINGULAR 272
#define FUNCTION 273
#define HASHFUNCTION 274
#define KNOWS 275
#define TRUSTED 276




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 14 "parser.y"
{
	char*  		str;
	struct tacnode*	tac;
	Symbol		symb;
	int		value;
}
/* Line 1529 of yacc.c.  */
#line 98 "parser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

