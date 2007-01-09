
/*  A Bison parser, made from parser.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	ID	257
#define	PROTOCOL	258
#define	ROLE	259
#define	READT	260
#define	SENDT	261
#define	CLAIMT	262
#define	VAR	263
#define	CONST	264
#define	RUN	265
#define	SECRET	266
#define	COMPROMISED	267
#define	INVERSEKEYS	268
#define	UNTRUSTED	269
#define	USERTYPE	270
#define	SINGULAR	271
#define	FUNCTION	272
#define	HASHFUNCTION	273
#define	KNOWS	274
#define	TRUSTED	275

#line 1 "parser.y"

#include "pheading.h"
#include "tac.h"
#include "error.h"

struct tacnode*	spdltac;

int yyerror(char *s);
int yylex(void);


#line 13 "parser.y"
typedef union{
	char*  		str;
	struct tacnode*	tac;
	Symbol		symb;
	int		value;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		121
#define	YYFLAG		-32768
#define	YYNTBASE	31

#define YYTRANSLATE(x) ((unsigned)(x) <= 275 ? yytranslate[x] : 53)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    23,
    24,     2,     2,    28,     2,    27,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    29,    22,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,    30,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    25,     2,    26,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
    17,    18,    19,    20,    21
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     2,     3,     6,    10,    17,    27,    31,    33,    34,
    37,    40,    48,    49,    51,    52,    54,    55,    58,    61,
    64,    71,    78,    85,    89,    93,    99,   105,   110,   118,
   122,   123,   125,   126,   129,   130,   133,   136,   137,   139,
   141,   143,   148,   153,   157,   159,   163,   165,   169
};

static const short yyrhs[] = {    32,
     0,     0,    33,    32,     0,    15,    50,    22,     0,    11,
    40,    23,    50,    24,    22,     0,     4,     3,    23,    50,
    24,    25,    34,    26,    37,     0,    16,    50,    22,     0,
    42,     0,     0,    35,    34,     0,    42,    34,     0,    36,
     5,     3,    25,    38,    26,    37,     0,     0,    17,     0,
     0,    22,     0,     0,    39,    38,     0,    42,    38,     0,
    41,    38,     0,     6,    46,    23,    50,    24,    22,     0,
     7,    46,    23,    50,    24,    22,     0,     8,    47,    23,
    50,    24,    22,     0,     3,    27,     3,     0,    20,    50,
    22,     0,    43,    10,    51,    44,    22,     0,    43,     9,
    51,    45,    22,     0,    12,    51,    44,    22,     0,    14,
    23,    49,    28,    49,    24,    22,     0,    13,    50,    22,
     0,     0,    12,     0,     0,    29,     3,     0,     0,    29,
    51,     0,    30,     3,     0,     0,    46,     0,     3,     0,
    48,     0,     3,    23,    50,    24,     0,    25,    50,    26,
    52,     0,    23,    50,    24,     0,    49,     0,    49,    28,
    50,     0,    48,     0,    48,    28,    51,     0,    49,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
    69,    73,    75,    79,    85,    92,   100,   106,   112,   114,
   116,   120,   131,   133,   137,   139,   143,   145,   147,   149,
   153,   160,   167,   176,   184,   191,   198,   205,   211,   217,
   224,   228,   235,   240,   247,   252,   258,   262,   264,   269,
   277,   279,   285,   289,   295,   297,   301,   303,   307
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","ID","PROTOCOL",
"ROLE","READT","SENDT","CLAIMT","VAR","CONST","RUN","SECRET","COMPROMISED","INVERSEKEYS",
"UNTRUSTED","USERTYPE","SINGULAR","FUNCTION","HASHFUNCTION","KNOWS","TRUSTED",
"';'","'('","')'","'{'","'}'","'.'","','","':'","'_'","spdlcomplete","spdlrep",
"spdl","roles","role","singular","optclosing","roledef","event","roleref","knowsdecl",
"declaration","secretpref","typeinfo1","typeinfoN","label","optlabel","basicterm",
"term","termlist","basictermlist","key", NULL
};
#endif

static const short yyr1[] = {     0,
    31,    32,    32,    33,    33,    33,    33,    33,    34,    34,
    34,    35,    36,    36,    37,    37,    38,    38,    38,    38,
    39,    39,    39,    40,    41,    42,    42,    42,    42,    42,
    43,    43,    44,    44,    45,    45,    46,    47,    47,    48,
    49,    49,    49,    49,    50,    50,    51,    51,    52
};

static const short yyr2[] = {     0,
     1,     0,     2,     3,     6,     9,     3,     1,     0,     2,
     2,     7,     0,     1,     0,     1,     0,     2,     2,     2,
     6,     6,     6,     3,     3,     5,     5,     4,     7,     3,
     0,     1,     0,     2,     0,     2,     2,     0,     1,     1,
     1,     4,     4,     3,     1,     3,     1,     3,     1
};

static const short yydefact[] = {    31,
     0,     0,    32,     0,     0,     0,     0,     1,    31,     8,
     0,     0,     0,     0,    40,    47,    33,    40,     0,     0,
    41,    45,     0,     0,     0,     0,     3,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,    30,
     0,     4,     7,    35,    33,     0,    24,     0,    48,    34,
    28,     0,    44,     0,    46,     0,     0,     0,     0,     0,
     0,    42,    49,    43,     0,    36,    27,    26,    31,     5,
     0,    14,     0,    31,     0,    31,    29,    15,    10,     0,
    11,    16,     6,     0,    31,     0,     0,    38,     0,     0,
    31,    31,    31,     0,     0,     0,    39,     0,     0,    15,
    18,    20,    19,    37,     0,     0,     0,    25,    12,     0,
     0,     0,     0,     0,     0,    21,    22,    23,     0,     0,
     0
};

static const short yydefgoto[] = {   119,
     8,     9,    73,    74,    75,    83,    90,    91,    14,    92,
    93,    11,    35,    58,    95,    98,    21,    22,    23,    17,
    64
};

static const short yypact[] = {    73,
     1,    16,    24,     0,     5,     0,     0,-32768,    73,-32768,
     8,     6,    11,    17,-32768,    19,    10,    22,     0,     0,
-32768,    20,    27,     0,    31,    32,-32768,    24,    24,     0,
    56,     0,    24,    58,    40,     0,    39,    41,     0,-32768,
    37,-32768,-32768,    43,    10,    42,-32768,    45,-32768,-32768,
-32768,    50,-32768,     0,-32768,     0,    24,    46,    53,    54,
    59,-32768,-32768,-32768,    66,-32768,-32768,-32768,    29,-32768,
    60,-32768,    65,    29,    75,    29,-32768,    70,-32768,    90,
-32768,-32768,-32768,    69,    44,    67,    67,    67,     0,    72,
    44,    44,    44,    92,    79,    80,-32768,    81,    74,    70,
-32768,-32768,-32768,-32768,     0,     0,     0,-32768,-32768,    82,
    83,    84,    87,    88,    89,-32768,-32768,-32768,   105,   112,
-32768
};

static const short yypgoto[] = {-32768,
   104,-32768,   -64,-32768,-32768,    14,   -84,-32768,-32768,-32768,
     2,-32768,    71,-32768,   -66,-32768,     3,   -19,    -6,   -13,
-32768
};


#define	YYLAST		116


static const short yytable[] = {    25,
    26,    10,    18,    12,    41,    16,   101,   102,   103,    79,
    10,    81,    37,    38,    44,    45,    28,    29,    13,    49,
    96,    97,    19,    46,    20,    48,    15,    24,    30,    52,
    16,    16,    55,   -13,    63,    16,    65,    31,    34,    32,
     3,     4,     5,    66,    36,    72,    33,    39,    40,    86,
    87,    88,    42,    43,    -9,     3,     4,     5,    47,    16,
    50,    51,    53,    89,    56,    60,    54,    67,    61,   -17,
    76,    57,    -2,    62,    68,    76,     1,    76,    69,    80,
    70,    77,    99,     2,     3,     4,     5,     6,     7,    71,
    78,    82,    84,    85,   104,   108,    94,   100,   110,   111,
   112,   105,   106,   107,   120,   113,   114,   115,   116,   117,
   118,   121,    27,   109,     0,    59
};

static const short yycheck[] = {     6,
     7,     0,     3,     3,    24,     3,    91,    92,    93,    74,
     9,    76,    19,    20,    28,    29,     9,    10,     3,    33,
    87,    88,    23,    30,    25,    32,     3,    23,    23,    36,
    28,    29,    39,     5,    54,    33,    56,    27,    29,    23,
    12,    13,    14,    57,    23,    17,    28,    28,    22,     6,
     7,     8,    22,    22,    26,    12,    13,    14,     3,    57,
     3,    22,    24,    20,    28,    24,    26,    22,    24,    26,
    69,    29,     0,    24,    22,    74,     4,    76,    25,     5,
    22,    22,    89,    11,    12,    13,    14,    15,    16,    24,
    26,    22,     3,    25,     3,    22,    30,    26,   105,   106,
   107,    23,    23,    23,     0,    24,    24,    24,    22,    22,
    22,     0,     9,   100,    -1,    45
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison.simple"
/* This file comes from bison-1.28.  */

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

#ifndef YYSTACK_USE_ALLOCA
#ifdef alloca
#define YYSTACK_USE_ALLOCA
#else /* alloca not defined */
#ifdef __GNUC__
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi) || (defined (__sun) && defined (__i386))
#define YYSTACK_USE_ALLOCA
#include <alloca.h>
#else /* not sparc */
/* We think this test detects Watcom and Microsoft C.  */
/* This used to test MSDOS, but that is a bad idea
   since that symbol is in the user namespace.  */
#if (defined (_MSDOS) || defined (_MSDOS_)) && !defined (__TURBOC__)
#if 0 /* No need for malloc.h, which pollutes the namespace;
	 instead, just don't use alloca.  */
#include <malloc.h>
#endif
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
/* I don't know what this was needed for, but it pollutes the namespace.
   So I turned it off.   rms, 2 May 1997.  */
/* #include <malloc.h>  */
 #pragma alloca
#define YYSTACK_USE_ALLOCA
#else /* not MSDOS, or __TURBOC__, or _AIX */
#if 0
#ifdef __hpux /* haible@ilog.fr says this works for HPUX 9.05 and up,
		 and on HPUX 10.  Eventually we can turn this on.  */
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#endif /* __hpux */
#endif
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc */
#endif /* not GNU C */
#endif /* alloca not defined */
#endif /* YYSTACK_USE_ALLOCA not defined */

#ifdef YYSTACK_USE_ALLOCA
#define YYSTACK_ALLOC alloca
#else
#define YYSTACK_ALLOC malloc
#endif

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Define __yy_memcpy.  Note that the size argument
   should be passed with type unsigned int, because that is what the non-GCC
   definitions require.  With GCC, __builtin_memcpy takes an arg
   of type size_t, but it can handle unsigned int.  */

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (to, from, count)
     char *to;
     char *from;
     unsigned int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *to, char *from, unsigned int count)
{
  register char *t = to;
  register char *f = from;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 217 "/usr/share/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
#ifdef YYPARSE_PARAM
int yyparse (void *);
#else
int yyparse (void);
#endif
#endif

int
yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;
  int yyfree_stacks = 0;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  if (yyfree_stacks)
	    {
	      free (yyss);
	      free (yyvs);
#ifdef YYLSP_NEEDED
	      free (yyls);
#endif
	    }
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
#ifndef YYSTACK_USE_ALLOCA
      yyfree_stacks = 1;
#endif
      yyss = (short *) YYSTACK_ALLOC (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss, (char *)yyss1,
		   size * (unsigned int) sizeof (*yyssp));
      yyvs = (YYSTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs, (char *)yyvs1,
		   size * (unsigned int) sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls, (char *)yyls1,
		   size * (unsigned int) sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 1:
#line 70 "parser.y"
{	spdltac = yyvsp[0].tac; ;
    break;}
case 2:
#line 74 "parser.y"
{	yyval.tac = NULL; ;
    break;}
case 3:
#line 76 "parser.y"
{	yyval.tac = tacCat(yyvsp[-1].tac,yyvsp[0].tac); ;
    break;}
case 4:
#line 80 "parser.y"
{	
		  	Tac t = tacCreate(TAC_UNTRUSTED);
		  	t->t1.tac = yyvsp[-1].tac;
			yyval.tac = t;
		  ;
    break;}
case 5:
#line 86 "parser.y"
{	
		  	Tac t = tacCreate(TAC_RUN);
		  	t->t1.tac = yyvsp[-4].tac;
			t->t2.tac = yyvsp[-2].tac;
			yyval.tac = t;
		  ;
    break;}
case 6:
#line 93 "parser.y"
{
		  	Tac t = tacCreate(TAC_PROTOCOL);
			t->t1.sym = yyvsp[-7].symb;
			t->t2.tac = yyvsp[-2].tac;
			t->t3.tac = yyvsp[-5].tac;
			yyval.tac = t;
		  ;
    break;}
case 7:
#line 101 "parser.y"
{
			Tac t = tacCreate(TAC_USERTYPE);
			t->t1.tac = yyvsp[-1].tac;
			yyval.tac = t;
		  ;
    break;}
case 8:
#line 107 "parser.y"
{
		  	yyval.tac = yyvsp[0].tac;
		  ;
    break;}
case 9:
#line 113 "parser.y"
{	yyval.tac = NULL; ;
    break;}
case 10:
#line 115 "parser.y"
{	yyval.tac = tacCat(yyvsp[-1].tac,yyvsp[0].tac); ;
    break;}
case 11:
#line 117 "parser.y"
{	yyval.tac = tacCat(yyvsp[-1].tac,yyvsp[0].tac); ;
    break;}
case 12:
#line 121 "parser.y"
{ 
		  	// TODO process singular (0/1)
		  	Tac t = tacCreate(TAC_ROLE);
			t->t1.sym = yyvsp[-4].symb;
			t->t2.tac = yyvsp[-2].tac;
			t->t3.value = yyvsp[-6].value;
			yyval.tac = t;
		  ;
    break;}
case 13:
#line 132 "parser.y"
{	yyval.value = 0; ;
    break;}
case 14:
#line 134 "parser.y"
{	yyval.value = 1; ;
    break;}
case 15:
#line 138 "parser.y"
{ ;
    break;}
case 16:
#line 140 "parser.y"
{ ;
    break;}
case 17:
#line 144 "parser.y"
{	yyval.tac = NULL; ;
    break;}
case 18:
#line 146 "parser.y"
{	yyval.tac = tacCat(yyvsp[-1].tac,yyvsp[0].tac); ;
    break;}
case 19:
#line 148 "parser.y"
{	yyval.tac = tacCat(yyvsp[-1].tac,yyvsp[0].tac); ;
    break;}
case 20:
#line 150 "parser.y"
{	yyval.tac = tacCat(yyvsp[-1].tac,yyvsp[0].tac); ;
    break;}
case 21:
#line 154 "parser.y"
{	Tac t = tacCreate(TAC_READ);
		  	t->t1.sym = yyvsp[-4].symb;
			/* TODO test here: tac2 should have at least 3 elements */
			t->t2.tac = yyvsp[-2].tac;
			yyval.tac = t;
		  ;
    break;}
case 22:
#line 161 "parser.y"
{	Tac t = tacCreate(TAC_SEND);
		  	t->t1.sym = yyvsp[-4].symb;
			/* TODO test here: tac2 should have at least 3 elements */
			t->t2.tac = yyvsp[-2].tac;
			yyval.tac = t;
		  ;
    break;}
case 23:
#line 169 "parser.y"
{	Tac t = tacCreate(TAC_CLAIM);
		  	t->t1.sym = yyvsp[-4].symb;
			t->t2.tac = yyvsp[-2].tac;
			yyval.tac = t;
		  ;
    break;}
case 24:
#line 177 "parser.y"
{	Tac t = tacCreate(TAC_ROLEREF);
		  	t->t1.sym = yyvsp[-2].symb;
			t->t2.sym = yyvsp[0].symb;
			yyval.tac = t;
		  ;
    break;}
case 25:
#line 185 "parser.y"
{	Tac t = tacCreate(TAC_KNOWS);
		  	t->t1.tac = yyvsp[-1].tac;
			yyval.tac = t;
		  ;
    break;}
case 26:
#line 192 "parser.y"
{	Tac t = tacCreate(TAC_CONST);
		  	t->t1.tac = yyvsp[-2].tac;
			t->t2.tac = yyvsp[-1].tac;
			t->t3.tac = yyvsp[-4].tac;
			yyval.tac = t;
		  ;
    break;}
case 27:
#line 199 "parser.y"
{	Tac t = tacCreate(TAC_VAR);
		  	t->t1.tac = yyvsp[-2].tac;
			t->t2.tac = yyvsp[-1].tac;
			t->t3.tac = yyvsp[-4].tac;
			yyval.tac = t;
		  ;
    break;}
case 28:
#line 206 "parser.y"
{	Tac t = tacCreate(TAC_SECRET);
		  	t->t1.tac = yyvsp[-2].tac;
			t->t2.tac = yyvsp[-1].tac;
			yyval.tac = t;
		  ;
    break;}
case 29:
#line 212 "parser.y"
{	Tac t = tacCreate(TAC_INVERSEKEYS);
			t->t1.tac = yyvsp[-4].tac;
			t->t2.tac = yyvsp[-2].tac;
			yyval.tac = t;
		  ;
    break;}
case 30:
#line 218 "parser.y"
{	Tac t = tacCreate(TAC_COMPROMISED);
		  	t->t1.tac= yyvsp[-1].tac;
			yyval.tac = t;
		  ;
    break;}
case 31:
#line 225 "parser.y"
{	
			yyval.tac = NULL;
		  ;
    break;}
case 32:
#line 229 "parser.y"
{
			Tac t = tacCreate(TAC_SECRET);
			yyval.tac = t;
		  ;
    break;}
case 33:
#line 236 "parser.y"
{
		  	Tac t = tacCreate(TAC_UNDEF);
			yyval.tac = t;
		  ;
    break;}
case 34:
#line 241 "parser.y"
{	Tac t = tacCreate(TAC_STRING);
		  	t->t1.sym = yyvsp[0].symb;
			yyval.tac = t;
		  ;
    break;}
case 35:
#line 248 "parser.y"
{
		  	Tac t = tacCreate(TAC_UNDEF);
			yyval.tac = t;
		  ;
    break;}
case 36:
#line 253 "parser.y"
{	
		  	yyval.tac = yyvsp[0].tac;
		  ;
    break;}
case 37:
#line 259 "parser.y"
{ yyval.symb = yyvsp[0].symb; ;
    break;}
case 38:
#line 263 "parser.y"
{ yyval.symb = NULL; ;
    break;}
case 39:
#line 265 "parser.y"
{ ;
    break;}
case 40:
#line 270 "parser.y"
{
		  	Tac t = tacCreate(TAC_STRING);
			t->t1.sym = yyvsp[0].symb;
			yyval.tac = t;
		  ;
    break;}
case 41:
#line 278 "parser.y"
{ ;
    break;}
case 42:
#line 280 "parser.y"
{
		  	Tac t = tacCreate(TAC_STRING);
			t->t1.sym = yyvsp[-3].symb;
			yyval.tac = tacJoin(TAC_ENCRYPT,tacTuple(yyvsp[-1].tac),t,NULL);
		  ;
    break;}
case 43:
#line 286 "parser.y"
{
		  	yyval.tac = tacJoin(TAC_ENCRYPT,tacTuple(yyvsp[-2].tac),yyvsp[0].tac,NULL);
		  ;
    break;}
case 44:
#line 290 "parser.y"
{ 
		  	yyval.tac = tacTuple(yyvsp[-1].tac);
		  ;
    break;}
case 45:
#line 296 "parser.y"
{ ;
    break;}
case 46:
#line 298 "parser.y"
{	yyval.tac = tacCat(yyvsp[-2].tac,yyvsp[0].tac); ;
    break;}
case 47:
#line 302 "parser.y"
{ ;
    break;}
case 48:
#line 304 "parser.y"
{	yyval.tac = tacCat(yyvsp[-2].tac,yyvsp[0].tac); ;
    break;}
case 49:
#line 308 "parser.y"
{ ;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 543 "/usr/share/bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;

 yyacceptlab:
  /* YYACCEPT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 0;

 yyabortlab:
  /* YYABORT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 1;
}
#line 313 "parser.y"


//! error handler routing
int yyerror(char *s)
{
	extern int yylineno;	//!< defined and maintained in lex.c
	extern char *yytext;	//!< defined and maintained in lex.c
  
	error ("%s at symbol '%s' on line %i.\n", s, yytext, yylineno);
	return 0;
}


