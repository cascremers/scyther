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

%{
#include "pheading.h"
#include "tac.h"
#include "error.h"
#include "list.h"
#include "string.h"
#include "switches.h"

struct tacnode*	spdltac;

int yyerror(char *s);
int yylex(void);

List macrolist=NULL;

List findMacroDefinition(Symbol s)
{
	List l;

	if (s == NULL)
	  {
	     return NULL;
	  }
	/* Now check if it is in the list
	 * already */
	for (l = list_rewind(macrolist); l != NULL; l = l->next)
	  {
	    Tac tmacro;
	    Symbol sl;
		
	    tmacro = (Tac) l->data;
	    sl = (tmacro->t1.tac)->t1.sym;	// The symbol
	    if (strcmp (sl->text, s->text) == 0)
	      {
	        return l;
	      }
	  }
	return NULL;
}

%}

%union{
	char*  		str;
	struct tacnode*	tac;
	Symbol		symb;
	int		value;
}

%token 	<symb>	ID
%token  <str> 	TEXT

%token 		PROTOCOL
%token 		ROLE
%token 		READT
%token 		RECVT
%token 		SENDT
%token 		CLAIMT
%token 		VAR
%token 		CONST
%token 		FRESH
%token 		RUN
%token 		SECRET
%token 		COMPROMISED
%token 		INVERSEKEYS
%token 		INVERSEKEYFUNCTIONS
%token 		UNTRUSTED
%token 		USERTYPE
%token		SINGULAR
%token		FUNCTION
%token 		HASHFUNCTION
%token		KNOWS
%token		TRUSTED
%token 		OPTION
%token 		MACRO
%token 		MATCH
%token 		NOT

%type	<tac>	spdlcomplete
%type	<tac>	spdlrep
%type	<tac>	spdl
%type	<tac>	roles
%type	<tac>	role
%type	<tac>	roledef
%type	<tac>	event
%type	<tac>	declaration
%type	<tac>	secretpref
%type	<tac>	typeinfo1
%type	<tac>	typeinfoN
%type	<tac>	term
%type	<tac>	basicterm
%type	<tac>	basicormacro
%type	<tac>	termlist
%type	<tac>	basictermlist
%type	<tac>	key
%type	<tac>	roleref
%type	<tac>	knowsdecl
%type	<tac>	macrodecl
%type	<tac>	options

%type   <value>	singular

%type	<symb>	label
%type	<symb>	optlabel

%start spdlcomplete


%%

spdlcomplete	: spdlrep
		  {	spdltac = $1; }
		;

spdlrep		: /* empty */
		  {	$$ = NULL; }
		| spdl spdlrep
		  {	$$ = tacCat($1,$2); }
		;

spdl		: UNTRUSTED termlist ';'
		  {	
		  	Tac t = tacCreate(TAC_UNTRUSTED);
		  	t->t1.tac = $2;
			$$ = t;
		  }
		| RUN roleref '(' termlist ')' ';'
		  {	
		  	Tac t = tacCreate(TAC_RUN);
		  	t->t1.tac = $2;
			t->t2.tac = $4;
			$$ = t;
		  }
		| PROTOCOL ID '(' termlist ')' '{' roles '}' optclosing
	 	  {
		  	Tac t = tacCreate(TAC_PROTOCOL);
			t->t1.sym = $2;
			t->t2.tac = $7;
			t->t3.tac = $4;
			$$ = t;
		  }
		| USERTYPE termlist ';'
		  {
			Tac t = tacCreate(TAC_USERTYPE);
			t->t1.tac = $2;
			$$ = t;
		  }
		| declaration
		  {
		  	$$ = $1;
		  }
		| options
		  {
		  	$$ = $1;
		  }
		;

options		: OPTION TEXT optclosing
		  {
		  	// Process 'option' as command-line options.
		  	process_switch_buffer($2);
			$$ = NULL;
		  }
		;

roles		: /* empty */
       		  {	$$ = NULL; }
       		| role roles
		  {	$$ = tacCat($1,$2); }
		| declaration roles
		  {	$$ = tacCat($1,$2); }
		;

role		: singular ROLE ID '{' roledef '}' optclosing
      		  { 
		  	// TODO process singular (0/1)
		  	Tac t = tacCreate(TAC_ROLE);
			t->t1.sym = $3;
			t->t2.tac = $5;
			t->t3.value = $1;
			$$ = t;
		  }
		;

singular	: /* empty */
	 	  {	$$ = 0; }
		| SINGULAR
		  {	$$ = 1; }
		;

optclosing	: /* empty */
		  { }
		| ';'
		  { }
		;

roledef		: /* empty */
		  {	$$ = NULL; }
		| event roledef
		  {	$$ = tacCat($1,$2); }
		| declaration roledef
		  {	$$ = tacCat($1,$2); }
		| knowsdecl roledef
		  {	$$ = tacCat($1,$2); }
		;

/*
 * For now, recv and read are synonyms, but have their own branch below. That's ugly duplication. Ultimately we want to deprecate read, 
 * but that will take a while I guess.
 */
event		: READT label '(' termlist ')' ';'
		  {	Tac t = tacCreate(TAC_RECV);
		  	t->t1.sym = $2;
			/* TODO test here: tac2 should have at least 3 elements */
			t->t2.tac = $4;
			$$ = t;
		  }
		| RECVT label '(' termlist ')' ';'
		  {	Tac t = tacCreate(TAC_RECV);
		  	t->t1.sym = $2;
			/* TODO test here: tac2 should have at least 3 elements */
			t->t2.tac = $4;
			$$ = t;
		  }
		| SENDT label '(' termlist ')' ';'
		  {	Tac t = tacCreate(TAC_SEND);
		  	t->t1.sym = $2;
			/* TODO test here: tac2 should have at least 3 elements */
			t->t2.tac = $4;
			$$ = t;
		  }
		| MATCH '(' term ',' term ')' ';'
		  {
		  	/* first argument is pattern, second should be
			 * ground term */
		  	Tac t= tacCreate(TAC_MATCH);
			t->t1.tac = $3;
			t->t2.tac = $5;
			t->t3.value = true;
			$$ = t;
		  }
		| NOT MATCH '(' term ',' term ')' ';'
		  {
		  	/* first argument is pattern, second should be
			 * ground term */
		  	Tac t= tacCreate(TAC_MATCH);
			t->t1.tac = $4;
			t->t2.tac = $6;
			t->t3.value = false;
			$$ = t;
		  }
		| CLAIMT optlabel '(' termlist ')' ';'
		/* TODO maybe claims should be in the syntax */
		  {	Tac t = tacCreate(TAC_CLAIM);
		  	t->t1.sym = $2;
			t->t2.tac = $4;
			$$ = t;
		  }
		;

roleref		: ID '.' ID
		  {	Tac t = tacCreate(TAC_ROLEREF);
		  	t->t1.sym = $1;
			t->t2.sym = $3;
			$$ = t;
		  }
		;

knowsdecl	: KNOWS termlist ';'
		  {	Tac t = tacCreate(TAC_KNOWS);
		  	t->t1.tac = $2;
			$$ = t;
		  }
		;

macrodecl	: MACRO basicterm '=' termlist ';'
		  {	
			List l;
		        Tac t;

			l = findMacroDefinition($2->t1.sym);
			if (l != NULL)
			  {
			    /* Already defined. We can consider this
			     * a bug or we can define it to
			     * overwrite.
			     *
			     * For now, we decide to overwrite. This
			     * will also aid in straightforward file
			     * composition, if both files contain
			     * macros.
			     */
			    macrolist = list_delete(l);
			    // Alternative:
			    //yyerror("macro symbol already defined earlier.");
			  }

			// Now we know that l does not occur in macrolist
		        /* Add to macro declaration list.
		         * TAC_MACRO doesn't show up in the compiler though.  */
		        t = tacCreate(TAC_MACRO);
		        t->t1.tac = $2;
		        t->t2.tac = tacTuple($4);
		        macrolist = list_append(macrolist, t);
			$$ = NULL;
		  }
		;

declaration	: secretpref CONST basictermlist typeinfo1 ';'
		  {	Tac t = tacCreate(TAC_CONST);
		  	t->t1.tac = $3; // names
			t->t2.tac = $4; // type
			t->t3.tac = $1; // secret?
			$$ = t;
		  }
		| FRESH basictermlist typeinfo1 ';'
		  {	Tac t = tacCreate(TAC_FRESH);
		  	t->t1.tac = $2;	// names
			t->t2.tac = $3; // type
			$$ = t;
		  }
		| secretpref VAR basictermlist typeinfoN ';'
		  {	Tac t = tacCreate(TAC_VAR);
		  	t->t1.tac = $3;
			t->t2.tac = $4;
			t->t3.tac = $1; // obsolete: should not even occur at the global level
			$$ = t;
		  }
		| SECRET basictermlist typeinfo1 ';'
		  {	Tac t = tacCreate(TAC_SECRET);
		  	t->t1.tac = $2;
			t->t2.tac = $3;
			$$ = t;
		  }
		| INVERSEKEYS '(' term ',' term ')' ';'
		  {	Tac t = tacCreate(TAC_INVERSEKEYS);
			t->t1.tac = $3;
			t->t2.tac = $5;
			$$ = t;
		  }
		| INVERSEKEYFUNCTIONS '(' term ',' term ')' ';'
		  {	Tac t = tacCreate(TAC_INVERSEKEYFUNCTIONS);
			t->t1.tac = $3;
			t->t2.tac = $5;
			$$ = t;
		  }
		| COMPROMISED termlist ';'
		  {	Tac t = tacCreate(TAC_COMPROMISED);
		  	t->t1.tac= $2;
			$$ = t;
		  }
		| secretpref funcORhash basictermlist ';'
		  {	Tac t = tacCreate(TAC_HASHFUNCTION);
		  	t->t1.tac = $3;
		  	t->t2.tac = tacCreate(TAC_UNDEF);
			t->t3.tac = $1;	// secret or not
			$$ = t;
		  }
		| macrodecl 
		  {	
		  	$$ = $1;
		  }
		;

funcORhash	: FUNCTION
	          { }
	        | HASHFUNCTION
	          { }
	        ;

secretpref	: /* empty */
		  {	
			$$ = NULL;
		  }
		| SECRET
		  {
			Tac t = tacCreate(TAC_SECRET);
			$$ = t;
		  }
		;

typeinfo1	: /* empty */
		  {
		  	Tac t = tacCreate(TAC_UNDEF);
			$$ = t;
		  }
		| ':' basicterm
		  {	
			$$ = $2;
		  }
		;

typeinfoN	: /* empty */
		  {
		  	Tac t = tacCreate(TAC_UNDEF);
			$$ = t;
		  }
		| ':' basictermlist
		  {	
		  	$$ = $2;
		  }
		;

label		: '_' ID
		  { $$ = $2; }
		;

optlabel        : /* empty */
                 { $$ = NULL; }
               | label
		  { }
                ;


basicterm	: ID
		  {
			Tac t;

			t = tacCreate(TAC_STRING);
			t->t1.sym = $1;
			$$ = t;
		  }
		;

basicormacro	: ID
		  {
			List l;
			Tac t;

			/* check if it is in the list
			 * already */
			l = findMacroDefinition($1);
			if (l == NULL)
			  {
			    t = tacCreate(TAC_STRING);
			    t->t1.sym = $1;
			  }
			else
			  {
			    Tac macrotac;

			    macrotac = (Tac) l->data;
			    t = tacCopy(macrotac->t2.tac);
			  }
			$$ = t;
		  }
		;

term  		: ID '(' termlist ')'
		  {
		  	Tac t = tacCreate(TAC_STRING);
			t->t1.sym = $1;
			$$ = tacJoin(TAC_FCALL,tacTuple($3),t,NULL);
		  }
		| '{' termlist '}' key
		  {
		  	$$ = tacJoin(TAC_ENCRYPT,tacTuple($2),$4,NULL);
		  }
		| '(' termlist ')'
		  { 
		  	$$ = tacTuple($2);
		  }
		| basicormacro
		  { }
		;

termlist	: term
		  { }
		| term ',' termlist
		  {	$$ = tacCat($1,$3); }
		;

basictermlist	: basicterm
		  { }
		| basicterm ',' basictermlist
		  {	$$ = tacCat($1,$3); }
		;

key		: term
		  { }
		;



%%

//! error handler routing
int yyerror(char *s)
{
	extern int yylineno;	//!< defined and maintained in lex.c
	extern char *yytext;	//!< defined and maintained in lex.c
  
	error ("[%i] %s at symbol '%s'.\n", yylineno, s, yytext);
	return 0;
}


