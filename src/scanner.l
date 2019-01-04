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

%option yylineno
%option never-interactive

%{
/* scanner for security protocols language */

#include <strings.h>
#include <string.h>
#include "pheading.h"
#include "tac.h"
#include "switches.h"
#include "error.h"

/* tokens for language */
#include "parser.h"

void mkname(char *name);
void mkval(void);
void mktext(void);

int yyerror(char *s);

Symbol mkstring(char *name);

struct stringlist {
	char*			string;
	struct stringlist*	next;
};

typedef struct stringlist* Stringlist;

static Stringlist allocatedStrings = NULL;


int mylineno = 0;

%}

comment1	"//".*
comment2	"#".*
delimiter	[ \t\r\n]
whitespace	{delimiter}+
uc_letter	[A-Z]
lc_letter	[a-z]
letter		{lc_letter}|{uc_letter}
digit		[0-9]
ascii_char	[^\"\n]
escaped_char	\\n|\\\"
integer		{digit}+
text		\"({ascii_char}|{escaped_char})*\"
id		@?({letter}|{digit}|[\^\-!'])+

/* the "incl" state is used for picking up the name of an include file
 */
%x incl inclend

%{
#define MAX_INCLUDE_DEPTH 10
YY_BUFFER_STATE include_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr = 0;
%}

%%
include		BEGIN(incl);
<incl>[ \t]*\"	/* eat the whitespace */
<incl>[^\"]+	{ /* got the include file name */
	                 if ( include_stack_ptr >= MAX_INCLUDE_DEPTH )
	                     {
	                     printfstderr( "Includes nested too deeply" );
	                     exit( 1 );
	                     }
	
	                 include_stack[include_stack_ptr++] =
	                     YY_CURRENT_BUFFER;
	
			 /* try to open, using scytherdirs environment variable as well. */
			 yyin = openFileSearch (yytext, NULL);
	
			 if (! yyin)
			 {
			 	error ("could not open include file %s.", yytext);
			 }
	
	                 yy_switch_to_buffer(
	                     yy_create_buffer( yyin, YY_BUF_SIZE ) );
	
	                 BEGIN(INITIAL);
		}

<inclend>\";?	{ /* eat the closing things */
			BEGIN(INITIAL);
		}

<INITIAL><<EOF>>	{
                 if ( --include_stack_ptr < 0 )
                     {
                        yyterminate();
                     }

                 else
                     {
                     	yy_delete_buffer( YY_CURRENT_BUFFER );
                     	yy_switch_to_buffer(
                        include_stack[include_stack_ptr] );
			BEGIN(inclend);
                     }
		}

"/*"		{
			register int c;

			for ( ; ; )
                        {
                        	while ( (c = input()) != '*' && c != '\n' && c != EOF )
                                      ;    /* eat up text of comment */

                                if ( c == '*' )
                                {
                                	while ( (c = input()) == '*' )
                                        	;
                                      	if ( c == '/' )
                                        	break;    /* found the end */
                                }

				if (c == '\n')
					mylineno++;

                                if ( c == EOF )
                                {
                                	yyerror( "EOF in comment" );
                                	break;
                        	}
                	}
                }

\n		{ mylineno++; }
{whitespace}	{ }
{comment1}	{ }
{comment2}	{ }

protocol	{ return PROTOCOL; }
role		{ return ROLE; }
read		{ return READT; }
recv		{ return RECVT; }
send		{ return SENDT; }
match		{ return MATCH; }
not		{ return NOT; }
macro		{ return MACRO; }
var		{ return VAR; }
const		{ return CONST; }
fresh		{ return FRESH; }
claim		{ return CLAIMT; }
run		{ return RUN; }
secret		{ return SECRET; }
inversekeys	{ return INVERSEKEYS; }
inversekeyfunctions	{ return INVERSEKEYFUNCTIONS; }
untrusted	{ return UNTRUSTED; }
compromised	{ return COMPROMISED; }
usertype	{ return USERTYPE; }
singular	{ return SINGULAR; }
function	{ return FUNCTION; }
hashfunction	{ return HASHFUNCTION; }
knows		{ return KNOWS; }
trusted		{ return TRUSTED; }
option 		{ return OPTION; }
{text} 		{ 
			int len;
			char *dest;
			char *src;
			
			if (strlen(yytext) >= 2)
			{
			  // Make a copy without the surrounding
			  // double-quotes.
			  // TODO: Allow to unescape quotes inside string if
			  // needed later.
			  len = strlen(yytext)-2;
			  src = yytext+1;
			}
			else
			{
			  // If only one character, then simply copy
			  len = strlen(yytext);
			  src = yytext;
			}
			// Copy
			dest = (char *)malloc(len+1);
			strncpy(dest,src,len);
			dest[len] = EOS;
			yylval.str = dest;

			return TEXT; 
		}
{id}		{	
			yylval.symb = mkstring(yytext);
			return ID;
		}
.		{ return yytext[0]; }



%%

Symbol mkstring(char *name)
{
	Symbol t;
	char* s;
	Stringlist sl;
	int len;

	if (( t = lookup(name)) != NULL)
	{
		return t;
	}
	// make new name
	len = strlen(name);
	s = (char *)malloc(len+1);
	sl = (Stringlist) malloc(sizeof(struct stringlist));
	strncpy(s,name,len);
	sl->next = allocatedStrings;
	allocatedStrings = sl;
	sl->string = s;
	s[len] = EOS;

	t = get_symb();
	t->lineno = yylineno;
	t->type = T_UNDEF;
	t->text = s;

	insert(t);
	return t;
}

void scanner_cleanup(void)
{
	yy_delete_buffer (YY_CURRENT_BUFFER);
}

void strings_cleanup(void)
{
	Stringlist sl;
	while (allocatedStrings != NULL)
	{
		sl = allocatedStrings;
		allocatedStrings = sl->next;
		free(sl->string);
		free(sl);
	}
}

int yywrap (void)
{
  /* signal true to let lex know that nothing else is coming */
  return 1;
}


/*
void mkval(void);
void mktext(void);
*/


// vim:ft=lex:
