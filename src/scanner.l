%option yylineno

%{
/* scanner for security protocols language */

#include <strings.h>
#include "pheading.h"
#include "memory.h"
#include "tac.h"

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
id		@?({letter}|{digit}|[\^\-])+

%%

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
send		{ return SENDT; }
var		{ return VAR; }
const		{ return CONST; }
claim		{ return CLAIMT; }
run		{ return RUN; }
secret		{ return SECRET; }
inversekeys	{ return INVERSEKEYS; }
untrusted	{ return UNTRUSTED; }
compromised	{ return COMPROMISED; }
usertype	{ return USERTYPE; }
singular	{ return SINGULAR; }
function	{ return FUNCTION; }
hashfunction	{ return HASHFUNCTION; }
knows		{ return KNOWS; }
trusted		{ return TRUSTED; }
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
