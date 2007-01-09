typedef union{
	char*  		str;
	struct tacnode*	tac;
	Symbol		symb;
	int		value;
} YYSTYPE;
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


extern YYSTYPE yylval;
