#ifndef SYMBOLS
#define SYMBOLS

/* Size of hashtable: optimistically large. */
#define HASHSIZE 997

#define T_UNDEF		-1
#define T_PROTOCOL	0
#define T_CONST		1
#define T_VAR		2
#define T_SYSCONST	3

#define EOS 0

struct symbol
{
  int type;
  int lineno;
  char *text;
  struct symbol *next;
  struct symbol *allocnext;
};

typedef struct symbol *Symbol;

void symbolsInit (void);
void symbolsDone (void);

Symbol get_symb (void);
void free_symb (Symbol s);

void insert (Symbol s);
Symbol lookup (char *s);
void symbolPrint (Symbol s);
Symbol symbolSysConst (char *str);

#endif
