#ifndef SYMBOLS
#define SYMBOLS

//! Size of symbol hashtable.
/** Optimistically large. Should be a prime, says theory.
 */
#define HASHSIZE 997

enum symboltypes
{ T_UNDEF = -1, T_PROTOCOL, T_CONST, T_VAR, T_SYSCONST };

#define EOS 0

struct symbol
{
  //! Type of symbol.
  /**
   *\sa T_UNDEF, T_PROTOCOL, T_CONST, T_VAR, T_SYSCONST
   */
  int type;
  //! Line number at which it occurred.
  int lineno;
  //! Ascii string with name of the symbol.
  const char *text;
  //! Possible next pointer.
  struct symbol *next;
  //! Used for linking all symbol blocks, freed or in use.
  struct symbol *allocnext;
};

typedef struct symbol *Symbol;

void symbolsInit (void);
void symbolsDone (void);

Symbol get_symb (void);
void free_symb (const Symbol s);

void insert (const Symbol s);
Symbol lookup (const char *s);
void symbolPrint (const Symbol s);
void symbolPrintAll (void);
Symbol symbolSysConst (const char *str);

void eprintf (char *fmt, ...);

extern int globalError;

#endif
