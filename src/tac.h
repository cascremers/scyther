#ifndef TAC_H
#define TAC_H

#include "symbols.h"

/*
 * TAC instructions
 */

#define TAC_UNDEF	0
#define TAC_SYM		1
#define TAC_TUPLE	3
#define TAC_ENCRYPT	4
#define TAC_VAR		7
#define TAC_CONST	8
#define TAC_READ	9
#define TAC_SEND	10
#define TAC_CLAIM	11
#define TAC_FUNC	12
#define TAC_STRING	13
#define TAC_ROLE	14
#define TAC_PROTOCOL	15
#define TAC_RUN		16
#define TAC_ROLEREF	17
#define TAC_SECRET	18
#define TAC_INVERSEKEYS	19
#define TAC_UNTRUSTED	20
#define TAC_COMPROMISED	21
#define TAC_USERTYPE	22

struct tacnode
{
  struct tacnode *next;
  struct tacnode *prev;
  struct tacnode *allnext;
  int op;
  int lineno;
  union
  {
    Symbol sym;
    struct tacnode *tac;
    char *str;
  } t1;
  union 
  {
    Symbol sym;
    struct tacnode *tac;
    char *str;
  } t2;
  union
  {
    Symbol sym;
    struct tacnode *tac;
    char *str;
  } t3;
};

typedef struct tacnode *Tac;

void tacInit (void);
void tacDone (void);
Tac tacCreate (int op);
Tac tacSymb (char *s);
Tac tacJoin (int op, Tac t1, Tac t2, Tac t3);
Tac tacTuple (Tac taclist);
Tac tacCat (Tac t1, Tac t2);
void tacPrint (Tac t);

#endif
