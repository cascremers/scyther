#ifndef CONSTRAINTS
#define CONSTRAINTS
#include "terms.h"
#include "knowledge.h"

struct constraint
{
  Term term;
  Knowledge know;
};

typedef struct constraint *Constraint;

struct constraintlist
{
  Constraint constraint;
  struct constraintlist *next;
  struct constraintlist *prev;
};

typedef struct constraintlist *Constraintlist;

Constraint makeConstraint (Term term, Knowledge know);
Constraint constraintDuplicate (Constraint co);
void constraintDestroy (Constraint cons);
Constraintlist constraintlistAdd (Constraintlist cl, Constraint co);
Constraintlist constraintlistConcat (Constraintlist cl1, Constraintlist cl2);
Constraintlist constraintlistRewind (Constraintlist cl);
Constraintlist constraintlistInsert (Constraintlist cl, Term term,
				     Knowledge know);
Constraintlist constraintlistUnlink (Constraintlist cl);
Constraintlist constraintlistRemove (Constraintlist cl);
void constraintlistDestroy (Constraintlist cl);
void constraintlistDelete (Constraintlist cl);
Constraintlist constraintlistShallow (Constraintlist oldcl);
Constraintlist constraintlistDuplicate (Constraintlist oldcl);
void constraintPrint (Constraint co);
void constraintlistPrint (Constraintlist cl);

Constraintlist firstNonVariable (Constraintlist cl);

#endif
