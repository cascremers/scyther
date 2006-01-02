#ifndef SUBSTITUTIONS
#define SUBSTITUTIONS

#include "termlist.h"
#include "knowledge.h"
#include "system.h"

//! substitution structure
struct substitution
{
  Term from;
  Term to;
};

typedef struct substitution *Substitution;	//!< substitution structure

//! substitution list
struct substitutionlist
{
  Substitution subst;
  struct substitutionlist *next;
};

typedef struct substitutionlist *Substitutionlist;	//!< substitution list structure


Substitution makeSubstitution (Term from, Term to);
void substitutionDelete (Substitution subs);
void substitutionDestroy (Substitution subs);
Term termSubstitute (Term term, Substitution subs);
Termlist termlistSubstitute (Termlist tl, Substitution subs);
void substitutionPrint (Term t, Substitution subs);
Term termSubstituteList (Term term, Substitutionlist sl);
Substitutionlist makeSubstitutionList (Substitution subs);
Substitutionlist substitutionlistAdd (Substitutionlist sl, Term from,
				      Term to);
void substitutionlistDestroy (Substitutionlist sl);
void substitutionlistAnnihilate (Substitutionlist sl);
Substitutionlist substitutionlistConcat (Substitutionlist sl1,
					 Substitutionlist sl2);
Termlist substitutionBatch (Termlist tl, Substitutionlist sl);
Roledef substitutionRoledef (Roledef rd, Substitutionlist sl);
Knowledge substitutionKnowledge (Knowledge know, Substitutionlist sl);
void substitutionlistPrint (Substitutionlist sl);

#endif
