#ifndef KNOWLEDGE
#define KNOWLEDGE

#include "terms.h"
#include "termlists.h"

struct knowledge
{
  Termlist basic;
  Termlist encrypt;
  Termlist inverses;
  union
  {
    Termlist vars;		// special: denotes unsubstituted variables
    struct knowledge *next;	// use for alternative memory management.
  };
};

typedef struct knowledge *Knowledge;

void knowledgeInit (void);
void knowledgeDone (void);
Knowledge makeKnowledge ();
Knowledge emptyKnowledge ();
Knowledge knowledgeDuplicate (Knowledge know);
void knowledgeDelete (Knowledge know);
void knowledgeDestroy (Knowledge know);
int knowledgeAddTerm (Knowledge know, Term term);
int knowledgeAddTermlist (Knowledge know, Termlist tl);
void knowledgeAddInverse (Knowledge know, Term t1, Term t2);
void knowledgeSetInverses (Knowledge know, Termlist tl);
void knowledgeSimplify (Knowledge know, Term decryptkey);
int inKnowledge (const Knowledge know, Term term);
void knowledgePrint (Knowledge know);
void knowledgeInversesPrint (Knowledge know);
int isKnowledgeEqual (Knowledge know1, Knowledge know2);
Termlist knowledgeSet (Knowledge know);
Termlist knowledgeGetInverses (Knowledge know);
int knowledgeSubstNeeded (const Knowledge know);
Knowledge knowledgeSubstDo (const Knowledge know);
void knowledgeSubstUndo (const Knowledge know);
Termlist knowledgeNew (const Knowledge oldk, const Knowledge newk);

#define mindwipe(k,recurse) \
	if (k != NULL && k->vars != NULL) { \
		Termlist tl = k->vars; \
		while (tl != NULL) { \
			if (tl->term->subst != NULL) { \
				Term oldsubst = tl->term->subst; \
				tl->term->subst = NULL; \
				int flag = recurse; \
				tl->term->subst = oldsubst; \
				return flag; \
			} \
			tl = tl->next; \
		} \
	} \


#endif
