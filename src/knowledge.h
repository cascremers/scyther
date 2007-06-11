/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007 Cas Cremers
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

#ifndef KNOWLEDGE
#define KNOWLEDGE

#include "term.h"
#include "termlist.h"

//! Knowledge structure.
/**
 * Contains a miminal representation of a knowledge set.
 */
struct knowledge
{
  //! A list of non-encrypted terms.
  Termlist basic;
  //! A list of terms encrypted, such that the inverse is not in the knowledge set.
  Termlist encrypt;
  //! List of inverse pairs (thus length of list is even)
  Termlist inverses;
  //! List of open variables in the knowledge set.
  /**
   * This list is used to determine whether the knowledge needs to be rewritten.
   * If a new substitution is done, one of the elements of this list will become closed,
   * and we need to reconstruct the knowledge set.
   */
  Termlist vars;		// special: denotes unsubstituted variables
};

//! Shorthand for knowledge pointer.
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
void knowledgePrintShort (const Knowledge know);
void knowledgeInversesPrint (Knowledge know);
int isKnowledgeEqual (Knowledge know1, Knowledge know2);
Termlist knowledgeSet (const Knowledge know);
Termlist knowledgeGetInverses (const Knowledge know);
Termlist knowledgeGetBasics (const Knowledge know);
int knowledgeSubstNeeded (const Knowledge know);
Knowledge knowledgeSubstDo (const Knowledge know);
void knowledgeSubstUndo (const Knowledge know);
Termlist knowledgeNew (const Knowledge oldk, const Knowledge newk);

//! Harnass macro for recursive procedures.
#define mindwipe(k,recurse) \
        Termlist tl; \
	int flag; \
	if (k != NULL && k->vars != NULL) { \
		tl = k->vars; \
		while (tl != NULL) { \
			if (tl->term->subst != NULL) { \
				Term oldsubst = tl->term->subst; \
				tl->term->subst = NULL; \
				flag = recurse; \
				tl->term->subst = oldsubst; \
				return flag; \
			} \
			tl = tl->next; \
		} \
	} \


#endif
