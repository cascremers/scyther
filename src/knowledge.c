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

/**
 *@file knowledge.c
 *\brief Procedures concerning knowledge structures.
 *
 * The main issue of this code is to maintain the minimal property of the knowledge set.
 */
#include <stdlib.h>
#include <stdio.h>
#include "termlist.h"
#include "knowledge.h"
#include "system.h"
#include "debug.h"
#include "error.h"
#include "specialterm.h"

/*
 * Knowledge stuff
 */

//! Open knowledge code.
void
knowledgeInit (void)
{
  return;
}

//! Close knowledge code.
void
knowledgeDone (void)
{
}

//! Allocate a fresh memory block the size of a knowledge struct.
/**
 * Memory will not be initialized.
 *@return Pointer to a fresh memory block.
 */
Knowledge
makeKnowledge ()
{
  return (Knowledge) malloc (sizeof (struct knowledge));
}

//! Create a new empty knowledge structure.
/**
 *@return Pointer to an empty knowledge structure.
 */
Knowledge
emptyKnowledge ()
{
  Knowledge know;

  know = makeKnowledge ();
  know->basic = NULL;
  know->encrypt = NULL;
  know->inversekeys = NULL;
  know->inversekeyfunctions = NULL;
  know->vars = NULL;
  know->publicfunctions = NULL;
  return know;
}

//! Duplicate a knowledge structure.
/**
 * Makes copies using termlistShallow() of knowledge::basic, knowledge::encrypt and 
 * knowledge::vars.
 * For the inverses, only the pointer is copied.
 *@param know The knowledge structure to be copied.
 *@return A pointer to a new memory struct.
 *\sa termlistShallow(), knowledgeDelete()
 */
Knowledge
knowledgeDuplicate (Knowledge know)
{
  Knowledge newknow;

  if (know == NULL)
    {
      warning ("Trying to copy empty knowledge.");
      return NULL;
    }
  newknow = makeKnowledge ();
  newknow->basic = termlistShallow (know->basic);
  newknow->encrypt = termlistShallow (know->encrypt);
  newknow->vars = termlistShallow (know->vars);
  newknow->inversekeys = know->inversekeys;
  newknow->inversekeyfunctions = know->inversekeyfunctions;
  newknow->publicfunctions = termlistShallow (know->publicfunctions);
  return newknow;
}

//! Delete a knowledge set.
/**
 * Typically used to destroy something made with knowledgeDuplicate().
 *\sa knowledgeDuplicate()
 */
void
knowledgeDelete (Knowledge know)
{
  if (know != NULL)
    {
      termlistDelete (know->basic);
      termlistDelete (know->encrypt);
      termlistDelete (know->vars);
      termlistDelete (know->publicfunctions);
      free (know);
    }
}

//! Destroy a knowledge set.
/**
 * Unlike knowledgeDelete(), uses termlistDestroy() to remove knowledge::basic, 
 * knowledge::encrypt and knowledge::vars substructures.
 *\sa knowledgeDelete()
 */
void
knowledgeDestroy (Knowledge know)
{
  if (know != NULL)
    {
      termlistDestroy (know->basic);
      termlistDestroy (know->encrypt);
      termlistDestroy (know->vars);
      // termlistDestroy(know->inversekeys);
      // termlistDestroy(know->inversekeyfunctions);
      termlistDestroy (know->publicfunctions);
      free (know);
    }
}

//! Add a term to a knowledge set.
/**
 *@param know The knowledge set.
 *@param term The term to be added.
 *@return True iff the term was actually new, and added.
 */
int
knowledgeAddTerm (Knowledge know, Term term)
{
  if (know == NULL)
    {
      warning ("Trying to add term to uninitialised (NULL) Know pointer.");
      return 1;
    }
  if (term == NULL)
    return 0;

  term = deVar (term);

  /* for tuples, simply recurse for components */
  if (isTermTuple (term))
    {
      int status;

      status = knowledgeAddTerm (know, TermOp1 (term));
      return knowledgeAddTerm (know, TermOp2 (term)) || status;
    }

  /* test whether we knew it before */
  if (inKnowledge (know, term))
    return 0;

  /* adding variables? */
  know->vars = termlistAddVariables (know->vars, term);

  knowledgeSimplify (know, term);
  if (isTermLeaf (term))
    {
      know->basic = termlistAdd (know->basic, term);
    }
  if (term->type == ENCRYPT)
    {
      Term invkey = inverseKey (know, TermKey (term));
      if (inKnowledge (know, invkey))
	{
	  /* we can decrypt it */
	  knowledgeAddTerm (know, TermOp (term));
	  if (!inKnowledge (know, TermKey (term)))
	    {
	      /* we know the op now, but not the key, so add it anyway */
	      know->encrypt = termlistAdd (know->encrypt, term);
	    }
	}
      else
	{
	  /* we cannot decrypt it, and from the initial test we know we could not construct it */
	  know->encrypt = termlistAdd (know->encrypt, term);
	}
      termDelete (invkey);
    }
  return 1;
}


//! Try to simplify knowledge based on a term.
/**
 *@param know A knowledge set.
 *@param key A key, i.e. it can decrypt anything that was encrypted with term^{-1}.
 */
void
knowledgeSimplify (Knowledge know, Term key)
{
  Termlist tldecrypts = NULL;
  Termlist scan = know->encrypt;
  Term invkey = inverseKey (know, key);

  while (scan != NULL)
    {
      if (isTermEqual (TermKey (scan->term), invkey))
	{
	  tldecrypts = termlistAdd (tldecrypts, TermOp (scan->term));
	  know->encrypt = termlistDelTerm (scan);
	  scan = know->encrypt;
	}
      else
	scan = scan->next;
    }
  termDelete (invkey);
  knowledgeAddTermlist (know, tldecrypts);
  termlistDelete (tldecrypts);
}

//! Add a termlist to the knowledge.
/*
 *@return True iff there was at least one new item.
 *\sa knowledgeAddTerm()
 */
int
knowledgeAddTermlist (Knowledge know, Termlist tl)
{
  int flag = 0;

  while (tl != NULL)
    {
      // Evil old fashioned code relies on lazy left-to-right parsing. Get rid of it.
      flag = knowledgeAddTerm (know, tl->term) || flag;
      tl = tl->next;
    }
  return flag;
}

//! Add an inverse pair to the knowledge
void
knowledgeAddInverseKeys (Knowledge know, Term t1, Term t2)
{
  know->inversekeys = termlistAdd (know->inversekeys, t1);
  know->inversekeys = termlistAdd (know->inversekeys, t2);
}

//! Add an inverse pair to the knowledge
void
knowledgeAddInverseKeyFunctions (Knowledge know, Term t1, Term t2)
{
  know->inversekeyfunctions = termlistAdd (know->inversekeyfunctions, t1);
  know->inversekeyfunctions = termlistAdd (know->inversekeyfunctions, t2);
}

//! Is a term a part of the knowledge?
/**
 *@param know The knowledge set.
 *@param term The term to be inferred.
 *@return True iff the term can be inferred from the knowledge set.
 */
int
inKnowledge (const Knowledge know, Term term)
{
  mindwipe (know, inKnowledge (know, term));

  /* if there is no term, then it's okay 'fur sure' */
  if (term == NULL)
    return 1;
  /* if there is a term, but no knowledge, we're in trouble */
  if (know == NULL)
    return 0;

  term = deVar (term);
  if (isTermLeaf (term))
    {
      return inTermlist (know->basic, term);
    }
  if (term->type == ENCRYPT)
    {
      return inTermlist (know->encrypt, term) ||
	(inKnowledge (know, TermKey (term))
	 && inKnowledge (know, TermOp (term)));
    }
  if (term->type == TUPLE)
    {
      return (inTermlist (know->encrypt, term) ||
	      (inKnowledge (know, TermOp1 (term)) &&
	       inKnowledge (know, TermOp2 (term))));
    }
  return 0;			/* unrecognized term type, weird */
}

//! Print a knowledge set.
void
knowledgePrint (Knowledge know)
{
  indent ();
  if (know == NULL)
    {
      eprintf ("Empty.\n");
      return;
    }
  eprintf (" [Basic]: ");
  termlistPrint (know->basic);
  eprintf ("\n");
  indent ();
  eprintf (" [Encrp]: ");
  termlistPrint (know->encrypt);
  eprintf ("\n");
  indent ();
  eprintf (" [Vars]: ");
  termlistPrint (know->vars);
  eprintf ("\n");
  eprintf (" [Inversekeys]: ");
  termlistPrint (know->inversekeys);
  eprintf ("\n");
  eprintf (" [Inversekeyfunctions]: ");
  termlistPrint (know->inversekeyfunctions);
  eprintf ("\n");
  eprintf (" [Publicfunctions]: ");
  termlistPrint (know->publicfunctions);
  eprintf ("\n");
}

//! Print a knowledge set, short version (no newline)
void
knowledgePrintShort (const Knowledge know)
{
  indent ();
  if (know == NULL)
    {
      eprintf ("Empty");
      return;
    }

  if (know->basic != NULL)
    {
      termlistPrint (know->basic);
      if (know->encrypt != NULL)
	{
	  eprintf (", ");
	}
    }
  if (know->encrypt != NULL)
    {
      termlistPrint (know->encrypt);
    }
}

//! Yield the set of representatives for the knowledge.
/**
 * Note: this is a shallow copy, and needs to be termlistDelete'd.
 *\sa termlistDelete()
 */
Termlist
knowledgeSet (const Knowledge know)
{
  Termlist tl1, tl2;

  tl1 = termlistShallow (know->basic);
  tl2 = termlistShallow (know->encrypt);
  return termlistConcat (tl1, tl2);
}

//! Check for elements in the knowledge set
int
inKnowledgeSet (const Knowledge know, Term t)
{
  return (inTermlist (know->basic, t) || inTermlist (know->encrypt, t));
}

//! check whether any substitutions where made in a knowledge set.
/**
 * Typically, when a substitution is made, a knowledge set has to be reconstructed.
 * This procedure detects this by checking knowledge::vars.
 *@return True iff an open variable was later closed by a substitution.
 *\sa knowledgeReconstruction()
 */
int
knowledgeSubstNeeded (const Knowledge know)
{
  Termlist tl;

  if (know == NULL)
    return 0;
  tl = know->vars;
  while (tl != NULL)
    {
      if (tl->term->subst != NULL)
	return 1;
      tl = tl->next;
    }
  return 0;
}

//! Add public function
void
knowledgeAddPublicFunction (const Knowledge know, const Term f)
{
  know->publicfunctions = termlistAdd (know->publicfunctions, f);
  return;
}

//! Check public function
int
isKnowledgePublicFunction (const Knowledge know, const Term f)
{
  return inTermlist (know->publicfunctions, f);
}

Term
funKey (Term orig, Term f)
{
  /* in: f'{op}, f
   * out: f{op'} */
  return makeTermFcall (termDuplicate (TermOp (orig)), termDuplicate (f));
}

//! Give the inverse key term of a term.
/**
 * Gives a duplicate of the inverse Key of some term (which is used to encrypt something), as is defined
 * by the termlist, which is a list of key1,key1inv, key2, key2inv, etc...
 *@param inverses The list of inverses, typically from the knowledge.
 *@param key Any term of which the inverse will be determined.
 *@return A pointer to a duplicate of the inverse key term. Use termDelete to remove it.
 *\sa termDuplicate(), knowledge::inverses
 */
Term
inverseKey (Knowledge know, Term key)
{
  Term f;

  key = deVar (key);

  /* inverse key function? */
  f = getTermFunction (key);
  if (f != NULL)
    {
      Termlist tl;

      tl = know->inversekeyfunctions;
      while (tl != NULL && tl->next != NULL)
	{
	  if (isTermEqual (TermKey (key), tl->term))
	    return funKey (key, tl->next->term);
	  if (isTermEqual (TermKey (key), tl->next->term))
	    return funKey (key, tl->term);
	  tl = tl->next->next;
	}
    }
  else
    {
      /* scanning for a direct inverse */
      Termlist tl;

      /* scan the list */
      tl = know->inversekeys;
      while (tl != NULL && tl->next != NULL)
	{
	  if (isTermEqual (key, tl->term))
	    return termDuplicate (tl->next->term);
	  if (isTermEqual (key, tl->next->term))
	    return termDuplicate (tl->term);
	  tl = tl->next->next;
	}
    }
  return termDuplicate (key);	/* defaults to symmetrical */
}
