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
#include "memory.h"
#include "system.h"
#include "debug.h"

/*
 * Knowledge stuff
 *
 * Note that a really weird thing is going on involving unpropagated substitutions.
 * Idea:
 *
 * 1. Substitute terms by filling in ->subst.
 * Now, either:
 * 2a. Undo this by knowledgeUndo.
 * 2b. Propagate it, modifying the knowledge beyond repair by knowledgeSubstDo. Now inKnowledge works again.
 * 2c. inKnowledge/knowledgeSet if something is in the knowledge: this does not consider the substitutions!, and 
 *     they now have some overhead.
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
  return (Knowledge) memAlloc (sizeof (struct knowledge));
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
  know->inverses = NULL;
  know->vars = NULL;
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
      printf ("Warning! Trying to copy empty knowledge!\n");
      return NULL;
    }
  newknow = makeKnowledge ();
  newknow->basic = termlistShallow (know->basic);
  newknow->encrypt = termlistShallow (know->encrypt);
  newknow->vars = termlistShallow (know->vars);
  newknow->inverses = know->inverses;
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
      memFree (know, sizeof (struct knowledge));
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
      // termlistDestroy(know->inverses);
      memFree (know, sizeof (struct knowledge));
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
      fprintf
	(stderr, "Warning: trying to add term to uninitialised (NULL) Know pointer.\n");
      return 1;
    }
  if (term == NULL)
    return 0;

  term = deVar (term);

  /* for tuples, simply recurse for components */
  if (isTermTuple (term))
    {
      int status;

      status = knowledgeAddTerm (know, term->left.op1);
      return knowledgeAddTerm (know, term->right.op2) || status;
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
      Term invkey = inverseKey (know->inverses, term->right.key);
      if (inKnowledge (know, invkey))
	{
	  /* we can decrypt it */
	  knowledgeAddTerm (know, term->left.op);
	  if (!inKnowledge (know, term->right.key))
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
  Term invkey = inverseKey (know->inverses, key);

  while (scan != NULL)
    {
      if (isTermEqual ((scan->term)->right.key, invkey))
	{
	  tldecrypts = termlistAdd (tldecrypts, (scan->term)->left.op);
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
      flag = knowledgeAddTerm (know, tl->term) || flag;
      tl = tl->next;
    }
  return flag;
}

//! Add an inverse pair to the knowledge
void
knowledgeAddInverse (Knowledge know, Term t1, Term t2)
{
  know->inverses = termlistAdd (know->inverses, t1);
  know->inverses = termlistAdd (know->inverses, t2);
  return;
}

//! Set an inverse pair list for the knowledge.
/**
 * List pointer is simply copied, so don't delete it later!
 */
void
knowledgeSetInverses (Knowledge know, Termlist tl)
{
  know->inverses = tl;
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
	(inKnowledge (know, term->right.key) && inKnowledge (know, term->left.op));
    }
  if (term->type == TUPLE)
    {
      return (inTermlist (know->encrypt, term) ||
	      (inKnowledge (know, term->left.op1) &&
	       inKnowledge (know, term->right.op2)));
    }
  return 0;			/* unrecognized term type, weird */
}

//! Compare two knowledge sets.
/**
 * This does not check currently for equivalence of inverse sets, which it should.
 *@return True iff both knowledge sets are equal.
 */
int
isKnowledgeEqual (Knowledge know1, Knowledge know2)
{
  if (know1 == NULL || know2 == NULL)
    {
      if (know1 == NULL && know2 == NULL)
	return 1;
      else
	return 0;
    }
  if (!isTermlistEqual (know1->encrypt, know2->encrypt))
    return 0;
  return isTermlistEqual (know1->basic, know2->basic);
}

//! Print a knowledge set.
void
knowledgePrint (Knowledge know)
{
  indent ();
  if (know == NULL)
    {
      printf ("Empty.\n");
      return;
    }
  printf (" [Basic]: ");
  termlistPrint (know->basic);
  printf ("\n");
  indent ();
  printf (" [Encrp]: ");
  termlistPrint (know->encrypt);
  printf ("\n");
  indent ();
  printf (" [Vars]: ");
  termlistPrint (know->vars);
  printf ("\n");
}

//! Print the inverses list of a knowledge set.
void
knowledgeInversesPrint (Knowledge know)
{
  Termlist tl;
  int after = 0;

  if (know == NULL)
    {
      printf ("Empty knowledge.");
      return;
    }

  tl = knowledgeGetInverses (know);
  if (tl == NULL)
    {
      printf ("None.");
    }
  else
    {
      while (tl != NULL && tl->next != NULL)
	{
	  if (after)
	    {
	      printf (",");
	    }
	  printf ("(");
	  termPrint (tl->term);
	  printf (",");
	  termPrint (tl->next->term);
	  printf (")");
	  after = 1;
	  tl = tl->next->next;
	}
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

//! Get the inverses pointer of the knowledge.
/**
 * Essentially the inverse function of knowledgeSetInverses()
 */
Termlist
knowledgeGetInverses (const Knowledge know)
{
  if (know == NULL)
    return NULL;
  else
    return know->inverses;
}

//! Get all basic elements in the knowledge
/**
 * This function is used by match_basic, to determine all basic elements in the knowledge set.
 * Most of the time this doesn't even change, so it might become a parameter of knowledge.
 * For now, this will have to do.
 *
 *@todo Investigate whether the basics in the knowledge set should be a parameter of knowledge, as it doesn't change very often.
 */
__inline__ Termlist
knowledgeGetBasics (const Knowledge know)
{
  return termlistAddBasics (termlistAddBasics(NULL, know->basic), know->encrypt);
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

//! Reconstruct a knowledge set.
/**
 * This is useful after e.g. substitutions.
 * Just rebuilds the knowledge in a new (shallow) copy.
 *@return The pointer to the new knowledge.
 *\sa knowledgeSubstNeeded()
 */
Knowledge
knowledgeReconstruction (const Knowledge know)
{
  Knowledge newknow = emptyKnowledge ();

  newknow->inverses = know->inverses;
  knowledgeAddTermlist (newknow, know->basic);
  knowledgeAddTermlist (newknow, know->encrypt);
  return newknow;
}

//! Propagate any substitutions just made.
/**
 * This usually involves reconstruction of the complete knowledge, which is
 * 'cheaper' than a thorough analysis, so we always make a copy.
 *\sa knowledgeReconstruction()
 */
Knowledge
knowledgeSubstDo (const Knowledge know)
{
  /* otherwise a copy (for deletion) is returned. */
  return knowledgeReconstruction (know);
}

//! Undo substitutions that were not propagated yet.
/**
 * Undo the substitutions just made. Note that this does not work anymore after knowledgeSubstDo()
 */
void
knowledgeSubstUndo (const Knowledge know)
{
  Termlist tl;

  tl = know->vars;
  while (tl != NULL)
    {
      tl->term->subst = NULL;
      tl = tl->next;
    }
}

//! Yield the minimal set of terms that are in some knowledge, but not in some other set.
/**
 * Yield a termlist (or NULL) that represents the reduced items that are
 * in the new set, but not in the old one.
 *@param oldk The old knowledge.
 *@param newk The new knowledge, possibly with new terms.
 *@return A termlist of miminal terms in newk, but not in oldk.
 */

Termlist
knowledgeNew (const Knowledge oldk, const Knowledge newk)
{
  Termlist newtl;

  void addNewStuff (Termlist tl)
  {
    while (tl != NULL)
      {
	if (!inKnowledge (oldk, tl->term))
	  {
	    newtl = termlistAdd (newtl, tl->term);
	  }
	tl = tl->next;
      }
  }
  
  newtl = NULL;
  addNewStuff (newk->basic);
  addNewStuff (newk->encrypt);
  return newtl;
}
