#include <stdlib.h>
#include <stdio.h>
#include "termlists.h"
#include "knowledge.h"
#include "memory.h"
#include "runs.h"
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

void
knowledgeInit (void)
{
  return;
}

void
knowledgeDone (void)
{
}

Knowledge
makeKnowledge ()
{
  return (Knowledge) memAlloc (sizeof (struct knowledge));
}

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

/*
 * knowledgeAddTerm
 *
 * returns a boolean:
 * true iff the term was actually new, and added.
 */

int
knowledgeAddTerm (Knowledge know, Term term)
{
  if (know == NULL)
    {
      printf
	("Warning: trying to add term to uninitialised (NULL) Know pointer.\n");
      return 1;
    }
  if (term == NULL)
    return 0;

  term = deVar (term);

  /* test whether we knew it before */
  if (inKnowledge (know, term))
    return 0;

  if (isTermTuple (term))
    {
      knowledgeAddTerm (know, term->op1);
      knowledgeAddTerm (know, term->op2);
    }

  /* adding variables? */
  know->vars = termlistAddVariables (know->vars, term);

  knowledgeSimplify (know, term);
  if (isTermLeaf (term))
    {
      know->basic = termlistAdd (know->basic, term);
    }
  if (term->type == ENCRYPT)
    {
      Term invkey = inverseKey (know->inverses, term->key);
      if (inKnowledge (know, invkey))
	{
	  /* we can decrypt it */
	  knowledgeAddTerm (know, term->op);
	  if (!inKnowledge (know, term->key))
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


/*
	Note: the input is a key k, i.e. it can decrypt
	anything that was encrypted with k^{-1}.
*/

void
knowledgeSimplify (Knowledge know, Term key)
{
  Termlist tldecrypts = NULL;
  Termlist scan = know->encrypt;
  Term invkey = inverseKey (know->inverses, key);

  while (scan != NULL)
    {
      if (isTermEqual ((scan->term)->key, invkey))
	{
	  tldecrypts = termlistAdd (tldecrypts, (scan->term)->op);
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

/*
 * Add a whole termlist.
 *
 * Returns true iff there was at least one new item.
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

/*

   add an inverse pair to the knowledge

 */

void
knowledgeAddInverse (Knowledge know, Term t1, Term t2)
{
  know->inverses = termlistAdd (know->inverses, t1);
  know->inverses = termlistAdd (know->inverses, t2);
  return;
}

/*
   same, but for list. List pointer is simply copied, so don't delete it later!
*/

void
knowledgeSetInverses (Knowledge know, Termlist tl)
{
  know->inverses = tl;
}

/*

inKnowledge

Is a term a part of the knowledge?

*/

int
inKnowledge (const Knowledge know, Term term)
{
  /* if there is no term, then it's okay 'fur sure' */
  if (term == NULL)
    return 1;
  /* if there is a term, but no knowledge, we're in trouble */
  if (know == NULL)
    return 0;

  mindwipe (know, inKnowledge (know, term));

  term = deVar (term);
  if (isTermLeaf (term))
    {
      return inTermlist (know->basic, term);
    }
  if (term->type == ENCRYPT)
    {
      return inTermlist (know->encrypt, term) ||
	(inKnowledge (know, term->key) && inKnowledge (know, term->op));
    }
  if (term->type == TUPLE)
    {
      return (inTermlist (know->encrypt, term) ||
	      (inKnowledge (know, term->op1) &&
	       inKnowledge (know, term->op2)));
    }
  return 0;			/* unrecognized term type, weird */
}

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

/*
   print inverses
 */

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

/*
   give the set of representatives for the knowledge.
   Note: this is a shallow copy, and needs to be termlistDelete'd.
 */

Termlist
knowledgeSet (Knowledge know)
{
  Termlist tl1, tl2;

  tl1 = termlistShallow (know->basic);
  tl2 = termlistShallow (know->encrypt);
  return termlistConcat (tl1, tl2);
}

/*
   get the inverses pointer of the knowledge.
   Essentially the inverse function of knowledgeSetInverses
*/

Termlist
knowledgeGetInverses (Knowledge know)
{
  if (know == NULL)
    return NULL;
  else
    return know->inverses;
}

/*
 * check whether any substitutions where made at all.
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

/*
 * knowledgeReconstruction
 *
 * This is useful after e.g. substitutions.
 * Just rebuilds the knowledge in a new (shallow) copy.
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

/*
 * propagate any substitutions just made.
 *
 * This usually involves reconstruction of the complete knowledge, which is
 * 'cheaper' than a thorough analysis, so we always make a copy.
 */

Knowledge
knowledgeSubstDo (const Knowledge know)
{
  /* otherwise a copy (for deletion) is returned. */
  return knowledgeReconstruction (know);
}

/*
 * Undo the substitutions just made. Note that this does not work anymore after knowledgeSubstDo!
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

/*
 * knowledgeNew(old,new)
 *
 * yield a termlist (or NULL) that represents the reduced items that are
 * in the new set, but not in the old one.
 */

Termlist
knowledgeNew (const Knowledge oldk, const Knowledge newk)
{
  Termlist newtl;

  newtl = NULL;

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
  addNewStuff (newk->basic);
  addNewStuff (newk->encrypt);
  return newtl;
}
