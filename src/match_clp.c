/*!\file match_clp.c
 *\brief Implements the match function.
 *
 * The match function here is integrated here with an enabled() function.
 * It is the constraint-logic based match.
 *
 *\warning Some code is obsolete, as there hasn't been any development on the CL version for a while.
 */

#include <stdlib.h>
#include <stdio.h>
#include "match_clp.h"
#include "system.h"
#include "memory.h"
#include "constraint.h"
#include "mgu.h"
#include "memory.h"
#include "debug.h"
#include "match_clp.h"
#include "modelchecker.h"

struct solvepass
{
  int (*solution) ();

  System sys;
  int run;
  int (*proceed) (System, int);
};

int
solve (const struct solvepass sp, Constraintlist solvecons)
{
  Constraintlist activecl, cl, beforecl;
  Constraint activeco;
  int flag;

  flag = 0;

  /* locate first non-variable constraint */
  activecl = firstNonVariable (solvecons);

  if (activecl == NULL)
    {
      /* no such thing, so that's nice */
      if (sp.solution != NULL)
	sp.solution (sp, solvecons);
      return 1;
    }

  /* there is an active constraint */
  /* detach it from the list, but retain */
  beforecl = activecl->prev;
  solvecons = constraintlistUnlink (activecl);
  activeco = activecl->constraint;
  if (isTermTuple (activeco->term))
    {
      /* it's a tuple, so we unfold it first */
      Constraintlist oldcl = solvecons;
      cl = constraintlistDuplicate (solvecons);
      cl =
	constraintlistAdd (cl,
			   makeConstraint (TermOp1 (deVar (activeco->term)),
					   activeco->know));
      cl =
	constraintlistAdd (cl,
			   makeConstraint (TermOp2 (deVar (activeco->term)),
					   activeco->know));
      solvecons = cl;
      flag = solve (sp, solvecons) || flag;
      constraintlistDestroy (solvecons);
      solvecons = oldcl;
      if (flag && sp.solution == NULL)
	return 1;
    }
  else
    {
      /* not a tuple. does it unify? */

      //TODO or remove: termNormalize(activeco->term);
      void examine (Termlist tl)
      {
	Termlist tlres, tlscan;
	int goodsubst;

	while (tl != NULL)
	  {
	    //TODO or remove: termNormalize(tl->term);
	    tlres = termMguTerm (activeco->term, tl->term);

	    /* check whether this is a valid
	     * substitution */
	    goodsubst = 1;
	    tlscan = tlres;
	    while (tlscan != NULL && tlres != MGUFAIL)
	      {
		if (validSubst (sp.sys->match, tlscan->term))
		  {
		    tlscan = tlscan->next;
		  }
		else
		  {
		    goodsubst = 0;
		    tlscan = NULL;
		  }
	      }
	    if (tlres != MGUFAIL && goodsubst)
	      {
		/* maybe this has modified current and previous knowledge! */
		/* modify and copy _all_ knowledge instances, if needed, that is
		   all constraints as well as all agent knowledge! */
		Constraintlist oldcl = NULL;
		int copied = 0;

		if (tlres != NULL)
		  {
		    Constraintlist cl;

		    copied = 1;
		    /* sometimes not needed, when no substitutions took place */
		    oldcl = solvecons;
		    solvecons = constraintlistDuplicate (solvecons);
		    cl = solvecons;
		    while (cl != NULL)
		      {
			cl->constraint->know =
			  knowledgeSubstDo (cl->constraint->know);
			cl = cl->next;
		      }
		  }

		/* explore this new state */
		flag = solve (sp, solvecons) || flag;

		/* undo changes */
		if (copied)
		  {
		    Constraintlist cl;
		    cl = solvecons;
		    while (cl != NULL)
		      {
			knowledgeDelete (cl->constraint->know);
			cl = cl->next;
		      }
		    constraintlistDestroy (solvecons);
		    solvecons = oldcl;
		    cl = solvecons;
		    while (cl != NULL)
		      {
			knowledgeSubstUndo (cl->constraint->know);
			cl = cl->next;
		      }
		  }

	      }
	    else
	      {
		/* unification failed */
	      }

	    if (tlres != MGUFAIL)
	      {
		tlscan = tlres;
		while (tlscan != NULL)
		  {
		    tlscan->term->subst = NULL;
		    tlscan = tlscan->next;
		  }
		termlistDelete (tlres);
	      }

	    /* abort if necessary */
	    if (flag && sp.solution == NULL)
	      return;

	    tl = tl->next;
	  }
      }

      examine (activeco->know->basic);
      if (flag && sp.solution == NULL)
	return 1;
      examine (activeco->know->encrypt);
      if (flag && sp.solution == NULL)
	return 1;

      if (isTermEncrypt (activecl->constraint->term))
	{
	  /* shouldn't this be a branch? TODO */

	  Constraintlist oldcl = solvecons;
	  cl = constraintlistDuplicate (oldcl);
	  cl =
	    constraintlistAdd (cl,
			       makeConstraint (TermOp (activeco->term),
					       activeco->know));
	  cl =
	    constraintlistAdd (cl,
			       makeConstraint (TermKey (activeco->term),
					       activeco->know));
	  solvecons = cl;
	  flag = solve (sp, solvecons) || flag;
	  constraintlistDestroy (solvecons);
	  solvecons = oldcl;
	  if (flag && sp.solution == NULL)
	    return 1;
	}
    }

  /* relink detached link */
  if (beforecl == NULL)
    {
      solvecons = constraintlistConcat (activecl, solvecons);
    }
  else
    {
      activecl->prev = beforecl;
      activecl->next = beforecl->next;
      beforecl->next = activecl;
      if (activecl->next != NULL)
	activecl->next->prev = activecl;
    }
  return flag;
}


int
matchRead_clp (const System sys, const int run, int (*proceed) (System, int))
{
  Constraintlist oldcl, newcl;
  Constraint co;
  Roledef runPoint;
  int flag;
  struct solvepass sp;

  /* check solvability */
  int solution (const struct solvepass sp, const Constraintlist cl)
  {
    Knowledge oldknow;
    int flag;
    int copied;
    Constraintlist oldcl;

    oldknow = NULL;
    flag = 0;
    copied = 0;
    oldcl = sys->constraints;

    sys->constraints = cl;
    if (knowledgeSubstNeeded (sys->know))
      {
	copied = 1;
	oldknow = sys->know;
	sys->know = knowledgeSubstDo (sys->know);
      }
    flag = sp.proceed (sys, run);
    if (copied)
      {
	knowledgeDelete (sys->know);
	sys->know = oldknow;
	knowledgeSubstUndo (sys->know);
      }
    sys->constraints = oldcl;
    return flag;
  }


  /* save old state */
  oldcl = sys->constraints;
  newcl = constraintlistShallow (oldcl);

  /* creat new state */
  runPoint = runPointerGet (sys, run);

  /* we know this is a read */
  co = makeConstraint (runPoint->message, sys->know);
  newcl = constraintlistAdd (newcl, co);
  sys->constraints = newcl;

#ifdef DEBUG
  if (DEBUGL (5))
    {
      constraintlistPrint (newcl);
    }
#endif

  sp.solution = solution;
  sp.sys = sys;
  sp.run = run;
  sp.proceed = proceed;
  flag = solve (sp, sys->constraints);

  /* restore memory allocation */
  constraintDestroy (co);
  constraintlistDelete (newcl);
  sys->constraints = oldcl;

  return flag;
}

int
enabled_clp (const System sys, const int run)
{
  return 1;
}

int
block_clp (const System sys, const int run)
{
  return 1;
}

int
secret_clp (const System sys, const Term t)
{
  Constraintlist oldcl, newcl;
  Constraint co;
  int flag;
  struct solvepass sp;

  /* save old state */
  oldcl = sys->constraints;
  newcl = constraintlistShallow (oldcl);

  /* we know this is a read */
  co = makeConstraint (t, sys->know);
  newcl = constraintlistAdd (newcl, co);
  sys->constraints = newcl;

  /* check solvability */

  sp.solution = NULL;
  sp.sys = sys;
  flag = !solve (sp, sys->constraints);

  /* restore memory allocation */
  constraintDestroy (co);
  constraintlistDelete (newcl);
  sys->constraints = oldcl;

  return flag;
}

void
sendAdd_clp (const System sys, const int run, const Termlist tl)
{
  Term t;
  Termlist tl2;

  if (tl == NULL)
    {
      /* TODO because the constraints might have changed, we can try to solve them again... */
      explorify (sys, run);
      return;
    }
  t = deVar (tl->term);
  if (realTermLeaf (t))
    {
      /* leaf: simply add it */
      knowledgeAddTerm (sys->know, t);
      sendAdd_clp (sys, run, tl->next);
      return;
    }
  else
    {
      /* node */
      if (realTermTuple (t))
	{
	  /* tuple */
	  tl2 = termlistShallow (tl->next);
	  tl2 = termlistAdd (tl2, TermOp1 (t));
	  tl2 = termlistAdd (tl2, TermOp2 (t));
	  sendAdd_clp (sys, run, tl2);
	  termlistDelete (tl2);
	}
      else
	{
	  /* encrypt */
	  Term invkey;

	  invkey = inverseKey (sys->know->inverses, TermKey (t));
	  if (!hasTermVariable (invkey))
	    {
	      /* simple case: no variable inside */
	      knowledgeAddTerm (sys->know, t);
	      tl2 = termlistShallow (tl->next);
	      if (inKnowledge (sys->know, invkey)
		  && hasTermVariable (TermOp (t)))
		tl2 = termlistAdd (tl2, TermOp (t));
	      sendAdd_clp (sys, run, tl2);
	      termlistDelete (tl2);
	    }
	  else
	    {
	      /* difficult case: variable in inverse
	       * key. We have to branch. */
	      Knowledge oldknow;
	      Constraint co;
	      Constraintlist clold, clbuf;

	      /* branch 1 : invkey not in knowledge */
	      /* TODO this yields a negative constraint, which we omit for the time being */
	      oldknow = knowledgeDuplicate (sys->know);

	      knowledgeAddTerm (sys->know, t);
	      sendAdd_clp (sys, run, tl->next);

	      knowledgeDelete (sys->know);
	      sys->know = oldknow;

	      /* branch 2 : invkey in knowledge */
	      oldknow = knowledgeDuplicate (sys->know);
	      clold = sys->constraints;
	      clbuf = constraintlistShallow (clold);
	      tl2 = termlistShallow (tl->next);

	      co = makeConstraint (invkey, sys->know);
	      sys->constraints = constraintlistAdd (clbuf, co);
	      /* we _could_ explore first if this is solveable */
	      knowledgeAddTerm (sys->know, t);
	      tl2 = termlistAdd (tl2, TermOp (t));
	      sendAdd_clp (sys, run, tl2);

	      termlistDelete (tl2);
	      constraintDestroy (co);
	      constraintlistDelete (clbuf);
	      sys->constraints = clold;
	      knowledgeDelete (sys->know);
	      sys->know = oldknow;
	    }
	}
    }
}

int
send_clp (const System sys, const int run)
{
  Roledef rd = runPointerGet (sys, run);
  /* execute send, push knowledge? */
  if (inKnowledge (sys->know, rd->message))
    {
      /* no new knowledge, so this remains */
      explorify (sys, run);
    }
  else
    {
      /* new knowledge, must store old state */
      Knowledge oldknow;
      Termlist tl;

      oldknow = sys->know;
      sys->know = knowledgeDuplicate (sys->know);

      tl = termlistAdd (NULL, rd->message);
      sendAdd_clp (sys, run, tl);
      termlistDelete (tl);

      knowledgeDelete (sys->know);
      sys->know = oldknow;
    }
  return 1;
}

int
isPossible_clp (const System sys, const int run, int
		(*proceed) (System, int), const Term t, const Knowledge k)
{
  Constraintlist oldcl, newcl;
  Constraint co;
  Roledef runPoint;
  int flag;
  struct solvepass sp;

  /* check solvability */
  int solution (const struct solvepass sp, const Constraintlist cl)
  {
    Knowledge oldknow;
    Constraintlist oldcl;
    int flag;
    int copied;

    oldknow = NULL;
    oldcl = sys->constraints;
    flag = 0;
    copied = 0;

    sys->constraints = cl;
    if (knowledgeSubstNeeded (sys->know))
      {
	copied = 1;
	oldknow = sys->know;
	sys->know = knowledgeSubstDo (sys->know);
      }
    flag = sp.proceed (sys, run);
    if (copied)
      {
	knowledgeDelete (sys->know);
	sys->know = oldknow;
	knowledgeSubstUndo (sys->know);
      }
    sys->constraints = oldcl;
    return flag;
  }


  /* save old state */
  oldcl = sys->constraints;
  newcl = constraintlistShallow (oldcl);

  /* creat new state */
  runPoint = runPointerGet (sys, run);

  /* add the new constraint */
  co = makeConstraint (t, k);
  newcl = constraintlistAdd (newcl, co);
  sys->constraints = newcl;

  sp.solution = solution;
  sp.sys = sys;
  sp.run = run;
  sp.proceed = proceed;
  flag = solve (sp, sys->constraints);

  /* restore memory allocation */
  constraintDestroy (co);
  constraintlistDelete (newcl);
  sys->constraints = oldcl;

  return flag;
}
