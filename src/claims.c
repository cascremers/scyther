#include <stdlib.h>
#include "termmaps.h"
#include "runs.h"
#include "error.h"

#define MATCH_NONE 0
#define MATCH_ORDER 1
#define MATCH_REVERSE 2

#define LABEL_GOOD -3
#define LABEL_TODO -2

/*
 * Validity checks for claims
 */

//! Check complete message match
/**
 *@returns any of the MATCH_ signals
 */
int
events_match (const System sys, const int i, const int j)
{
  Roledef rdi, rdj;

  rdi = sys->traceEvent[i];
  rdj = sys->traceEvent[j];
  if ((isTermEqual (rdi->message, rdj->message)) && 
      (isTermEqual (rdi->from, rdj->from)) &&
      (isTermEqual (rdi->to, rdj->to)) && 
      (isTermEqual (rdi->label, rdj->label)) &&
      !(rdi->internal || rdj->internal))
    {
      if (rdi->type == SEND && rdj->type == READ)
	{
	  if (i<j)
	      return MATCH_ORDER;
	  else
	      return MATCH_REVERSE;
	}
      if (rdi->type == READ && rdj->type == SEND)
	{
	  if (i>j)
	      return MATCH_ORDER;
	  else
	      return MATCH_REVERSE;
	}
    }
  return MATCH_NONE;
}

//! nisynch generalization
/**
 * f maps the involved roles to run identifiers.
 * g maps all labels in prec to the event indices for things already found,
 * or to LABEL_TODO for things not found yet but in prec, and LABEL_GOOD for well linked messages (and that have thus defined a runid for the corresponding role).
 * All values not in prec map to -1.
 *@returns 1 iff the claim is allright, 0 iff it is violated.
 */
int
oki_nisynch (const System sys, const int i, const Termmap f, const Termmap g)
{
  // Check for completed trace
  if (i < 0)
    {
      // Are all labels well linked?
      Termmap gscan;

      gscan = g;
      while (gscan != NULL)
	{
	  if (gscan->result != LABEL_GOOD)
	      return 0;
	  gscan = gscan->next;
	}
      return 1;
    }
  else
    {
      Roledef rd;
      int rid;

      rd = sys->traceEvent[i];
      rid = sys->traceRun[i];
      /*
       * Simple case: internal event or claim
       */
      if (rd->type == CLAIM || rd->internal)
	{
	  return oki_nisynch (sys,i-1,f,g);
	}
      else
	{
	  /*
	   * More difficult cases: send and read
	   */
	  if (rd->type == READ)
	    {
	      /*
	       * Read is only relevant for already involved runs, and labels in prec
	       */
              Termmap fscan;

	      fscan = f;
	      while (fscan != NULL)
		{
		  if (fscan->result == rid)
		    {
		      // Involved, but is it a prec label?
		      if (termmapGet (g, rd->label) == LABEL_TODO)
			{
			  Termmap gbuf;
			  int result;

			  gbuf = termmapDuplicate (g);
			  gbuf = termmapSet (gbuf, rd->label, i);
			  result = oki_nisynch (sys,i-1,f,gbuf);
			  termmapDelete (gbuf);
			  return result;
		        }
		    }
		  fscan = fscan->next;
		}
	      // Apparently not involved
	      return oki_nisynch (sys,i-1,f,g);
	    }
	  if (rd->type == SEND)
	    {
	      // Scan whether we were waiting for it or not
	      int result;
	      int rid2;
	      Term rolename;

	      /*
	       * Two options: it is either involved or not
	       */
	      // 1. Assume that this run is not yet involved 
	      result = oki_nisynch (sys, i-1, f, g);
	      // 2. It is involved. Then either already used for this role, or will be now.
	      rolename = sys->runs[rid].role->nameterm;
	      rid2 = termmapGet (f, rolename);
	      if (rid2 == -1 || rid2 == rid)
		{
	          Termmap gscan;
		  // Was not involved yet in a registerd way, or was the correct rid
		  gscan = g;
		  while (!result && gscan != NULL)
		    {
		      // Ordered match needed
		      if (gscan->result > -1 && 
			  events_match (sys, gscan->result, i) == 1)
			{
			  Termmap fbuf, gbuf;

			  /**
			   *@todo Optimization can be done when rid2 == rid, no copy of f needs to be made.
			   */
			  fbuf = termmapDuplicate (f);
			  fbuf = termmapSet (fbuf, rolename, rid);
			  gbuf = termmapDuplicate (g);
			  gbuf = termmapSet (gbuf, rd->label, -3);
			  result = oki_nisynch (sys, i-1, fbuf, gbuf);
			  termmapDelete (gbuf);
			  termmapDelete (fbuf);
			}
		      gscan = gscan->next;
		    }
		}
	      return result;
	    }
	  /*
	   * Exception: no send, no read, what is it?
	   */
	  error ("Unrecognized event type in claim scanner at %i.", i);
	}
    }
}

/*
 * Real checks
 */

//! Check validity of ni-synch claim at event i.
/**
 *@returns 1 iff claim is true.
 */
int
check_claim_nisynch (const System sys, const int i)
{
  Roledef rd;
  int result;
  int rid;
  Termmap f,g;
  Term label;
  Claimlist cl;
  Termlist tl;

  rid = sys->traceRun[i];
  rd = sys->traceEvent[i];
  cl = rd->claiminfo;
  cl->count = statesIncrease (cl->count);
  f = termmapSet (NULL, sys->runs[rid].role->nameterm, rid);

  // map all labels in prec to LABEL_TODO
  g = NULL;
  label = rd->label;

  tl = cl->prec;
  while (tl != NULL)
    {
      g = termmapSet (g, tl->term, LABEL_TODO);
      tl = tl->next;
    }
  /*
   * Check claim
   */
  result = oki_nisynch(sys, i, f, g);
  if (!result)
    {
      cl->failed = statesIncrease (cl->failed);

//#ifdef DEBUG 
      warning ("Claim has failed!");
      printf ("To be exact, claim label ");
      termPrint (cl->label);
      printf (" with prec set ");
      termlistPrint (cl->prec);
      printf ("\n");
      printf ("i: %i\nf: ",i);
      termmapPrint (f);
      printf ("\ng: ");
      termmapPrint (g);
      printf ("\n");
//#endif

    }
  termmapDelete (f);
  termmapDelete (g);
  return result;
}

