#include <stdlib.h>
#include "termmaps.h"
#include "runs.h"
#include "error.h"

#define MATCH_NONE 0
#define MATCH_ORDER 1
#define MATCH_REVERSE 2

#define LABEL_GOOD -3
#define LABEL_TODO -2

// Debugging the NI-SYNCH checks
//#define OKIDEBUG

/*
 * Validity checks for claims
 */

#ifdef OKIDEBUG
int indac = 0;

void indact ()
{
  int i;

  i = indac;
  while (i > 0)
    {
      printf ("|   ");
      i--;
    }
}
#endif

//! Check complete message match
/**
 *@returns any of the MATCH_ signals
 */
__inline__ int
events_match (const System sys, const int i, const int j)
{
  Roledef rdi, rdj;

  rdi = sys->traceEvent[i];
  rdj = sys->traceEvent[j];
  if (isTermEqual (rdi->message, rdj->message) && 
      isTermEqual (rdi->from,    rdj->from) &&
      isTermEqual (rdi->to,      rdj->to) && 
      isTermEqual (rdi->label,   rdj->label) &&
      !(rdi->internal || rdj->internal)
      )
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


//! Check nisynch from label_to_index.
__inline__ int
oki_nisynch_full (const System sys, const Termmap label_to_index)
{
  // Are all labels well linked?
  Termmap label_to_index_scan;

  label_to_index_scan = label_to_index;
  while (label_to_index_scan != NULL)
    {
      if (label_to_index_scan->result != LABEL_GOOD)
	{
#ifdef OKIDEBUG
	  indact ();
	  printf ("Incorrectly linked label at the end,");
	  printf ("label: ");
	  termPrint (label_to_index_scan->term);
	  printf ("\n");
#endif
	  return 0;
	}
      label_to_index_scan = label_to_index_scan->next;
    }
  // Apparently they are all well linked
  return 1;
}

//! Evaluate claims or internal reads (chooses)
__inline__ int
oki_nisynch_other (const System sys, const int trace_index, const Termmap role_to_run, const Termmap label_to_index)
{
  int result;

#ifdef OKIDEBUG
  indact ();
  printf ("Exploring further assuming this (claim) run is not involved.\n");
  indac++;
#endif
  result =  oki_nisynch (sys, trace_index-1, role_to_run, label_to_index);
#ifdef OKIDEBUG
  indact ();
  printf (">%i<\n", result);
  indac--;
#endif
  return result;
}

//! Evaluate reads
__inline__ int
oki_nisynch_read (const System sys, const int trace_index, const Termmap role_to_run, const Termmap label_to_index)
{
  /*
   * Read is only relevant for already involved runs, and labels in prec
   */
  Termmap role_to_run_scan;
  int result = 7;
  Roledef rd;
  int rid;

  rd = sys->traceEvent[trace_index];
  rid = sys->traceRun[trace_index];

  role_to_run_scan = role_to_run;
  while (role_to_run_scan != NULL)
    {
      if (role_to_run_scan->result == rid)
	{
	  // Involved, but is it a prec label?
	  if (termmapGet (label_to_index, rd->label) == LABEL_TODO)
	    {
	      Termmap label_to_index_buf;
	      int result;

	      label_to_index_buf = termmapDuplicate (label_to_index);
	      label_to_index_buf = termmapSet (label_to_index_buf, rd->label, trace_index);
#ifdef OKIDEBUG
	      indact ();
	      printf ("Exploring because this (read) run is involved.\n");
	      indac++;
#endif
	      result = oki_nisynch (sys, trace_index-1, role_to_run, label_to_index_buf);
#ifdef OKIDEBUG
	      indact ();
	      printf (">%i<\n", result);
	      indac--;
#endif
	      termmapDelete (label_to_index_buf);
	      return result;
	    }
	}
      role_to_run_scan = role_to_run_scan->next;
    }
  // Apparently not involved
#ifdef OKIDEBUG
  indact ();
  printf ("Exploring further assuming this (read) run is not involved.\n");
  indac++;
#endif
  result = oki_nisynch (sys, trace_index-1, role_to_run, label_to_index);
#ifdef OKIDEBUG
  indac--;
#endif
  return result;
}


//! Evaluate sends
__inline__ int
oki_nisynch_send (const System sys, const int trace_index, const Termmap role_to_run, const Termmap label_to_index)
{
  Roledef rd;
  int rid;
  int result = 8;
  int old_run;
  Term rolename;

  rd = sys->traceEvent[trace_index];
  rid = sys->traceRun[trace_index];
  /*
   * Two options: it is either involved or not
   */
  // 1. Assume that this run is not yet involved 
#ifdef OKIDEBUG
  indact ();
  printf ("Exploring further assuming (send) run %i is not involved.\n", rid);
  indac++;
#endif
  result = oki_nisynch (sys, trace_index-1, role_to_run, label_to_index);
#ifdef OKIDEBUG
  indact ();
  printf (">%i<\n", result);
  indac--;
#endif
  if (result)
      return 1;

#ifdef OKIDEBUG
  indact ();
  printf ("Exploring when %i is involved.\n", rid);
#endif
  // 2. It is involved. Then either already used for this role, or will be now.
  rolename = sys->runs[rid].role->nameterm;
  old_run = termmapGet (role_to_run, rolename);	// what was already stored for this role as the runid
  if (old_run == -1 || old_run == rid)
    {
      int partner_index;

      // Was not involved yet in a registerd way, or was the correct rid
      partner_index = termmapGet (label_to_index, rd->label);
      // Ordered match needed for this label
      // So it already needs to be filled by a read
      if (partner_index >= 0)
	{
	  // There is already a read for it
	  if (events_match (sys, partner_index, trace_index) == MATCH_ORDER)
	    {
	      // They match in the right order
	      Termmap role_to_run_buf, label_to_index_buf;

#ifdef OKIDEBUG
	      indact ();
	      printf ("Matching messages found for label ");
	      termPrint (rd->label);
	      printf ("\n");
#endif
	      /**
	       *@todo Optimization can be done when old_run == rid, no copy of role_to_run needs to be made.
	       */
	      role_to_run_buf = termmapDuplicate (role_to_run);
	      role_to_run_buf = termmapSet (role_to_run_buf, rolename, rid);
	      label_to_index_buf = termmapDuplicate (label_to_index);
	      label_to_index_buf = termmapSet (label_to_index_buf, rd->label, LABEL_GOOD);
#ifdef OKIDEBUG
	      indact ();
	      printf ("In NI-Synch scan, assuming %i run is involved.\n", rid);
	      indact ();
	      printf ("Exploring further assuming this matching, which worked.\n");
	      indac++;
#endif
	      result = oki_nisynch (sys, trace_index-1, role_to_run_buf, label_to_index_buf);
#ifdef OKIDEBUG
	      indact ();
	      printf (">%i<\n", result);
	      indac--;
#endif
	      termmapDelete (label_to_index_buf);
	      termmapDelete (role_to_run_buf);
	      return result;
	    }
	}
    }
  return 0;
}


//! nisynch generalization
/**
 * role_to_run maps the involved roles to run identifiers.
 * label_to_index maps all labels in prec to the event indices for things already found,
 * or to LABEL_TODO for things not found yet but in prec, and LABEL_GOOD for well linked messages (and that have thus defined a runid for the corresponding role).
 * All values not in prec map to -1.
 *@returns 1 iff the claim is allright, 0 iff it is violated.
 */
int
oki_nisynch (const System sys, const int trace_index, const Termmap role_to_run, const Termmap label_to_index)
{
  int type;

  // Check for completed trace
  if (trace_index < 0)
      return oki_nisynch_full (sys, label_to_index);

#ifdef OKIDEBUG
  indact ();
  printf ("Checking event %i", trace_index);
  printf (" = #%i : ", sys->traceRun[trace_index]);
  roledefPrint (sys->traceEvent[trace_index]);
  printf ("\n");
#endif

  type = sys->traceEvent[trace_index]->type;

  if (type == CLAIM || sys->traceEvent[trace_index]->internal)
      return oki_nisynch_other (sys, trace_index, role_to_run, label_to_index);
  if (type == READ)
      return oki_nisynch_read (sys, trace_index, role_to_run, label_to_index);
  if (type == SEND)
      return oki_nisynch_send (sys, trace_index, role_to_run, label_to_index);
  /*
   * Exception: no claim, no send, no read, what is it?
   */
  error ("Unrecognized event type in claim scanner at %i.", trace_index);
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

