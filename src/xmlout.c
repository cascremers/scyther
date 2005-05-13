/*
 * xmlout.c
 *
 * XML output for Scyther
 *
 * Module to output detailed Scyther information in XML format, for easier
 * interaction with external programs. Originally developed for attack output
 * details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "term.h"
#include "termlist.h"
#include "system.h"
#include "binding.h"
#include "arachne.h"		// for get_semitrace_length

#include "xmlout.h"

/*
 * Externally defined
 */
extern Protocol INTRUDER;	// from arachne.c
extern Term TERM_Function;	// from termlist.c

/*
 * Global/static stuff.
 */
static int xmlindent;		// indent level for xml elements in output
static Term only_claim_label;	// if NULL, show all claims in xml event lists. Otherwise, only this one.

/*
 * Default external interface: init/done
 */

//! Init this module
void
xmlOutInit (void)
{
  printf ("<scyther>\n");
  xmlindent = 1;
  only_claim_label = NULL;
}

//! Close up
void
xmlOutDone (void)
{
  printf ("</scyther>\n");
}

/*
 * Local code, needed for any further real code.
 */

//! Indent code
void
xmlIndentPrint ()
{
  int i;

  i = xmlindent;
  while (i > 0)
    {
      printf ("  ");
      i--;
    }
}

//! XML print
/**
 * Input is comparable to printf, but indents (according to xmlindent) and adds
 * a newline.
 */
void
xmlPrint (char *fmt, ...)
{
  va_list args;

  xmlIndentPrint ();
  va_start (args, fmt);
  vfprintf (stdout, fmt, args);
  va_end (args);
  printf ("\n");
}

//! Print a simple integer value element
void
xmlOutInteger (const char *tag, const int value)
{
  xmlPrint ("<%s>%i</%s>", tag, value, tag);
}

//! Print a term in XML form (iteration inner)
void
xmlTermPrintInner (const Term term)
{
  if (term != NULL)
    {
      if (realTermLeaf (term))
	{
	  // Variable?
	  if (realTermVariable (term))
	    {
	      Term substbuffer;

	      printf ("<var name=\"");
	      if (term->subst == NULL)
		{
		  // Free variable
		  termPrint (term);	// Must be a normal termPrint
		  printf ("\" free=\"true\" />");
		}
	      else
		{
		  // Bound variable
		  substbuffer = term->subst;	// Temporarily unsubst for printing
		  term->subst = NULL;
		  termPrint (term);	// Must be a normal termPrint
		  term->subst = substbuffer;
		  printf ("\">");
		  xmlTermPrintInner (term->subst);
		  printf ("</var>");
		}
	    }
	  else
	    {
	      // Constant
	      termPrint (term);	// Must be a normal termPrint
	    }
	}
      else
	{
	  // Node
	  if (realTermEncrypt (term))
	    {
	      if (isTermLeaf (TermKey (term))
		  && inTermlist (TermKey (term)->stype, TERM_Function))
		{
		  /* function application */
		  printf ("<apply><function>");
		  xmlTermPrintInner (TermKey (term));
		  printf ("</function><arg>");
		  xmlTermPrintInner (TermOp (term));
		  printf ("</arg></apply>");
		}
	      else
		{
		  printf ("<encrypt><op>");
		  xmlTermPrintInner (TermOp (term));
		  printf ("</op><key>");
		  xmlTermPrintInner (TermKey (term));
		  printf ("</key></encrypt>");
		}
	    }
	  else
	    {
	      // Assume tuple
	      printf ("<tuple><op1>");
	      xmlTermPrintInner (TermOp1 (term));
	      printf ("</op1><op2>");
	      xmlTermPrintInner (TermOp2 (term));
	      printf ("</op2></tuple>");
	    }
	}
    }
}

//! Print a term in XML form (wrapper)
void
xmlTermPrint (const Term term)
{
  printf ("<term>");
  xmlTermPrintInner (term);
  printf ("</term>");
}

//! Print a termlist in XML form
void
xmlTermlistPrint (Termlist tl)
{
  xmlPrint ("<termlist>");
  xmlindent++;
  while (tl != NULL)
    {
      xmlIndentPrint ();
      xmlTermPrint (tl->term);
      printf ("\n");
      tl = tl->next;
    }
  xmlindent--;
  xmlPrint ("</termlist>");
}

//! Print a term for an element
void
xmlOutTerm (const char *tag, const Term term)
{
  if (term != NULL)
    {
      xmlIndentPrint ();
      printf ("<%s>", tag);
      xmlTermPrint (term);
      printf ("</%s>\n", tag);
    }
}

//! Attribute term
void
xmlAttrTerm (const char *tag, const Term term)
{
  if (term != NULL)
    {
      printf (" %s=\"", tag);
      xmlTermPrint (term);
      printf ("\"");
    }
}

//! Print a term, known to be a role name
/**
 * Arachne turns all role names into variables for convenience. Here we
 * temporarily undo it for pretty-printing.
 */
void
roleTermPrint (const Term t)
{
  if (t != NULL)
    {
      int typebuffer;

      typebuffer = t->type;
      t->type = GLOBAL;
      xmlTermPrint (t);
      t->type = typebuffer;
    }
}

//! Show initial knowledge
void
xmlInitialKnowledge (const System sys)
{
  Termlist knowlist;

  xmlPrint ("<initialknowledge>");
  xmlindent++;
  knowlist = knowledgeSet (sys->know);
  xmlTermlistPrint (knowlist);
  termlistDelete (knowlist);
  xmlindent--;
  xmlPrint ("</initialknowledge>");
}

//! Determine whether a protocol is involved in the current semitrace.
int
isProtocolInvolved (const System sys, const Protocol p)
{
  int run;

  run = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].protocol == p)
	{
	  return 1;
	}
      run++;
    }
  return 0;
}

//! Determine whether to show an event
int
isEventInteresting (const Roledef rd)
{
  if (rd->type != CLAIM)
    {
      return 1;
    }
  else
    {
      // A claim
      if (only_claim_label == NULL)
	{
	  return 1;
	}
      else
	{
	  if (isTermEqual (only_claim_label, rd->label))
	    {
	      return 1;
	    }
	}
    }
  return 0;
}

//! Show a single event from a run
/**
 * run and index will only be output if they are nonnegative.
 * Also prints any bindings, if this events follows some other events
 * (typically when this is a read).
 *
 * If run < 0, it is assumed to be a role event, and thus no bindings will be shown.
 */
void
xmlOutEvent (const System sys, Roledef rd, const int run, const int index)
{
  if (!isEventInteresting (rd))
    {
      return;
    }

  xmlIndentPrint ();

  printf ("<event type=\"");
  switch (rd->type)
    {
      /* Read or send types are fairly similar.
       * Currently, choose events are not distinguished yet. TODO
       */
    case READ:
      printf ("read");
      break;
    case SEND:
      printf ("send");
      break;
    case CLAIM:
      printf ("claim");
      break;
    default:
      printf ("unknown code=\"%i\"", rd->type);
      break;
    }

  printf ("\"");
  printf (" index=\"%i\"", index);
  printf (">\n");
  xmlindent++;
  xmlOutTerm ("label", rd->label);
  if (rd->type != CLAIM)
    {
      /* read or send */
      xmlOutTerm ("from", rd->from);
      xmlOutTerm ("to", rd->to);
      xmlOutTerm ("message", rd->message);
    }
  else
    {
      /* claim */
      xmlOutTerm ("role", rd->from);
      xmlOutTerm ("type", rd->to);
      xmlOutTerm ("argument", rd->message);
    }


  // Display any incoming bindings
  {
    int incomingArrows;

    int xmlBindingState (void *dt)
    {
      Binding b;

      void xmlRunIndex (char *desc, const int run, const int index)
      {
	xmlPrint ("<%s run=\"%i\" index=\"%i\" />", desc, run, index);
      }

      b = (Binding) dt;
      if (b->run_to == run && b->ev_to == index)
	{
	  if (isTermVariable (b->term) && !b->done)
	    {
	      // Generate from m0
	      xmlPrint ("<choose>");

	      xmlindent++;
	      xmlIndentPrint ();
	      xmlTermPrint (b->term);
	      printf ("\n");
	      xmlindent--;

	      xmlPrint ("</choose>");
	    }
	  else
	    {
	      // Normal binding
	      xmlPrint ("<follows>");

	      xmlindent++;
	      if (b->done)
		xmlRunIndex ("after", b->run_from, b->ev_from);
	      else
		xmlPrint ("<unbound />");
	      if (b->blocked)
		printf ("<blocked />");
	      xmlIndentPrint ();
	      xmlTermPrint (b->term);
	      printf ("\n");
	      xmlindent--;

	      xmlPrint ("</follows>");
	    }
	}
      return 1;
    }

    xmlindent++;
    // Only if real run, and not a roledef
    if (run >= 0 && sys->bindings != NULL)
      {
	list_iterate (sys->bindings, xmlBindingState);
      }
    xmlindent--;
  }

  xmlindent--;
  xmlPrint ("</event>");
}

//! Print a list of role events, from a roledef pointer
void
xmlRoleEventlist (const System sys, Roledef rd, int index)
{
  while (rd != NULL)
    {
      xmlOutEvent (sys, rd, -1, index);
      index++;
      rd = rd->next;
    }
}

//! Show all protocol roles that are in the attack.
void
xmlInvolvedProtocolRoles (const System sys)
{
  Protocol p;

  p = sys->protocols;
  while (p != NULL)
    {
      if (isProtocolInvolved (sys, p))
	{
	  Role r;

	  xmlPrint ("<protocol>");
	  xmlindent++;
	  xmlOutTerm ("name", p->nameterm);
	  r = p->roles;
	  while (r != NULL)
	    {
	      xmlPrint ("<role>");
	      xmlindent++;
	      xmlOutTerm ("name", r->nameterm);
	      xmlRoleEventlist (sys, r->roledef, 0);
	      xmlindent--;
	      xmlPrint ("</role>");
	      r = r->next;
	    }
	  xmlindent--;
	  xmlPrint ("</protocol>");
	}
      p = p->next;
    }
}

//! Global system info
/**
 * To be used by concrete trace as well as semitrace output
 */
void
xmlOutSysInfo (const System sys)
{
  xmlPrint ("<system>");
  xmlindent++;

  xmlOutInteger ("match", sys->match);

  xmlInitialKnowledge (sys);
  xmlInvolvedProtocolRoles (sys);
  xmlindent--;
  xmlPrint ("</system>");
}

//! Nicely format the role and agents we think we're talking to.
void
xmlAgentsOfRunPrint (const System sys, const int run)
{
  Termlist roles;

  xmlPrint ("<roleagents>");
  xmlindent++;

  roles = sys->runs[run].protocol->rolenames;
  while (roles != NULL)
    {
      xmlPrint ("<role>");
      xmlOutTerm ("name", roles->term);
      xmlOutTerm ("agent", deVar (agentOfRunRole (sys, run, roles->term)));
      xmlPrint ("</role>");
      roles = roles->next;
    }

  xmlindent--;
  xmlPrint ("</roleagents>");
}

//! Static information about a run
void
xmlRunInfo (const System sys, const int run)
{
  Role r;
  Term oldagent;

  xmlOutInteger ("runid", run);
  xmlIndentPrint ();
  printf ("<protocol");
  if (sys->runs[run].protocol == INTRUDER)
    {
      printf (" intruder=\"true\"");
    }
  printf (">");
  xmlTermPrint (sys->runs[run].protocol->nameterm);
  printf ("</protocol>\n");
  r = sys->runs[run].role;

  /* undo substitution temporarily to retrieve role name */
  /* Note that this is fairly tailored towards the Arachne method, TODO: make
   * more generic. */
  oldagent = r->nameterm->subst;
  r->nameterm->subst = NULL;
  xmlIndentPrint ();
  printf ("<role>");
  roleTermPrint (r->nameterm);
  printf ("</role>\n");
  /* reinstate substitution */
  r->nameterm->subst = oldagent;
  if (oldagent != NULL)
    {
      xmlOutTerm ("agent", r->nameterm);
    }
  xmlAgentsOfRunPrint (sys, run);
}

//! Display runs
void
xmlOutRuns (const System sys)
{
  int run;

  for (run = 0; run < sys->maxruns; run++)
    {
      xmlPrint ("<run>");
      xmlindent++;

      xmlRunInfo (sys, run);

      xmlPrint ("<eventlist>");
      xmlindent++;
      {
	Roledef rd;
	int index;

	index = 0;
	rd = sys->runs[run].start;
	while (rd != NULL && index < sys->runs[run].step)
	  {
	    xmlOutEvent (sys, rd, run, index);
	    index++;
	    rd = rd->next;
	  }
      }
      xmlindent--;
      xmlPrint ("</eventlist>");
      xmlindent--;
      xmlPrint ("</run>");
    }
}


/*
 * -----------------------------------------------------------------------------------
 * Publicly available functions
 */

//! Output for a concrete trace (from modelchecker)
void
xmlOutTrace (const System sys)
{
}

//! Output for a semitrace (from arachne method)
/**
 * Note: Uses get_trace_length(), which is defined for the arachne method
 * only.
 */
void
xmlOutSemitrace (const System sys)
{
  Term buffer_only_claim_label;

  xmlIndentPrint ();
  printf ("<attack");
  /* add trace length attribute */
  printf (" tracelength=\"%i\"", get_semitrace_length ());
  printf (">\n");
  xmlindent++;

  /* mention the broken claim */
  buffer_only_claim_label = only_claim_label;
  if (sys->current_claim != NULL)
    {
      xmlPrint ("<broken>");
      xmlindent++;
      xmlOutTerm ("claim", sys->current_claim->type);
      xmlOutTerm ("label", sys->current_claim->label);
      xmlindent--;
      xmlPrint ("</broken>");
      only_claim_label = sys->current_claim->label;
    }
  else
    {
      only_claim_label = NULL;
    }
  /* any global information about the system */
  xmlOutSysInfo (sys);
  /* semitrace */
  xmlPrint ("<semitrace>");
  xmlindent++;
  xmlOutRuns (sys);
  xmlindent--;
  xmlPrint ("</semitrace>");
  xmlindent--;
  xmlPrint ("</attack>");

  /* restore only claim buffer */
  only_claim_label = buffer_only_claim_label;
}
