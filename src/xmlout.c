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
#include "switches.h"
#include "specialterm.h"

#include "xmlout.h"

/*
 * Externally defined
 */
extern Protocol INTRUDER;	// from arachne.c
extern Term TERM_Data;		// from specialterm.c

/*
 * Global/static stuff.
 */
static int xmlindent;		// indent level for xml elements in output
static Term only_claim_label;	// if NULL, show all claims in xml event lists. Otherwise, only this one.
static int show_substitution_path;	// is only set to true for variable printing, normally false.

/*
 * Default external interface: init/done
 */

//! Init this module
void
xmlOutInit (void)
{
  eprintf ("<scyther>\n");
  xmlindent = 1;
  only_claim_label = NULL;
  show_substitution_path = false;
}

//! Close up
void
xmlOutDone (void)
{
  eprintf ("</scyther>\n");
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
      eprintf ("  ");
      i--;
    }
}

//! XML print
/**
 * Input is comparable to eprintf, but indents (according to xmlindent) and adds
 * a newline.
 */
void
xmlPrint (char *fmt, ...)
{
  va_list args;

  xmlIndentPrint ();
  va_start (args, fmt);
  eprintf (fmt, args);
  va_end (args);
  eprintf ("\n");
}

//! Print a simple integer value element
void
xmlOutInteger (const char *tag, const int value)
{
  xmlPrint ("<%s>%i</%s>", tag, value, tag);
}

//! Print a string
void
xmlOutString (const char *tag, const char *s)
{
  xmlPrint ("<%s>%s</%s>", tag, s, tag);
}

//! Print a term in XML form (iteration inner)
void
xmlTermPrintInner (Term term)
{
  if (term != NULL)
    {
      if (!show_substitution_path)
	{
	  /* In a normal situation, variables are immediately substituted, and
	   * only the result is output.
	   */
	  term = deVar (term);
	}

      if (realTermLeaf (term))
	{
	  // Variable?
	  if (realTermVariable (term))
	    {
	      Term substbuffer;

	      eprintf ("<var name=\"");
	      if (term->subst == NULL)
		{
		  // Free variable
		  termPrint (term);	// Must be a normal termPrint
		  eprintf ("\" free=\"true\" />");
		}
	      else
		{
		  // Bound variable
		  substbuffer = term->subst;	// Temporarily unsubst for printing
		  term->subst = NULL;
		  termPrint (term);	// Must be a normal termPrint
		  term->subst = substbuffer;
		  eprintf ("\">");
		  xmlTermPrintInner (term->subst);
		  eprintf ("</var>");
		}
	    }
	  else
	    {
	      // Constant
	      eprintf ("<const>");
	      termPrint (term);	// Must be a normal termPrint
	      eprintf ("</const>");
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
		  eprintf ("<apply><function>");
		  xmlTermPrintInner (TermKey (term));
		  eprintf ("</function><arg>");
		  xmlTermPrintInner (TermOp (term));
		  eprintf ("</arg></apply>");
		}
	      else
		{
		  eprintf ("<encrypt><op>");
		  xmlTermPrintInner (TermOp (term));
		  eprintf ("</op><key>");
		  xmlTermPrintInner (TermKey (term));
		  eprintf ("</key></encrypt>");
		}
	    }
	  else
	    {
	      // Assume tuple
	      eprintf ("<tuple><op1>");
	      xmlTermPrintInner (TermOp1 (term));
	      eprintf ("</op1><op2>");
	      xmlTermPrintInner (TermOp2 (term));
	      eprintf ("</op2></tuple>");
	    }
	}
    }
}

//! Print a term in XML form (wrapper)
/**
 * In the original setupt, a <term> wrapper was added. It is disabled for now.
 * If this turns out to be the preferred situation, xmlTermPrintInner can be
 * renamed to xmlTermPrint and all will be well.
 */
void
xmlTermPrint (const Term term)
{
  // eprintf ("<term>");
  xmlTermPrintInner (term);
  // eprintf ("</term>");
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
      eprintf ("\n");
      tl = tl->next;
    }
  xmlindent--;
  xmlPrint ("</termlist>");
}

//! Print a term for an element
/**
 * If the first parameter (the tag) is NULL then only the term is printed without a wrapper tag.
 */
void
xmlOutTerm (const char *tag, const Term term)
{
  if (term != NULL)
    {
      xmlIndentPrint ();
      if (tag != NULL)
	eprintf ("<%s>", tag);
      xmlTermPrint (term);
      if (tag != NULL)
	eprintf ("</%s>", tag);
      eprintf ("\n");
    }
}

//! Attribute term
void
xmlAttrTerm (const char *tag, const Term term)
{
  if (term != NULL)
    {
      eprintf (" %s=\"", tag);
      xmlTermPrint (term);
      eprintf ("\"");
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
      termPrint (t);
      t->type = typebuffer;
    }
}

//! Print a role term with <rolename> tag and indenting etc.
void
xmlRoleTermPrint (const Term t)
{
  xmlIndentPrint ();
  eprintf ("<rolename>");
  roleTermPrint (t);
  eprintf ("</rolename>\n");
}

//! Show a single variable instantiation, depth one
void
xmlVariableDepthOne (const Term variable)
{
  /*
   * To print a variable, we would wish to see only the first substitution.
   * Therefore, we temporarily undo any further substitutions, and reset
   * them at the end.
   */
  Term varsubst;		// substitution shortcut
  Term nextsubst;		// temporary buffer

  varsubst = variable->subst;
  if (varsubst != NULL && realTermVariable (varsubst))
    {
      nextsubst = varsubst->subst;
      varsubst->subst = NULL;
    }
  else
    {
      nextsubst = NULL;
    }

  // Print the actual term
  xmlIndentPrint ();
  xmlTermPrint (variable);
  eprintf ("\n");

  if (nextsubst != NULL)
    {
      varsubst->subst = nextsubst;
    }

}

//! Show a term and its type, on single lines
void
xmlTermType (const Term t)
{
  Term substbuf;

  if (realTermVariable (t))
    {
      substbuf = t->subst;
      t->subst = NULL;
    }

  xmlindent++;
  xmlPrint ("<term>");
  xmlindent++;
  xmlIndentPrint ();
  xmlTermPrint (t);
  eprintf ("\n");
  xmlindent--;
  xmlPrint ("</term>");

  xmlPrint ("<type>");
  xmlindent++;
  xmlTermlistPrint (t->stype);
  xmlindent--;
  xmlPrint ("</type>");
  xmlindent--;

  if (realTermVariable (t))
    {
      t->subst = substbuf;
    }
}

//! Show a single variable instantiation
void
xmlVariable (const System sys, const Term variable, const int run)
{
  if (realTermVariable (variable))
    {
      xmlIndentPrint ();
      eprintf ("<variable typeflaw=\"");
      if (!checkTypeTerm (0, variable))
	{
	  eprintf ("true");
	}
      else
	{
	  eprintf ("false");
	}
      eprintf ("\" run=\"%i\">\n", run);
      xmlindent++;

      xmlPrint ("<name>");
      xmlTermType (variable);
      xmlPrint ("</name>");
      if (variable->subst != NULL)
	{
	  xmlPrint ("<substitution>");
	  xmlTermType (deVar (variable));
	  xmlPrint ("</substitution>");
	}
      xmlindent--;
      xmlPrint ("</variable>");
    }
}

//! Show variable instantiations
/**
 * Show the instantiations of all variables. Maybe we need to restrict this,
 * and scan only for those variables that actually occur in the semitrace.
 */
void
xmlVariables (const System sys)
{
  int prev_mode;		// buffer for show mode
  int run;			// for loop

  prev_mode = show_substitution_path;
  show_substitution_path = true;
  xmlPrint ("<variables>");
  xmlindent++;
  run = 0;
  while (run < sys->maxruns)
    {
      if (sys->runs[run].protocol != INTRUDER)
	{
	  Termlist varlist;

	  varlist = sys->runs[run].locals;
	  while (varlist != NULL)
	    {
	      if (realTermVariable (varlist->term))
		{
		  xmlVariable (sys, varlist->term, run);
		}
	      varlist = varlist->next;
	    }
	}
      run++;
    }
  xmlindent--;
  xmlPrint ("</variables>");
  show_substitution_path = prev_mode;
}

//! Show inverses
void
xmlInverses (const System sys)
{
  Termlist invlist;

  xmlPrint ("<inversekeys>");
  xmlindent++;
  invlist = sys->know->inverses;
  while (invlist != NULL && invlist->next != NULL)
    {
      xmlPrint ("<keypair>");
      xmlindent++;
      xmlOutTerm (NULL, invlist->term);
      xmlOutTerm (NULL, invlist->next->term);
      xmlindent--;
      xmlPrint ("</keypair>");

      invlist = invlist->next->next;
    }
  xmlindent--;
  xmlPrint ("</inversekeys>");
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
  xmlInverses (sys);
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
isEventInteresting (const System sys, const Roledef rd)
{
  if (switches.human)
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
  else
    {
      return 1;
    }
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
  if (!isEventInteresting (sys, rd))
    {
      return;
    }

  xmlIndentPrint ();

  eprintf ("<event type=\"");
  switch (rd->type)
    {
      /* Read or send types are fairly similar.
       * Currently, choose events are not distinguished yet. TODO
       */
    case READ:
      eprintf ("read");
      break;
    case SEND:
      eprintf ("send");
      break;
    case CLAIM:
      eprintf ("claim");
      break;
    default:
      eprintf ("unknown code=\"%i\"", rd->type);
      break;
    }

  eprintf ("\"");
  eprintf (" index=\"%i\"", index);
  eprintf (">\n");
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
	      eprintf ("\n");
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
		eprintf ("<blocked />");
	      xmlIndentPrint ();
	      xmlTermPrint (b->term);
	      eprintf ("\n");
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
  xmlPrint ("<eventlist>");
  xmlindent++;
  while (rd != NULL)
    {
      xmlOutEvent (sys, rd, -1, index);
      index++;
      rd = rd->next;
    }
  xmlindent--;
  xmlPrint ("</eventlist>");
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
	      xmlRoleTermPrint (r->nameterm);
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

//! Untrusted agents
void
xmlUntrustedAgents (const System sys)
{
  xmlPrint ("<untrusted>");
  xmlindent++;
  xmlTermlistPrint (sys->untrusted);
  xmlindent--;
  xmlPrint ("</untrusted>");
}

//! Commandline
void
xmlOutCommandline (void)
{
  int i;

  xmlPrint ("<commandline>");
  xmlindent++;
  i = 0;
  while (i < switches.argc)
    {
      xmlPrint ("<arg>%s</arg>", switches.argv[i]);
      i++;
    }
  xmlindent--;
  xmlPrint ("</commandline>");
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

  xmlOutCommandline ();
  xmlOutInteger ("match", switches.match);

  xmlInitialKnowledge (sys);
  xmlInvolvedProtocolRoles (sys);
  xmlUntrustedAgents (sys);
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
      xmlindent++;
      xmlRoleTermPrint (roles->term);
      xmlOutTerm ("agent", deVar (agentOfRunRole (sys, run, roles->term)));
      xmlindent--;
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
  eprintf ("<protocol");
  if (sys->runs[run].protocol == INTRUDER)
    {
      eprintf (" intruder=\"true\"");
    }
  else
    {
      // Non-intruder run, check whether communicates with untrusted agents
      if (!isRunTrusted (sys, run))
	{
	  eprintf (" untrustedrun=\"true\"");
	}
    }
  eprintf (">");
  xmlTermPrint (sys->runs[run].protocol->nameterm);
  eprintf ("</protocol>\n");
  r = sys->runs[run].role;

  /* undo substitution temporarily to retrieve role name */
  /* Note that this is fairly tailored towards the Arachne method, TODO: make
   * more generic. */
  oldagent = r->nameterm->subst;
  r->nameterm->subst = NULL;
  xmlRoleTermPrint (r->nameterm);
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

	//! Test whether to display this event
	/**
	 * Could be integrated into a single line on the while loop,
	 * but that makes it rather hard to understand.
	 */
	int showthis (void)
	{
	  if (rd != NULL)
	    {
	      if (index < sys->runs[run].step)
		{
		  return true;
		}
	      else
		{
		  if (switches.extendTrivial || switches.extendNonReads)
		    {
		      if (rd->type != READ)
			{
			  return true;
			}
		      else
			{
			  if (switches.extendTrivial)
			    {
			      /* This is a read, and we don't know whether to
			       * include it. Default behaviour would be to jump
			       * out of the conditions, and return false.
			       * Instead, we check whether it can be trivially
			       * satisfied by the knowledge from the preceding
			       * events.
			       */
			      if (isTriviallyKnownAtArachne (sys,
							     rd->message,
							     run, index))
				{
				  return true;
				}
			      else
				{
				  /* We cannot extend it trivially, based on
				   * the preceding events, but maybe we can
				   * base it on another (*all*) event. That
				   * would in fact introduce another implicit
				   * binding. Currently, we do not explicitly
				   * introduce this binding, but just allow
				   * displaying the event.
				   *
				   * TODO consider what it means to leave out
				   * this binding.
				   */
				  if (isTriviallyKnownAfterArachne
				      (sys, rd->message, run, index))
				    {
				      return true;
				    }
				}
			    }
			}
		    }
		}
	    }
	  return false;
	}

	index = 0;
	rd = sys->runs[run].start;
	while (showthis ())
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
  eprintf ("<attack");
  /* add trace length attribute */
  /* Note that this is the length of the attack leading up to the broken
   * claim, thus without any run extensions (--extend-nonreads).
   */
  eprintf (" tracelength=\"%i\"", get_semitrace_length ());
  /* add attack id attribute (within this scyther call) */
  eprintf (" id=\"%i\"", sys->attackid);
  eprintf (">\n");
  xmlindent++;

  /* mention the broken claim */
  buffer_only_claim_label = only_claim_label;
  only_claim_label = NULL;
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

  /* any global information about the system */
  xmlOutSysInfo (sys);
  /* instantiations of the variables */
  xmlVariables (sys);
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
