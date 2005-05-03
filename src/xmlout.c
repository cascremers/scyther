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
 * Global/static stuff.
 */
static int xmlindent;		// indent level for xml elements in output

/*
 * Default external interface: init/done
 */

//! Init this module
void
xmlOutInit (void)
{
  printf ("<scyther>\n");
  xmlindent = 1;
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

//! Print a term for an element
void
xmlOutTerm (const char *tag, const Term term)
{
  if (term != NULL)
    {
      xmlIndentPrint ();
      printf ("<%s>", tag);
      termPrint (term);
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
      termPrint (term);
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
      termPrint (t);
      t->type = typebuffer;
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

  {
    Protocol p;

    p = sys->protocols;
    while (p != NULL)
      {
	xmlOutTerm ("protocol", p->nameterm);
	p = p->next;
      }
  }

  xmlOutInteger ("match", sys->match);

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
      xmlIndentPrint ();
      printf ("<");
      roleTermPrint (roles->term);
      printf (">");
      termPrint (agentOfRunRole (sys, run, roles->term));
      printf ("</");
      roleTermPrint (roles->term);
      printf (">\n");
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
  xmlOutTerm ("protocol", sys->runs[run].protocol->nameterm);
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

//! Show a single event from a run
/**
 * run and index will only be output if they are nonnegative.
 */
void
xmlOutEvent (const System sys, Roledef rd, const int run, const int index)
{
  xmlIndentPrint ();

  printf ("<");
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

  xmlAttrTerm ("label", rd->label);
  if (rd->type != CLAIM)
    {
      /* read or send */
      xmlAttrTerm ("from", rd->from);
      xmlAttrTerm ("to", rd->to);
      xmlAttrTerm ("message", rd->message);
    }
  else
    {
      /* claim */
      xmlAttrTerm ("role", rd->from);
      xmlAttrTerm ("type", rd->to);
      xmlAttrTerm ("argument", rd->message);
    }

  if (run >= 0)
    {
      printf (" run=\"%i\"", run);
    }
  if (index >= 0)
    {
      printf (" index=\"%i\"", index);
    }
  printf (" />\n");
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
	while (rd != NULL)
	  {
	    xmlOutEvent (sys, rd, -1, index);
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


//! Output list of bindings
void
xmlOutBindings (const System sys)
{
  int xmlBindingState (void *dt)
  {
    Binding b;
    void xmlRunIndex (char *desc, const int run, const int index)
    {
      xmlPrint ("<%s run=\"%i\" index=\"%i\" />", desc, run, index);
    }

    b = (Binding) dt;
    xmlIndentPrint ();
    printf ("<binding term=\"");
    termPrint (b->term);
    printf ("\" >\n");
    xmlindent++;
    if (b->done)
      xmlRunIndex ("from", b->run_from, b->ev_from);
    else
      xmlPrint ("<unbound />");
    xmlRunIndex ("to", b->run_to, b->ev_to);
    if (b->blocked)
      printf ("<blocked />");
    xmlindent--;
    xmlPrint ("</binding>");
    return 1;
  }

  xmlPrint ("<bindinglist>");
  xmlindent++;
  if (sys->bindings != NULL)
    {
      list_iterate (sys->bindings, xmlBindingState);
    }
  xmlindent--;
  xmlPrint ("</bindinglist>");
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
  xmlIndentPrint ();
  printf ("<attack");
  /* mention the broken claim in the attributes */
  if (sys->current_claim != NULL)
    {
      xmlAttrTerm ("claim", sys->current_claim->type);
      xmlAttrTerm ("label", sys->current_claim->label);
    }
  /* add trace length attribute */
  printf (" tracelength=\"%i\"", get_semitrace_length ());
  printf (">\n");
  xmlindent++;
  /* any global information about the system */
  xmlOutSysInfo (sys);
  /* semitrace */
  xmlPrint ("<semitrace>");
  xmlindent++;
  xmlOutRuns (sys);
  xmlOutBindings (sys);
  xmlindent--;
  xmlPrint ("</semitrace>");
  xmlindent--;
  xmlPrint ("</attack>");
}
