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

/** @file hidelevel.c \brief Hidelevel lemma base functions.
 *
 * The Hidelevel lemma is fairly complex and so it requires some buffering,
 * instead of fully recomputing the required data each time again.
 */

#include <stdlib.h>
#include <limits.h>
#include "hidelevel.h"
#include "system.h"
#include "debug.h"

extern Term TERM_Hidden;

//! hide level within protocol
unsigned int
protocolHidelevel (const System sys, const Term t)
{
  unsigned int minlevel;

  int itsends (const Protocol p, const Role r)
  {
    int sends (Roledef rd)
    {
      if (rd->type == SEND)
	{
	  unsigned int l;

	  l = termHidelevel (t, rd->from);
	  if (l < minlevel)
	    minlevel = l;
	  l = termHidelevel (t, rd->to);
	  if (l < minlevel)
	    minlevel = l;
	  l = termHidelevel (t, rd->message);
	  if (l < minlevel)
	    minlevel = l;
	}
      return true;
    }

    roledef_iterate_events (r->roledef, sends);
    return true;
  }

  minlevel = INT_MAX;
  iterateRoles (sys, itsends);

  return minlevel;
}

//! hide level within initial knowledge
unsigned int
knowledgeHidelevel (const System sys, const Term t)
{
  unsigned int minlevel;
  Termlist tl;

  minlevel = INT_MAX;
  tl = knowledgeSet (sys->know);
  while (tl != NULL)
    {
      unsigned int l;

      l = termHidelevel (t, tl->term);
      if (l < minlevel)
	{
	  minlevel = l;
	}
      tl = tl->next;
    }
  termlistDelete (tl);

  return minlevel;
}

//! Check hide levels
void
hidelevelCompute (const System sys)
{
  Termlist tl;

  sys->hidden = NULL;
  tl = sys->globalconstants;

  // Add 'hidden' terms
  tl = termlistAdd (tl, TERM_Hidden);

#ifdef DEBUG
  if (DEBUGL (4))
    {
      eprintf ("Global constants: ");
      termlistPrint (tl);
      eprintf ("\n");
    }
#endif

  while (tl != NULL)
    {
      unsigned int l1, l2, l;

      l1 = knowledgeHidelevel (sys, tl->term);
      l2 = protocolHidelevel (sys, tl->term);
      if (l1 < l2)
	{
	  l = l1;
	}
      else
	{
	  l = l2;
	}

      // Interesting only if higher than zero
      if (l > 0)
	{
	  Hiddenterm ht;

	  ht = (Hiddenterm) malloc (sizeof (struct hiddenterm));
	  ht->term = tl->term;
	  ht->hideminimum = l;
	  ht->hideprotocol = l2;
	  ht->hideknowledge = l1;
	  ht->next = sys->hidden;
	  sys->hidden = ht;

#ifdef DEBUG
	  if (DEBUGL (5))
	    {
	      eprintf ("Added possibly interesting term: ");
	      termPrint (tl->term);
	      eprintf ("; know %i, prot %i\n", l1, l2);
	    }
#endif
	}

      tl = tl->next;
    }
}

//! Determine flag from parameters
unsigned int
hidelevelParamFlag (unsigned int l, unsigned int lmin, unsigned int lprot,
		    unsigned int lknow)
{
  // Given the parameters, determine where the term with hidelevel l could be generated from.
  if (l < lmin)
    {
      return HLFLAG_NONE;
    }
  else
    {
      // One should work (at least)
      if (l < lprot)
	{
	  // Know should be possible
	  return HLFLAG_KNOW;
	}
      else
	{
	  // Prot can, know also?
	  if (l < lknow)
	    {
	      // Nope, just prot
	      return HLFLAG_PROT;
	    }
	  else
	    {
	      // Both
	      return HLFLAG_BOTH;
	    }
	}
    }
}

//! Given a term, iterate over all factors
int
iterate_interesting (const System sys, const Term goalterm, int (*func) ())
{
  Hiddenterm ht;

  ht = sys->hidden;
  while (ht != NULL)
    {
      unsigned int l;
      // Test the goalterm for occurrences of this

      l = termHidelevel (ht->term, goalterm);
      if (l < INT_MAX)
	{
	  if (!func (l, ht->hideminimum, ht->hideprotocol, ht->hideknowledge))
	    {
	      return false;
	    }
	}

      ht = ht->next;
    }
  return true;
}

//! Determine whether a goal is impossible to satisfy because of the hidelevel lemma.
int
hidelevelImpossible (const System sys, const Term goalterm)
{
  int possible (unsigned int l, unsigned int lmin, unsigned int lprot,
		unsigned int lknow)
  {
    if (l < lmin)
      {
	// impossible, abort!
	return false;
      }
    return true;
  }

  return !iterate_interesting (sys, goalterm, possible);
}

//! Return flag on the basis of the Hidelevel lemma
unsigned int
hidelevelFlag (const System sys, const Term goalterm)
{
  unsigned int flag;

  int getflag (unsigned int l, unsigned int lmin, unsigned int lprot,
	       unsigned int lknow)
  {
    // Determine new flag
    flag = flag | hidelevelParamFlag (l, lmin, lprot, lknow);

    // Should we proceed?
    if (flag == HLFLAG_NONE)
      {
	// abort iteration: it cannot get worse
	return false;
      }
    return true;
  }

  flag = HLFLAG_BOTH;
  iterate_interesting (sys, goalterm, getflag);
  return flag;
}
