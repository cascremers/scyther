/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2009 Cas Cremers
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

#include <stdlib.h>
#include <stdio.h>
#include "termmap.h"
#include "debug.h"

//! Open termmaps code.
void
termmapsInit (void)
{
  return;
}

//! Close termmaps code.
void
termmapsDone (void)
{
  return;
}

//! Allocate memory for a termmap node.
/**
 *@return A pointer to uninitialised memory of the size of a termmap node.
 */
Termmap
makeTermmap (void)
{
  /* inline candidate */
  return (Termmap) malloc (sizeof (struct termmap));
}

//! Get function result
/**
 *@return Yields f(x), or -1 when it is not present.
 */
int
termmapGet (Termmap f, const Term x)
{
  while (f != NULL)
    {
      if (isTermEqual (x, f->term))
	return f->result;
      f = f->next;
    }
  return -1;
}

//! Add a value to a function.
/**
 *@return Adds f(x)=y to an existing function f. If f is NULL, a function is created. If x is already in the domain, the value is replaced.
 */
Termmap
termmapSet (const Termmap f, const Term x, const int y)
{
  Termmap fscan;

  //! Determine whether term already occurs
  fscan = f;
  while (fscan != NULL)
    {
      if (isTermEqual (x, fscan->term))
	{
	  //! Is the result correct already?
	  if (fscan->result != y)
	    fscan->result = y;
	  return f;
	}
      fscan = fscan->next;
    }
  //! Not occurred yet, make new node
  fscan = makeTermmap ();
  fscan->term = x;
  fscan->result = y;
  fscan->next = f;
  return fscan;
}

//! Duplicate a function
Termmap
termmapDuplicate (const Termmap f)
{
  if (f != NULL)
    {
      Termmap g;

      g = makeTermmap ();
      g->term = f->term;
      g->result = f->result;
      g->next = termmapDuplicate (f->next);
      return g;
    }
  else
    {
      return NULL;
    }
}

//! Delete a domain element
Termmap
termmapRemove (Termmap f, const Term t)
{
  Termmap fscan;
  Termmap fprev;

  if (f == NULL)
    {
      return NULL;
    }
  // There are elements, check which one
  fprev = NULL;
  for (fscan = f; fscan != NULL; fscan = fscan->next)
    {
      if (isTermEqual (fscan->term, t))
	{
	  // Remove fscan
	  if (fprev != NULL)
	    {
	      // Not the first element, string up nicely
	      fprev->next = fscan->next;
	    }
	  else
	    {
	      // The first element
	      f = fscan->next;
	    }
	  free (fscan);
	  return f;
	}
      fprev = fscan;
    }
  return f;
}

//! Delete a function
void
termmapDelete (const Termmap f)
{
  if (f != NULL)
    {
      termmapDelete (f->next);
      free (f);
    }
}

//! Print a function
void
termmapPrint (Termmap f)
{
  if (f != NULL)
    {
      eprintf ("\"");
      termPrint (f->term);
      eprintf ("\" -> %i", f->result);
      if (f->next != NULL)
	{
	  eprintf (", ");
	  termmapPrint (f->next);
	}
    }
}

//! Check for inclusion in range
int
inTermmapRange (Termmap f, const int x)
{
  while (f != NULL)
    {
      if (x == f->result)
	{
	  return true;
	}
      f = f->next;
    }
  return false;
}

//! Create an iterator
Termmap
termmapIterInit (Termlist tinit, const int min)
{
  Termlist tl;
  Termmap f;

  f = NULL;
  for (tl = tinit; tl != NULL; tl = tl->next)
    {
      f = termmapSet (f, tl->term, min);
    }
  return f;
}

//! Advance iterator
/**
 * Advance each to max, then flip over to min
 * When done, delete termmap and return NULL
 */
Termmap
termmapIterNext (Termmap f, const int min, const int max)
{
  Termmap fi;

  for (fi = f; fi != NULL; fi = fi->next)
    {
      int y;

      y = fi->result + 1;
      if (y <= max)
	{
	  fi->result = y;
	  return f;
	}
      else
	{
	  fi->result = min;
	}
    }
  termmapDelete (f);
  return NULL;
}
