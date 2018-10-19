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

/**
 * Label info
 */

#include <stdlib.h>
#include "term.h"
#include "label.h"
#include "list.h"
#include "system.h"

//! Retrieve rightmost thing of label
Term
rightMostTerm (Term t)
{
  if (t != NULL)
    {
      t = deVar (t);
      if (realTermTuple (t))
	{
	  return rightMostTerm (TermOp2 (t));
	}
    }
  return t;
}

//! Create a new labelinfo node
Labelinfo
label_create (const Term label, const Protocol protocol)
{
  Labelinfo li;
  Term tl;

  li = (Labelinfo) malloc (sizeof (struct labelinfo));
  li->label = label;
  li->protocol = protocol;
  li->sendrole = NULL;
  li->recvrole = NULL;
  // Should we ignore it?
  li->ignore = false;
  tl = rightMostTerm (label);
  if (tl != NULL)
    {
      if (TermSymb (tl)->text[0] == '!')
	{
	  li->ignore = true;
	}
    }
  return li;
}

//! Destroy a labelinfo node
void
label_destroy (Labelinfo linfo)
{
  free (linfo);
}

//! Given a list of label infos, yield the correct one or NULL
Labelinfo
label_find (List labellist, const Term label)
{
  List ll;

  if (label == NULL)
    {
      return NULL;
    }

  for (ll = labellist; ll != NULL; ll = ll->next)
    {
      Labelinfo linfo;

      linfo = (Labelinfo) ll->data;
      if (isTermEqual (label, linfo->label))
	{
	  return linfo;
	}
    }
  return NULL;
}
