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
  li->readrole = NULL;
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
  Labelinfo linfo;

  int label_find_scan (void *data)
  {
    Labelinfo linfo_scan;

    linfo_scan = (Labelinfo) data;
    if (isTermEqual (label, linfo_scan->label))
      {
	linfo = linfo_scan;
	return 0;
      }
    else
      {
	return 1;
      }
  }

  linfo = NULL;
  if (label != NULL)
    {
      list_iterate (labellist, label_find_scan);
    }
  return linfo;
}
