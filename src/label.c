/**
 * Label info
 */

#include "memory.h"
#include "term.h"
#include "label.h"
#include "list.h"
#include "system.h"

//! Create a new labelinfo node
Labelinfo label_create (const Term label, const Protocol protocol)
{
  Labelinfo li;

  li = (Labelinfo) memAlloc (sizeof (struct labelinfo));
  li->label = label;
  li->protocol = protocol;
  li->sendrole = NULL;
  li->readrole = NULL;
  return li;
}

//! Destroy a labelinfo node
void label_destroy (Labelinfo linfo)
{
  memFree (linfo, sizeof (struct labelinfo));
}

//! Given a list of label infos, yield the correct one or NULL
Labelinfo label_find (List labellist, const Term label)
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

