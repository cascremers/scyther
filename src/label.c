/**
 * Label info
 */

#include "memory.h"
#include "term.h"
#include "label.h"

Labelinfo label_create (const Term label, const Term protocol)
{
  Labelinfo li;

  li = (Labelinfo) memAlloc (sizeof (struct labelinfo));
  li->label = label;
  li->protocol = protocol;
  li->sendrole = NULL;
  li->readrole = NULL;
  return li;
}

void label_destroy (Labelinfo linfo)
{
  memFree (linfo, sizeof (struct labelinfo));
}

