#ifndef LABEL
#define LABEL

#include "term.h"

/*
 * Structure to store label information
 */
struct labelinfo
{
    Term label;
    Term protocol;
    Term sendrole;
    Term readrole;
};

typedef struct labelinfo* Labelinfo;

Labelinfo label_create (const Term label, const Term protocol);
void label_destroy (Labelinfo linfo);

#endif
