#ifndef HIDELEVELS
#define HIDELEVELS

#include "term.h"
#include "system.h"

/*
 * Flags for hidelevel lemma
 *
 * Use binary or (|) to compose results: by default, a term can be satisfied by
 * both the protocol and the initial knowledge.
 */
#define HLFLAG_BOTH 0
#define HLFLAG_KNOW 1
#define HLFLAG_PROT 2
#define HLFLAG_NONE 3

/*
 * The structure hiddenterm/Hiddenterm is defined in system.h
 */

void hidelevelCompute (const System sys);
int hidelevelInteresting (const System sys, const Term goalterm);
int hidelevelImpossible (const System sys, const Term goalterm);
unsigned int hidelevelFlag (const System sys, const Term goalterm);

#endif
