#ifndef HIDELEVELS
#define HIDELEVELS

#include "term.h"
#include "system.h"

/*
 * The structure hiddenterm/Hiddenterm is defined in system.h
 */

void hidelevelCompute (const System sys);
int hidelevelInteresting (const System sys, const Term goalterm);
int hidelevelImpossible (const System sys, const Term goalterm);

#endif

