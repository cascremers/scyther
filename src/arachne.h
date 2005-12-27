#ifndef ARACHNE
#define ARACHNE

#include "system.h"

void arachneInit (const System sys);
void arachneDone ();
int arachne ();
int get_semitrace_length ();
void indentPrint ();
int isTriviallyKnownAtArachne (const System sys, const Term t, const int run,
			       const int index);
int isTriviallyKnownAfterArachne (const System sys, const Term t,
				  const int run, const int index);
int ranks_to_lines (int *ranks, const int nodes);
void iterate_incoming_arrows (void (*func) (), const int run, const int ev);
void iterate_outgoing_arrows (void (*func) (), const int run, const int ev);

#endif
