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
void arachneOutputAttack ();
void printSemiState ();
int countIntruderActions ();
void role_name_print (const int run);

#endif
