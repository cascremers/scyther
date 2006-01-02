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

struct goalstruct
{
  int run;
  int index;
  Roledef rd;
};

typedef struct goalstruct Goal;

#endif
