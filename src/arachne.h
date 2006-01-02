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

//! Goal structure
/**
 * Signals a read event or claim event to which a term has to be bound.
 */
struct goalstruct
{
  int run;			//!< run of goal
  int index;			//!< index of goal in the run
  Roledef rd;			//!< pointer to the role definition
};

typedef struct goalstruct Goal;	//!< pointer to goal structure

#endif
