#ifndef TERMMAPS
#define TERMMAPS

#include "terms.h"

//! The function container for the term to integer function type.
/**
 *\sa term
 */
struct termmap
{
  //! The term element for this node.
  Term term;
  //! Next node pointer or NULL for the last element of the function.
  struct termmap *next;
  //! Function result
  int result;
};

//! Shorthand for termmap pointers.
typedef struct termmap *Termmap;

void termmapsInit (void);
void termmapsDone (void);
int termmapGet (Termmap f, const Term x);
Termmap termmapSet (const Termmap f, const Term x, const int y);
Termmap termmapDuplicate (const Termmap f);
void termmapDelete (const Termmap f);
void termmapPrint (Termmap f);

#endif
