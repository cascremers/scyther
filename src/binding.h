#ifndef BINDINGS
#define BINDINGS

#include "term.h"
#include "termmap.h"
#include "system.h"

/*
 * Idea is the ev_from *has to* precede the ev_to
 */
struct binding
{
  int done;			//!< Iff true, it is bound
  int child;			//!< Signifies some tuple unfolding, to remove created bindings.

  int run_from;
  int ev_from;

  int run_to;
  int ev_to;

  int *graph;
  int nodes;

  Term term;
  int level;
};

typedef struct binding *Binding;


void bindingInit (const System mysys);
void bindingDone ();

int node_count ();
int node_number (int run, int ev);


int binding_print (Binding b);

void goal_add (Term term, const int run, const int ev, const int level);
void goal_remove_last ();
int goal_bind (const Binding b, const int run, const int ev);
void goal_unbind (const Binding b);
int labels_ordered (Termmap runs, Termlist labels);

int bindings_c_minimal ();

#endif
