/**
 * Handle bindings for Arache engine.
 */

#include "list.h"
#include "system.h"
#include "binding.h"
#include "memory.h"

/*
 * Idea is the ev_from *has to* precede the ev_to
 */
struct binding
{
  int run_from;
  int ev_from;

  int run_to;
  int ev_to;

  int manual;
};

typedef struct binding *Binding;

static System sys;

/*
 *
 * Assist stuff
 *
 */

//! Create mem for binding
Binding
binding_create (int run_from, int ev_from, int run_to, int ev_to, int manual)
{
  Binding b;

  b = memAlloc (sizeof (struct binding));
  b->run_from = run_from;
  b->ev_from = ev_from;
  b->run_to = run_to;
  b->ev_to = ev_to;
  b->manual = manual;
  return b;
}

//! Remove mem for binding
void
binding_destroy (Binding b)
{
  memFree (b, sizeof (struct binding));
}

/*
 *
 * Main
 *
 */

//! Init module
void
bindingInit (const System mysys)
{
  sys = mysys;
  sys->bindings = NULL;
}

//! Close up
void
bindingDone ()
{
  int delete (Binding b)
  {
    binding_destroy (b);
    return 1;
  }
  list_iterate (sys->bindings, delete);
  list_destroy (sys->bindings);
}


/**
 *
 * Externally available functions
 *
 */

//! Add a binding
/**
 * Note that bindings are added to the head of the list.
 *@returns True iff is a valid additional binding. False if not. If false, nothing needs to be destroyed.
 */
int
binding_add (int run_from, int ev_from, int run_to, int ev_to)
{
  Binding b;

  b = binding_create (run_from, ev_from, run_to, ev_to, 1);
  sys->bindings = list_insert (sys->bindings, b);
  return 1;
}

//! Remove last additions, including last manual addition
/**
 * Note that this concerns the head of the list.
 */
void
binding_remove_last ()
{
  List list;
  int manual;

  manual = 0;
  list = sys->bindings;

  while (list != NULL && !manual)
    {
      Binding b;

      b = (Binding) list->data;
      manual = b->manual;
      binding_destroy (b);
      list = list_delete (list);
    }
  sys->bindings = list;
}
