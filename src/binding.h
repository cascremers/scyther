#ifndef BINDINGS
#define BINDINGS

void bindingInit (const System mysys);
void bindingDone ();

int binding_add (int run_from, int ev_from, int run_to, int ev_to);
void binding_remove_last ();

#endif
