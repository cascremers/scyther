#ifndef BINDINGS
#define BINDINGS

void bindingInit (const System mysys);
void bindingDone ();

int node_count ();
int node_number (int run, int ev);
int binding_add (int run_from, int ev_from, int run_to, int ev_to);
void binding_remove_last ();
int binding_print (void *bindany);

#endif
