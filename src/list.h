#ifndef GENERICLIST
#define GENERICLIST

struct list_struct
{
  struct list_struct *next;
  struct list_struct *prev;
  void *data;
};

typedef struct list_struct *List;

List list_create (const void *data);
List list_rewind (List list);
List list_forward (List  list);
List list_insert (List list, const void *data);
List list_add (List list, const void *data);
List list_append (List list, const void *data);
List list_delete (List list);
int in_list (List list, const void *data);
int list_iterate (List list, int (*func) ());
List list_duplicate (List list);
void list_destroy (List list);

#endif
