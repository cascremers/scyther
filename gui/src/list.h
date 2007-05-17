#ifndef GENERICLIST
#define GENERICLIST

//! generic list structure node
struct list_struct
{
  struct list_struct *next;	//!< pointer to next node
  struct list_struct *prev;	//!< pointer to previous node
  void *data;			//!< pointer to the actual data element (should be typecast)
};

typedef struct list_struct *List;	//!< pointer to generic list node

List list_create (const void *data);
List list_rewind (List list);
List list_forward (List list);
List list_insert (List list, const void *data);
List list_add (List list, const void *data);
List list_append (List list, const void *data);
List list_delete (List list);
int in_list (List list, const void *data);
int list_iterate (List list, int (*func) ());
List list_duplicate (List list);
void list_destroy (List list);
List list_shift (List list, int n);
int list_length (List list);

#endif
