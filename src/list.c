/**
 *@file list.c
 * Generic list type
 *
 * A doubly linked list with void* as data type.
 */

#include "list.h"
#include <malloc.h>

//! Make a node
List
list_create (const void *data)
{
  List newlist;

  newlist = (List) malloc (sizeof (struct list_struct));
  newlist->prev = NULL;
  newlist->next = NULL;
  newlist->data = (void *) data;
  return newlist;
}

//! Rewind list
List
list_rewind (List list)
{
  if (list != NULL)
    {
      while (list->prev != NULL)
	{
	  list = list->prev;
	}
    }
  return list;
}

//! Forward list
List
list_forward (List  list)
{
  if (list == NULL)
    {
      return NULL;
    }
  else
    {
      while (list->next != NULL)
	{
	  list = list->next;
	}
      return list;
    }
}

//! Add element to list, inserting it just before the current node.
/**
 * @returns the head of the list
 */
List
list_insert (List list, const void *data)
{
  List newnode;

  newnode = list_create (data);
  if (list == NULL)
    {
      return newnode;
    }
  newnode->next = list;
  newnode->prev = list->prev;
  list->prev = newnode;
  if (newnode->prev != NULL)
    {
      newnode->prev->next = newnode;
      return list_rewind (newnode->prev);
    }
  else
    {
      return newnode;
    }
}

//! Add element to list, inserting it just after the current node.
/**
 * @returns the head of the list
 */
List
list_add (List list, const void *data)
{
  List newnode;

  newnode = list_create (data);
  if (list == NULL)
    {
      return newnode;
    }
  else
    {
      newnode->next = list->next;
      newnode->prev = list;
      list->next = newnode;
      if (newnode->next != NULL)
	{
	  newnode->next->prev = newnode;
	}
      return list_rewind (list);
    }
}

//! Add element to list, inserting it at the tail of the list.
/**
 * @returns the head of the list
 */
List
list_append (List list, const void *data)
{
  List newnode;
  List lastnode;

  newnode = list_create (data);
  if (list == NULL)
    {
      return newnode;
    }
  else
    {
      lastnode = list_forward (list);
      newnode->prev = lastnode;
      lastnode->next = newnode;
      return list_rewind (list);
    }
}


//! Destroy a node
/**
 * @returns the head of the list
 */
List
list_delete (List list)
{
  if (list != NULL)
    {
      List prenode, postnode;

      prenode = list->prev;
      postnode = list->next;
      free (list);
      if (postnode != NULL)
	{
	  postnode->prev = prenode;
	}
      if (prenode != NULL)
	{
	  prenode->next = postnode;
	  return list_rewind (prenode);
	}
      else
	{
	  return postnode;
	}
    }
  else
    {
      return NULL;
    }
}

//! Test if it's already in the list, using pointer equality.
/**
 *@warn Only scans forward, so make sure the list is rewound.
 *@returns The boolean result.
 */
int
in_list (List list, const void *compdata)
{
  while (list != NULL)
    {
      if (list->data == compdata)
	{
	  return 1;
	}
      list = list->next;
    }
  return 0;
}

//! Iterator
/**
 * Function used returns int; if non-zero (true), iteration continues.
 * Function is called with data as argument, *not* the list node.
 *
 *@returns true iff domain empty or all applications true. If false, some iteration aborted the run.
 */
int
list_iterate (List list, int (*func) ())
{
  while (list != NULL)
    {
      if (!func (list->data))
	{
	  return 0;
	}
      list = list->next;
    }
  return 1;
}

//! Duplicate (always shallow)
List
list_duplicate (List list)
{
  List newlist;

  if (list == NULL)
    {
      return NULL;
    }
  list = list_forward (list);
  newlist = NULL;
  while (list != NULL)
    {
      newlist = list_insert (newlist, list->data);
      list = list->prev;
    }
  return newlist;
}

//! Destroy (shallow)
void
list_destroy (List list)
{
  list = list_rewind (list);
  while (list != NULL)
    {
      List node;

      node = list;
      list = list->next;
      free (node);
    }
}
