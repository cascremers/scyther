/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2013 Cas Cremers
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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
