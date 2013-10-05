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

#ifndef BINDINGS
#define BINDINGS

#include "term.h"
#include "termmap.h"
#include "system.h"

//! Binding structure
/*
 * Idea is the ev_from *has to* precede the ev_to
 *
 * @TODO: blocked is no longer used. For evaluations, it may be considered
 * false (no binding is ever blocked).
 */
struct binding
{
  int done;			//!< Iff true, it is bound
  int blocked;			//!< Iff true, ignore it

  int run_from;			//!< origination run
  int ev_from;			//!< step in origination run

  int run_to;			//!< destination run
  int ev_to;			//!< step in destination run

  Term term;			//!< Binding term
  int level;			//!< ???
};

typedef struct binding *Binding;	//!< pointer to binding structure


void bindingInit (const System mysys);
void bindingDone ();

int binding_print (Binding b);
int valid_binding (Binding b);
int same_binding (const Binding b1, const Binding b2);

int goal_add (Term term, const int run, const int ev, const int level);
int goal_add_fixed (Term term, const int run, const int ev, const int fromrun,
		    const int fromev);
void goal_remove_last (int n);
int goal_bind (const Binding b, const int run, const int ev);
void goal_unbind (const Binding b);
int binding_block (Binding b);
int binding_unblock (Binding b);
int labels_ordered (Termmap runs, Termlist labels);

int iterate_bindings (int (*func) (Binding b));
int iterate_preceding_bindings (const int run, const int ev,
				int (*func) (Binding b));

int non_redundant ();
int countBindingsDone ();

#endif
