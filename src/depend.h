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

#ifndef DEPEND
#define DEPEND

#include "system.h"

/*
 * The code here mainly involves an interface for creating graphs etc., but
 * most of it is implicit: we just add dependencies/runs and undo them again
 * later.
 */

void dependInit (const System sys);
void dependPrint ();
void dependDone (const System sys);

/*
 * The push code returns true or false: if false, the operation fails because
 * it there is now a cycle in the graph, and there is no need to pop the
 * result.
 */
void dependPushRun (const System sys);
void dependPopRun ();
int dependPushEvent (const int r1, const int e1, const int r2, const int e2);
void dependPopEvent ();

/*
 * Test/set
 */

int getNode (const int n1, const int n2);
void setNode (const int n1, const int n2);
int isDependEvent (const int r1, const int e1, const int r2, const int e2);	// r1,e1 before r2,e2
void setDependEvent (const int r1, const int e1, const int r2, const int e2);

/*
 * Outside helpers
 */
int hasCycle ();
int eventNode (const int r, const int e);
int nodeCount (void);
int iteratePrecedingEvents (const System sys, int (*func) (int run, int ev),
			    const int run, const int ev);

#endif
