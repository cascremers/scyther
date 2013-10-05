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

#ifndef HIDELEVELS
#define HIDELEVELS

#include "term.h"
#include "system.h"

/*
 * Flags for hidelevel lemma
 *
 * Use binary or (|) to compose results: by default, a term can be satisfied by
 * both the protocol and the initial knowledge.
 */
#define HLFLAG_BOTH 0
#define HLFLAG_KNOW 1
#define HLFLAG_PROT 2
#define HLFLAG_NONE 3

/*
 * The structure hiddenterm/Hiddenterm is defined in system.h
 */

void hidelevelCompute (const System sys);
int hidelevelImpossible (const System sys, const Term goalterm);
unsigned int hidelevelFlag (const System sys, const Term goalterm);

#endif
