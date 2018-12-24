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

#ifndef MGU
#define MGU

#include "term.h"
#include "termlist.h"

//! A special constant do denote failure.
/**
 * \c NULL already denotes equality, so an extra signal is needed to
 * denote that a unification fails.
 * \todo Find a portable solution for this \c MGUFAIL constant:
 * maybe a pointer to some special constant.
 */
#define MGUFAIL (Termlist) -1

void termlistSubstReset (Termlist tl);
int checkRoletermMatch (const Term t1, const Term t2, const Termlist tl);

// The new iteration methods
int unify (Term t1, Term t2, Termlist tl, int (*callback) (), void *state);
int
subtermUnify (Term tbig, Term tsmall, Termlist tl, Termlist keylist,
	      int (*callback) (), void *state);

#endif
