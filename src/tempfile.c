/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2012 Cas Cremers
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

/**
 *
 * @file tempfile.c
 *
 * Generate a temporary file stream
 *
 * Before Vista this was trivial, more or less. However Vista restricts access
 * so much that this call usually breaks, which is a pretty annoying bug.
 */

#include <stdio.h>
#include <stdlib.h>

#ifdef FORWINDOWS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "bool.h"
#include "symbol.h"

//! Create a new temporary file and return the pointer.
/**
 * Before Vista this was trivial, more or less. However Vista restricts access
 * so much that this call usually breaks, which is a pretty annoying bug.
 *
 * http://msdn2.microsoft.com/en-us/library/aa363875.aspx
 */
FILE *
scyther_tempfile (void)
{
#ifdef FORWINDOWS
  /* For now, just the broken copy, I'm sorry. */
  return tmpfile ();
#else
  /* On any other platform the normal stuff just works (tm) */
  return tmpfile ();
#endif
}
