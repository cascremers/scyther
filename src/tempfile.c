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
