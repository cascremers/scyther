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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "error.h"

//! Die from error with exit code
void
error_die (void)
{
  exit (EXIT_ERROR);
}

//! print to stderror (must be generic to capture linux variants)
void
vprintfstderr (char *fmt, va_list args)
{
#ifdef USESTDERR
  vfprintf (stderr, fmt, args);
#else
  // no alternative yet
#endif
}

void
printfstderr (char *fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  vprintfstderr (fmt, args);
  va_end (args);
}

//! Print error message header
/**
 * Adapted from [K&R2], p. 174
 *@todo It would be nice to redirect all output to stderr, which would enable use of termprint etc.
 */
void
error_pre (void)
{
  printfstderr ("error: ");
}

//! Print post-error message and die.
/**
 * Adapted from [K&R2], p. 174
 * Input is comparable to printf, only end of line is not required.
 */
void
error_post (char *fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  vprintfstderr (fmt, args);
  printfstderr ("\n");
  va_end (args);
  exit (EXIT_ERROR);
}

//! Print error message and die.
/**
 * Adapted from [K&R2], p. 174
 * Input is comparable to printf, only end of line is not required.
 */
void
error (char *fmt, ...)
{
  va_list args;

  error_pre ();
  va_start (args, fmt);
  vprintfstderr (fmt, args);
  printfstderr ("\n");
  va_end (args);
  error_die ();
}

//! Warning pre
void
warning_pre (void)
{
  printfstderr ("warning: ");
}

//! Print warning
/**
 * Input is comparable to printf, only end of line is not required.
 */
void
warning (char *fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  warning_pre ();
  vprintfstderr (fmt, args);
  printfstderr ("\n");
  va_end (args);
}
