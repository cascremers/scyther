#include <stdio.h>
#include <stdarg.h>
#include "error.h"

//! Die from error with exit code
void
error_die (void)
{
  exit(1);
}

//! Print error message header
/**
 * Adapted from [K&R2], p. 174
 *@todo It would be nice to redirect all output to stderr, which would enable use of termprint etc.
 */
void
error_pre (void)
{
  fprintf (stderr, "error: ");
}

//! Print post-error message and die.
/**
 * Adapted from [K&R2], p. 174
 * Input is comparable to printf, only end of line is not required.
 */
void
error_post (char *fmt, ... )
{
  va_list args;

  va_start (args, fmt);
  vfprintf (stderr, fmt, args);
  fprintf (stderr, "\n");
  va_end (args);
  exit(1);
}

//! Print error message and die.
/**
 * Adapted from [K&R2], p. 174
 * Input is comparable to printf, only end of line is not required.
 */
void
error (char *fmt, ... )
{
  va_list args;

  error_pre ();
  va_start (args, fmt);
  vfprintf (stderr, fmt, args);
  fprintf (stderr, "\n");
  va_end (args);
  error_die ();
}

//! Print warning
/**
 * Input is comparable to printf, only end of line is not required.
 */
void
warning (char *fmt, ... )
{
  va_list args;

  va_start (args, fmt);
  fprintf (stderr, "warning: ");
  vfprintf (stderr, fmt, args);
  fprintf (stderr, "\n");
  va_end (args);
}
