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
#ifdef linux
  vfprintf (stderr, fmt, args);
#else
  // nothing for non-linux yet
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

//! Print warning
/**
 * Input is comparable to printf, only end of line is not required.
 */
void
warning (char *fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  printfstderr ("warning: ");
  vprintfstderr (fmt, args);
  printfstderr ("\n");
  va_end (args);
}
