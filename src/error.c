#include <stdio.h>
#include <stdarg.h>
#include "error.h"

//! Print error message and die.
/**
 * Adapted from [K&R2], p. 174
 * Input is comparable to printf, only end of line is not required.
 */
void error (char *fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  fprintf (stderr, "error: ");
  vprintf (stderr, fmt, args);
  fprintf (stderr, "\n");
  va_end (args);
  exit(1);
}
