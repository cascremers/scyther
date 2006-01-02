/** @file color.c \brief Color output for terminals.
 *
 * Depends on the switches (to disable them with a --plain switch)
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "switches.h"

//! Substitution string for --plain output
char *empty = "";
//! Reset colors
char *COLOR_Reset = "[0m";
//! Red
char *COLOR_Red = "[31m";
//! Green
char *COLOR_Green = "[32m";
//! Bold
char *COLOR_Bold = "[1m";

//! Init colors
void
colorInit (void)
{
  if (switches.plain)
    {
      COLOR_Reset = empty;
      COLOR_Red = empty;
      COLOR_Green = empty;
      COLOR_Bold = empty;
    }
}

//! Exit colors
void
colorDone (void)
{
}
