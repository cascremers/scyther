/** @file color.c \brief Color output for terminals.
 *
 * Depends on the switches (to disable them with a --plain switch)
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "switches.h"

char *empty = "";
char *COLOR_Reset = "[0m";
char *COLOR_Red = "[31m";
char *COLOR_Green = "[32m";
char *COLOR_Bold = "[1m";

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

void
colorDone (void)
{
}
