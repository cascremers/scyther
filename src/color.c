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
