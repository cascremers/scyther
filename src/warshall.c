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

// @file warshall.c
/* Based on public-domain code from Berkeley Yacc */

#include "warshall.h"

void
transitive_closure (unsigned int *R, int n)
{
  register int rowsize;
  register unsigned mask;
  register unsigned *rowj;
  register unsigned *rp;
  register unsigned *rend;
  register unsigned *ccol;
  register unsigned *relend;
  register unsigned *cword;
  register unsigned *rowi;

  rowsize = WORDSIZE (n);
  relend = R + n * rowsize;

  cword = R;
  mask = 1;
  rowi = R;
  while (rowi < relend)
    {
      ccol = cword;
      rowj = R;

      while (rowj < relend)
	{
	  if (*ccol & mask)
	    {
	      rp = rowi;
	      rend = rowj + rowsize;
	      while (rowj < rend)
		*rowj++ |= *rp++;
	    }
	  else
	    {
	      rowj += rowsize;
	    }

	  ccol += rowsize;
	}

      mask <<= 1;
      if (mask == 0)
	{
	  mask = 1;
	  cword++;
	}

      rowi += rowsize;
    }
}

void
reflexive_transitive_closure (unsigned int *R, int n)
{
  register int rowsize;
  register unsigned mask;
  register unsigned *rp;
  register unsigned *relend;

  transitive_closure (R, n);

  rowsize = WORDSIZE (n);
  relend = R + n * rowsize;

  mask = 1;
  rp = R;
  while (rp < relend)
    {
      *rp |= mask;
      mask <<= 1;
      if (mask == 0)
	{
	  mask = 1;
	  rp++;
	}

      rp += rowsize;
    }
}
