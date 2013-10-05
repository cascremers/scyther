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
#include <io.h>
#endif

#include "bool.h"
#include "symbol.h"
#include "error.h"

//! Create a new temporary file and return the pointer.
/**
 * Before Vista this was trivial, more or less. However Vista restricts access
 * so much that this call usually breaks, which is a pretty annoying bug.
 *
 * See e.g., http://msdn2.microsoft.com/en-us/library/aa363875.aspx
 */

#ifdef FORWINDOWS

/* 
 * tmpfile() replacement for Windows Vista (and later?)
 */
FILE *
win32_tmpfile (void)
{
  DWORD pathlength;
  WCHAR path[MAX_PATH + 1];

  pathlength = GetTempPathW (MAX_PATH, path);
  if ((pathlength > 0) && (pathlength < MAX_PATH))
    {
      WCHAR filename[MAX_PATH + 1];

      if (GetTempFileNameW (path, L"scyther_", 0, filename) != 0)
	{
	  HANDLE handle;

	  handle = CreateFileW (filename,
				GENERIC_READ | GENERIC_WRITE,
				0,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL |
				FILE_FLAG_DELETE_ON_CLOSE, NULL);
	  if (handle != INVALID_HANDLE_VALUE)
	    {
	      int fd;

	      fd = _open_osfhandle ((intptr_t) handle, 0);
	      if (fd < 0)
		{
		  CloseHandle (handle);
		}
	      else
		{
		  FILE *fp;

		  fp = fdopen (fd, "w+b");
		  if (fp == NULL)
		    {
		      _close (fd);
		    }
		  else
		    {
		      // Return a real filepointer
		      return fp;
		    }
		}
	    }
	  else
	    {
	      DeleteFileW (filename);
	    }
	}
    }
  return NULL;
}

#endif

//! Create a tempfile
/**
 * Returns a filepointer to an open temporary file.
 *
 * Really, this should always work and the calling code should not be required
 * to check for errors (such as fp=NULL).  We therefore simply throw an error
 * if the underlying code returns NULL.
 */
FILE *
scyther_tempfile (void)
{
  FILE *fp;

#ifdef FORWINDOWS
  /* Do special version because of M$ breaking tmpfile in Vista */
  fp = win32_tmpfile ();
#else
  /* On any other platform the normal stuff just works (tm) */
  fp = tmpfile ();
#endif
  if (fp == NULL)
    {
      error
	("Attempt at creating a temporary file failed for unknown reasons.");
    }
  return fp;
}
