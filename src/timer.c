/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2009 Cas Cremers
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

#include "timer.h"
#include "error.h"

/*
 * Timer functions
 *
 * Currently, this only works under linux (where the linux macro is defined by the compiler). Otherwise, it simply assumes the timer is never passed.
 */

#ifdef linux
#include <time.h>
static clock_t clockstart;
#endif
static double time_max_seconds;

void
timeInit (void)
{
  time_max_seconds = 0;
#ifdef linux
  clockstart = clock ();
#endif
}

void
timeDone (void)
{
  return;
}

//! Set initial time limit.
/**
 * <= 0 means none.
 */
void
set_time_limit (double seconds)
{
#ifdef linux
  if (seconds > 0)
    {
      time_max_seconds = seconds;
    }
  else
    {
      time_max_seconds = 0;
    }
#else
  warning ("This build of Scyther does not support the --timer (-T) switch.");
#endif
}

//! Retrieve time limit
int
get_time_limit ()
{
  return time_max_seconds;
}

//! Check whether time limit has passed.
int
passed_time_limit ()
{
#ifdef linux
  if (time_max_seconds == 0)
    {
      return false;
    }
  else
    {
      time_t clockend;
      double duration;

      clockend = clock ();
      duration = ((double) (clockend - clockstart)) / CLOCKS_PER_SEC;
      if (duration > time_max_seconds)
	{
	  return true;
	}
    }
#endif
  return false;
}

//! Check time limit and store cause if so
int
passed_time_limit_store (const System sys)
{
  if (passed_time_limit ())
    {
      sys->current_claim->timebound = 1;
      return true;
    }
  return false;
}
