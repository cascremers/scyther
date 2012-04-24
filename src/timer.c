/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2012 Cas Cremers
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
#include "switches.h"
#include "arachne.h"

/*
 * Timer functions
 *
 * Currently, this only works under linux (where the linux macro is defined by the compiler). Otherwise, it simply assumes the timer is never passed.
 */

#ifdef linux
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/times.h>
static clock_t endwait = 0;
#endif

static int time_max_seconds = 0;

void
timeInit (void)
{
  time_max_seconds = 0;
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
set_time_limit (int seconds)
{
  if (seconds > 0)
    {
      time_max_seconds = seconds;
#ifdef linux
      endwait = seconds * sysconf (_SC_CLK_TCK);
#endif
    }
  else
    {
      time_max_seconds = 0;
#ifdef linux
      endwait = 0;
#endif
    }
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
  if (endwait <= 0)
    {
      return 0;
    }
  else
    {
      struct tms t;

      times (&t);
      if ((t.tms_utime + t.tms_stime) > endwait)
	return 1;
      else if (switches.output == PROOF)
	{
	  indentPrint ();
	  eprintf ("Clockticks per second: %jd\tTicks passed: %jd\n",
		   (intmax_t) (sysconf (_SC_CLK_TCK)),
		   (intmax_t) (t.tms_utime + t.tms_stime));
	}
      return 0;
    }
#else
  return 0;
#endif
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
