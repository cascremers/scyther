#include "timer.h"

#include <time.h>
#include <sys/times.h>

static int time_max_seconds = 0;
static clock_t endwait = 0;

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
      endwait = seconds * CLK_TCK;
    }
  else
    {
      time_max_seconds = 0;
      endwait = 0;
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
  if (endwait <= 0)
    {
      return 0;
    }
  else
    {
      struct tms t;

      times (&t);
      if (t.tms_utime > endwait)
	return 1;
      else
	return 0;
    }
}
