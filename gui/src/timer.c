#include "timer.h"

/*
 * Timer functions
 *
 * Currently, this only works under linux (where the linux macro is defined by the compiler). Otherwise, it simply assumes the timer is never passed.
 */

#ifdef linux
#include <time.h>
#include <sys/times.h>
static clock_t endwait = 0;
#endif

static int time_max_seconds = 0;

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
      endwait = seconds * CLOCKS_PER_SEC;
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
      if (t.tms_utime > endwait)
	return 1;
      else
	return 0;
    }
#else
  return 0;
#endif
}
