#ifndef MATCHCLP
#define MATCHCLP

#include "runs.h"

int matchRead_clp (const System sys, const int run,
		   int (*proceed) (System, int));
int enabled_clp (const System sys, const int run);
int block_clp (const System sys, const int run);
int secret_clp (const System sys, const Term t);
int send_clp (const System sys, const int run);

#endif
