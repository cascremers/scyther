#ifndef MATCHBASIC
#define MATCHBASIC

int matchRead_basic (const System sys, const int run,
		     int (*proceed) (System, int));
int enabled_basic (const System sys, const Knowledge know,
		   const Term newterm);
int block_basic (const System sys, const int run);
int send_basic (const System sys, const int run);

#endif
