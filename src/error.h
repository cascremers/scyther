#ifndef ERROR
#define ERROR

void error_die (void);
void error_pre (void);
void error_post (char *fmt, ... );
void error (char *fmt, ... );
void warning (char *fmt, ... );

#endif
