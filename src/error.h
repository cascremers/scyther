#ifndef ERROR
#define ERROR

//! Types of exit codes
enum exittypes
{ EXIT_NOATTACK = 0, EXIT_ERROR = 1, EXIT_NOCLAIM = 2, EXIT_ATTACK = 3 };

void vprintfstderr (char *fmt, va_list args);
void printfstderr (char *fmt, ...);
void error_die (void);
void error_pre (void);
void error_post (char *fmt, ...);
void error (char *fmt, ...);
void warning (char *fmt, ...);

#endif
