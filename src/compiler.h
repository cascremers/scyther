#ifndef COMPILER
#define COMPILER

void compilerInit (const System sys);
void compilerDone (void);

void compile (Tac tc, int maxruns);
void preprocess (const System sys);
Term findGlobalConstant (const char *s);
Term makeGlobalConstant (const char *s);
void compute_role_variables (const System sys, Protocol p, Role r);

#endif
