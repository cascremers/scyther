#ifndef COMPILER
#define COMPILER

#include "tac.h"
#include "role.h"
#include "system.h"

void compilerInit (const System sys);
void compilerDone (void);

void compile (Tac tc, int maxruns);
void preprocess (const System sys);
Term findGlobalConstant (const char *s);
Term makeGlobalConstant (const char *s);
Term makeGlobalVariable (const char *s);
void compute_role_variables (const System sys, Protocol p, Role r);

Term symbolDeclare (Symbol s, int isVar);
void levelTacDeclaration (Tac tc, int isVar);

#define	levelDeclareVar(s)	levelTacDeclaration(s,1)
#define	levelDeclareConst(s)	levelTacDeclaration(s,0)
#define	levelVar(s)	symbolDeclare(s,1)
#define	levelConst(s)	symbolDeclare(s,0)

#endif
