/*
 * LaTeX output component header
 */

#ifndef LATEX
#define LATEX

#include "runs.h"

void latexInit(const System sys, int argc, char **argv);
void latexDone(const System sys);
void latexTimers(const System sys);
void latexMSCStart();
void latexMSCEnd();
void latexDeclInst(const System sys);
void latexMessagePrint(const System sys, int from, int to);
void latexLearnComment(const System sys, Termlist tl);
void latexTracePrint(System sys);
void attackDisplayLatex(System sys);

#endif
