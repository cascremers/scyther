/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2013 Cas Cremers
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

int isStringEqual (const char *s1, const char *s2);

#endif
