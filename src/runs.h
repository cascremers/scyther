#ifndef RUNS
#define RUNS

#include "terms.h"
#include "termlists.h"
#include "knowledge.h"
#include "constraints.h"

#define	READ	1
#define SEND	2
#define CLAIM	3

#define runPointerGet(sys,run)		sys->runs[run].index
#define runPointerSet(sys,run,newp)	sys->runs[run].index = newp

struct roledef
{
  /* flag for internal actions (overriding normal type) */
  int internal;
  int type;
  Term label;
  Term from;
  Term to;
  Term message;
  struct roledef *next;

  /* illegal injections */
  Knowledge forbidden;
  /* knowledge transitions counter */
  int knowPhase;

  /* evt runid for synchronisation, but that is implied in the
     base array */
};

typedef struct roledef *Roledef;


struct role
{
  Term nameterm;
  Roledef roledef;
  Termlist locals;
  struct role *next;
};

typedef struct role *Role;

struct protocol
{
  Term nameterm;
  Role roles;
  Termlist rolenames;
  Termlist locals;
  struct protocol *next;
};

typedef struct protocol *Protocol;

struct run
{
  Protocol protocol;
  Role role;
  Termlist agents;
  Roledef index;
  Roledef start;
  Knowledge know;
  Termlist locals;
};

typedef struct run *Run;

struct varbuf
{
  Termlist	from;
  Termlist	to;
  Termlist	empty;
};

typedef struct varbuf *Varbuf;

struct tracebuf
{
  int		length;
  int		reallength;
  Roledef	*event;
  int		*run;
  int		*status;
  int		*link;
  int		violatedclaim;	// index of violated claim in trace
  Knowledge	*know;
  Termlist	requiredterms;
  Varbuf	variables;
};

struct system
{
  int step;			// can be managed globally
  Knowledge know;
  struct parameters *parameters;	// misc
  /* static run info, maxruns */
  Run runs;

  /* global */
  int maxruns;

  /* properties */
  Termlist secrets;		// integrate secrets list into system
  int shortestattack;		// length of shortest attack trace

  /* switches */
  int report;
  int prune;			// type of pruning
  int switch_maxtracelength;	// helps to remember the length of the last trace
  int maxtracelength;		// helps to remember the length of the last trace
  int switchM;			// memory
  int switchT;			// time
  int switchS;			// progress (traversed states)
  int porparam;			// a multi-purpose integer parameter, passed to the partial order reduction method selected
  int latex;			// latex output switch

  /* traversal */
  int traverse;			// traversal method
  int explore;			// boolean: explore states after actions or not

  /* counters */
  unsigned long int statesLow;
  unsigned long int statesHigh;
  unsigned long int claims;	// number of claims encountered
  unsigned long int failed;	// number of claims failed

  /* matching */
  int match;			// matching type
  int clp;			// do we use clp?

  /* protocol definition */
  Protocol protocols;
  Termlist locals;
  Termlist variables;
  Termlist untrusted;

  /* constructed trace pointers, static */
  Roledef *traceEvent;		// MaxRuns * maxRoledef
  int *traceRun;		// MaxRuns * maxRoledef
  Knowledge *traceKnow;		// Maxruns * maxRoledef

  /* POR reduction assistance */
  int PORphase;			// -1: init (all sends), 0...: recurse reads
  int PORdone;			// simple bit to denote something was done.
  int knowPhase;		// which knowPhase have we already explored?
  Constraintlist constraints;	// only needed for CLP match

  /* relevant: storage of shortest attack */
  struct tracebuf* attack;
};

typedef struct system *System;

System systemInit ();
void systemReset (const System sys);
System systemDuplicate (System fromsys);
void statesPrint (System sys);
void statesPrintShort (System sys);
void systemDestroy (System sys);
void systemDone (System sys);
void ensureValidRun (System sys, int run);
void runAdd (System sys, int run, int type, Term label, Term from, Term to,
	     Term msg);
void roledefPrint (Roledef rd);
void runPrint (Roledef rd);
void runsPrint (System sys);
Term agentOfRunRole (const System sys, const int run, const Term role);
Term agentOfRun (const System sys, const int run);
Roledef roledefDuplicate1 (const Roledef rd);
Roledef roledefDuplicate (Roledef rd);
void roledefDelete (Roledef rd);
void roledefDestroy (Roledef rd);
void roleInstance (const System sys, const Protocol protocol, const Role role,
		   const Termlist tolist);
Roledef roledefInit (int type, Term label, Term from, Term to, Term msg);
Roledef roledefAdd (Roledef rd, int type, Term label, Term from, Term to,
		    Term msg);
void systemStart (System sys);
void indentActivate ();
void indentSet (int i);
void indent ();

Protocol protocolCreate (Term nameterm);
Role roleCreate (Term nameterm);
void locVarPrint (Termlist tl);
void protocolPrint (Protocol p);
void protocolsPrint (Protocol p);
void rolePrint (Role r);
void rolesPrint (Role r);
int untrustedAgent (System sys, Termlist agents);
int getMaxTraceLength (const System sys);
void agentsOfRunPrint (const System sys, const int run);
void violatedClaimPrint (const System sys, int i);
int attackLength(struct tracebuf* tb);

#endif
