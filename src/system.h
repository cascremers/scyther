#ifndef SYSTEM
#define SYSTEM

#include "term.h"
#include "termmap.h"
#include "termlist.h"
#include "knowledge.h"
#include "constraint.h"
#include "states.h"
#include "role.h"
#include "list.h"

#define runPointerGet(sys,run)		sys->runs[run].index
#define runPointerSet(sys,run,newp)	sys->runs[run].index = newp

enum outputs
{ EMPTY, ATTACK, STATESPACE, SCENARIOS, SUMMARY, PROOF };

enum engines
{ POR_ENGINE, ARACHNE_ENGINE };

//! Protocol definition.
struct protocol
{
  //! Name of the protocol encoded in a term.
  Term nameterm;
  //! List of role definitions.
  Role roles;
  //! List of role names.
  Termlist rolenames;
  //! List of local terms for this protocol.
  Termlist locals;
  //! Pointer to next protocol.
  struct protocol *next;
};

//! Shorthand for protocol pointer.
typedef struct protocol *Protocol;

//! Run container.
struct run
{
  Protocol protocol;		//!< Protocol of this run.
  Role role;			//!< Role of this run.
  Termlist agents;		//!< Agents involved in this run.
  int step;			//!< Current execution point in the run (integer)
  Roledef index;		//!< Current execution point in the run (roledef pointer)
  Roledef start;		//!< Head of the run definition.
  Knowledge know;		//!< Current knowledge of the run.
  Termlist locals;		//!< Locals of the run.
  Termlist artefacts;		//!< Stuff created especially for this run.
  Termlist substitutions;	//!< The substitutions as they came from the roledef unifier
  int prevSymmRun;		//!< Used for symmetry reduction. Either -1, or the previous run with the same role def and at least a single parameter.
  int firstNonAgentRead;	//!< Used for symmetry reductions for equal agents runs; -1 if there is no candidate.
  int firstReal;		//!< 1 if a choose was inserted, otherwise 0
};

//! Shorthand for run pointer.
typedef struct run *Run;

//! Buffer for variables substitution state.
struct varbuf
{
  //! List of closed variables.
  Termlist from;
  //! List of terms to which the closed variables are bound.
  Termlist to;
  //! List of open variables.
  Termlist empty;
};

//! Shorthand for varbuf pointer.
typedef struct varbuf *Varbuf;

//! Trace buffer.
struct tracebuf
{
  //! Length of trace.
  int length;
  //! Length of trace minus the redundant events.
  int reallength;
  //! Array of events.
  Roledef *event;
  //! Array of run identifiers for each event.
  int *run;
  //! Array of status flags for each event.
  /**
   *\sa S_OKE, S_RED, S_TOD, S_UNK
   */
  int *status;
  //! Array for matching sends to reads.
  int *link;
  //! Index of violated claim in trace.
  int violatedclaim;
  //! Array of knowledge sets for each event.
  Knowledge *know;
  //! List of terms required to be in the final knowledge.
  Termlist requiredterms;
  //! List of variables in the system.
  Varbuf variables;
};

//! The main state structure.
struct system
{
  int engine;			//!< Engine type (POR_ENGINE,ARACHNE_ENGINE)
  int step;			//!< Step in trace during exploration. Can be managed globally
  Knowledge know;		//!< Knowledge in currect step of system.
  struct parameters *parameters;	// misc
  /* static run info, maxruns */
  Run runs;

  /* global */
  int maxruns;			//!< Number of runs in the system.

  /* properties */
  Termlist secrets;		//!< Integrate secrets list into system.
  Termlist synchronising_labels;	//!< List of labels that might synchronise.
  int shortestattack;		//!< Length of shortest attack trace.

  /* switches */
  int output;			//!< From enum outputs: what should be produced. Default ATTACK.
  int report;
  int prune;			//!< Type of pruning.
  int switch_maxproofdepth;	//!< Maximum proof depth
  int switch_maxtracelength;	//!< Maximum trace length allowed
  int maxtracelength;		//!< helps to remember the length of the last trace.
  int switchM;			//!< Memory display switch.
  int switchT;			//!< Time display switch.
  int switchS;			//!< Progress display switch. (traversed states)
  int porparam;			//!< A multi-purpose integer parameter, passed to the partial order reduction method selected.
  int switchRuns;		//!< The number of runs as in the switch
  int switchScenario;		//!< -1 to count, 0 for disable, 1-n to select the choose scenario
  int switchScenarioSize;	//!< Scenario size, also called fixed trace prefix length
  int switchForceChoose;	//!< Force chooses for each run, even if involved in first read
  int switchChooseFirst;	//!< Priority to chooses, implicit and explicit
  int switchReadSymm;		//!< Enable read symmetry reduction
  int switchAgentSymm;		//!< Enable agent symmetry reduction
  int switchSymmOrder;		//!< Enable symmetry order reduction
  int switchNomoreClaims;	//!< Enable no more claims cutter
  int switchReduceEndgame;	//!< Enable endgame cutter
  int switchReduceClaims;	//!< Symmetry reduction on claims (only works when switchAgentSymm is true)
  int switchClaims;		//!< Enable clails report
  int switchGoalSelectMethod;	//!< Goal selection method for Arachne engine
  Term switchClaimToCheck;	//!< Which claim should be checked?
  int switchXMLoutput;		//!< xml output
  int switchHuman;		//!< human readable

  //! Latex output switch.
  /**
   * Obsolete. Use globalLatex instead.
   *\sa globalLatex
   */
  int latex;

  /* traversal */
  int traverse;			//!< Traversal method.
  int explore;			//!< Boolean: explore states after actions or not.

  /* counters */
  states_t states;		//!< States traversed
  states_t statesScenario;	//!< States traversed that are within the scenario, not the prefix
  states_t interval;		//!< Used to update state printing at certain intervals
  states_t claims;		//!< Number of claims encountered.
  states_t failed;		//!< Number of claims failed.
  int attackid;			//!< Global counter of attacks (used for assigning identifiers) within this Scyther call.
  int countScenario;		//!< Number of scenarios skipped.

  /* matching */
  int match;			//!< Matching type.
  int clp;			//!< Do we use clp?

  /* protocol definition */
  Protocol protocols;		//!< List of protocols in the system
  Termlist locals;		//!< List of local terms
  Termlist variables;		//!< List of all variables
  Termlist untrusted;		//!< List of untrusted agent names

  /* protocol preprocessing */
  int rolecount;		//!< Number of roles in the system
  int roleeventmax;		//!< Maximum number of events in a single role
  int lastChooseRun;		//!< Last run with a choose event
  Claimlist claimlist;		//!< List of claims in the system, with occurrence counts
  List labellist;		//!< List of labelinfo stuff

  /* constructed trace pointers, static */
  Roledef *traceEvent;		//!< Trace roledefs: MaxRuns * maxRoledef
  int *traceRun;		//!< Trace run ids: MaxRuns * maxRoledef
  Knowledge *traceKnow;		//!< Trace intruder knowledge: Maxruns * maxRoledef
  states_t *traceNode;		//!< Trace node traversal: Maxruns * maxRoledef

  /* POR reduction assistance */
  int PORphase;			//!< -1: init (all sends), 0...: recurse reads
  int PORdone;			//!< Simple bit to denote something was done.
  int knowPhase;		//!< Which knowPhase have we already explored?
  Constraintlist constraints;	//!< Only needed for CLP match

  /* Arachne assistance */
  List bindings;		//!< List of bindings
  Claimlist current_claim;	//!< The claim under current investigation

  //! Shortest attack storage.
  struct tracebuf *attack;

  //! Command line arguments
  int argc;
  char **argv;
};

typedef struct system *System;

System systemInit ();
void systemReset (const System sys);
void systemRuns (const System sys);
System systemDuplicate (const System fromsys);
void statesPrint (const System sys);
void statesPrintShort (const System sys);
void systemDestroy (const System sys);
void systemDone (const System sys);
void ensureValidRun (const System sys, int run);
void runPrint (Roledef rd);
void runsPrint (const System sys);
Term agentOfRunRole (const System sys, const int run, const Term role);
Term agentOfRun (const System sys, const int run);
void roleInstance (const System sys, const Protocol protocol, const Role role,
		   const Termlist paramlist, Termlist substlist);
void roleInstanceDestroy (const System sys);
void systemStart (const System sys);
void indentActivate ();
void indentSet (int i);
void indent ();

Protocol protocolCreate (Term nameterm);
void locVarPrint (Termlist tl);
void protocolPrint (Protocol p);
void protocolsPrint (Protocol p);
int untrustedAgent (const System sys, Termlist agents);
int getMaxTraceLength (const System sys);
void agentsOfRunPrint (const System sys, const int run);
void violatedClaimPrint (const System sys, int i);
int attackLength (struct tracebuf *tb);
void commandlinePrint (FILE * stream, const System sys);

int compute_rolecount (const System sys);
int compute_roleeventmax (const System sys);

void scenarioPrint (const System sys);
int system_iterate_roles (const System sys, int (*func) ());

#endif
