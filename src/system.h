#ifndef SYSTEM
#define SYSTEM

#include "term.h"
#include "termmap.h"
#include "termlist.h"
#include "knowledge.h"
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
  int step;			//!< Current execution point in the run (integer)
  int rolelength;		//!< Length of role

  Roledef index;		//!< Current execution point in the run (roledef pointer)
  Roledef start;		//!< Head of the run definition.
  Knowledge know;		//!< Current knowledge of the run.

  Termlist rho;			//!< As in semantics (copies in artefacts)
  Termlist sigma;		//!< As in semantics (copies in artefacts)
  Termlist constants;		//!< As in semantics (copies in artefacts)

  Termlist locals;		//!< Locals of the run (will be deprecated eventually)
  Termlist artefacts;		//!< Stuff created especially for this run, which can also include tuples (anything allocated)
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

//! Structure for information on special terms (cacheing)
struct hiddenterm
{
  Term term;
  unsigned int hideminimum;
  unsigned int hideprotocol;
  unsigned int hideknowledge;
  struct hiddenterm *next;
};

//! Pointer shorthand
typedef struct hiddenterm *Hiddenterm;

//! The main state structure.
struct system
{
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
  int maxtracelength;		//!< helps to remember the length of the last trace.

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
  int num_regular_runs;		//!< Number of regular runs
  int num_intruder_runs;	//!< Number of intruder runs

  /* protocol definition */
  Protocol protocols;		//!< List of protocols in the system
  Termlist locals;		//!< List of local terms
  Termlist variables;		//!< List of all variables
  Termlist agentnames;		//!< List of all agent names (trusted and untrusted)
  Termlist untrusted;		//!< List of untrusted agent names
  Termlist globalconstants;	//!< List of global constants
  Hiddenterm hidden;		//!< List of hiddenterm constructs for Hidelevel lemma

  /* protocol preprocessing */
  int rolecount;		//!< Number of roles in the system
  int roleeventmax;		//!< Maximum number of events in a single role
  int lastChooseRun;		//!< Last run with a choose event
  Claimlist claimlist;		//!< List of claims in the system, with occurrence counts
  List labellist;		//!< List of labelinfo stuff
  int knowledgedefined;		//!< True if knowledge is defined for some role (which triggers well-formedness check etc.)

  /* constructed trace pointers, static */
  Roledef *traceEvent;		//!< Trace roledefs: MaxRuns * maxRoledef
  int *traceRun;		//!< Trace run ids: MaxRuns * maxRoledef
  Knowledge *traceKnow;		//!< Trace intruder knowledge: Maxruns * maxRoledef
  states_t *traceNode;		//!< Trace node traversal: Maxruns * maxRoledef

  /* Arachne assistance */
  List bindings;		//!< List of bindings
  Claimlist current_claim;	//!< The claim under current investigation
  Termlist trustedRoles;	//!< Roles that should be trusted for this claim (the default, NULL, means all)
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
void commandlinePrint (FILE * stream);

int compute_rolecount (const System sys);
int compute_roleeventmax (const System sys);

void scenarioPrint (const System sys);
int isAgentTrusted (const System sys, Term agent);
int isAgentlistTrusted (const System sys, Termlist agents);
int isRunTrusted (const System sys, const int run);

int iterateRuns (const System sys, int (*callback) (int r));
int iterateRegularRuns (const System sys, int (*callback) (int r));
int iterateEvents (const System sys, const int run,
		   int (*callback) (Roledef rd, int ev));
int iterateAllEvents (const System sys,
		      int (*callback) (int run, Roledef rd, int ev));
int iterateEventsType (const System sys, const int run, const int evtype,
		       int (*callback) (Roledef rd, int ev));
int iterateLocalToOther (const System sys, const int myrun,
			 int (*callback) (Term t));
int iterateRoles (const System sys, int (*callback) (Protocol p, Role r));
int firstOccurrence (const System sys, const int r, Term t, int evtype);
Roledef eventRoledef (const System sys, const int run, const int ev);
int countInitiators (const System sys);
int selfResponder (const System sys, const int run);
int selfResponders (const System sys);
int selfInitiator (const System sys, const int run);
int selfInitiators (const System sys);
int enoughAttacks (const System sys);


//! Equality for run structure naming
/**
 * For the modelchecker, there was an index called step. In Strand Space
 * terminology, something like that is the height of the strand.
 */
#define height	step

#endif
