#ifndef RUNS
#define RUNS

#include "terms.h"
#include "termmaps.h"
#include "termlists.h"
#include "knowledge.h"
#include "constraints.h"

#define	READ	1
#define SEND	2
#define CLAIM	3

#define runPointerGet(sys,run)		sys->runs[run].index
#define runPointerSet(sys,run,newp)	sys->runs[run].index = newp

//! The container for the claim info list
struct claimlist
{
  //! The term element for this node.
  Term label;
  //! The name of the role in which it occurs.
  Term rolename;
  //! Number of occurrences in system exploration.
  int count;
  //! Number of occurrences that failed.
  int failed;
  int r;	//!< role number for mapping
  int ev;	//!< event index in role
  //! Preceding label list
  Termlist prec;
  //! Next node pointer or NULL for the last element of the function.
  struct claimlist *next;
};

//! Shorthand for claimlist pointers.
typedef struct claimlist *Claimlist;

//! Structure for a role event node or list.
/**
 *\sa role
 */
struct roledef
{
  //! flag for internal actions.
  /**
   * Typically, this is true to signify internal reads (e.g. variable choices)
   * as opposed to a normal read.
   */
  int internal;
  //! Type of event.
  /**
   *\sa READ, SEND, CLAIM
   */
  int type;
  //! Event label.
  Term label;
  //! Event sender.
  Term from;
  //! Event target.
  Term to;
  //! Event message.
  Term message;
  //! Pointer to next roledef node.
  struct roledef *next;

  /*
   * Substructure for reads
   */
  //! Illegal injections for this event.
  Knowledge forbidden;
  //! knowledge transitions counter.
  int knowPhase;

  /*
   * Substructure for claims
   */
  //! Pointer to claim type info
  Claimlist claiminfo;

  /* evt runid for synchronisation, but that is implied in the
     base array */
};

//! Shorthand for roledef pointer.
typedef struct roledef *Roledef;

//! Role definition.
/**
 *\sa roledef
 */
struct role
{
  //! Name of the role encoded in a term.
  Term nameterm;
  //! List of role events.
  Roledef roledef;
  //! Local constants for this role.
  Termlist locals;
  //! Pointer to next role definition.
  struct role *next;
};

//! Shorthand for role pointer.
typedef struct role *Role;

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
  //! Protocol of this run.
  Protocol protocol;
  //! Role of this run.
  Role role;
  //! Agents involved in this run.
  Termlist agents;
  //! Current execution point in the run.
  Roledef index;
  //! Head of the run definition.
  Roledef start;
  //! Current knowledge of the run.
  Knowledge know;
  //! Locals of the run.
  Termlist locals;
};

//! Shorthand for run pointer.
typedef struct run *Run;

//! Buffer for variables substitution state.
struct varbuf
{
  //! List of closed variables.
  Termlist	from;
  //! List of terms to which the closed variables are bound.
  Termlist	to;
  //! List of open variables.
  Termlist	empty;
};

//! Shorthand for varbuf pointer.
typedef struct varbuf *Varbuf;

//! Trace buffer.
struct tracebuf
{
  //! Length of trace.
  int		length;
  //! Length of trace minus the redundant events.
  int		reallength;
  //! Array of events.
  Roledef	*event;
  //! Array of run identifiers for each event.
  int		*run;
  //! Array of status flags for each event.
  /**
   *\sa S_OKE, S_RED, S_TOD, S_UNK
   */
  int		*status;
  //! Array for matching sends to reads.
  int		*link;
  //! Index of violated claim in trace.
  int		violatedclaim;	
  //! Array of knowledge sets for each event.
  Knowledge	*know;
  //! List of terms required to be in the final knowledge.
  Termlist	requiredterms;
  //! List of variables in the system.
  Varbuf	variables;
};

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
  int shortestattack;		//!< Length of shortest attack trace.

  /* switches */
  int report;
  int prune;			//!< Type of pruning.
  int switch_maxtracelength;	//!< Helps to remember the length of the last trace.
  int maxtracelength;		//!< helps to remember the length of the last trace.
  int switchM;			//!< Memory display switch.
  int switchT;			//!< Time display switch.
  int switchS;			//!< Progress display switch. (traversed states)
  int porparam;			//!< A multi-purpose integer parameter, passed to the partial order reduction method selected.
  int switchStatespace;		//!< Output statespace for dot package
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
  unsigned long int statesLow;	//!< State number (low)
  unsigned long int statesHigh; //!< State number (high)
  unsigned long int claims;	//!< Number of claims encountered.
  unsigned long int failed;	//!< Number of claims failed.

  unsigned long int parentState; //!< Parent state number

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
  Claimlist claimlist;		//!< List of claims in the system, with occurrence counts

  /* constructed trace pointers, static */
  Roledef *traceEvent;		//!< Trace roledefs: MaxRuns * maxRoledef
  int *traceRun;		//!< Trace run ids: MaxRuns * maxRoledef
  Knowledge *traceKnow;		//!< Trace intruder knowledge: Maxruns * maxRoledef

  /* POR reduction assistance */
  int PORphase;			//!< -1: init (all sends), 0...: recurse reads
  int PORdone;			//!< Simple bit to denote something was done.
  int knowPhase;		//!< Which knowPhase have we already explored?
  Constraintlist constraints;	//!< Only needed for CLP match

  //! Shortest attack storage.
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
Roledef roledefInit (int type, Term label, Term from, Term to, Term msg, Claimlist cl);
Roledef roledefAdd (Roledef rd, int type, Term label, Term from, Term to, Term msg, Claimlist cl);
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

int compute_rolecount (const System sys);
int compute_roleeventmax (const System sys);

#endif
