#ifndef ROLES
#define ROLES

#include "term.h"
#include "termmap.h"
#include "termlist.h"
#include "knowledge.h"
#include "constraint.h"
#include "states.h"

enum eventtype
{ READ, SEND, CLAIM };

//! The container for the claim info list
struct claimlist
{
  //! The type of claim
  Term type;
  //! The term element for this node.
  Term label;
  //! The name of the role in which it occurs.
  Term rolename;
  //! Number of occurrences in system exploration.
  states_t count;
  //! Number of occurrences that failed.
  states_t failed;
  int r;			//!< role number for mapping
  int ev;			//!< event index in role
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
  /**
   * For send this means that the send is allowed if it is NULL, otherwise it is blocked.
   */
  Knowledge forbidden;
  //! knowledge transitions counter.
  int knowPhase;

  /*
   * Substructure for claims
   */
  //! Pointer to claim type info
  Claimlist claiminfo;

  /*
   * Bindings for Arachne engine
   */
  int bind_run;			//!< -1 for unbound
  int bind_index;

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
  //! Local variables for this role.
  Termlist variables;
  //! Pointer to next role definition.
  struct role *next;
};

//! Shorthand for role pointer.
typedef struct role *Role;

void roledefPrint (Roledef rd);
Roledef roledefDuplicate1 (const Roledef rd);
Roledef roledefDuplicate (Roledef rd);
void roledefDelete (Roledef rd);
void roledefDestroy (Roledef rd);
Roledef roledefInit (int type, Term label, Term from, Term to, Term msg,
		     Claimlist cl);
Roledef roledefAdd (Roledef rd, int type, Term label, Term from, Term to,
		    Term msg, Claimlist cl);
Role roleCreate (Term nameterm);
void rolePrint (Role r);
void rolesPrint (Role r);
int roledef_iterate_events (Roledef rd, int (*func) ());

#endif
