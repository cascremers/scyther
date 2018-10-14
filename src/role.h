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

#ifndef ROLES
#define ROLES

#include "term.h"
#include "termmap.h"
#include "termlist.h"
#include "knowledge.h"
#include "states.h"

enum eventtype
{ RECV, SEND, CLAIM, ANYEVENT };

//! The container for the claim info list
/**
 * Defaults are set in compiler.c (claimCreate)
 */
struct claimlist
{
  //! The type of claim
  Term type;
  //! The term element for this node.
  Term label;
  //! Any parameters
  Term parameter;
  //! The pointer to the protocol (not defined typically, because
  //! at compile time of the claim the protocol structure is not known yet.)
  void *protocol;
  //! The name of the role in which it occurs.
  Term rolename;
  //! The pointer to the role structure
  void *role;
  //! The pointer to the roledef
  void *roledef;
  //! Number of occurrences in system exploration.
  states_t count;
  //! Number of occurrences that failed.
  states_t failed;
  //! Number of iterations traversed for this claim.
  states_t states;
  //! Whether the result is complete or not (failings always are!)
  int complete;
  //! If we ran into the time bound (incomplete, and bad for results)
  int timebound;
  //! Some claims are always true (shown by the initial scan)
  int alwaystrue;
  //! Warnings should tell you more
  int warnings;

  int r;			//!< role number for mapping
  int ev;			//!< event index in role
  //! Preceding label list
  Termlist prec;
  //! Roles that are involved (nameterms)
  Termlist roles;
  //! Next node pointer or NULL for the last element of the function.
  struct claimlist *next;

  int lineno;
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
   * Typically, this is true to signify internal recvs (e.g. variable choices)
   * as opposed to a normal recv.
   */
  int internal;
  //! Type of event.
  /**
   *\sa RECV, SEND, CLAIM
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
   * Substructure for recvs
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
  int bound;			//!< determines whether it is already bound

  /* evt runid for synchronisation, but that is implied in the
     base array */
  int lineno;
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
  //! Declared constants for this role
  Termlist declaredconsts;
  //! Declared variables for this role
  Termlist declaredvars;
  //! Initial role knowledge
  Termlist knows;
  //! Flag for initiator roles
  int initiator;
  //! Flag for singular roles
  int singular;
  //! Pointer to next role definition.
  struct role *next;
  //! Line number
  int lineno;
};

//! Shorthand for role pointer.
typedef struct role *Role;

void roledefPrint (Roledef rd);
void roledefPrintShort (Roledef rd);
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
int roledef_length (Roledef rd);
Roledef roledef_shift (Roledef rd, int i);
int roledefSubTerm (Roledef rd, Term tsub);
Roledef firstEventWithTerm (Roledef rd, Term t);

#endif
