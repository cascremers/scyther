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

#include <stdlib.h>
#include <stdio.h>
#include "term.h"
#include "termlist.h"
#include "compiler.h"
#include "error.h"

/*
 * Some macros
 */
#define langhide(x,y) x = levelConst(symbolSysConst(" _" y "_ "))
#define langtype(x,y) x->stype = termlistAdd(x->stype,y)
#define langcons(x,y,z) x = levelConst(symbolSysConst(y)); langtype(x,z)
#define symmEveKey(a,b) knowledgeAddTerm (sys->know, makeTermEncrypt ( makeTermTuple(a, b), TERM_K ) );


/* externally used:
 */

Term TERM_Agent;
Term TERM_Function;
Term TERM_Hidden;
Term TERM_CoOld;
Term TERM_CoNew;
Term TERM_DeEx;
Term TERM_DeNew;
Term TERM_Type;
Term TERM_Nonce;
Term TERM_Ticket;
Term TERM_SessionKey;
Term TERM_Data;

Term TERM_Claim;
Term CLAIM_Secret;
Term CLAIM_Alive;
Term CLAIM_Weakagree;
Term CLAIM_Nisynch;
Term CLAIM_Niagree;
Term CLAIM_Empty;
Term CLAIM_Reachable;
Term CLAIM_SID;
Term CLAIM_SKR;
Term CLAIM_Commit;
Term CLAIM_Running;
Term CLAIM_Notequal;

Term AGENT_Alice;
Term AGENT_Bob;
Term AGENT_Charlie;
Term AGENT_Dave;
Term AGENT_Eve;
Term AGENT_Simon;
Term AGENT_Pete;
Term TERM_PK;
Term TERM_SK;
Term TERM_K;

Term LABEL_Match;

Termlist CLAIMS_dep_prec;

//! Init special terms
/**
 * This is called by compilerInit
 */
void
specialTermInit (const System sys)
{
  /* Init system constants */

  langhide (TERM_Type, "Type");
  langhide (TERM_Hidden, "Hidden");
  langhide (TERM_Claim, "Claim");
  langhide (TERM_CoOld, "Co(Old)");
  langhide (TERM_CoNew, "Co(New)");
  langhide (TERM_DeEx, "DeEx");
  langhide (TERM_DeNew, "DeNew");

  langcons (TERM_Agent, "Agent", TERM_Type);
  langcons (TERM_Function, "Function", TERM_Type);
  langcons (TERM_Nonce, "Nonce", TERM_Type);
  langcons (TERM_Ticket, "Ticket", TERM_Type);
  langcons (TERM_SessionKey, "SessionKey", TERM_Type);
  langcons (TERM_Data, "Data", TERM_Type);

  langcons (CLAIM_Secret, "Secret", TERM_Claim);
  langcons (CLAIM_Alive, "Alive", TERM_Claim);
  langcons (CLAIM_Weakagree, "Weakagree", TERM_Claim);
  langcons (CLAIM_Nisynch, "Nisynch", TERM_Claim);
  langcons (CLAIM_Niagree, "Niagree", TERM_Claim);
  langcons (CLAIM_Empty, "Empty", TERM_Claim);
  langcons (CLAIM_Reachable, "Reachable", TERM_Claim);
  langcons (CLAIM_Notequal, "NotEqual", TERM_Claim);

  langcons (CLAIM_SID, "SID", TERM_Claim);	// claim specifying session ID
  langcons (CLAIM_SKR, "SKR", TERM_Claim);	// claim specifying session key : doubles as secrecy claim

  langcons (CLAIM_Commit, "Commit", TERM_Claim);	// claim specifying session agreement for a subset of data items
  langcons (CLAIM_Running, "Running", TERM_Claim);	// claim for signaling data item possession (checked by commit)

  /* Define default PKI using PK/SK/K */
  langcons (TERM_PK, "pk", TERM_Function);
  langcons (TERM_SK, "sk", TERM_Function);
  langcons (TERM_K, "k", TERM_Function);
  knowledgeAddInverseKeyFunctions (sys->know, TERM_PK, TERM_SK);
  knowledgeAddTerm (sys->know, TERM_PK);

  /* Define a prefix for labels for the match function */
  langcons (LABEL_Match, "!Match", TERM_Hidden);

  /* Construct a list of claims that depend on prec being not-empty */
  /* basically all authentication claims */
  CLAIMS_dep_prec = termlistAdd (NULL, CLAIM_Niagree);
  CLAIMS_dep_prec = termlistAdd (CLAIMS_dep_prec, CLAIM_Nisynch);
  CLAIMS_dep_prec = termlistAdd (CLAIMS_dep_prec, CLAIM_Alive);
  CLAIMS_dep_prec = termlistAdd (CLAIMS_dep_prec, CLAIM_Weakagree);
}

//! After compilation (so the user gets the first choice)
void
specialTermInitAfter (const System sys)
{
  Term SKE;

  langcons (AGENT_Alice, "Alice", TERM_Agent);
  langcons (AGENT_Bob, "Bob", TERM_Agent);
  langcons (AGENT_Charlie, "Charlie", TERM_Agent);
  langcons (AGENT_Dave, "Dave", TERM_Agent);
  langcons (AGENT_Eve, "Eve", TERM_Agent);
  langcons (AGENT_Simon, "Simon", TERM_Agent);
  langcons (AGENT_Pete, "Pete", TERM_Agent);

  knowledgeAddTerm (sys->know, AGENT_Alice);
  knowledgeAddTerm (sys->know, AGENT_Bob);
  knowledgeAddTerm (sys->know, AGENT_Charlie);
  knowledgeAddTerm (sys->know, AGENT_Dave);
  knowledgeAddTerm (sys->know, AGENT_Eve);
  knowledgeAddTerm (sys->know, AGENT_Simon);
  knowledgeAddTerm (sys->know, AGENT_Pete);

  // Make special Eve keys and add to initial knowledge
  SKE = makeTermEncrypt (AGENT_Eve, TERM_SK);
  knowledgeAddTerm (sys->know, SKE);
  symmEveKey (AGENT_Alice, AGENT_Eve);
  symmEveKey (AGENT_Bob, AGENT_Eve);
  symmEveKey (AGENT_Charlie, AGENT_Eve);
  symmEveKey (AGENT_Eve, AGENT_Alice);
  sys->untrusted = termlistAddNew (sys->untrusted, AGENT_Eve);
}

//! Determine whether this is a leaf construct with a ticket in it
int
isTicketTerm (Term t)
{
  if (t != NULL)
    {
      if (realTermLeaf (t))
	{
	  if (inTermlist (t->stype, TERM_Ticket))
	    {
	      return true;
	    }
	  else
	    {
	      if (realTermVariable (t))
		{
		  return isTicketTerm (t->subst);
		}
	    }
	}
    }
  return false;
}

//! Determine whether this is a term with a Ticket in it
int
hasTicketSubterm (Term t)
{
  // Doesn't work yet
  return true;
}
