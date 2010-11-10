/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007 Cas Cremers
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

/* externally used:
 */

Term TERM_Agent;
Term TERM_Function;
Term TERM_Hidden;
Term TERM_Type;
Term TERM_Nonce;
Term TERM_Ticket;
Term TERM_Data;

Term TERM_Claim;
Term CLAIM_Secret;
Term CLAIM_Nisynch;
Term CLAIM_Niagree;
Term CLAIM_Empty;
Term CLAIM_Reachable;

Term AGENT_Alice;
Term AGENT_Bob;
Term AGENT_Charlie;
Term AGENT_Dave;
Term AGENT_Eve;
Term TERM_PK;
Term TERM_SK;
Term TERM_K;

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

  langcons (TERM_Agent, "Agent", TERM_Type);
  langcons (TERM_Function, "Function", TERM_Type);
  langcons (TERM_Nonce, "Nonce", TERM_Type);
  langcons (TERM_Ticket, "Ticket", TERM_Type);
  langcons (TERM_Data, "Data", TERM_Type);

  langcons (CLAIM_Secret, "Secret", TERM_Claim);
  langcons (CLAIM_Nisynch, "Nisynch", TERM_Claim);
  langcons (CLAIM_Niagree, "Niagree", TERM_Claim);
  langcons (CLAIM_Empty, "Empty", TERM_Claim);
  langcons (CLAIM_Reachable, "Reachable", TERM_Claim);

  /* Define default PKI using PK/SK/K */
  langcons (TERM_PK, "pk", TERM_Function);
  langcons (TERM_SK, "sk", TERM_Function);
  langcons (TERM_K, "k", TERM_Function);
  knowledgeAddInverse (sys->know, TERM_PK, TERM_SK);
  knowledgeAddTerm (sys->know, TERM_PK);

  /* Construct a list of claims that depend on prec being not-empty */
  /* basically all authentication claims */
  CLAIMS_dep_prec = termlistAdd (NULL, CLAIM_Niagree);
  CLAIMS_dep_prec = termlistAdd (CLAIMS_dep_prec, CLAIM_Nisynch);

}

//! After compilation (so the user gets the first choice)
void
specialTermInitAfter (const System sys)
{
  langcons (AGENT_Alice, "Alice", TERM_Agent);
  langcons (AGENT_Bob, "Bob", TERM_Agent);
  langcons (AGENT_Charlie, "Charlie", TERM_Agent);
  langcons (AGENT_Dave, "Dave", TERM_Agent);
  langcons (AGENT_Eve, "Eve", TERM_Agent);

  knowledgeAddTerm (sys->know, AGENT_Alice);
  knowledgeAddTerm (sys->know, AGENT_Bob);
  knowledgeAddTerm (sys->know, AGENT_Charlie);
  knowledgeAddTerm (sys->know, AGENT_Dave);
  knowledgeAddTerm (sys->know, AGENT_Eve);

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
