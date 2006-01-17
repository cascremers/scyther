#include <stdlib.h>
#include <stdio.h>
#include "term.h"
#include "termlist.h"
#include "compiler.h"

/*
 * Some macros
 */
#define langhide(x,y) x = levelConst(symbolSysConst(" _" y "_ "))
#define langtype(x,y) x->stype = termlistAdd(x->stype,y);
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

  /* Construct a list of claims that depend on prec being not-empty */
  /* basically all authentication claims */
  CLAIMS_dep_prec = termlistAdd (NULL, CLAIM_Niagree);
  CLAIMS_dep_prec = termlistAdd (CLAIMS_dep_prec, CLAIM_Nisynch);

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
