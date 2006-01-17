#ifndef SPECIALTERM
#define SPECIALTERM

#include "term.h"
#include "termlist.h"

/*
 * Some declarations in spercialterm.c
 */

extern Term TERM_Agent;
extern Term TERM_Function;
extern Term TERM_Hidden;
extern Term TERM_Type;
extern Term TERM_Nonce;
extern Term TERM_Ticket;
extern Term TERM_Data;

extern Term TERM_Claim;
extern Term CLAIM_Secret;
extern Term CLAIM_Nisynch;
extern Term CLAIM_Niagree;
extern Term CLAIM_Empty;
extern Term CLAIM_Reachable;

extern Termlist CLAIMS_dep_prec;

int isTicketTerm (Term t);
int hasTicketSubterm (Term t);

#endif
