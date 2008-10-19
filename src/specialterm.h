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

#ifndef SPECIALTERM
#define SPECIALTERM

#include "term.h"
#include "termlist.h"
#include "system.h"

/*
 * Some declarations in spercialterm.c
 */

extern Term TERM_Agent;
extern Term TERM_Function;
extern Term TERM_Hidden;
extern Term TERM_Type;
extern Term TERM_Nonce;
extern Term TERM_Ticket;
extern Term TERM_SessionKey;
extern Term TERM_Marker;
extern Term TERM_Data;
extern Term TERM_Compromise;

extern Term TERM_Claim;
extern Term CLAIM_Secret;
extern Term CLAIM_Nisynch;
extern Term CLAIM_Niagree;
extern Term CLAIM_Empty;
extern Term CLAIM_Reachable;
extern Term CLAIM_SID;

extern Term AGENT_Alice;
extern Term AGENT_Bob;
extern Term AGENT_Charlie;
extern Term AGENT_Dave;
extern Term AGENT_Eve;
extern Term TERM_PK;
extern Term TERM_SK;
extern Term TERM_K;

extern Termlist CLAIMS_dep_prec;

void specialTermInit (const System sys);
void specialTermInitAfter (const System sys);
int isTicketTerm (Term t);
int hasTicketSubterm (Term t);

#endif
