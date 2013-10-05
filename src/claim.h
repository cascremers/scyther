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

/**
 * ===============================================
 * NOTE:
 * The claim object structure is defined in role.h
 * ===============================================
 */

#ifndef CLAIMS
#define CLAIMS

int check_claim_nisynch (const System sys, const int i);
int check_claim_niagree (const System sys, const int i);
int arachne_claim_niagree (const System sys, const int claim_run,
			   const int claim_index);
int arachne_claim_nisynch (const System sys, const int claim_run,
			   const int claim_index);

int prune_claim_specifics (const System sys);
int add_claim_specifics (const System sys, const Claimlist cl, const
			 Roledef rd, int (*callback) (void));
void count_false_claim (const System sys);
int property_check (const System sys);
int claimStatusReport (const System sys, Claimlist cl);
int isClaimRelevant (const Claimlist cl);
int isClaimSignal (const Claimlist cl);

#endif
