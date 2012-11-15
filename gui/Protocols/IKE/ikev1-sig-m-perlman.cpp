/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv1)                 
 * @reference	RFC 2409,                                              
 *				Boyd C. and Mathuria A., Protocols for Authentication  
 *				and Key Agreement                                      
 * @variant		Digital signature authentication (aggressive mode) with
 *				a modification suggested by Perlman et al.             
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV1__
#ifndef __ORACLE__
#include "common.h"
#endif

#define SKEYIDi prf(Ni,Nr,Zi)
#define SKEYIDr prf(Ni,Nr,Zr)
#define HASH_Ii prf(Ni, Nr, Zi, g(i), Gr, Ci, Cr, list, I)
#define HASH_Ir prf(Ni, Nr, Zr, Gi, g(r), Ci, Cr, list, I)
#define HASH_Ri prf(Ni, Nr, Zi, Gr, g(i), Cr, Ci, list, R)
#define HASH_Rr prf(Ni, Nr, Zr, g(r), Gi, Cr, Ci, list, R)

usertype String;
const list, algo: String;


/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling Diffie-Hellman keys.
 */
protocol @executability(O) {
#define Gi g(i)
#define Gr g(r)
	role O {
		var i, r, Ni, Nr, Ci, Cr: Nonce;
		var I, R: Agent;

		// msg 4
		recv_!O1( O, O, {R, {HASH_Rr}sk(R)}SKr );
		send_!O2( O, O, {R, {HASH_Ri}sk(R)}SKi );

		// msg 5
		recv_!O3( O, O, {I, {HASH_Ii}sk(I)}SKi );
		send_!O4( O, O, {I, {HASH_Ir}sk(I)}SKr );

	}
#undef Gi
#undef Gr
}


protocol ikev1-sig-m-perlman(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		send_1( I, R, Ci, list );
		recv_2( R, I, Ci, Cr, algo );
		send_3( I, R, Ci, Cr, g(i), Ni );
		recv_!4( R, I, Ci, Cr, Gr, Nr, {R, {HASH_Ri}sk(R)}SKi );
		claim( I, Running, R, Ni, Nr, g(i), Gr, Ci, Cr );
		send_!5( I, R, Ci, Cr, {I, {HASH_Ii}sk(I)}SKi );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R, Ni, Nr, g(i), Gr, Ci, Cr );
				
	}

	role R {
		fresh  r, Nr, Cr:	Nonce;
		var    Ni, Ci:		Nonce;
		var    Gi:			Ticket;

		recv_1( I, R, Ci, list );
		send_2( R, I, Ci, Cr, algo );
		recv_3( I, R, Ci, Cr, Gi, Ni );
		claim( R, Running, I, Ni, Nr, Gi, g(r), Ci, Cr );
		send_!4( R, I, Ci, Cr, g(r), Nr, {R, {HASH_Rr}sk(R)}SKr );
		recv_!5( I, R, Ci, Cr, {I, {HASH_Ir}sk(I)}SKr );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Ni, Nr, Gi, g(r), Ci, Cr );
				
	}
}
