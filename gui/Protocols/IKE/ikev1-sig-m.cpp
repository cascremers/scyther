/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv1)                 
 * @reference	RFC 2409,                                              
 *				Boyd C. and Mathuria A., Protocols for Authentication  
 *				and Key Agreement                                      
 * @variant		Digital signature authentication (aggressive mode)     
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV1__
#ifndef __ORACLE__
#include "common.h"
#endif

#define HDR (Ci,Cr)
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

		// msg 5
		recv_!O1( O, O, {I, {HASH_Ii}sk(I)}SKi );
		send_!O2( O, O, {I, {HASH_Ir}sk(I)}SKr );

		// msg 6
		recv_!O3( O, O, {R, {HASH_Rr}sk(R)}SKr );
		send_!O4( O, O, {R, {HASH_Ri}sk(R)}SKi );

	}
#undef Gi
#undef Gr
}

protocol ikev1-sig-m(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		send_1( I, R, Ci, list );
		recv_2( R, I, HDR, algo );
		send_3( I, R, HDR, g(i), Ni );
		recv_4( R, I, HDR, Gr, Nr );
		claim( I, Running, R, Ni, Nr, g(i), Gr, Ci, Cr );
		send_!5( I, R, HDR, {I, {HASH_Ii}sk(I)}SKi );
		recv_!6( R, I, HDR, {R, {HASH_Ri}sk(R)}SKi );

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
		send_2( R, I, HDR, algo );
		recv_3( I, R, HDR, Gi, Ni );
		send_4( R, I, HDR, g(r), Nr );
		recv_!5( I, R, HDR, {I, {HASH_Ir}sk(I)}SKr );
		claim( R, Running, I, Ni, Nr, Gi, g(r), Ci, Cr );
		send_!6( R, I, HDR, {R, {HASH_Rr}sk(R)}SKr );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Ni, Nr, Gi, g(r), Ci, Cr );
				
	}
}
