/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv1)                 
 * @reference	RFC 2409,                                              
 *				Boyd C. and Mathuria A., Protocols for Authentication  
 *				and Key Agreement                                      
 * @variant		Pre-shared key authentication (main mode) incorporating
 *				a fix by Perlman et. al.                               
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV1_PSK__
#ifndef __ORACLE__
#include "common.h"
#endif

#define HASH_Ii prf(k(I,R), Ni, Nr, g(i), Gr, Ci, Cr, list, I)
#define HASH_Ir prf(k(R,I), Ni, Nr, Gi, g(r), Ci, Cr, list, I)
#define HASH_Ri prf(k(I,R), Ni, Nr, Gr, g(i), Cr, Ci, list, R)
#define HASH_Rr prf(k(R,I), Ni, Nr, g(r), Gi, Cr, Ci, list, R)


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
		recv_!O1( O, O, {I, HASH_Ii}Zi );
		send_!O2( O, O, {I, HASH_Ir}Zr );

		// msg 6
		recv_!O3( O, O, {R, HASH_Rr}Zr );
		send_!O4( O, O, {R, HASH_Ri}Zi );

	}
#undef Gi
#undef Gr
}


protocol ikev1-psk-m-perlman(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		send_1( I, R, Ci, list );
		recv_2( R, I, Ci, Cr, algo );
		send_3( I, R, Ci, Cr, g(i), Ni );
		recv_4( R, I, Ci, Cr, Gr, Nr );
		claim( I, Running, R, Ni, Nr, g(i), Gr, Ci, Cr );
		send_!5( I, R, Ci, Cr, {I, HASH_Ii}Zi );
		recv_!6( R, I, Ci, Cr, {R, HASH_Ri}Zi );
		
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
		send_4( R, I, Ci, Cr, g(r), Nr );
		recv_!5( I, R, Ci, Cr, {I, HASH_Ir}Zr );
		claim( R, Running, I, Ni, Nr, Gi, g(r), Ci, Cr );
		send_!6( R, I, Ci, Cr, {R, HASH_Rr}Zr );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Ni, Nr, Gi, g(r), Ci, Cr );
				
	}
}
