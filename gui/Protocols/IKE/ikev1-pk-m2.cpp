/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv1)                 
 * @reference	RFC 2409,                                              
 *				Boyd C. and Mathuria A., Protocols for Authentication  
 *				and Key Agreement                                      
 * @variant		Public key authentication (main mode),                 
 *				Nonce and id encrypted together                        
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV1__
#ifndef __ORACLE__
#include "common.h"
#endif

#define SKEYID prf(H(Ni,Nr),Ci,Cr)
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
		recv_!O1( O, O, {HASH_Ii}SKi );
		send_!O2( O, O, {HASH_Ir}SKr );

		// msg 6
		recv_!O3( O, O, {HASH_Rr}SKr );
		send_!O4( O, O, {HASH_Ri}SKi );

	}
#undef Gi
#undef Gr
}

protocol ikev1-pk-m2(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		send_1( I, R, Ci, list );
		recv_2( R, I, Ci, Cr, algo );
		send_3( I, R, Ci, Cr, g(i), {I,Ni}pk(R) );
		recv_4( R, I, Ci, Cr, Gr, {R,Nr}pk(I) );
		claim( I, Running, R, g(i),Gr,Ci,Cr,Ni,Nr );
		send_!5( I, R, Ci, Cr, {HASH_Ii}SKi );
		recv_!6( R, I, Ci, Cr, {HASH_Ri}SKi );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R, g(i),Gr,Ci,Cr,Ni,Nr );
				
	}

	role R {
		fresh  r, Nr, Cr:	Nonce;
		var    Ni, Ci:		Nonce;
		var    Gi:			Ticket;

		recv_1( I, R, Ci, list );
		send_2( R, I, Ci, Cr, algo );
		recv_3( I, R, Ci, Cr, Gi, {I,Ni}pk(R) );
		send_4( R, I, Ci, Cr, g(r), {R,Nr}pk(I) );
		recv_!5( I, R, Ci, Cr, {HASH_Ir}SKr );
		claim( R, Running, I, Gi,g(r),Ci,Cr,Ni,Nr );
		send_!6( R, I, Ci, Cr, {HASH_Rr}SKr );


		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Gi,g(r),Ci,Cr,Ni,Nr );
				
	}
}
