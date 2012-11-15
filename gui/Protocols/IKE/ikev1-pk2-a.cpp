/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv1)                 
 * @reference	RFC 2409,                                              
  *				Boyd C. and Mathuria A., Protocols for Authentication  
 *				and Key Agreement                                      
 * @variant		Revised public key authentication (aggressive mode)    
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
#define Nei prf(Ni, Ci)
#define Ner prf(Nr, Cr)


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

		// msg 2
		recv_!O1( O, O, HASH_Rr );
		send_!O2( O, O, HASH_Ri );

		// msg 3
		recv_!O3( O, O, HASH_Ir );
		send_!O4( O, O, HASH_Ii );

	}
#undef Gi
#undef Gr
}


protocol ikev1-pk2-a(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		send_1( I, R, Ci, list, {Ni}pk(R), {g(i)}Nei, {I}Nei );
		recv_!2( R, I, Ci, Cr, algo, {Nr}pk(I), {Gr}Ner, {R}Ner,  HASH_Ri );
		claim( I, Running, R, g(i),Gr,Ci,Cr,Ni,Nr );
		send_!3( I, R, Ci, Cr, HASH_Ii );
		
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

		recv_1( I, R, Ci, list, {Ni}pk(R), {Gi}Nei, {I}Nei );
		claim( R, Running, I, Gi,g(r),Ci,Cr,Ni,Nr );
		send_!2( R, I, Ci, Cr, algo, {Nr}pk(I), {g(r)}Ner, {R}Ner,  HASH_Rr );
		recv_!3( I, R, Ci, Cr, HASH_Ir );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Gi,g(r),Ci,Cr,Ni,Nr );
				
	}
}
