/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv1)                 
 * @reference	RFC 2409,                                              
 *				Boyd C. and Mathuria A., Protocols for Authentication
 *				and Key Agreement
 * @variant		Quick mode (pfs), optional identities included         
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV1_QUICK__
#ifndef __ORACLE__
#include "common.h"
#endif

/* k(I,R) equals Ka from the spec */
#define HASH1i prf(k(I,R), mid, list, Ni, g(i), I, R)
#define HASH1r prf(k(R,I), mid, list, Ni, Gi, I, R)
#define HASH2i prf(k(I,R), mid, Ni, algo, Nr, Gr, I, R)
#define HASH2r prf(k(R,I), mid, Ni, algo, Nr, g(r), I, R)
#define HASH3i prf(k(I,R), mid, Ni, Nr)
#define HASH3r prf(k(R,I), mid, Ni, Nr)


protocol ikev1-quick(I, R)
{
	role I {
		fresh i, Ni, Ci, mid, list:	Nonce;
		var   Nr, Cr, algo:			Nonce;
		var   Gr:					Ticket;

		send_!1( I, R, mid, {HASH1i, list, Ni, g(i), I, R}k(I,R) );
		recv_!2( R, I, mid, {HASH2i, algo, Nr, Gr, I, R}k(I,R) );
		claim( I, Running, R, Ni, Nr, g(i), Gr );
		send_!3( I, R, mid, {HASH3i}k(I,R) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R, Ni, Nr, g(i), Gr );
				
	}

	role R {
		fresh  r, Nr, Cr, algo:		Nonce;
		var    Ni, Ci, mid, list:	Nonce;
		var    Gi:					Ticket;

		recv_!1( I, R, mid, {HASH1r, list, Ni, Gi, I, R}k(I,R) );
		claim( R, Running, I, Ni, Nr, Gi, g(r) );
		send_!2( R, I, mid, {HASH2r, algo, Nr, g(r), I, R}k(I,R) );
		recv_!3( I, R, mid, {HASH3r}k(I,R) );


		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Ni, Nr, Gi, g(r) );
				
	}
}
// TODO: Incorporate into various phase 1 protocols (see spec for adaptions)
// NOTE: If incorporated in phase 1, make sure to model with and without optional identities in msg 2 & 3
