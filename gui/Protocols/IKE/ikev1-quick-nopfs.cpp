/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv1)                 
 * @reference	RFC 2409,                                              
 *				Boyd C. and Mathuria A., Protocols for Authentication
 *				and Key Agreement
 * @variant		Quick mode (no pfs), without optional identities       
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV1_QUICK_NOPFS__
#ifndef __ORACLE__
#include "common.h"
#endif

/* k(I,R)=k(R,I) equal Ka from the spec */
#define HASH1i prf(k(I,R), mid, list, Ni)
#define HASH1r prf(k(R,I), mid, list, Ni)
#define HASH2i prf(k(I,R), mid, Ni, algo, Nr)
#define HASH2r prf(k(R,I), mid, Ni, algo, Nr)
#define HASH3i prf(k(I,R), mid, Ni, Nr)
#define HASH3r prf(k(R,I), mid, Ni, Nr)

usertype String;
const list, algo: String;

/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling k(I,R) = k(R,I).
 */
protocol @executability(O) {
	role O {
		var mid, Ni, Nr: Nonce;
		var I, R: Agent;

		// msg 1
		recv_!O1( O, O, {HASH1i, list, Ni}k(I,R) );
		send_!O2( O, O, {HASH1r, list, Ni}k(R,I) );

		// msg 2
		recv_!O3( O, O, {HASH2r, algo, Nr}k(R,I) );
		send_!O4( O, O, {HASH2i, algo, Nr}k(I,R) );

		// msg 3
		recv_!O5( O, O, {HASH3i}k(I,R) );
		send_!O6( O, O, {HASH3r}k(R,I) );

	}
}


protocol ikev1-quick-nopfs(I, R)
{
	role I {
		fresh i, Ni, Ci, mid:	Nonce;
		var   Nr, Cr:			Nonce;

		send_!1( I, R, mid, {HASH1i, list, Ni}k(I,R) );
		recv_!2( R, I, mid, {HASH2i, algo, Nr}k(I,R) );
		claim( I, Running, R, Ni, Nr );
		send_!3( I, R, mid, {HASH3i}k(I,R) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R, Ni, Nr );
				
	}

	role R {
		fresh  r, Nr, Cr:	Nonce;
		var    Ni, Ci, mid:	Nonce;

		recv_!1( I, R, mid, {HASH1r, list, Ni}k(R,I) );
		claim( R, Running, I, Ni, Nr );
		send_!2( R, I, mid, {HASH2r, algo, Nr}k(R,I) );
		recv_!3( I, R, mid, {HASH3r}k(R,I) );


		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Ni, Nr );
				
	}
}
// TODO: Incorporate into various phase 1 protocols (see spec for adaptions)
// NOTE: If incorporated in phase 1, make sure to model with and without optional identities in msg 2 & 3 
