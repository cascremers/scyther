/** HEADDOC
 * @protocol	SKEME
 * @reference	Krawczyk, H., SKEME: A Versatile Secure Key Exchange Mechanism
 *				for Internet,
 *				Boyd C. and Mathuria A., Protocols for Authentication and 
 *				Key Agreement
 * @description	SKEME is a set of protocols suitable for negotiation of 
 *				services in a general networked environment. The main 
 *				characteristics are forward secrecy, privacy and anonymity, 
 *				and DoS protection.
 * @variant		Fast rekeying protocol
**/

/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __SKEME_REKEY__
#ifndef __ORACLE__
#include "common.h"
#endif

/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling k(I,R) = k(R,I).
 */
protocol @executability(O) {
#define Gi g(i)
#define Gr g(r)
	role O {
		var Ni, Nr: Nonce;
		var I, R: Agent;

		// msg 2
		recv_!O1( O, O, prf(k(R,I), Ni, Nr, R, I) );
		send_!O2( O, O, prf(k(I,R), Ni, Nr, R, I) );

		// msg 3
		recv_!O3( O, O, prf(k(I,R), Nr, Ni, I, R) );
		send_!O4( O, O, prf(k(R,I), Nr, Ni, I, R) );

	}
#undef Gi
#undef Gr
}

protocol skeme-rekey(I, R)
{
	role I {
		fresh Ni:	Nonce;
		var   Nr:	Nonce;

		send_1( I, R, Ni );
		recv_!2( R, I, Nr, prf(k(I,R), Ni, Nr, R, I) );
		send_!3( I, R, prf(k(I,R), Nr, Ni, I, R) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  Nr:	Nonce;
		var    Ni:	Nonce;

		recv_1( I, R, Ni );
		send_!2( R, I, Nr, prf(k(I,R), Ni, Nr, R, I) );
		recv_!3( I, R, prf(k(I,R), Nr, Ni, I, R) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}