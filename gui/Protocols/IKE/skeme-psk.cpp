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
 * @variant		Basic mode with pre-shared keys and correct application of DH
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __SKEME__
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
		var i, r: Nonce;
		var I, R: Agent;

		// msg 2
		recv_!O1( O, O, prf(k(R,I), Gi, g(r), R, I) );
		send_!O2( O, O, prf(k(I,R), Gi, g(r), R, I) );

		// msg 3
		recv_!O3( O, O, prf(k(I,R), Gr, g(i), I, R) );
		send_!O4( O, O, prf(k(R,I), Gr, g(i), I, R) );

	}
#undef Gi
#undef Gr
}


protocol skeme-psk(I, R)
{
	role I {
		fresh i:	Nonce;
		var   Gr:	Ticket;

		send_1( I, R, g(i) );
		recv_!2( R, I, Gr, prf(k(I,R), g(i), Gr, R, I) );
		send_!3( I, R, prf(k(I,R), Gr, g(i), I, R) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r:	Nonce;
		var    Gi:	Ticket;

		recv_1( I, R, Gi );
		send_!2( R, I, g(r), prf(k(R,I), Gi, g(r), R, I) );
		recv_!3( I, R, prf(k(R,I), g(r), Gi, I, R) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}