/** HEADDOC
 * @protocol	Just Fast Keying
 * @reference	Aiello et al., Just Fast Keying: Key Agreement In A Hostile
 *				Internet
 * @description	
 * @variant		Core cryptographic protocol of JFKr
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __JFK_CORE__
#ifndef __ORACLE__
#include "common.h"
#endif

/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling Diffie-Hellman keys.
 */
protocol @executability(O) {
#define Gi g(i)
#define Gr g(r)
	role O {
		var i, r, Ni, Nr: Nonce;
		var I, R: Agent;

		// msg 3
		recv_!O1( O, O, H(SKr, Nr, Ni, R) );
		send_!O2( O, O, H(SKi, Nr, Ni, R) );

		// msg 4
		recv_!O3( O, O, H(SKi, Nr, Ni, I) );
		send_!O4( O, O, H(SKr, Nr, Ni, I) );

	}
#undef Gi
#undef Gr
}


// Abstractions: same key for ENC, MAC
protocol jfkr-core(I, R)
{
	role I {
		fresh i, Ni:	Nonce;
		var   Nr, Gr:	Ticket;

		send_1( I, R, Ni, g(i) );
		recv_!2( R, I, Nr, Ni, R, Gr, {Nr, Ni, Gr, g(i)}sk(R), H(SKi, Nr, Ni, R) );
		send_!3( I, R, Nr, Ni, I, {Nr, Ni, Gr, g(i)}sk(I), H(SKi, Nr, Ni, I) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r, Nr:	Nonce;
		var    Ni, Gi:	Ticket;

		recv_1( I, R, Ni, Gi );
		send_!2( R, I, Nr, Ni, R, g(r), {Nr, Ni, g(r), Gi}sk(R), H(SKr, Nr, Ni, R) );
		recv_!3( I, R, Nr, Ni, I, {Nr, Ni, g(r), Gi}sk(I), H(SKr, Nr, Ni, I) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}