/** HEADDOC
 * @protocol	Station-to-Station Protocol (STS)
 * @reference	Diffie W., van Oorschot P. C., and Wiener M. J., 
 *				Authentication and authenticated key exchange,
 *				Boyd C. and Mathuria A., Protocols for Authentication and 
 *				Key Agreement
 * @description	STS adds a digital signaure to the exchanged messages to 
 *				provide authentication for the Diffie-Hellman protocol. In 
 *				addition, the shared secret is used to provide further 
 *				assurances.
**/

#define __STS__
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
		var i, r: Nonce;
		var I, R: Agent;

		// msg 2
		recv_!O1( O, O, {{g(r), Gi}sk(R)}SKr );
		send_!O2( O, O, {{g(r), Gi}sk(R)}SKi );

		// msg 3
		recv_!O3( O, O,  {{g(i), Gr}sk(I)}SKi );
		send_!O4( O, O,  {{g(i), Gr}sk(I)}SKr );

	}
#undef Gi
#undef Gr
}


// It is not specified how the session key is derived from the ephemeral DH 
// secret Z; we use KDF(Z).
protocol sts-main(I, R)
{
	role I {
		fresh i:	Nonce;
		var   Gr:	Ticket;

		send_1( I, R, g(i) );
		recv_!2( R, I, Gr, {{Gr, g(i)}sk(R)}SKi );
		send_!3( I, R, {{g(i), Gr}sk(I)}SKi );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r:	Nonce;
		var    Gi:	Ticket;

		recv_1( I, R, Gi );
		send_!2( R, I, g(r), {{g(r), Gi}sk(R)}SKr );
		recv_!3( I, R, {{Gi, g(r)}sk(I)}SKr );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}