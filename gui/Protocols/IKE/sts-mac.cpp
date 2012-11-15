/** HEADDOC
 * @protocol	Station-to-Station Protocol (STS)
 * @reference	Diffie W., van Oorschot P. C., and Wiener M. J., 
 *				Authentication and authenticated key exchange,
 *				Boyd C. and Mathuria A., Protocols for Authentication and 
 *				Key Agreement
 * @description	STS adds a diGital signaure to the exchanged messages to 
 *				provide authentication for the Diffie-Hellman protocol. In 
 *				addition, the shared secret is used to provide further 
 *				assurances.
 * @variant		Variant using MACs
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

		// msg 2
		recv_!O1( O, O, MAC(Zr, g(r), Gi) );
		send_!O2( O, O, MAC(Zi, g(r), Gi) );

		// msg 3
		recv_!O3( O, O,  MAC(Zi, Gi, g(r)) );
		send_!O4( O, O,  MAC(Zr, Gi, g(r)) );

	}
#undef Gi
#undef Gr
}

// It is not specified how the session key is derived from the ephemeral DH 
// secret Z; we use KDF(Z).
protocol sts-mac(I, R)
{
	role I {
		fresh i:	Nonce;
		var   Gr:	Ticket;

		send_1( I, R, g(i) );
		recv_!2( R, I, Gr, {Gr, g(i)}sk(R), MAC(Zi, Gr, g(i)) );
		send_!3( I, R, {g(i), Gr}sk(I), MAC(Zi, g(i), Gr) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r:	Nonce;
		var    Gi:	Ticket;

		recv_1( I, R, Gi );
		send_!2( R, I, Gi, {g(r), Gi}sk(R), MAC(Zr, g(r), Gi) );
		recv_!3( I, R, {Gi, g(r)}sk(I), MAC(Zr, Gi, g(r)) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}