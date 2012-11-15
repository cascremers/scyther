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
 * @variant		Variant proposed by Boyd et al to prevent unknown key-share
 *				attacks.
**/

#define __STS__
#ifndef __ORACLE__
#include "common.h"
#endif

// It is not specified how the session key is derived from the ephemeral DH 
// secret Z; we use KDF(Z).
protocol sts-modified(I, R)
{
	role I {
		fresh i:	Nonce;
		var   Gr:	Ticket;

		send_1( I, R, g(i) );
		recv_2( R, I, Gr, {Gr, g(i), I}sk(R) );
		send_3( I, R, {g(i), Gr, R}sk(I) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r:	Nonce;
		var    Gi:	Ticket;

		recv_1( I, R, Gi );
		send_2( R, I, g(r), {g(r), Gi, I}sk(R) );
		recv_3( I, R, {Gi, g(r), R}sk(I) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}