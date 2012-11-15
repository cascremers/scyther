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
 * @variant		Basic mode
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 * Note: May use the same oracles as sts
**/
#define __SKEME__
#ifndef __ORACLE__
#include "common.h"
#endif
#define Kir prf(Ni,Nr)


protocol skeme-basic(I, R)
{
	role I {
		fresh i, Ni:	Nonce;
		var   Nr:		Nonce;
		var   Gr:		Ticket;

		send_1( I, R, {I, Ni}pk(R), g(i) );
		recv_2( R, I, {Nr}pk(I), Gr, prf(Kir, g(i), Gr, R, I) );
		send_3( I, R, prf(Kir, Gr, g(i), I, R) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r, Nr:	Nonce;
		var    Ni:		Nonce;
		var    Gi:		Ticket;

		recv_1( I, R, {I, Ni}pk(R), Gi );
		send_2( R, I, {Nr}pk(I), g(r), prf(Kir, Gi, g(r), R, I) );
		recv_3( I, R, prf(Kir, g(r), Gi, I, R) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}