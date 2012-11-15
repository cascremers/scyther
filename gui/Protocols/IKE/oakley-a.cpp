/**
 * @protocol	OAKLEY
 * @reference	RFC 2412, 
 *				Boyd C. and Mathuria A., Protocols for Authentication and 
 *				Key Agreement
 * @description	OAKLEY is related to STS and allows for shared key 
 *				determination via authenticated Diffie-Hellman exchanges and
 *				provides perfect forward secrecy for the shared key.
 * @variant		Aggressive mode
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __OAKLEY__
#ifndef __ORACLE__
#include "common.h"
#endif


usertype String;
const list, algo: String;

protocol oakley-a(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		send_1( I, R, Ci, g(i), list, I, R, Ni, {I, R, Ni, g(i), list}sk(I) );
		recv_2( R, I, Cr, Ci, Gr, algo, R, I, Nr, Ni, {R, I, Nr, Ni, g(i), Gr, algo}sk(R) );
		send_3( I, R, Ci, Cr, g(i), algo, I, R, Ni, Nr, {I, R, Ni, Nr, g(i), Gr, algo}sk(I) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r, Nr, Cr:	Nonce;
		var    Ni, Ci:		Nonce;
		var    Gi:			Ticket;

		recv_1( I, R, Ci, Gi, list, I, R, Ni, {I, R, Ni, Gi, list}sk(I) );
		send_2( R, I, Cr, Ci, g(r), algo, R, I, Nr, Ni, {R, I, Nr, Ni, Gi, g(r), algo}sk(R) );
		recv_3( I, R, Ci, Cr, Gi, algo, I, R, Ni, Nr, {I, R, Ni, Nr, Gi, g(r), algo}sk(I) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}