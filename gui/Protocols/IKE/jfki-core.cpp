/** HEADDOC
 * @protocol	Just Fast Keying
 * @reference	Aiello et al., Just Fast Keying: Key Agreement In A Hostile
 *				Internet
 * @description	
 * @variant		Core cryptographic protocol of JFKi
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __JFK_CORE__
#ifndef __ORACLE__
#include "common.h"
#endif


protocol jfki-core(I, R)
{
	role I {
		fresh i, Ni:	Nonce;
		var   Nr:		Nonce;
		var   Gr:		Ticket;

		send_1( I, R, Ni, I, g(i) );
		recv_2( R, I, Nr, Ni, R, Gr, {Nr, Ni, Gr, g(i), I}sk(R) );
		send_3( I, R, Nr, Ni, {Nr, Ni, Gr, g(i), R}sk(I) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh r, Nr:	Nonce;
		var   Ni:		Nonce;
		var   Gi:		Ticket;

		recv_1( I, R, Ni, I, Gi );
		send_2( R, I, Nr, Ni, R, g(r), {Nr, Ni, g(r), Gi, I}sk(R) );
		recv_3( I, R, Nr, Ni, {Nr, Ni, g(r), Gi, R}sk(I) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}