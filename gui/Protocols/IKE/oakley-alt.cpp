/** HEADDOC
 * @protocol	OAKLEY
 * @reference	RFC 2412, 
 *				Boyd C. and Mathuria A., Protocols for Authentication and 
 *				Key Agreement
 * @description	OAKLEY is related to STS and allows for shared key 
 *				determination via authenticated Diffie-Hellman exchanges and
 *				provides perfect forward secrecy for the shared key.
 * @variant		Alternative variant to prevent user identity disclosure
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __OAKLEY__
#ifndef __ORACLE__
#include "common.h"
#endif
#define AK prf(Ni,Nr)


usertype String;
const list, algo: String;

protocol oakley-alt(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		// NOTE: pk(R) is sent in plain so that the recipient knows which decryption key to use
		// In the specification, there is a distinction between the R in pk(R) and the encrypted R
		send_1( I, R, Ci, g(i), list, pk(R), {I, R, Ni}pk(R) );
		recv_2( R, I, Cr, Ci, Gr, algo, {R, I, Nr}pk(I), prf(AK, R, I, Gr, g(i), algo) );
		send_3( I, R, Ci, Cr, prf(AK, I, R, g(i), Gr, algo) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r, Nr, Cr:	Nonce;
		var    Ni, Ci:		Nonce;
		var    Gi:			Ticket;

		recv_1( I, R, Ci, Gi, list, pk(R), {I, R, Ni}pk(R) );
		send_2( R, I, Cr, Ci, g(r), algo, {R, I, Nr}pk(I), prf(AK, R, I, g(r), Gi, algo) );
		recv_3( I, R, Ci, Cr, prf(AK, I, R, Gi, g(r), algo) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}