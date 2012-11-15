/** HEADDOC
 * @protocol	OAKLEY
 * @reference	RFC 2412, 
 *				Boyd C. and Mathuria A., Protocols for Authentication and 
 *				Key Agreement
 * @description	OAKLEY is related to STS and allows for shared key 
 *				determination via authenticated Diffie-Hellman exchanges and
 *				provides perfect forward secrecy for the shared key.
 * @variant		Conservative mode with identity hiding
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __OAKLEY_CONSERVATIVE__
#ifndef __ORACLE__
#include "common.h"
#endif

#define Kpi prf(Zi)
#define Kpr prf(Zr)
#define Kir prf(Ni,Nr)


usertype String;
const OK, list, algo: String;


/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling Diffie-Hellman keys.
 */
protocol @executability(O) {
#define Gi g(i)
#define Gr g(r)
	role O {
		var i, r, Ni, Nr, Ci, Cr: Nonce;
		var I, R: Agent;

		// msg 5
		recv_!O1( O, O, {I, R, {Ni}pk(R)}Kpi );
		send_!O2( O, O, {I, R, {Ni}pk(R)}Kpr );

		// msg 6
		recv_!O3( O, O, {{Nr, Ni}pk(I), R, I, prf(Kir, R, I, Gr, g(i), algo)}Kpr );
		send_!O4( O, O, {{Nr, Ni}pk(I), R, I, prf(Kir, R, I, Gr, g(i), algo)}Kpi );

		// msg 7
		recv_!O5( O, O, {prf(Kir, I, R, g(i), Gr, algo)}Kpi );
		send_!O6( O, O, {prf(Kir, I, R, g(i), Gr, algo)}Kpr );

	}
#undef Gi
#undef Gr
}


protocol oakley-c(I, R)
{
	role I {
		fresh i, Ni, Ci:	Nonce;
		var   Nr, Cr:		Nonce;
		var   Gr:			Ticket;

		send_1( I, R, OK );
		recv_2( R, I, Cr );
		send_3( I, R, Ci, Cr, g(i), list );
		recv_4( R, I, Cr, Ci, Gr, algo );
		send_!5( I, R, Ci, Cr, g(i), {I, R, {Ni}pk(R)}Kpi );
		recv_!6( R, I, Cr, Ci, {{Nr, Ni}pk(I), R, I, prf(Kir, R, I, Gr, g(i), algo)}Kpi );
		send_!7( I, R, Ci, Cr, {prf(Kir, I, R, g(i), Gr, algo)}Kpi );

		/* SECURITY CLAIMS */
		claim( I, SKR, Kpi );
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r, Nr, Cr:	Nonce;
		var    Ni, Ci:		Nonce;
		var    Gi:			Ticket;

		recv_1( I, R, OK );
		send_2( R, I, Cr );
		recv_3( I, R, Ci, Cr, Gi, list );
		send_4( R, I, Cr, Ci, g(r), algo );
		recv_!5( I, R, Ci, Cr, Gi, {I, R, {Ni}pk(R)}Kpr );
		send_!6( R, I, Cr, Ci, {{Nr, Ni}pk(I), R, I, prf(Kir, R, I, g(r), Gi, algo)}Kpr );
		recv_!7( I, R, Ci, Cr, {prf(Kir, I, R, Gi, g(r), algo)}Kpr );

		/* SECURITY CLAIMS */
		claim( R, SKR, Kpr );

		claim( R, SKR, SKr );
		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}