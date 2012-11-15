/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv2)                 
 * @subprotocol IKE Create Child SA                                    
 * @reference	RFC 4306                                               
 * @variant		Supports perfect forward secrecy                       
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV2_CHILD__
#ifndef __ORACLE__
#include "common.h"
#endif


usertype SecurityAssociation;
const SA1 ,SA2, SA3: SecurityAssociation;

/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling k(I,R) = k(R,I).
 */
protocol @executability(O) {
#define Gi g(i)
#define Gr g(r)
	role O {
		var i, r, Ni, Nr: Nonce;
		var I, R: Agent;

		// msg 1
		recv_!O1( O, O, {SA3, Ni, g(i)}k(I,R) );
		send_!O2( O, O, {SA3, Ni, g(i)}k(R,I) );

		// msg 2
		recv_!O3( O, O, {SA3, Nr, Gr}k(R,I) );
		send_!O4( O, O, {SA3, Nr, Gr}k(I,R) );

	}
#undef Gi
#undef Gr
}

// Note: SPIs not modeled as they would lead to trivial attacks where the adversary 
// tampers with the SPIs (they are not subsequently authenticated)
protocol ikev2-child(I, R)
{

	role I {
		fresh i, Ni:	Nonce;
		var   Nr:		Nonce;
		var   Gr:		Ticket;

		/* IKE_SA_INIT */
		claim( I, Running, R,Ni,g(i) );
		send_!1( I, R, {SA3, Ni, g(i)}k(I,R) );
		recv_!2( R, I, {SA3, Nr, Gr}k(I,R) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R,Ni,g(i),Nr,Gr );
				
	}

	role R {
		fresh r, Nr:	Nonce;
		var   Ni:		Nonce;
		var   Gi:		Ticket;

		recv_!1( I, R, {SA3, Ni, Gi}k(R,I) );
		claim( R, Running, I,Ni,Gi,Nr,g(r) );
		send_!2( R, I, {SA3, Nr, g(r)}k(R,I) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I,Ni,Gi );
	}
}
