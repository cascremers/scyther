/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv2)                 
 * @subprotocol IKE Create Child SA                                    
 * @reference	RFC 4306                                               
 * @variant		No perfect forward secrecy support                     
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV2_CHILD_NOPFS__
#ifndef __ORACLE__
#include "common.h"
#endif

const SA3: Nonce;

/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling k(I,R) = k(R,I).
 */
protocol @executability(O) {
	role O {
		var Ni, Nr: Nonce;
		var I, R: Agent;

		// msg 1
		recv_!O1( O, O, {SA3, Ni}k(I,R) );
		send_!O2( O, O, {SA3, Ni}k(R,I) );

		// msg 2
		recv_!O3( O, O, {SA3, Nr}k(R,I) );
		send_!O4( O, O, {SA3, Nr}k(I,R) );

	}
}


protocol ikev2-child-nopfs(I, R)
{

	role I {
		fresh Ni:	Nonce;
		var   Nr:	Nonce;

		/* IKE_SA_INIT */
		claim( I, Running, R,Ni );
		send_!1( I, R, {SA3, Ni}k(I,R) );
		recv_!2( R, I, {SA3, Nr}k(I,R) );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R,Ni,Nr );

	}

	role R {
		fresh Nr:	Nonce;
		var   Ni:	Nonce;

		recv_!1( I, R, {SA3, Ni}k(R,I) );
		claim( R, Running, I,Ni,Nr );
		send_!2( R, I, {SA3, Nr}k(R,I) );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I,Ni );
	}
}
