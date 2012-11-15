/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv2)                 
 * @reference	RFC 4306                                               
 * @variant		Initiator authenticates itself using digital signatures
 *				while responder uses message authentication codes.     
 *				Includes optional payloads                             
 **********************************************************************/

/**
 * MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
 */

#define __IKEV2__
#ifndef __ORACLE__
#include "common.h"
#endif

#define AUTHii {SPIi, O, SA1, g(i), Ni, Nr, prf(SKi, I)}sk(I)
#define AUTHir {SPIi, O, SA1, Gi, Ni, Nr, prf(SKr, I)}sk(I)
#define AUTHri MAC(k(I,R), SPIi, SPIr, SA1, Gr, Nr, Ni, prf(SKi, R))
#define AUTHrr MAC(k(R,I), SPIi, SPIr, SA1, g(r), Nr, Ni, prf(SKr, R))


usertype Number, SecurityAssociation, TrafficSelector;
const O: Number;
const SA1 ,SA2, SA3: SecurityAssociation;
const TSi, TSr: TrafficSelector;

/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling Diffie-Hellman keys.
 */
protocol @executability(E) {
#define Gi g(i)
#define Gr g(r)
	role E {
		var i, r, Ni, Nr, SPIi, SPIr: Nonce;
		var I, R: Agent;

		// msg 3
		recv_!E1( E, E, {I, R, AUTHii, SA2, TSi, TSr}SKi );
		send_!E2( E, E, {I, R, AUTHir, SA2, TSi, TSr}SKr );

		// msg 4
		recv_!E3( E, E, {R, AUTHrr, SA2, TSi, TSr}SKr );
		send_!E4( E, E, {R, AUTHri, SA2, TSi, TSr}SKi );

	}
#undef Gi
#undef Gr
}


protocol ikev2-sigtomac(I, R)
{
	role I {
		fresh i, Ni, SPIi:	Nonce;
		var   Nr, SPIr:		Nonce;
		var   Gr:			Ticket;


		/* IKE_SA_INIT */
		send_1( I, R, SPIi, O, SA1, g(i), Ni );
		recv_2( R, I, SPIi, SPIr, SA1, Gr, Nr );

		/* IKE_AUTH */
		claim( I, Running, R,g(i),Gr,Ni,Nr );
		send_!3( I, R, SPIi, SPIr, {I, R, AUTHii, SA2, TSi, TSr}SKi );
		recv_!4( R, I, SPIi, SPIr, {R, AUTHri, SA2, TSi, TSr}SKi );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R,g(i),Gr,Ni,Nr );
				
	}

	role R {
		fresh r, Nr, SPIr:	Nonce;
		var   Ni, SPIi:		Nonce;
		var   Gi:			Ticket;


		/* IKE_SA_INIT */
		recv_1( I, R, SPIi, O, SA1, Gi, Ni );
		send_2( R, I, SPIi, SPIr, SA1, g(r), Nr );

		/* IKE_AUTH */
		recv_!3( I, R, SPIi, SPIr, {I, R, AUTHir, SA2, TSi, TSr}SKr );
		claim( R, Running, I,Gi,g(r),Ni,Nr );
		send_!4( R, I, SPIi, SPIr, {R, AUTHrr, SA2, TSi, TSr}SKr );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I,Gi,g(r),Ni,Nr );
	}
}
