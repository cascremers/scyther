/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv2)                 
 * @reference	RFC 4306                                               
 * @variant		Combination of signature authenticated IKEv2 and       
 *				CREATE_CHILD_SA, includes optional payloads            
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
#define AUTHri {SPIi, SPIr, SA1, Gr, Nr, Ni, prf(SKi, R)}sk(R)
#define AUTHrr {SPIi, SPIr, SA1, g(r), Nr, Ni, prf(SKr, R)}sk(R)
#define KEYMATi KDF(Ni, Nr, Zi, h(Gt,j), Mi, Mr)
#define KEYMATr KDF(Ni, Nr, Zr, h(Gi,t), Mi, Mr)


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
		var i, j, r, t, Mi, Ni, Mr, Nr, SPIi, SPIr: Nonce;
		var I, R: Agent;

		// msg 3
		recv_!E1( E, E, {I, R, AUTHii, SA2, TSi, TSr}SKi );
		send_!E2( E, E, {I, R, AUTHir, SA2, TSi, TSr}SKr );

		// msg 4
		recv_!E3( E, E, {R, AUTHrr, SA2, TSi, TSr}SKr );
		send_!E4( E, E, {R, AUTHri, SA2, TSi, TSr}SKi );

		// msg 5
		recv_!E5( E, E, {SA3, Mi, g(j), TSi, TSr}SKi );
		send_!E6( E, E, {SA3, Mi, g(j), TSi, TSr}SKr );

		// msg 6
		recv_!E7( E, E, {SA3, Mr, g(t), TSi, TSr}SKr );
		send_!E8( E, E, {SA3, Mr, g(t), TSi, TSr}SKr );
	}
#undef Gi
#undef Gr
}
protocol @ora(S) {
#define Gi g(i)
#define Gj g(j)
#define Gr g(r)
#define Gt g(t)
	role S {
		var i, j, r, t, Mi, Ni, Mr, Nr, SPIi, SPIr: Nonce;

		recv_!S1( S, S, KDF(Ni, Nr, Zi, h(Gt,j), Mi, Mr) );
		send_!S2( S, S, KDF(Ni, Nr, Zr, h(Gj,t), Mi, Mr) );
	}
#undef Gi
#undef Gj
#undef Gr
#undef Gt
}


protocol ikev2-sig-child(I, R)
{
	role I {
		fresh i, j, Ni, Mi, SPIi:	Nonce;
		var   Nr, Mr, SPIr:			Nonce;
		var   Gr, Gt:				Ticket;


		/* IKE_SA_INIT */
		send_1( I, R, SPIi, O, SA1, g(i), Ni );
		recv_2( R, I, HDR, SA1, Gr, Nr );

		/* IKE_AUTH */
		send_!3( I, R, HDR, {I, R, AUTHii, SA2, TSi, TSr}SKi );
		recv_!4( R, I, HDR, {R, AUTHri, SA2, TSi, TSr}SKi );

		/* CREATE_CHILD_SA */
		claim( I, Running, R,g(i),g(j),Gr );
		send_!5( I, R, HDR, {SA3, Mi, g(j), TSi, TSr}SKi );
		recv_!6( R, I, HDR, {SA3, Mr, Gt,   TSi, TSr}SKi );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );
		claim( I, SKR, KEYMATi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R,g(i),g(j),Gr,Gt );
				
	}

	role R {
		fresh r, t, Nr, Mr, SPIr:	Nonce;
		var   Ni, Mi, SPIi:			Nonce;
		var   Gi, Gj:				Ticket;


		/* IKE_SA_INIT */
		recv_1( I, R, SPIi, O, SA1, Gi, Ni );
		send_2( R, I, HDR, SA1, g(r), Nr );

		/* IKE_AUTH */
		recv_!3( I, R, HDR, {I, R, AUTHir, SA2, TSi, TSr}SKr );
		send_!4( R, I, HDR, {R, AUTHrr, SA2, TSi, TSr}SKr );

		/* CREATE_CHILD_SA */
		recv_!5( I, R, HDR, {SA3, Mi, Gj,   TSi, TSr}SKr );
		claim( R, Running, I,Gi,Gj,g(r),g(t) );
		send_!6( R, I, HDR, {SA3, Mr, g(t), TSi, TSr}SKr );

		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );
		claim( R, SKR, KEYMATr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I,Gi,Gj,g(r) );
	}
}
