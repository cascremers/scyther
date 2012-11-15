/**********************************************************************
 * @protocol	Internet Key Exchange Protocol (IKEv2)                 
 * @subprotocol IKE EAP                                                
 * @reference	RFC 4306                                               
 * @variant		Includes optional payloads                             
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
		var i, r, Ni, Nr, SPIi, SPIr, EAP, EAPOK: Nonce;
		var I, R: Agent;

		// msg 3
		recv_!E1( E, E, {I, R, SA2, TSi, TSr}SKi );
		send_!E2( E, E, {I, R, SA2, TSi, TSr}SKr );

		// msg 4
		recv_!E3( E, E, {R, AUTHrr, EAP}SKr );
		send_!E4( E, E, {R, AUTHri, EAP}SKi );

		// msg 5
		recv_!E5( E, E, {EAP}SKi );
		send_!E6( E, E, {EAP}SKr );

		// msg 6
		recv_!E7( E, E, {EAPOK}SKr );
		send_!E8( E, E, {EAPOK}SKi );

		// msg 7
		recv_!E9( E, E, {AUTHii}SKi );
		send_!EA( E, E, {AUTHir}SKr );

		// msg 8
		send_!EB( E, E, {AUTHrr, SA2, TSi, TSr}SKr );
		send_!EC( E, E, {AUTHri, SA2, TSi, TSr}SKi );
	}
#undef Gi
#undef Gr
}


protocol ikev2-eap(I, R)
{

	role I {
		fresh i, Ni, SPIi:	Nonce;
		var   Nr, SPIr:		Nonce;
		var   EAP, EAPOK:	Nonce;
		var   Gr:			Ticket;


		/* IKE_SA_INIT */
		send_1( I, R, SPIi, O, SA1, g(i), Ni );
		recv_2( R, I, HDR, SA1, Gr, Nr );

		/* IKE_AUTH */
		send_!3( I, R, HDR, {I, R, SA2, TSi, TSr}SKi );
		recv_!4( R, I, HDR, {R, AUTHri, EAP}SKi );
		send_!5( I, R, HDR, {EAP}SKi );
		recv_!6( R, I, HDR, {EAPOK}SKi );
		claim( I, Running, R, Ni,g(i),Nr,Gr,TSi,TSr,EAP,EAPOK );
		send_!7( I, R, HDR, {AUTHii}SKi );
		recv_!8( R, I, HDR, {AUTHri, SA2, TSi, TSr}SKi );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
		claim( I, Commit, R, Ni,g(i),Nr,Gr,TSi,TSr,EAP,EAPOK );
				
	}

	role R {
		fresh EAP, EAPOK:	Nonce;
		fresh r, Nr, SPIr:	Nonce;
		var   Ni, SPIi:		Nonce;
		var   Gi:			Ticket;


		/* IKE_SA_INIT */
		recv_1( I, R, SPIi, O, SA1, Gi, Ni );
		send_2( R, I, HDR, SA1, g(r), Nr );

		/* IKE_AUTH */
		recv_!3( I, R, HDR, {I, R, SA2, TSi, TSr}SKr );
		send_!4( R, I, HDR, {R, AUTHrr, EAP}SKr );
		recv_!5( I, R, HDR, {EAP}SKr );
		send_!6( R, I, HDR, {EAPOK}SKr );
		recv_!7( I, R, HDR, {AUTHir}SKr );
		claim( R, Running, I, Ni,Gi,Nr,g(r),TSi,TSr,EAP,EAPOK );
		send_!8( R, I, HDR, {AUTHrr, SA2, TSi, TSr}SKr );


		/* SECURITY CLAIMS */
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
		claim( R, Commit, I, Ni,Gi,Nr,g(r),TSi,TSr,EAP,EAPOK );
				
	}
}
