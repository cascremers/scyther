/** HEADDOC
 * @protocol	Just Fast Keying
 * @reference	Aiello et al., Just Fast Keying: Key Agreement In A Hostile
 *				Internet
 * @description	
 * @variant		Initiatior is identity protected
**/


/** MACRO DEFINITIONS
 * Needs preprocessing by cpp before fed to scyther
**/
#define __JFK__
#ifndef __ORACLE__
#include "common.h"
#endif

/**
 * This role serves as an "oracle" to ensure the executability of the 
 * protocol by taking care of the problems that arise from our way of 
 * modelling Diffie-Hellman keys.
 */
protocol @executability(O) {
#define Gi g(i)
#define Gr g(r)
	role O {
		var i, r, Ni, Nr, SAi, SAr: Nonce;
		var I, R: Agent;

		// msg 3
		recv_!O1( O, O, {I, SAi, {H(Ni), Nr, g(i), Gr, R, SAi}sk(I)}SKi );
		send_!O2( O, O, {I, SAi, {H(Ni), Nr, g(i), Gr, R, SAi}sk(I)}SKr );

		// msg 4
		recv_!O3( O, O, {{H(Ni), Nr, g(i), Gr, I, SAi, SAr}sk(R), SAr}SKr );
		send_!O4( O, O, {{H(Ni), Nr, g(i), Gr, I, SAi, SAr}sk(R), SAr}SKi );

	}
#undef Gi
#undef Gr
}


// Abstractions: no grpinfo, no MAC(ENC(M)), no ID_R', no IPi
protocol jfki(I, R)
{
	role I {
		fresh i, Ni, SAi:	Nonce;
		var   Nr, SAr:		Nonce;
		var   Gr, TH:		Ticket;

		send_1( I, R, H(Ni), g(i) );
		recv_2( R, I, H(Ni), Nr, Gr, R, {Gr}sk(R), TH );
		send_!3( I, R, Ni, Nr, g(i), Gr, TH, {I, SAi, {H(Ni), Nr, g(i), Gr, R, SAi}sk(I)}SKi );
		recv_!4( R, I, {{H(Ni), Nr, g(i), Gr, I, SAi, SAr}sk(R), SAr}SKi );

		/* SECURITY CLAIMS */
		claim( I, SKR, SKi );

		claim( I, Alive );
		claim( I, Weakagree );
				
	}

	role R {
		fresh  r, Nr, SAr, HKr:	Nonce;
		var    Ni, SAi:			Nonce;
		var    Gi, HNi:			Ticket;

		recv_1( I, R, HNi, Gi );
		send_2( R, I, HNi, Nr, g(r), R, {g(r)}sk(R), H(HKr, g(r), Nr, HNi) );
		// Note: if R can receive H(HKr, g(r), Nr, H(Ni)) then HNi=H(Ni)
		recv_!3( I, R, Ni, Nr, Gi, g(r), H(HKr, g(r), Nr, H(Ni)), {I, SAi, {H(Ni), Nr, Gi, g(r), R, SAi}sk(I)}SKr );
        send_!4( R, I, {{H(Ni), Nr, Gi, g(r), I, SAi, SAr}sk(R), SAr}SKr );

		/* SECURITY CLAIMS */
		claim( R, Secret, HKr );
		claim( R, SKR, SKr );

		claim( R, Alive );
		claim( R, Weakagree );
				
	}
}