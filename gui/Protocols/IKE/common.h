/****************************************************************************
 * THIS FILE CONTAINS DEFINITIONS OF COMMON MACROS AND TYPES                *
 ****************************************************************************/

 hashfunction prf, KDF;

/**********************************
 * DIFFIE-HELLMAN ABSTRACTIONS    *
 * Zi = Gr^i = g^(ri)
 * Zr = Gi^r = g^(ir)
 **********************************/
const g, h: Function;
#define Zi h(Gr,i)
#define Zr h(Gi,r)

/**********************************
 * PROTOCOL DEPENDENT DEFINITIONS *
 **********************************/
#ifdef __IKEV1__
hashfunction H;
#define SKi KDF(Ni, Nr, Zi, Ci, Cr)
#define SKr KDF(Ni, Nr, Zr, Ci, Cr)
#endif

#ifdef __IKEV1_PSK__
#define SKi prf(k(I,R), Ni, Nr, Zi, Ci, Cr)
#define SKr prf(k(R,I), Ni, Nr, Zr, Ci, Cr)
#endif

#ifdef __IKEV1_QUICK__
/* k(.,.) equals Kd from the spec */
#define SKi KDF(k(I,R),Zi,Ni,Nr)
#define SKr KDF(k(R,I),Zr,Ni,Nr)
#endif

#ifdef __IKEV1_QUICK_NOPFS__
/* k(.,.) equals Kd from the spec */
#define SKi KDF(k(I,R),Ni,Nr)
#define SKr KDF(k(R,I),Ni,Nr)
#endif

#ifdef __IKEV2__
hashfunction MAC;
#define HDR (SPIi,SPIr)
#define SKi KDF(Ni,Nr,Zi,SPIi,SPIr)
#define SKr KDF(Ni,Nr,Zr,SPIi,SPIr)
#endif

#ifdef __IKEV2_CHILD__
#define SKi KDF(k(I,R),Zi,Ni,Nr)
#define SKr KDF(k(R,I),Zr,Ni,Nr)
#endif

#ifdef __IKEV2_CHILD_NOPFS__
#define SKi KDF(k(I,R),Ni,Nr)
#define SKr KDF(k(R,I),Ni,Nr)
#endif

#ifdef __JFK_CORE__
hashfunction H;
#define SKi KDF(Zi, Ni, Nr)
#define SKr KDF(Zr, Ni, Nr)
#endif

#ifdef __JFK__
hashfunction H;
#define SKi KDF(Zi, H(Ni), Nr)
#define SKr KDF(Zr, H(Ni), Nr)
#endif

#ifdef __OAKLEY__
#define SKi KDF(Ni, Nr, Zi, Ci, Cr)
#define SKr KDF(Ni, Nr, Zr, Ci, Cr)
#endif

#ifdef __OAKLEY_CONSERVATIVE__
#define SKi KDF(Ni, Nr, Zi, Ci, Cr)
#define SKr KDF(Ni, Nr, Zr, Ci, Cr)
#endif

#ifdef __SKEME__
#define SKi KDF(Zi)
#define SKr KDF(Zr)
#endif

#ifdef __SKEME_REKEY__
#define SKi KDF(k(I,R),prf(k(I,R), Ni, Nr, R, I))
#define SKr KDF(k(R,I),prf(k(R,I), Ni, Nr, R, I))
#endif

#ifdef __STS__
#define SKi KDF(Zi)
#define SKr KDF(Zr)
hashfunction MAC;
#endif

protocol @oracle (DH, SWAP) {
#define Gi g(i)
#define Gr g(r)

	/* Diffie-Hellman oracle: If the adversary is in possession of g^xy, he 
	 * can obtain g^yx.
	 * @obsolete	The adversary does not need DH as long as SWAP exists
	 */
	role DH {
		var i, r: Nonce;

		recv_!DH1( DH, DH, Zi );
		send_!DH2( DH, DH, Zr );
	}

	/* Session key swap oracle: If the adversary is in possession of eg the 
	 * initiators session key, he can obtain the responders session key.
	 */
	role SWAP {
		var i, r, Ni, Nr: Nonce;

#ifdef __IKEV1__
		var Ci, Cr: Nonce;
#endif
#ifdef __IKEV1_PSK__
		var Ci, Cr: Nonce;
		var I, R: Agent;
#endif
#ifdef __IKEV1_QUICK__
		var I, R: Agent;
#endif
#ifdef __IKEV1_QUICK_NOPFS__
		var I, R: Agent;
#endif
#ifdef __IKEV2__
		var SPIi, SPIr: Nonce;
#endif
#ifdef __IKEV2_CHILD__
		var I, R: Agent;
#endif
#ifdef __IKEV2_CHILD_NOPFS__
		var I, R: Agent;
#endif
#ifdef __OAKLEY__
		var Ci, Cr: Nonce;
#endif
#ifdef __OAKLEY_CONSERVATIVE__
		var Ci, Cr: Nonce;
#endif
#ifdef __SKEME_REKEY__
		var I, R: Agent;
#endif

		recv_!SWAP1( SWAP, SWAP, SKi );
		send_!SWAP2( SWAP, SWAP, SKr );

	}
#undef Gi
#undef Gr
}
#define __ORACLE__