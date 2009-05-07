/* 
 * Okamoto
 *
 * a1 == sk(A,1) etc.
 */
#define pk1(A) mult(exp(g1,sk(A,1)),exp(g2,sk(A,2)))
#define pk2(A) mult(exp(g1,sk(A,3)),exp(g2,sk(A,4)))

hashfunction H;
hashfunction exp;
hashfunction mult;
hashfunction add;
usertype Generator;
usertype Integer;
const g1,g2: Generator;
const 1,2,3,4: Integer;
hashfunction FCAS;

protocol @exphelper(H1,H2)
{
	role H1
	{
		var n1,n2: Nonce;
		var X,Y: Ticket;
		var g: Generator;

		recv_!1(H1,H1, H(n1,n2,exp(exp(g,X),Y)) );
		send_!2(H1,H1, H(n1,n2,exp(exp(g,Y),X)) );
	}
	role H2
	{
		recv_!3(H2,H2, H2);
		send_!4(H2,H2, pk1(H2),pk2(H2) );
	}
}

// The protocol description

protocol Okamoto(A,B)
{
	role A
	{
		const x1,x2: Nonce;
		var Y1,Y2,Y3: Ticket;

		#define squig(A) (pk1(A),pk2(A))
		/*
		 * Strange: how to interpret (x,x_3) <- X + Y ?
		 *
		 * My current interpretation: x,x_3 are just different hashes on
		 * x1,x2,and all a's
		 */
		#define FX(A,Y,Z)  FCAS(1,squig(A),Y,Z)
		#define FX3(A,Y,Z) FCAS(2,squig(A),Y,Z)

		#define  X123(A,x1,x2)  exp(g1,FX(A,x1,x2)), exp(g2,FX(A,x1,x2)), exp(g1,FX3(A,x1,x2))
		send_1(A,B, X123(A,x1,x2) );
		recv_2(B,A, Y1,Y2,Y3 );

		/* ca is badly modeled as it not clear to me now what
		 * should be the exact definition of H_a (or h_a for
		 * that matter). It's linked to the underlying
		 * mechanisms but contains some undefined symbols in the
		 * protocol description.
		 *
		 * As both parties must compute H_a it can't be private
		 * info containing.
		 */
		#define ca	FCAS(A,A,B,Y1,Y2,Y3)
		#define da	FCAS(A,B,A,X123(A,x1,x2))
		#define sigma1a	exp(Y1,add(sk(A,1), mult(ca,sk(A,3))))
		#define sigma2a	exp(Y2,add(sk(A,2), mult(ca,sk(A,4))))
		#define sigma3a	exp(Y3,FX3(A,x1,x2))
		#define sigma4a exp(pk1(B),FX(A,x1,x2))
		#define sigma5a exp(pk2(B),mult(da,FX(A,x1,x2)))
		#define sigmaa 	mult(mult(mult(mult(sigma1a,sigma2a),sigma3a),sigma4a),sigma5a)
		#define sida	(A,B,X123(A,x1,x2),Y1,Y2,Y3)
		claim(A, SKR, FCAS(sigmaa, sida) );
	}
	role B
	{
		var X1,X2,X3: Ticket;
		const y1,y2: Nonce;

		recv_1(A,B, X1,X2,X3 );
		/*
		 * FY = FX, FY3 = FX3...
		 */
		#define FY(A,Y,Z)  FCAS(1,squig(A),Y,Z)
		#define FY3(A,Y,Z) FCAS(2,squig(A),Y,Z)
		#define Y123(B,y1,y2)  exp(g1,FY(B,y1,y2)), exp(g2,FY(B,y1,y2)), exp(g1,FY3(B,y1,y2))
		send_2(B,A, Y123(B,y1,y2) );

		#define cb	FCAS(A,A,B,Y123(B,y1,y2) )
		#define db	FCAS(A,B,A,X1,X2,X3)
		#define sigma1b	exp(X1,add(sk(B,1), mult(db,sk(B,3))))
		#define sigma2b	exp(X2,add(sk(B,2), mult(db,sk(B,4))))
		#define sigma3b	exp(X3,FY3(B,y1,y2))
		#define sigma4b exp(pk1(B),FY(B,y1,y2))
		#define sigma5b exp(pk2(B),mult(cb,FY(B,y1,y2)))
		#define sigmab 	mult(mult(mult(mult(sigma1b,sigma2b),sigma3b),sigma4b),sigma5b)
		#define sidb	(A,B,X1,X2,X3,Y123(B,y1,y2))
		claim(B, SKR, FCAS(sigmab, sidb) );
	}
}

