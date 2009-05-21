/* 
 * NAXOS AKE (Authenticated Key Exchange) protocol
 *
 * From "Stronger Security of Authenticated Key Exchange"
 * LaMacchia Lauter Mityagin 2006
 *
 * It's not really NAXOS in the sense that we don't have the group
 * exponentiations. These are emulated by the exponentiation protocol,
 * which simulates the g^ab = g^ba relation inside of the generated key
 * term. This is of course an underapproximation of the algebraic
 * properties but because we are here only looking for attacks, it seems
 * to be no problem.
 *
 * Attacks:
 * 
 * For full-compromise (generated) and matching partners, we find
 * attacks for both the initiator and responder roles.
 */

// Hash functions
const h1,h2,g1,g2: Function;
secret unh1,unh2,ung1,ung2: Function;
hashfunction h3;
hashfunction h2prime;

usertype bit;
const INIT: bit;
const RESP: bit;

inversekeys (h1,unh1);
inversekeys (h2,unh2);
inversekeys (g1,ung1);
inversekeys (g2,ung2);

/*
 * Hack to simulate public knowledge of public keys.
 */
protocol @publickeys(PK)
{
	role PK
	{
		send_!1(PK,PK, g1(sk(PK)));
	}
}
		
/*
 * Hack to simulate g^ab = g^ba inside terms.
 * '@' prefix of protocol name denotes helper protocol, which is used by
 * Scyther for displaying, and such protocols are ignored in
 * auto-generation of protocol modifiers.
 */
protocol @exponentiation(RA,RB,RC)
{
	role RA
	{
		var X,Y, T1,T2: Ticket;

		recv_!1(RA,RA, h2(
		  g2(g1(X),Y),
		  T1, T2, RA,RB
		  ));
		send_!2(RA,RA, h2(
		  g2(g1(Y),X),
		  T1, T2, RA,RB
		  ));
	}
	role RB
	{
		var X,Y, T1,T2: Ticket;

		recv_!3(RB,RB, h2(
		  T1,
		  g2(g1(X),Y),
		  T2, RA,RB
		  ));
		send_!4(RB,RB, h2(
		  T1,
		  g2(g1(Y),X),
		  T2, RA,RB
		  ));
	}
	role RC
	{
		var X,Y, T1,T2: Ticket;

		recv_!5(RC,RC, h2(
		  T1, T2,
		  g2(g1(X),Y),
		  RA,RB
		  ));
		send_!6(RC,RC, h2(
		  T1, T2,
		  g2(g1(Y),X),
		  RA,RB
		  ));
	}
}

protocol @keysymmetry(R1,R2,R3)
{
	role R1
	{
		var Y,X: Ticket;
		var Z1,Z2: Ticket;

		recv_!1(R1,R1, h2( 
			g2(g1(Y),X),
			Z1,Z2,
			R1,R2));
		send_!2(R1,R1, h2( 
			g2(g1(X),Y), 
			Z1,Z2,
			R1,R2));
	}
	role R2
	{
		var Y,X: Ticket;
		var Z1,Z2: Ticket;

		recv_!4(R2,R2, h2( 
			Z1,
			g2(g1(Y),X),
			Z2,
			R2,R3));
		send_!5(R2,R2, h2( 
			Z1,
			g2(g1(X),Y), 
			Z2,
			R2,R3));
	}
	role R3
	{
		var Y,X: Ticket;
		var Z1,Z2: Ticket;

		recv_!5(R3,R3, h2( 
			g2(g1(Y),X),
			Z1,
			Z2,
			R3,R1));
		send_!6(R3,R3, h2( 
			g2(g1(X),Y), 
			Z1,
			Z2,
			R3,R1));
	}
}

// The protocol description

protocol naxos-C(I,R)
{
	role I
	{
		const eskI: Nonce;
		var YI: Ticket;

		#define xI h1(eskI,sk(I))
		#define XI g1(xI)
		send_!1(I,R, XI );

		#define kbaseI I,R,XI,YI,g2(YI,sk(I)),g2(g1(sk(R)),xI),g2(YI,xI)
		#define kI h2(kbaseI)
		#define kprimeI h2prime(kbaseI)
		#define tAI h3(kprimeI,INIT,I,R,XI,YI)
		#define tBI h3(kprimeI,RESP,R,I,YI,XI)

		recv_!2(R,I, YI, tBI);
		claim(I,SID,(XI,YI));

		send_!3(I,R, XI,YI,tBI,tAI);

		claim(I,SKR,kI);
	}	
	
	role R
	{
		const eskR: Nonce;
		var XR: Ticket;

		#define yR h1(eskR,sk(R))
		#define YR g1(yR)
		recv_!1(I,R, XR );
		claim(R,SID,(XR,YR));

		#define kbaseR I,R,XR,YR,g2(g1(sk(I)),yR),g2(XR,sk(R)),g2(XR,yR)
		#define kR h2(kbaseR)
		#define kprimeR h2prime(kbaseR)
		#define tAR h3(kprimeR,INIT,I,R,XR,YR)
		#define tBR h3(kprimeR,RESP,R,I,YR,XR)

		send_!2(R,I, YR, tBR);

		recv_!3(I,R, XR, YR, tBR, tAR);

		claim(R,SKR,kR);
	}
}

