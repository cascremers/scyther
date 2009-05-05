/* 
 * Okamoto
 *
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

protocol @exphelper(H1,H2)
{
	role H1
	{
		var n1,n2: Nonce;
		var X,Y: Ticket;

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

		#define x add(FHAT(x1),FSQUIG(x2));
		/*
		 * Strange: how to interpret (x,x_3) <- X + Y ?
		 */


