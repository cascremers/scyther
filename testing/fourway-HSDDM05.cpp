/*
 * This is a model of a version of the four-way handshake protocol as modeled
 * by He,Sundararajan,Datta,Derek and Mitchell in the paper: "A modular
 * correctness proof of IEEE 802.11i and TLS".
 */
#define ptk hash( pmk(X,Y),x,y )

/* below is just Scyther input and no further macro definitions */

usertype Params, String;

const hash: Function;
secret unhash: Function;
inversekeys(hash,unhash);
secret pmk: Function;

const msg1,msg2,msg3,msg4: String;

const Alice, Bob, Eve: Agent;

protocol fourway(X,Y)
{
	role X
	{
		fresh x: Nonce;
		var y: Nonce;

		send_1( X,Y, x,msg1 );
		recv_2( Y,X, y,msg2,hash( ptk,y,msg2 ) );
		send_3( X,Y, x,msg3,hash( ptk,x,msg3 ) );
		recv_4( Y,X, msg4,hash( ptk,msg4 ) );

		claim_X1( X, Secret, ptk );
		claim_X2( X, Niagree );
	}	
	
	role Y
	{
		var x: Nonce;
		fresh y: Nonce;

		recv_1( X,Y, x,msg1 );
		send_2( Y,X, y,msg2,hash( ptk,y,msg2 ) );
		recv_3( X,Y, x,msg3,hash( ptk,x,msg3 ) );
		send_4( Y,X, msg4,hash( ptk,msg4 ) );

		claim_Y1( Y, Secret, ptk );
		claim_Y2( Y, Niagree );
	}
}



