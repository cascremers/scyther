/*
 * This is a model of a version of the TLS protocol as modeled by
 * He,Sundararajan,Datta,Derek and Mitchell in the paper: "A modular
 * correctness proof of IEEE 802.11i and TLS".
 *
 * The .cpp file cannot be fed into scyther directly; rather, one needs
 * to type: (for *nix type systems with cpp)
 *
 * 	cpp tls-HSDDM05.cpp >tls-HSDDM05.spdl
 *
 * in order to generate a valid spdl file for the Scyther.
 *
 * This allows for macro expansion, as seen in the next part, which is
 * particularly useful for expanding the handshakes.
 *
 */
#define CERT(a) { a,pk(a) }sk(Terence)
#define msg1 X,Nx,pa
#define msg2 Ny,pb,CERT(Y)
#define handShake1 msg1,msg2
#define msg3 CERT(X),{handShake1}sk(X),{msecret}pk(Y),hash(msecret,handShake1,clientstring)
#define handShake2 msg1,msg2,msg3
#define msg4 hash(msecret,handShake2,serverstring)


/* below is just Scyther input and no further macro definitions */

usertype Params, String;

const pk,hash: Function;
secret sk,unhash: Function;
inversekeys(pk,sk);
inversekeys(hash,unhash);

const clientstring,serverstring: String;

const Alice, Bob, Eve: Agent;
const Terence: Agent;

protocol tls-HSDDM05(X,Y)
{
	role X
	{
		fresh Nx: Nonce;
		fresh msecret: Nonce;
		fresh pa: Params;
		var Ny: Nonce;
		var pb: Params;

		send_1( X,Y, msg1 );
		recv_2( Y,X, msg2 );
		send_3( X,Y, msg3 );
		recv_4( Y,X, msg4 );

		claim_X1( X, Secret, msecret );
	}	
	
	role Y
	{
		var Nx: Nonce;
		var msecret: Nonce;
		var pa: Params;
		fresh Ny: Nonce;
		fresh pb: Params;

		recv_1( X,Y, msg1 );
		send_2( Y,X, msg2 );
		recv_3( X,Y, msg3 );
		send_4( Y,X, msg4 );

		claim_Y1( Y, Secret, msecret );
	}
}



