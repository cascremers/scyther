/*
 * This is a model of a version of the TLS protocol as modeled by
 * He,Sundararajan,Datta,Derek and Mitchell in the paper: "A modular
 * correctness proof of IEEE 802.11i and TLS".
 *
 * This is the fixed version, with quite some differences:
 *
 * 1) new definition of handShake1 (including preceding tuples)
 * 2) new definition of both handshakes (now hashed)
 * 3) changed order in msg3 so msecret is part of handShake1
 *
 * (These are the suggestions made by Cas to Anupam Datta)
 */
define(`CERTY',`{ Y,pk(Y) }sk(Terence)')
define(`CERTX',`{ X,pk(X) }sk(Terence)')
define(`msg1',`X,Nx,pa')
define(`msg2',`Ny,pb,CERTY')
define(`handShake1',`hash(msg1,msg2,{msecret}pk(Y))')
define(`msg3',`CERTX,{msecret}pk(Y),{handShake1}sk(X),hash(msecret,handShake1,clientstring)')
define(`handShake2',`hash(msg1,msg2,msg3)')
define(`msg4',`hash(msecret,handShake2,serverstring)')

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



