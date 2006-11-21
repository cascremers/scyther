/*
 * This is a model of a version of the TLS protocol as modeled by
 * He,Sundararajan,Datta,Derek and Mitchell in the paper: "A modular
 * correctness proof of IEEE 802.11i and TLS".
 *
 * The .cpp file cannot be fed into scyther directly; rather, one needs
 * to type: (for *nix type systems with cpp)
 *
 * 	cpp tls-mitchell.cpp >tls-mitchell.spdl
 *
 * in order to generate a valid spdl file for the Scyther.
 *
 * This allows for macro expansion, as seen in the next part, which is
 * particularly useful for expanding the handshakes.
 *
 */
#define CERT(a) { a,pk(a) }sk(Terence)
#define handShake1 X,Nx,pa,Ny,pb,CERT(Y)
#define handShake2 handShake1,CERT(X),{ handShake1 }sk(X),{ msecret }pk(Y), hash(msecret, handShake1, clientstring)

/* below is just Scyther input and no further macro definitions */

usertype Params, String;

const pk,hash: Function;
secret sk,unhash: Function;
inversekeys(pk,sk);
inversekeys(hash,unhash);

const clientstring,serverstring: String;

const Alice, Bob, Eve: Agent;
const Terence: Agent;

protocol tlsmitchell(X,Y)
{
	role X
	{
		const Nx: Nonce;
		const msecret: Nonce;
		const pa: Params;
		var Ny: Nonce;
		var pb: Params;

		send_1( X,Y, X,Nx,pa );
		read_2( Y,X, Ny,pb,CERT(Y) );
		send_3( X,Y, CERT(X),
			     { handShake1 }sk(X),
			     { msecret }pk(Y),
			     hash(msecret, handShake1, clientstring)
			  );
		read_4( Y,X, hash(msecret, handShake2, serverstring) );

		claim_X1( X, Secret, msecret );
	}	
	
	role Y
	{
		var Nx: Nonce;
		var msecret: Nonce;
		var pa: Params;
		const Ny: Nonce;
		const pb: Params;

		read_1( X,Y, X,Nx,pa );
		send_2( Y,X, Ny,pb,CERT(Y) );
		read_3( X,Y, CERT(X),
			     { handShake1 }sk(X),
			     { msecret }pk(Y),
			     hash(msecret, handShake1, clientstring)
			  );
		send_4( Y,X, hash(msecret, handShake2, serverstring) );

		claim_Y1( Y, Secret, msecret );
	}
}


untrusted Eve;
compromised sk(Eve);

