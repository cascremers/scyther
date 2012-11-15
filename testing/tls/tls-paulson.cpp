/*
 * This is a model of the TLS version as modeled by Paulson
 *
 * The .cpp file cannot be fed into scyther directly; rather, one needs
 * to type:
 *
 * 	cpp tls-paulson.cpp >tls-paulson.spdl
 *
 * in order to generate a valid spdl file for scyther.
 *
 * This allows for macro expansion, as seen in the next part.
 *
 */
#define CERT(a) { a,pk(a) }sk(Terence)
#define MSG a,na,sid,pa,pb,nb,sid,pb,CERT(a),CERT(b),{pms}pk(b) 
#define M hash(pms,na,nb)
#define F hash(M,MSG)
#define CLIENTK hash(sid,M,na,pa,a,nb,pb,b,false)
#define SERVERK hash(sid,M,na,pa,a,nb,pb,b,true)

usertype Params, Bool, SessionID;

const pk,hash: Function;
secret sk,unhash: Function;
inversekeys(pk,sk);
inversekeys(hash,unhash);

const pa,pb: Params;
const false,true: Bool;


protocol tlspaulson(a,b)
{
	role a
	{
		fresh na: Nonce;
		fresh sid: SessionID;
		fresh pms: Nonce;
		var nb: Nonce;
		var pb: Params;

		send_1( a,b, a,na,sid,pa );
		recv_2( b,a, nb,sid,pb );
		recv_3( b,a, CERT(b) );
		send_4( a,b, CERT(a) );
		send_5( a,b, { pms }pk(b) );
		send_6( a,b, { hash(nb,b,pms) }sk(a) );
		send_7( a,b, { F }CLIENTK );
		recv_8( b,a, { F }SERVERK );

		claim_9a(a, Secret, SERVERK);
		claim_9b(a, Secret, CLIENTK);

	}	
	
	role b
	{
		var na: Nonce;
		var sid: SessionID;
		var pms: Nonce;
		fresh nb: Nonce;
		fresh pb: Params;

		recv_1( a,b, a,na,sid,pa );
		send_2( b,a, nb,sid,pb );
		send_3( b,a, CERT(b) );
		recv_4( a,b, CERT(a) );
		recv_5( a,b, { pms }pk(b) );
		recv_6( a,b, { hash(nb,b,pms) }sk(a) );
		recv_7( a,b, { F }CLIENTK );
		send_8( b,a, { F }SERVERK );

		claim_10a(b, Secret, SERVERK);
		claim_10b(b, Secret, CLIENTK);
	}
}


const side: SessionID;
const pe: Params;


