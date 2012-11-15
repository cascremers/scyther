/*
 * This is a model of a version of the TLS protocol as modeled in
 * Boyd, Mathuria "Protocols for Authentication and key establishment"
 *
 * It's a very simplified form.
 */
define(`msg1',`na')
define(`msg2',`nb')
define(`kab',`hash(pmk,na,nb)')
define(`msg3a',`{ pmk }pk(B)')
define(`M1',`hash(msg1,msg2,msg3a)')
define(`msg3b',`{ M1 }sk(A)')
define(`M2',`hash(msg1,msg2,msg3a,msg3b)')
define(`msg3c',`{ M2 }kab')
define(`msg3',`msg3a,msg3b,msg3c')
define(`M3',`msg1,msg2,msg3')
define(`msg4',`{ M3 }kab')

/* below is just Scyther input and no further macro definitions */

const pk,hash: Function;
secret sk,unhash: Function;
inversekeys(pk,sk);
inversekeys(hash,unhash);

const Alice, Bob, Eve: Agent;
const Terence: Agent;

protocol tls-bm-1(A,B)
{
	role A
	{
		fresh na: Nonce;
		fresh pmk: Nonce;
		var nb: Nonce;

		send_1( A,B, msg1 );
		recv_2( B,A, msg2 );
		send_3( A,B, msg3 );
		recv_4( B,A, msg4 );

		claim_A1( A, Secret, kab );
		claim_A2( A, Nisynch );
	}	
	
	role B
	{
		var na: Nonce;
		var pmk: Nonce;
		fresh nb: Nonce;

		recv_1( A,B, msg1 );
		send_2( B,A, msg2 );
		recv_3( A,B, msg3 );
		send_4( B,A, msg4 );

		claim_B1( B, Secret, kab );
		claim_B2( B, Nisynch );
	}
}



