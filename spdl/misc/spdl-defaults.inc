/* default includes */

/* asymmetric */

const pk,hash: Function;
secret sk,unhash: Function;
inversekeys (pk,sk);
inversekeys (hash,unhash);


/* symmetric */

usertype SessionKey;
secret k: Function;

/* agents */

const A,B,E: Agent;


/* untrusted E */

untrusted E;
compromised sk(E);
const nE: Nonce;
const kEE: SessionKey;

compromised k(E,E);
compromised k(E,A);
compromised k(E,B);
compromised k(A,E);
compromised k(B,E);


