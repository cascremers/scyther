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

const a,b,e: Agent;


/* untrusted e */

untrusted e;
compromised sk(e);
const ne: Nonce;
const kee: SessionKey;

compromised k(e,e);
compromised k(e,a);
compromised k(e,b);
compromised k(a,e);
compromised k(b,e);


