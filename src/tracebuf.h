#ifndef TRACEBUF
#define TRACEBUF

#include "terms.h"
#include "termlists.h"
#include "knowledge.h"
#include "system.h"

/* STATUS symbols */
#define S_UNK 0 // UNKnown   : unprocessed.
#define S_OKE 1 // OKE       : done, but required for the attack.
#define S_RED 2 // REDundant : is not needed for attack, we're sure.
#define S_TOD 3	// TODo      : The previous suggestion REQ was too similar to RED.
		//             This is reserved for reads.


/*
 * tracebuf struct is defined in system.h to avoid loops.
 */

int tracebufRebuildKnow(struct tracebuf *tb);
struct tracebuf* tracebufInit (void);
void tracebufDone (struct tracebuf *tb);
struct tracebuf* tracebufSet (const System sys, int length, int claimev);


#endif
