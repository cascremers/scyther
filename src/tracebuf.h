#ifndef TRACEBUF
#define TRACEBUF

#include "term.h"
#include "termlist.h"
#include "knowledge.h"
#include "system.h"

/* STATUS symbols */
enum statussymbols
{
  S_UNK,			// UNKnown   : unprocessed.
  S_OKE,			// OKE       : done, but required for the attack.
  S_RED,			// REDundant : is not needed for attack, we're sure.
  S_TOD				// TODo      : The previous suggestion REQ was too similar to RED. This is reserved for reads.
};


/*
 * tracebuf struct is defined in system.h to avoid loops.
 */

int tracebufRebuildKnow (struct tracebuf *tb);
struct tracebuf *tracebufInit (void);
void tracebufDone (struct tracebuf *tb);
struct tracebuf *tracebufSet (const System sys, int length, int claimev);


#endif
