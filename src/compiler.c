#include <stdlib.h>
#include <stdio.h>
#include "tac.h"
#include "term.h"
#include "termlist.h"
#include "memory.h"
#include "system.h"
#include "knowledge.h"
#include "symbol.h"
#include "substitution.h"
#include "compiler.h"

/*
   Simple sys pointer as a global. Yields cleaner code although it's against programming standards.
   It is declared as static to hide it from the outside world, and to indicate its status.
   Other modules will just see a nicely implemented sys parameter of compile, so we can always change
   it later if somebody complains. Which they won't.
*/

static System sys;
static Tac tac_root;

/*
 * Declaration from system.c
 */
extern int protocolCount;

/*
   Forward declarations.
*/

void tacProcess (Tac tc);
void levelInit (void);
void levelDone (void);
Term symbolDeclare (Symbol s, int isVar);
void levelTacDeclaration (Tac tc, int isVar);
Term levelFind (Symbol s, int i);
Term symbolFind (Symbol s);
Term tacTerm (Tac tc);
Termlist tacTermlist (Tac tc);
Term levelDeclare (Symbol s, int isVar, int level);
void compute_role_variables (const System sys, Protocol p, Role r);

#define	levelDeclareVar(s)	levelTacDeclaration(s,1)
#define	levelDeclareConst(s)	levelTacDeclaration(s,0)
#define	levelVar(s)	symbolDeclare(s,1)
#define	levelConst(s)	symbolDeclare(s,0)

/* externally used:
 * TERM_Function in termlists.c for inversekeys
 * TERM_Type in system.c for type determination.
 */

Term TERM_Agent;
Term TERM_Function;
Term TERM_Hidden;
Term TERM_Type;
Term TERM_Nonce;
Term TERM_Agent;

Term TERM_Claim;
Term CLAIM_Secret;
Term CLAIM_Nisynch;
Term CLAIM_Niagree;

/*
 * Global stuff
 */

//! Levels of scope: global, protocol, role
#define MAXLEVELS 3
static Termlist leveltl[MAXLEVELS];
static int level;
static int maxruns;
static Protocol thisProtocol;
static Role thisRole;

//! Init terms and such
void
compilerInit (const System mysys)
{
  int i;

  /* transfer to global static variable */
  sys = mysys;
  /* init levels */
  for (i = 0; i < MAXLEVELS; i++)
    leveltl[i] = NULL;
  level = -1;
  levelInit ();

  /* Init system constants */
#define langhide(x,y) x = levelConst(symbolSysConst(" _" y "_ "))
#define langtype(x,y) x->stype = termlistAdd(x->stype,y);
#define langcons(x,y,z) x = levelConst(symbolSysConst(y)); langtype(x,z)

  langhide (TERM_Type, "Type");
  langhide (TERM_Hidden, "Hidden");
  langhide (TERM_Claim, "Claim");

  langcons (TERM_Agent, "Agent", TERM_Type);
  langcons (TERM_Function, "Function", TERM_Type);
  langcons (TERM_Nonce, "Nonce", TERM_Type);

  langcons (CLAIM_Secret, "Secret", TERM_Claim);
  langcons (CLAIM_Nisynch, "Nisynch", TERM_Claim);
  langcons (CLAIM_Niagree, "Niagree", TERM_Claim);
}

//! Make a global constant
Term
makeGlobalConstant (const char *s)
{
  return levelDeclare (symbolSysConst (s), 0, 0);
}

//! Make a global variable
Term
makeGlobalVariable (const char *s)
{
  return levelDeclare (symbolSysConst (s), 1, 0);
}

//! Clean up afterwards
void
compilerDone (void)
{
  return;
}

/* ------------------------------------------------------------------- */

//! Compile the tac into the system
/**
 *@todo Currently, the semantics assume all labels are globally unique, but this is not enforced yet. There should be some automatic renaming when compositing protocols.
 *\sa oki_nisynch
 */
void
compile (Tac tc, int maxrunsset)
{
  /* Init globals */
  maxruns = maxrunsset;
  tac_root = tc;

  /* process the tac */
  tacProcess (tac_root);

  /* Clean up keylevels */
  symbol_fix_keylevels ();

  /* cleanup */
  levelDone ();
}

//! Print error line number.
/**
 *@todo This is obsolete, and should all go to stderr
 */
void
errorTac (int lineno)
{
  printf (" on line %i.\n", lineno);
  exit (1);
}

//! Enter nested scope.
void
levelInit (void)
{
  level++;
  if (level >= MAXLEVELS)
    {
      error ("level is increased too much.");
    }
  leveltl[level] = NULL;
}

//! Leave nested scope.
void
levelDone (void)
{
  if (level < 0)
    {
      error ("level is decreased too much.");
    }
  leveltl[level] = NULL;
  level--;
}

Term
levelDeclare (Symbol s, int isVar, int level)
{
  Term t;

  t = levelFind (s, level);
  if (t == NULL)
    {
      /* new! */
      if (isVar)
	{
	  t = makeTermType (VARIABLE, s, -(level + 1));
	  sys->variables = termlistAdd (sys->variables, t);
	}
      else
	{
	  t = makeTermType (GLOBAL, s, -(level + 1));
	}
      leveltl[level] = termlistAdd (leveltl[level], t);

      /* add to relevant list */
      switch (level)
	{
	case 0:
	  sys->locals = termlistAdd (sys->locals, t);
	  break;
	case 1:
	  thisProtocol->locals = termlistAdd (thisProtocol->locals, t);
	  break;
	case 2:
	  thisRole->locals = termlistAdd (thisRole->locals, t);
	  break;
	}
    }
  return t;
}

Term
symbolDeclare (Symbol s, int isVar)
{
  return levelDeclare (s, isVar, level);
}

Term
levelFind (Symbol s, int level)
{
  Termlist tl;

  tl = leveltl[level];
  while (tl != NULL)
    {
      if (isTermLeaf (tl->term))
	{
	  if (tl->term->left.symb == s)
	    {
	      return tl->term;
	    }
	}
      tl = tl->next;
    }
  return NULL;
}

Term
symbolFind (Symbol s)
{
  int i;
  Term t;

  i = level;
  while (i >= 0)
    {
      t = levelFind (s, i);
      if (t != NULL)
	return t;
      i--;
    }
  return NULL;
}

//! Yield a basic global constant term (we suppose it exists) or NULL, given a string
Term
findGlobalConstant (const char *s)
{
  return levelFind (lookup (s), 0);
}

void
defineUsertype (Tac tcdu)
{
  Tac tc;
  Term t;
  Term tfind;

  tc = tcdu->t1.tac;

  if (tc == NULL)
    {
      error ("Empty usertype declaration on line %i.", tcdu->lineno);
    }
  while (tc != NULL && tc->op == TAC_STRING)
    {
      /* check whether this term is already declared in the same way
       * (i.e. as a type) */

      tfind = levelFind (tc->t1.sym, 0);
      if (tfind == NULL)
	{
	  /* this is what we expected: this type is not declared yet */
	  t = levelDeclare (tc->t1.sym, 0, 0);
	  t->stype = termlistAdd (NULL, TERM_Type);
	}
      else
	{
	  /* oi!, there's already one. Let's hope is is a type too. */
	  if (inTermlist (tfind->stype, TERM_Type))
	    {
	      /* phew. warn anyway */
	      printf ("WARNING: double declaration of usertype ");
	      termPrint (tfind);
	      printf ("\n");
	    }
	  else
	    {
	      /* that's not right! */
	      error
		("Conflicting definitions in usertype definition on line %i.",
		 tc->lineno);
	    }
	}
      tc = tc->next;
    }
}

void
levelTacDeclaration (Tac tc, int isVar)
{
  Tac tscan;
  Termlist typetl = NULL;
  Term t;

  tscan = tc->t2.tac;
  if (!isVar && tscan->next != NULL)
    {
      error ("Multiple type definition for constant on line %i.",
	     tscan->lineno);
    }
  while (tscan != NULL && tscan->op == TAC_STRING)
    {
      /* apparently there is type info, termlist? */
      t = levelFind (tscan->t1.sym, 0);

      if (t == NULL)
	{
	  /* not declared, that is unacceptable. */
	  error ("Undeclared type on line %i.", tscan->lineno);
	}
      else
	{
	  if (!inTermlist (t->stype, TERM_Type))
	    {
	      error ("Non-type constant in type declaration on line %i.",
		     tscan->lineno);
	    }
	}
      typetl = termlistAdd (typetl, t);
      tscan = tscan->next;
    }
  /* parse all constants and vars */
  tscan = tc->t1.tac;
  while (tscan != NULL)
    {
      t = symbolDeclare (tscan->t1.sym, isVar);
      t->stype = typetl;
      tscan = tscan->next;
    }
}

void
commEvent (int event, Tac tc)
{
  /* Add an event to the roledef, send or read */
  Claimlist cl;
  Term fromrole = NULL;
  Term torole = NULL;
  Term msg = NULL;
  Term label = NULL;
  Term claim = NULL;
  Term claimbig = NULL;
  int n = 0;
  Tac trip;

  /* Construct label, if any */
  if (tc->t1.sym == NULL)
    {
      label = NULL;
    }
  else
    {
      label = levelFind (tc->t1.sym, level - 1);
      if (label == NULL)
	{
	  /* effectively, labels are bound to the protocol */
	  level--;
	  /* leaves a garbage tuple. dunnoh what to do with it */
	  label =
	    makeTermTuple (thisProtocol->nameterm, levelConst (tc->t1.sym));
	  level++;
	}
    }
  trip = tc->t2.tac;
  switch (event)
    {
    case READ:
    case SEND:
      /* now parse triplet info */
      if (trip == NULL || trip->next == NULL || trip->next->next == NULL)
	{
	  error ("Problem with %i event on line %i.", event, tc->lineno);
	}
      fromrole = tacTerm (trip);
      torole = tacTerm (trip->next);
      msg = tacTerm (tacTuple ((trip->next->next)));
      cl = NULL;

      if (event == SEND)
	{
	  /* set keylevels based on send events */
	  term_set_keylevels (fromrole);
	  term_set_keylevels (torole);
	  term_set_keylevels (msg);
	}

      break;
    case CLAIM:
      /* now parse tuple info */
      if (trip == NULL || trip->next == NULL)
	{
	  error ("Problem with claim %i event on line %i.", event,
		 tc->lineno);
	}
      fromrole = tacTerm (trip);
      claimbig = tacTerm (tacTuple ((trip->next)));
      /* check for several types */
      claim = tupleProject (claimbig, 0);
      torole = claim;

      /* check for ignored claim types */
      if (sys->switchClaimToCheck != NULL && sys->switchClaimToCheck != claim)
	{
	  /* abort the construction of the node */
	  return;
	}

      /* check for obvious flaws */
      if (claim == NULL)
	{
	  error ("Invalid claim specification on line %i.", tc->lineno);
	}
      if (!inTermlist (claim->stype, TERM_Claim))
	{
	  printf ("ERROR: unknown claim type ");
	  termPrint (claim);
	  errorTac (trip->next->lineno);
	}
      /* unfold parameters to msg */
      msg = NULL;
      n = tupleCount (claimbig) - 1;
      if (n < 1)
	{
	  /* no parameters */
	  n = 0;
	}
      else
	{
	  /* n parameters */
	  msg = deVar (claimbig)->right.op2;
	  if (tupleCount (msg) != n)
	    {
	      error ("Problem with claim tuple unfolding at line %i.",
		     trip->next->lineno);
	    }
	}

      /* store claim in claim list */

      // First check whether label is unique
      cl = sys->claimlist;
      while (cl != NULL)
	{
	  if (isTermEqual (cl->label, label))
	    {
	      /**
	       *@todo This should not error exit, but automatically generate a fresh claim label.
	       */
	      error ("Claim label is not unique at line %i.", tc->lineno);
	    }
	  cl = cl->next;
	}
      // Assert: label is unique, add claimlist info
      cl = memAlloc (sizeof (struct claimlist));
      cl->type = claim;
      cl->label = label;
      cl->protocol = thisProtocol;
      cl->rolename = fromrole;
      cl->role = thisRole;
      cl->roledef = NULL;
      cl->count = 0;
      cl->complete = 0;
      cl->failed = 0;
      cl->prec = NULL;
      cl->next = sys->claimlist;
      sys->claimlist = cl;

      /* handles all claim types differently */

      if (claim == CLAIM_Secret)
	{
	  if (n == 0)
	    {
	      error
		("Secrecy claim requires a list of terms to be secret on line %i.",
		 trip->next->lineno);
	    }
	  break;
	}
      if (claim == CLAIM_Nisynch)
	{
	  if (n != 0)
	    {
	      error ("NISYNCH claim requires no parameters at line %i.",
		     trip->next->lineno);
	    }
	  break;
	}
      if (claim == CLAIM_Niagree)
	{
	  if (n != 0)
	    {
	      error ("NIAGREE claim requires no parameters at line %i.",
		     trip->next->lineno);
	    }
	  break;
	}

      /* hmm, no handler yet */

      printf ("ERROR: No know handler for this claim type: ");
      termPrint (claim);
      printf (" ");
      errorTac (trip->next->lineno);
      break;
    }
  /* and make that event */
  thisRole->roledef = roledefAdd (thisRole->roledef, event, label,
				  fromrole, torole, msg, cl);
}

int
normalDeclaration (Tac tc)
{
  switch (tc->op)
    {
    case TAC_VAR:
      levelDeclareVar (tc);
      if (level < 2 && tc->t3.tac == NULL)
	knowledgeAddTermlist (sys->know, tacTermlist (tc->t1.tac));
      break;
    case TAC_CONST:
      levelDeclareConst (tc);
      if (level < 2 && tc->t3.tac == NULL)
	knowledgeAddTermlist (sys->know, tacTermlist (tc->t1.tac));
      break;
    case TAC_SECRET:
      levelDeclareConst (tc);
      break;
    case TAC_COMPROMISED:
      knowledgeAddTermlist (sys->know, tacTermlist (tc->t1.tac));
      break;
    case TAC_INVERSEKEYS:
      knowledgeAddInverse (sys->know, tacTerm (tc->t1.tac),
			   tacTerm (tc->t2.tac));
      break;
    default:
      /* abort with false */
      return 0;
    }
  return 1;
}

void
roleCompile (Term nameterm, Tac tc)
{
  Role r;

  /* make new (empty) current protocol with name */
  r = roleCreate (nameterm);
  thisRole = r;
  /* add protocol to list */
  r->next = thisProtocol->roles;
  thisProtocol->roles = r;

  /* parse the content of the role */
  levelInit ();

  while (tc != NULL)
    {
      switch (tc->op)
	{
	case TAC_READ:
	  commEvent (READ, tc);
	  break;
	case TAC_SEND:
	  commEvent (SEND, tc);
	  break;
	case TAC_CLAIM:
	  commEvent (CLAIM, tc);
	  break;
	default:
	  if (!normalDeclaration (tc))
	    {
	      printf ("ERROR: illegal command %i in role ", tc->op);
	      termPrint (thisRole->nameterm);
	      printf (" ");
	      errorTac (tc->lineno);
	    }
	  break;
	}
      tc = tc->next;
    }
  compute_role_variables (sys, thisProtocol, thisRole);
  levelDone ();
}

void
runInstanceCreate (Tac tc)
{
  /* create an instance of an existing role
   * tac1 is the dot-separated reference to the role.
   * tac2 is the list of parameters to be filled in.
   */

  Protocol p;
  Role r;
  Symbol psym, rsym;
  Termlist instParams;

  /* check whether we can still do it */
  if (sys->maxruns >= maxruns)
    return;

  /* first, locate the protocol */
  psym = tc->t1.tac->t1.sym;
  p = sys->protocols;
  while (p != NULL && p->nameterm->left.symb != psym)
    p = p->next;
  if (p == NULL)
    {
      printf ("Trying to create a run of a non-declared protocol ");
      symbolPrint (psym);
      printf (" ");
      errorTac (tc->lineno);
    }

  /* locate the role */
  rsym = tc->t1.tac->t2.sym;
  r = p->roles;
  while (r != NULL && r->nameterm->left.symb != rsym)
    r = r->next;
  if (r == NULL)
    {
      printf ("Protocol ");
      symbolPrint (psym);
      printf (" has no role called ");
      symbolPrint (rsym);
      printf (" ");
      errorTac (tc->lineno);
    }

  /* we now know what we are instancing, equal numbers? */
  instParams = tacTermlist (tc->t2.tac);
  if (termlistLength (instParams) != termlistLength (p->rolenames))
    {
      printf
	("Run instance has different number of parameters than protocol ");
      termPrint (p->nameterm);
      printf (" ");
      errorTac (tc->lineno);
    }

  /* equal numbers, so it seems to be safe */
  roleInstance (sys, p, r, instParams, NULL);	// technically, we don't need to do this for Arachne [fix later]

  /* after creation analysis */
  /* AC1: untrusted agents */
  /*      first: determine whether the run is untrusted,
   *      by checking whether one of the untrusted agents occurs
   *      in the run instance  */
  if (untrustedAgent (sys, instParams))
    {
      /* nothing yet */
      /* claims handle this themselves */

      /* some reduction might be possible, by cutting of the last few actions
       * of such an untrusted run */

      /* but most of it might be handled dynamically */
    }

  /* AC2: originator assumption for CLP ? */
  /* TODO */
}

void
protocolCompile (Symbol prots, Tac tc, Tac tcroles)
{
  Protocol pr;
  Term t;

  if (levelFind (prots, level) != NULL)
    {
      printf ("ERROR: Double declaration of protocol ");
      symbolPrint (prots);
      printf (" ");
      errorTac (tc->lineno);
    }
  /* make new (empty) current protocol with name */
  pr = protocolCreate (levelConst (prots));
  thisProtocol = pr;
  /* add protocol to list */
  pr->next = sys->protocols;
  sys->protocols = pr;
  protocolCount++;

  levelInit ();
  /* add the role names */
  pr->rolenames = NULL;
  while (tcroles != NULL)
    {
      if (sys->engine == ARACHNE_ENGINE)
	{
	  Term rolename;

	  rolename = levelVar (tcroles->t1.sym);
	  rolename->stype = termlistAdd (NULL, TERM_Agent);
	  pr->rolenames = termlistAppend (pr->rolenames, rolename);
	}
      else
	{
	  pr->rolenames =
	    termlistAppend (pr->rolenames, levelConst (tcroles->t1.sym));
	}
      tcroles = tcroles->next;
    }

  /* parse the content of the protocol */
  while (tc != NULL)
    {
      switch (tc->op)
	{
	case TAC_UNTRUSTED:
	  sys->untrusted =
	    termlistConcat (sys->untrusted, tacTermlist (tc->t1.tac));
	  break;
	case TAC_ROLE:
	  t = levelFind (tc->t1.sym, level);
	  if (t != NULL)
	    {
	      roleCompile (t, tc->t2.tac);
	    }
	  else
	    {
	      printf ("ERROR: undeclared role ");
	      symbolPrint (tc->t1.sym);
	      printf (" in protocol ");
	      termPrint (pr->nameterm);
	      errorTac (tc->t1.sym->lineno);
	    }
	  break;
	default:
	  if (!normalDeclaration (tc))
	    {
	      printf ("ERROR: illegal command %i in protocol ", tc->op);
	      termPrint (thisProtocol->nameterm);
	      errorTac (tc->lineno);
	    }
	  break;
	}
      tc = tc->next;
    }
  levelDone ();
}

void
tacProcess (Tac tc)
{
  while (tc != NULL)
    {
      switch (tc->op)
	{
	case TAC_PROTOCOL:
	  protocolCompile (tc->t1.sym, tc->t2.tac, tc->t3.tac);
	  break;
	case TAC_UNTRUSTED:
	  sys->untrusted =
	    termlistConcat (sys->untrusted, tacTermlist (tc->t1.tac));
	  break;
	case TAC_RUN:
	  runInstanceCreate (tc);
	  break;
	case TAC_USERTYPE:
	  defineUsertype (tc);
	  break;
	default:
	  if (!normalDeclaration (tc))
	    {
	      printf ("ERROR: illegal command %i at the global level.\n",
		      tc->op);
	      errorTac (tc->lineno);
	    }
	  break;
	}
      tc = tc->next;
    }
}

Term
tacTerm (Tac tc)
{
  switch (tc->op)
    {
    case TAC_ENCRYPT:
      return makeTermEncrypt (tacTerm (tc->t1.tac), tacTerm (tc->t2.tac));
    case TAC_TUPLE:
      return makeTermTuple (tacTerm (tc->t1.tac), tacTerm (tc->t2.tac));
    case TAC_STRING:
      {
	Term t = symbolFind (tc->t1.sym);
	if (t == NULL)
	  {
	    printf ("Undeclared symbol ");
	    symbolPrint (tc->t1.sym);
	    errorTac (tc->lineno);
	  }
	return t;
      }
    default:
      return NULL;
    }
}

Termlist
tacTermlist (Tac tc)
{
  Termlist tl = NULL;

  while (tc != NULL)
    {
      tl = termlistAppend (tl, tacTerm (tc));
      tc = tc->next;
    }
  return tl;
}

//! Compute variables for a roles (for Arachne)
void
compute_role_variables (const System sys, Protocol p, Role r)
{
  if (r->variables == NULL)
    {
      // Not computed before, for some reason
      Termlist tl;

      int process_event (Roledef rd)
      {
	tl = termlistAddVariables (tl, rd->from);
	tl = termlistAddVariables (tl, rd->to);
	tl = termlistAddVariables (tl, rd->message);
	return 1;
      }

      tl = NULL;
      roledef_iterate_events (r->roledef, process_event);
      r->variables = tl;

#ifdef DEBUG
      if (DEBUGL (5))
	{
	  eprintf ("All variables for role ");
	  termPrint (r->nameterm);
	  eprintf (" are ");
	  termlistPrint (tl);
	  eprintf ("\n");
	}
#endif
    }
}

//! Compute prec() sets for each claim.
/**
 * Generates two auxiliary structures. First, a table that contains
 * a mapping from all events to event/claim labels.
 * A second table is used to compute the precedence order, and 
 * Warshall's algorithm is used to compute the transitive closure.
 *@returns For each claim in the claim list, a preceding label set is defined.
 */
void
compute_prec_sets (const System sys)
{
  Term *eventlabels;		// array: maps events to labels
  int *prec;			// array: maps event*event to precedence
  int size;			// temp constant: rolecount * roleeventmax
  int r1, r2, ev1, ev2;		// some counters
  int i, j;
  Claimlist cl;

  // Assist: compute index from role, lev
  int index (int r, int lev)
  {
    return r * sys->roleeventmax + lev;
  }

  // Assist: compute matrix index from i*i
  int index2 (int i1, int i2)
  {
    return i1 * size + i2;
  }
  // Assist: yield roledef from r, lev
  Roledef roledef_re (int r, int lev)
  {
    Protocol pr;
    Role ro;
    Roledef rd;

    pr = sys->protocols;
    ro = pr->roles;
    while (r > 0 && ro != NULL)
      {
	ro = ro->next;
	if (ro == NULL)
	  {
	    pr = pr->next;
	    if (pr != NULL)
	      {
		ro = pr->roles;
	      }
	    else
	      {
		ro = NULL;
	      }
	  }
	r--;
      }
    if (ro != NULL)
      {
	rd = ro->roledef;
	while (lev > 0 && rd != NULL)
	  {
	    rd = rd->next;
	    lev--;
	  }
	return rd;
      }
    else
      {
	return NULL;
      }
  }

  // Assist: print matrix
  void show_matrix (void)
  {
    int r1, r2, ev1, ev2;

    r1 = 0;
    while (r1 < sys->rolecount)
      {
	ev1 = 0;
	while (ev1 < sys->roleeventmax)
	  {
	    printf ("prec %i,%i:  ", r1, ev1);
	    r2 = 0;
	    while (r2 < sys->rolecount)
	      {
		ev2 = 0;
		while (ev2 < sys->roleeventmax)
		  {
		    printf ("%i ",
			    prec[index2 (index (r2, ev2), index (r1, ev1))]);
		    ev2++;
		  }
		printf (" ");
		r2++;
	      }
	    printf ("\n");
	    ev1++;
	  }
	printf ("\n");
	r1++;
      }
    printf ("\n");
  }

  /*
   * Phase 1: Allocate structures and map to labels
   */
  //printf ("Rolecount: %i\n", sys->rolecount);
  //printf ("Maxevent : %i\n", sys->roleeventmax);
  size = sys->rolecount * sys->roleeventmax;
  eventlabels = memAlloc (size * sizeof (Term));
  prec = memAlloc (size * size * sizeof (int));
  // Clear tables
  i = 0;
  while (i < size)
    {
      eventlabels[i] = NULL;
      j = 0;
      while (j < size)
	{
	  prec[index2 (i, j)] = 0;
	  j++;
	}
      i++;
    }
  // Assign labels
  r1 = 0;
  while (r1 < sys->rolecount)
    {
      Roledef rd;

      ev1 = 0;
      rd = roledef_re (r1, ev1);
      while (rd != NULL)
	{
	  eventlabels[index (r1, ev1)] = rd->label;
	  //termPrint (rd->label);
	  //printf ("\t");
	  ev1++;
	  rd = rd->next;
	}
      //printf ("\n");
      r1++;
    }
  // Set simple precedence (progress within a role)
  r1 = 0;
  while (r1 < sys->rolecount)
    {
      ev1 = 0;
      while (ev1 < (sys->roleeventmax - 1))
	{
	  prec[index2 (index (r1, ev1), index (r1, ev1 + 1))] = 1;
	  ev1++;
	}
      r1++;
    }
  // Scan for label correspondence
  r1 = 0;
  while (r1 < sys->rolecount)
    {
      ev1 = 0;
      while (ev1 < sys->roleeventmax)
	{
	  Roledef rd1;

	  rd1 = roledef_re (r1, ev1);
	  if (rd1 != NULL && rd1->type == SEND)
	    {
	      r2 = 0;
	      while (r2 < sys->rolecount)
		{
		  ev2 = 0;
		  while (ev2 < sys->roleeventmax)
		    {
		      Roledef rd2;

		      rd2 = roledef_re (r2, ev2);
		      if (rd2 != NULL && rd2->type == READ
			  && isTermEqual (rd1->label, rd2->label))
			{
			  prec[index2 (index (r1, ev1), index (r2, ev2))] = 1;
			}
		      ev2++;
		    }
		  r2++;
		}
	    }
	  ev1++;
	}
      r1++;
    }
  //[x] show_matrix ();

  /*
   * Compute transitive closure (Warshall).
   */
  warshall (prec, size);

  // [x] show_matrix ();

  /*
   * Last phase: Process all individual claims
   */
  cl = sys->claimlist;
  while (cl != NULL)
    {
      Term t;
      Roledef rd;
      Term label;
      int claim_index;

      label = cl->label;
      // Locate r,lev from label, requires (TODO) unique labeling of claims!
      r1 = 0;
      ev1 = -1;
      do
	{
	  ev1++;
	  if (ev1 == sys->roleeventmax)
	    {
	      ev1 = 0;
	      r1++;
	    }
	}
      while (r1 < sys->rolecount
	     && !isTermEqual (label, eventlabels[index (r1, ev1)]));
      if (r1 == sys->rolecount)
	{
	  error
	    ("Prec() setup: Could not find the event corresponding to a claim label.");
	}
      rd = roledef_re (r1, ev1);
      if (rd->type != CLAIM)
	{
	  error
	    ("Prec() setup: First event with claim label doesn't seem to be a claim.");
	}
      // Store in claimlist structure
      cl->r = r1;
      cl->ev = ev1;
      cl->roledef = rd;

      /*
       * We have found the claim roledef, and r1,ev1
       * Now we compute the preceding label set
       */
      cl->prec = NULL;		// clear first
      claim_index = index (r1, ev1);
      r2 = 0;
      while (r2 < sys->rolecount)
	{
	  Roledef rd2;

	  ev2 = 0;
	  rd = roledef_re (r2, ev2);
	  while (rd != NULL)
	    {
	      if (prec[index2 (index (r2, ev2), claim_index)] == 1)
		{
		  // This event precedes the claim

		  if (rd->type == READ)
		    {
		      // Only store read labels (but send would work as well)
		      cl->prec = termlistAdd (cl->prec, rd->label);
		    }
		}
	      rd = rd->next;
	      ev2++;
	    }
	  r2++;
	}
      /**
       * ---------------------------
       * Distinguish types of claims
       * ---------------------------
       */

      // For ni-synch, the preceding label sets are added to the synchronising_labels sets.
      if (cl->type == CLAIM_Nisynch)
	{
	  Termlist tl_scan;

	  tl_scan = cl->prec;
	  while (tl_scan != NULL)
	    {
	      sys->synchronising_labels =
		termlistAddNew (sys->synchronising_labels, tl_scan->term);
	      tl_scan = tl_scan->next;
	    }
	}

      // For ni-agree, the preceding set is also important, but we furthermore need a restricted
      // synchronising_labels set

      //@todo Fix ni-agree synchronising label sets
      if (cl->type == CLAIM_Niagree)
	{
	  int r_scan;

	  // Scan each role (except the current one) and pick out the last prec events.
	  r_scan = 0;
	  while (r_scan < sys->rolecount)
	    {
	      // Only other roles
	      if (r_scan != r1)
		{
		  // Scan fully
		  int ev_scan;
		  Term t_buf;

		  t_buf = NULL;
		  ev_scan = 0;
		  while (ev_scan < sys->roleeventmax)
		    {
		      // if this event preceds the claim, replace the label term
		      if (prec[index2 (index (r_scan, ev_scan), claim_index)]
			  == 1)
			{
			  Roledef rd;

			  rd = roledef_re (r_scan, ev_scan);
			  if (rd->label != NULL)
			    {
			      t_buf = rd->label;
			    }
			}
		      ev_scan++;
		    }
		  // Store only the last label
		  if (t_buf != NULL)
		    {
		      sys->synchronising_labels =
			termlistAddNew (sys->synchronising_labels, t_buf);
		    }
		}
	      r_scan++;
	    }
	}

#ifdef DEBUG
      // Porparam = 100 (weirdness) [x][cc][debug] can turn of the synchronising label sets (override).
      if (sys->porparam == 100)
	{
	  termlistDelete (sys->synchronising_labels);
	  sys->synchronising_labels = NULL;
	  warning
	    ("Emptied synchronising labels set manually because --pp=100.");
	}
#endif
      // Check for empty stuff
      //@todo This is for debugging, mainly.
      if (cl->prec == NULL)
	{
	  fprintf (stderr,
		   "Warning: claim with empty prec() set at r:%i, ev:%i\n",
		   r1, ev1);
	}
      else
	{
	  // printf ("Preceding label set for r:%i, ev:%i = ", r1,ev1);
	  // termlistPrint (cl->prec);
	  // printf ("\n");
	}

      // Proceed to next claim
      cl = cl->next;
    }

  /*
   * Cleanup
   */
  memFree (eventlabels, size * sizeof (Term));
  memFree (prec, size * size * sizeof (int));

#ifdef DEBUG
  if (DEBUGL (2))
    {
      printf ("Synchronising labels set: ");
      termlistPrint (sys->synchronising_labels);
      printf ("\n");
    }
#endif

}

//! Preprocess after system compilation
void
preprocess (const System sys)
{
  /*
   * init some counters
   */
  sys->rolecount = compute_rolecount (sys);
  sys->roleeventmax = compute_roleeventmax (sys);
  /*
   * compute preceding label sets
   */
  compute_prec_sets (sys);
}
