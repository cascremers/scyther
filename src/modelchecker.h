#define MAX_GRAPH_STATES 1000	//!< Maximum number of state space nodes drawn
int traverse (const System oldsys);
int explorify (const System sys, const int run);
int executeStep (const System sys, const int run);
int propertyCheck (const System sys);
Termlist claimViolationDetails (const System sys, const int run, const Roledef
		rd, const Knowledge know);
