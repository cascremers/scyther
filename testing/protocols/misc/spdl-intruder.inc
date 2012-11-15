

protocol myintruder (encr,decr,tupl,proj,m0)
{
	role encr
	{
		var R,X,Y: Ticket;

		read_e1 (R,encr, X);
		read_e2 (R,encr, Y);
		send_e3 (encr,R, {X}Y );
	}

	role decr
	{
		var R,X: Ticket;

		read_d1 (R,decr, {X}pk(E));
		send_d2 (decr,R, X );
	}

	role tupl
	{
		var R,X,Y: Ticket;

		read_t1 (R,tupl, X);
		read_t2 (R,tupl, Y);
		send_t3 (tupl,R, X,Y );
	}

	role proj
	{
		var R,X,Y: Ticket;

		read_p1 (R,proj, X,Y );
		send_p2 (proj,R, X );
		send_p3 (proj,R, Y );
	}

	singular role m0
	{
		send_m0 (m0,m0, pk, pk(A), pk(B), nE, sk(E), E);
	}
}
