/*
 * Scyther : An automatic verifier for security protocols.
 * Copyright (C) 2007-2013 Cas Cremers
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef STATES
#define STATES
/**
 * Header file for the states counter datatype.
 *
 * Previously, the states number was just a unsigned int, but that
 * turned out to be insufficient.
 */

#include <stdio.h>

typedef unsigned long int states_t;
#define STATES0 0

states_t statesIncrease (const states_t states);
void statesFormat (const states_t states);

#endif
