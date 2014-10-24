/* 
 * Mach Operating System
 * Copyright (c) 1990 Carnegie-Mellon University
 * Copyright (c) 1989 Carnegie-Mellon University
 * Copyright (c) 1988 Carnegie-Mellon University
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	@(#)config.y	5.8 (Berkeley) 6/18/88
 */

%union {
	char	*str;
	int	val;
	struct	file_list *file;
	struct	idlst *lst;
}

%token	BUILDDIR
%token	COMMA
%token	EQUALS
%token	INIT
%token	MACHINE
%token	OBJECTDIR
%token	OPTIONS
%token	MAKEOPTIONS
%token	PSEUDO_DEVICE
%token	SEMICOLON
%token	SOURCEDIR
%token	TRACE

%token	<str>	ID
%token	<val>	NUMBER

%type	<str>	Save_id
%type	<str>	Opt_value
%type	<str>	Dev

%{

#include "config.h"
#include <ctype.h>
#include <stdio.h>

struct	device cur;
struct	device *curp = 0;
char	*temp_id;
char	*val_id;
/* char	*malloc(); */

int yylex(void);

void deverror(const char *systemname, const char *devtype);

%}
%%
Configuration:
	Many_specs
		;

Many_specs:
	Many_specs Spec
		|
	/* lambda */
		;

Spec:
	Device_spec SEMICOLON
	      { newdev(&cur); } |
	Config_spec SEMICOLON
		|
	TRACE SEMICOLON
	      { do_trace = !do_trace; } |
	SEMICOLON
		|
	error SEMICOLON
		;

Config_spec:
	MACHINE Save_id
		{ machinename = ns($2); }
		|
	OPTIONS Opt_list
		|
	MAKEOPTIONS Mkopt_list
		|
	BUILDDIR Save_id
		{ build_directory = ns($2); }
		|
	OBJECTDIR Save_id
		{ object_directory = ns($2); }
		|
	SOURCEDIR Save_id
		{ source_directory = ns($2); }
		;


Opt_list:
	Opt_list COMMA Option
		|
	Option
		;

Option:
	Save_id
	      {
		struct opt *op = (struct opt *)malloc(sizeof (struct opt));
		op->op_name = ns($1);
		op->op_next = (struct opt *) 0;
		op->op_value = 0;
		if (opt == (struct opt *) 0)
			opt = op;
		else
			opt_tail->op_next = op;
		opt_tail = op;
		free(temp_id);
	      } |
	Save_id EQUALS Opt_value
	      {
		struct opt *op = (struct opt *)malloc(sizeof (struct opt));
		op->op_name = ns($1);
		op->op_next = (struct opt *) 0;
		op->op_value = ns($3);
		if (opt == (struct opt *) 0)
			opt = op;
		else
			opt_tail->op_next = op;
		opt_tail = op;
		free(temp_id);
		if (val_id)
			free(val_id);
	      } ;

Opt_value:
	ID
	      { $$ = val_id = ns($1); } |
	NUMBER
	      { char nb[16];
	          (void) sprintf(nb, "%u", $1);
	      	  $$ = val_id = ns(nb);
	      } |
	/* lambda from MIPS -- WHY */
	      { $$ = val_id = ns(""); }
	      ;

Save_id:
	ID
	      { $$ = temp_id = ns($1); }
	;

Mkopt_list:
	Mkopt_list COMMA Mkoption
		|
	Mkoption
		;

Mkoption:
	Save_id
	      {
		struct opt *op = (struct opt *)malloc(sizeof (struct opt));
		op->op_name = ns($1);
		op->op_next =  (struct opt *) 0;
		op->op_value = 0;
		mkopt = op;
		free(temp_id);
	      } |
	Save_id EQUALS Opt_value
	      {
		struct opt *op = (struct opt *)malloc(sizeof (struct opt));
		op->op_name = ns($1);
		op->op_next =  (struct opt *) 0;
		op->op_value = ns($3);
		if (mkopt == (struct opt *) 0)
			mkopt = op;
		else
			mkopt_tail->op_next = op;
		mkopt_tail = op;
		free(temp_id);
		if (val_id)
			free(val_id);
	      } ;

Dev:
	ID
	      { $$ = ns($1); }
	;

Device_spec:
	PSEUDO_DEVICE Init_dev Dev
	      {
		cur.d_name = $3;
		cur.d_type = PSEUDO_DEVICE;
		} |
	PSEUDO_DEVICE Init_dev Dev NUMBER
	      {
		cur.d_name = $3;
		cur.d_type = PSEUDO_DEVICE;
		cur.d_slave = $4;
		} |
	PSEUDO_DEVICE Init_dev Dev INIT ID
	      {
		cur.d_name = $3;
		cur.d_type = PSEUDO_DEVICE;
		cur.d_init = ns($5);
		} |
	PSEUDO_DEVICE Init_dev Dev NUMBER INIT ID
	      {
		cur.d_name = $3;
		cur.d_type = PSEUDO_DEVICE;
		cur.d_slave = $4;
		cur.d_init = ns($6);
		};

Init_dev:
	/* lambda */
	      { init_dev(&cur); };

%%

void
yyerror(const char *s)
{
	fprintf(stderr, "config: line %d: %s\n", yyline, s);
}

/*
 * return the passed string in a new space
 */
char *
ns(const char *str)
{
	register char *cp;

	cp = malloc((unsigned)(strlen(str)+1));
	(void) strcpy(cp, str);
	return (cp);
}

/*
 * add a device to the list of devices
 */
void
newdev(struct device *dp)
{
	register struct device *np;

	np = (struct device *) malloc(sizeof *np);
	*np = *dp;
	if (curp == 0)
		dtab = np;
	else
		curp->d_next = np;
	curp = np;
	curp->d_next = 0;
}

void
init_dev(struct device *dp)
{

	dp->d_name = "OHNO!!!";
	dp->d_type = PSEUDO_DEVICE;
	dp->d_flags = 0;
	dp->d_slave = UNKNOWN;
	dp->d_init = 0;
}

void
deverror(const char *systemname, const char *devtype)
{

	fprintf(stderr, "config: %s: %s device not configured\n",
		systemname, devtype);
}
