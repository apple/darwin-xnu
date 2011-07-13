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

%token	ADDRMOD
%token	AND
%token	ANY
%token	ARGS
%token	AT
%token	BIN
%token	BUILDDIR
%token	COMMA
%token	CONFIG
%token	CONFIGDIR
%token	CONTROLLER
%token	CPU
%token	CSR
%token	DEVICE
%token	DISK
%token	DRIVE
%token	DST
%token	DUMPS
%token	EQUALS
%token	FLAGS
%token	HZ
%token	IDENT
%token	INIT
%token	MACHINE
%token	MAJOR
%token	MASTER
%token	MAXUSERS
%token	MAXDSIZ
%token	MBA
%token	MBII
%token	MINOR
%token	MINUS
%token	NEXUS
%token	OBJECTDIR
%token	ON
%token	OPTIONS
%token	MAKEOPTIONS
%token	PRIORITY
%token	PROFILE
%token	PSEUDO_DEVICE
%token	ROOT
%token	SEMICOLON
%token	SIZE
%token	SLAVE
%token	SOURCEDIR
%token	SWAP
%token	TIMEZONE
%token	TRACE
%token	UBA
%token	VECTOR
%token	VME
%token  VME16D16
%token  VME24D16
%token  VME32D16
%token  VME16D32
%token  VME24D32
%token  VME32D32

/* following 3 are unique to CMU */
%token	LUN
%token	SLOT
%token	TAPE

%token	<str>	ID
%token	<val>	NUMBER
%token	<val>	FPNUMBER

%type	<str>	Save_id
%type	<str>	Opt_value
%type	<str>	Dev
%type	<lst>	Id_list
%type	<val>	optional_size
%type	<str>	device_name
%type	<val>	major_minor
%type	<val>	arg_device_spec
%type	<val>	root_device_spec
%type	<val>	dump_device_spec
%type	<file>	swap_device_spec
%type	<val>	Value

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

int finddev(dev_t dev);
int alreadychecked(dev_t dev, dev_t list[], dev_t *last);
void deverror(const char *systemname, const char *devtype);
void mkconf(char *sysname);
struct file_list *newswap(void);
void mkswap(struct file_list *syslist, struct file_list *fl, int size);
struct device *huhcon(const char *dev);
void check_nexus(struct device *dev, int num);
void check_slot(struct device *dev, int num);
void checksystemspec(struct file_list *fl);
void verifysystemspecs(void);
dev_t *verifyswap(struct file_list *fl, dev_t checked[], dev_t *pchecked);
struct device *dconnect(const char *dev, int num);

%}
%%
Configuration:
	Many_specs
		{ verifysystemspecs(); }
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
	    {
		if (!strcmp($2, "vax")) {
			machine = MACHINE_VAX;
			machinename = "vax";
		} else if (!strcmp($2, "sun")) {
			/* default to Sun 3 */
			machine = MACHINE_SUN3;
			machinename = "sun3";
		} else if (!strcmp($2, "sun2")) {
			machine = MACHINE_SUN2;
			machinename = "sun2";
		} else if (!strcmp($2, "sun3")) {
			machine = MACHINE_SUN3;
			machinename = "sun3";
		} else if (!strcmp($2, "sun4")) {
			machine = MACHINE_SUN4;
			machinename = "sun4";
		} else if (!strcmp($2, "romp")) {
			machine = MACHINE_ROMP;
			machinename = "romp";
		} else if (!strcmp($2, "ca")) {
			machine = MACHINE_ROMP;
			machinename = "ca";
		} else if (!strcmp($2, "mmax")) {
			machine = MACHINE_MMAX;
			machinename = "mmax";
		} else if (!strcmp($2, "sqt")) {
			machine = MACHINE_SQT;
			machinename = "sqt";
		} else if (!strcmp($2, "i")) {
			machine = MACHINE_I386;
			machinename = "i386";
		} else if (!strcmp($2, "i386")) {
			machine = MACHINE_I386;
			machinename = "i386";
		} else if (!strcmp($2, "ix")) {
			machine = MACHINE_IX;
			machinename = "ix";
		} else if (!strcmp($2, "mipsy")) {
			machine = MACHINE_MIPSY;
			machinename = "mipsy";
		} else if (!strcmp($2, "mips")) {
			machine = MACHINE_MIPS;
			machinename = "mips";
		} else if (!strcmp($2, "i860")) {
			machine = MACHINE_I860;
			machinename = "i860";
		} else if (!strcmp($2, "m68k")) {
			machine = MACHINE_M68K;
			machinename = "m68k";
		} else if (!strcmp($2, "m88k")) {
			machine = MACHINE_M88K;
			machinename = "m88k";
		} else if (!strcmp($2, "m98k")) {
			machine = MACHINE_M98K;
			machinename = "m98k";
		} else if (!strcmp($2, "hppa")) {
			machine = MACHINE_HPPA;
			machinename = "hppa";
		} else if (!strcmp($2, "sparc")) {
			machine = MACHINE_SPARC;
			machinename = "sparc";
		} else if (!strcmp($2, "ppc")) {
			machine = MACHINE_PPC;
			machinename = "ppc";
		} else if (!strcmp($2, "arm")) {
			machine = MACHINE_ARM;
			machinename = "arm";
		} else if (!strcmp($2, "x86_64")) {
			machine = MACHINE_X86_64;
			machinename = "x86_64";
		} else
			yyerror("Unknown machine type");
	      } |
	CPU Save_id
	      {
		struct cputype *cp =
		    (struct cputype *)malloc(sizeof (struct cputype));
		cp->cpu_name = ns($2);
		cp->cpu_next = cputype;
		cputype = cp;
		free(temp_id);
	      } |
	OPTIONS Opt_list
		|
	MAKEOPTIONS Mkopt_list
		|
	IDENT ID
	      { ident = ns($2); }
		|
	System_spec
		|
	MAXUSERS NUMBER
	      { maxusers = $2; }
		|
	BUILDDIR Save_id
		{ build_directory = ns($2); }
		|
	CONFIGDIR Save_id
		{ config_directory = ns($2); }
		|
	OBJECTDIR Save_id
		{ object_directory = ns($2); }
		|
	SOURCEDIR Save_id
		{ source_directory = ns($2); }
		|
	PROFILE
		{ profiling++; }
		;

System_spec:
	  System_id
		{ checksystemspec(*confp); }
	| System_id System_parameter_list
		{ checksystemspec(*confp); }
	;

System_id:
	  CONFIG Save_id
		{ mkconf($2); }
	;

System_parameter_list:
	  System_parameter_list System_parameter
	| System_parameter
	;

System_parameter:
	  swap_spec
	| root_spec
	| dump_spec
	| arg_spec
	;

swap_spec:
	  SWAP optional_on swap_device_list
	;

swap_device_list:
	  swap_device_list AND swap_device
	| swap_device
	;

swap_device:
	  swap_device_spec optional_size
	      { mkswap(*confp, $1, $2); }
	;

swap_device_spec:
	  device_name
		{
			struct file_list *fl = newswap();

			if (eq($1, "generic"))
				fl->f_fn = $1;
			else {
				fl->f_swapdev = nametodev($1, 0, 'b');
				fl->f_fn = devtoname(fl->f_swapdev);
			}
			$$ = fl;
		}
	| major_minor
		{
			struct file_list *fl = newswap();

			fl->f_swapdev = $1;
			fl->f_fn = devtoname($1);
			$$ = fl;
		}
	;

root_spec:
	  ROOT optional_on root_device_spec
		{
			struct file_list *fl = *confp;

			if (fl && fl->f_rootdev != NODEV)
				yyerror("extraneous root device specification");
			else
				fl->f_rootdev = $3;
		}
	;

root_device_spec:
	  device_name
		{ $$ = nametodev($1, 0, 'a'); }
	| major_minor
	;

dump_spec:
	  DUMPS optional_on dump_device_spec
		{
			struct file_list *fl = *confp;

			if (fl && fl->f_dumpdev != NODEV)
				yyerror("extraneous dump device specification");
			else
				fl->f_dumpdev = $3;
		}

	;

dump_device_spec:
	  device_name
		{ $$ = nametodev($1, 0, 'b'); }
	| major_minor
	;

arg_spec:
	  ARGS optional_on arg_device_spec
		{
			struct file_list *fl = *confp;

			if (fl && fl->f_argdev != NODEV)
				yyerror("extraneous arg device specification");
			else
				fl->f_argdev = $3;
		}
	;

arg_device_spec:
	  device_name
		{ $$ = nametodev($1, 0, 'b'); }
	| major_minor
	;

major_minor:
	  MAJOR NUMBER MINOR NUMBER
		{ $$ = makedev($2, $4); }
	;

optional_on:
	  ON
	| /* empty */
	;

optional_size:
	  SIZE NUMBER
	      { $$ = $2; }
	| /* empty */
	      { $$ = 0; }
	;

device_name:
	  Save_id
		{ $$ = $1; }
	| Save_id NUMBER
		{
			char buf[80];

			(void) sprintf(buf, "%s%d", $1, $2);
			$$ = ns(buf); free($1);
		}
	| Save_id NUMBER ID
		{
			char buf[80];

			(void) sprintf(buf, "%s%d%s", $1, $2, $3);
			$$ = ns(buf); free($1);
		}
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
	UBA
	      { $$ = ns("uba"); } |
	MBA
	      { $$ = ns("mba"); } |
        VME16D16
	      {
		if (machine != MACHINE_SUN2 && machine != MACHINE_SUN3
		    && machine != MACHINE_SUN4)
			yyerror("wrong machine type for vme16d16");
		$$ = ns("vme16d16");
		} |
	VME24D16
	      {
		if (machine != MACHINE_SUN2 && machine != MACHINE_SUN3
		    && machine != MACHINE_SUN4)
			yyerror("wrong machine type for vme24d16");
			$$ = ns("vme24d16");
		} |
	VME32D16
	      {
		if (machine != MACHINE_SUN3 && machine != MACHINE_SUN4)

                        yyerror("wrong machine type for vme32d16");
                $$ = ns("vme32d16");
                } |
        VME16D32
              {
                if (machine != MACHINE_SUN3  && machine != MACHINE_SUN4)
                        yyerror("wrong machine type for vme16d32");
                $$ = ns("vme16d32");
                } |
        VME24D32
              {
		if (machine != MACHINE_SUN3 && machine != MACHINE_SUN4)
			yyerror("wrong machine type for vme24d32");
		$$ = ns("vme24d32");
		} |
        VME32D32
	      {
		if (machine != MACHINE_SUN3 && machine != MACHINE_SUN4)
			yyerror("wrong machine type for vme32d32");
		$$ = ns("vme32d32");
		} |
	VME
	      {
		if (machine != MACHINE_MIPSY && machine != MACHINE_MIPS)
			yyerror("wrong machine type for vme");
			$$ = ns("vme");
		} |
	MBII
	      {
		if (machine != MACHINE_MIPSY && machine != MACHINE_MIPS)
			yyerror("wrong machine type for mbii");
			$$ = ns("mbii");
		} |
	ID
	      { $$ = ns($1); }
	;

Device_spec:
	DEVICE Dev_name Dev_info Int_spec
	      { cur.d_type = DEVICE; } |
	MASTER Dev_name Dev_info Int_spec
	      { cur.d_type = MASTER; } |
	DISK Dev_name Dev_info Int_spec
	      { cur.d_dk = 1; cur.d_type = DEVICE; } |
/* TAPE rule is unique to CMU */
	TAPE Dev_name Dev_info Int_spec
	      { cur.d_type = DEVICE; } |
	CONTROLLER Dev_name Dev_info Int_spec
	      { cur.d_type = CONTROLLER; } |
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

Dev_name:
	Init_dev Dev NUMBER
	      {
		cur.d_name = $2;
		if (eq($2, "mba"))
			seen_mba = 1;
		else if (eq($2, "uba"))
			seen_uba = 1;
		else if (eq($2, "mbii"))
			seen_mbii = 1;
		else if (eq($2, "vme"))
			seen_vme = 1;
		cur.d_unit = $3;
		};

Init_dev:
	/* lambda */
	      { init_dev(&cur); };

Dev_info:
	Con_info Info_list
		|
	/* lambda */
		;

Con_info:
	AT Dev NUMBER
	      {
		if (eq(cur.d_name, "mba") || eq(cur.d_name, "uba")
		    || eq(cur.d_name, "mbii") || eq(cur.d_name, "vme")) {
			(void) sprintf(errbuf,
			    "%s must be connected to a nexus", cur.d_name);
			yyerror(errbuf);
		}
		cur.d_conn = dconnect($2, $3);
		if (machine == MACHINE_SQT)
			dev_param(&cur, "index", cur.d_unit);
		} |
/* AT SLOT NUMBER rule is unique to CMU */
	AT SLOT NUMBER
	      { 
		check_slot(&cur, $3);
		cur.d_addr = $3;
		cur.d_conn = TO_SLOT; 
		 } |
	AT NEXUS NUMBER
	      { check_nexus(&cur, $3); cur.d_conn = TO_NEXUS; };

Info_list:
	Info_list Info
		|
	/* lambda */
		;

Info:
	CSR NUMBER
	      {
		cur.d_addr = $2;
		if (machine == MACHINE_SQT) {
			dev_param(&cur, "csr", $2);
		}
		} |
	DRIVE NUMBER
	      {
			cur.d_drive = $2;
			if (machine == MACHINE_SQT) {
				dev_param(&cur, "drive", $2);
			}
		} |
	SLAVE NUMBER
	      {
		if (cur.d_conn != 0 && cur.d_conn != TO_NEXUS &&
		    cur.d_conn->d_type == MASTER)
			cur.d_slave = $2;
		else
			yyerror("can't specify slave--not to master");
		} |
/* MIPS */
	ADDRMOD NUMBER
	      { cur.d_addrmod = $2; } |
/* LUN NUMBER rule is unique to CMU */
	LUN NUMBER
	      {
		if ((cur.d_conn != 0) && (cur.d_conn != TO_SLOT) &&
			(cur.d_conn->d_type == CONTROLLER)) {
			cur.d_addr = $2; 
		}
		else {
			yyerror("device requires controller card");
		    }
		} |
	FLAGS NUMBER
	      {
		cur.d_flags = $2;
		if (machine == MACHINE_SQT) {
			dev_param(&cur, "flags", $2);
		}
	      } |
	BIN NUMBER
	      { 
		 if (machine != MACHINE_SQT)
			yyerror("bin specification only valid on Sequent Balance");
		 if ($2 < 1 || $2 > 7)  
			yyerror("bogus bin number");
		 else {
			cur.d_bin = $2;
			dev_param(&cur, "bin", $2);
		}
	       } |
	Dev Value
	      {
		if (machine != MACHINE_SQT)
			yyerror("bad device spec");
		dev_param(&cur, $1, $2);
		};

Value:
	NUMBER
	      |
	MINUS NUMBER
	      { $$ = -($2); }
	;

Int_spec:
        Vec_spec
	      { cur.d_pri = 0; } |
	PRIORITY NUMBER
	      { cur.d_pri = $2; } |
        PRIORITY NUMBER Vec_spec
	      { cur.d_pri = $2; } |
        Vec_spec PRIORITY NUMBER
	      { cur.d_pri = $3; } |
	/* lambda */
		;

Vec_spec:
        VECTOR Id_list
	      { cur.d_vec = $2; };


Id_list:
	Save_id
	      {
		struct idlst *a = (struct idlst *)malloc(sizeof(struct idlst));
		a->id = $1; a->id_next = 0; $$ = a;
		a->id_vec = 0;
		} |
	Save_id Id_list
		{
		struct idlst *a = (struct idlst *)malloc(sizeof(struct idlst));
	        a->id = $1; a->id_next = $2; $$ = a;
		a->id_vec = 0;
		} |
        Save_id NUMBER
	      {
		struct idlst *a = (struct idlst *)malloc(sizeof(struct idlst));
		a->id_next = 0; a->id = $1; $$ = a;
		a->id_vec = $2;
		} |
        Save_id NUMBER Id_list
	      {
		struct idlst *a = (struct idlst *)malloc(sizeof(struct idlst));
		a->id_next = $3; a->id = $1; $$ = a;
		a->id_vec = $2;
		};

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

/*
 * note that a configuration should be made
 */
void
mkconf(char *sysname)
{
	register struct file_list *fl, **flp;

	fl = (struct file_list *) malloc(sizeof *fl);
	fl->f_type = SYSTEMSPEC;
	fl->f_needs = sysname;
	fl->f_rootdev = NODEV;
	fl->f_argdev = NODEV;
	fl->f_dumpdev = NODEV;
	fl->f_fn = 0;
	fl->f_next = 0;
	for (flp = confp; *flp; flp = &(*flp)->f_next)
		;
	*flp = fl;
	confp = flp;
}

struct file_list *
newswap(void)
{
	struct file_list *fl = (struct file_list *)malloc(sizeof (*fl));

	fl->f_type = SWAPSPEC;
	fl->f_next = 0;
	fl->f_swapdev = NODEV;
	fl->f_swapsize = 0;
	fl->f_needs = 0;
	fl->f_fn = 0;
	return (fl);
}

/*
 * Add a swap device to the system's configuration
 */
void
mkswap(struct file_list *syslist, struct file_list *fl, int size)
{
	register struct file_list **flp;

	if (syslist == 0 || syslist->f_type != SYSTEMSPEC) {
		yyerror("\"swap\" spec precedes \"config\" specification");
		return;
	}
	if (size < 0) {
		yyerror("illegal swap partition size");
		return;
	}
	/*
	 * Append swap description to the end of the list.
	 */
	flp = &syslist->f_next;
	for (; *flp && (*flp)->f_type == SWAPSPEC; flp = &(*flp)->f_next)
		;
	fl->f_next = *flp;
	*flp = fl;
	fl->f_swapsize = size;
	/*
	 * If first swap device for this system,
	 * set up f_fn field to insure swap
	 * files are created with unique names.
	 */
	if (syslist->f_fn)
		return;
	if (eq(fl->f_fn, "generic"))
		syslist->f_fn = ns(fl->f_fn);
	else
		syslist->f_fn = ns(syslist->f_needs);
}

/*
 * find the pointer to connect to the given device and number.
 * returns 0 if no such device and prints an error message
 */
struct device *
dconnect(const char *dev, int num)
{
	register struct device *dp;

	if (num == QUES)
		return (huhcon(dev));
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if ((num != dp->d_unit) || !eq(dev, dp->d_name))
			continue;
		if (dp->d_type != CONTROLLER && dp->d_type != MASTER) {
			(void) sprintf(errbuf,
			    "%s connected to non-controller", dev);
			yyerror(errbuf);
			return (0);
		}
		return (dp);
	}
	(void) sprintf(errbuf, "%s %d not defined", dev, num);
	yyerror(errbuf);
	return (0);
}

/*
 * connect to an unspecific thing
 */
struct device *
huhcon(const char *dev)
{
	register struct device *dp, *dcp;
	struct device rdev;	/* only used if dp is NULL */
	int oldtype;

	memset(&rdev, 0, sizeof rdev);

	/*
	 * First make certain that there are some of these to wildcard on
	 */
	for (dp = dtab; dp != 0; dp = dp->d_next)
		if (eq(dp->d_name, dev))
			break;
	if (dp == 0) {
		(void) sprintf(errbuf, "no %s's to wildcard", dev);
		yyerror(errbuf);
		return (0);
	}
	oldtype = dp->d_type;
	dcp = dp->d_conn;
	/*
	 * Now see if there is already a wildcard entry for this device
	 * (e.g. Search for a "uba ?")
	 */
	for (; dp != 0; dp = dp->d_next)
		if (eq(dev, dp->d_name) && dp->d_unit == -1)
			break;
	/*
	 * If there isn't, make one because everything needs to be connected
	 * to something.
	 */
	if (dp == 0) {
		dp = &rdev;
		init_dev(dp);
		dp->d_unit = QUES;
		dp->d_name = ns(dev);
		dp->d_type = oldtype;
		newdev(dp);
		dp = curp;
		/*
		 * Connect it to the same thing that other similar things are
		 * connected to, but make sure it is a wildcard unit
		 * (e.g. up connected to sc ?, here we make connect sc? to a
		 * uba?).  If other things like this are on the NEXUS or
		 * if they aren't connected to anything, then make the same
		 * connection, else call ourself to connect to another
		 * unspecific device.
		 */
		if (dcp == TO_NEXUS || dcp == 0)
			dp->d_conn = dcp;
		else
			dp->d_conn = dconnect(dcp->d_name, QUES);
	}
	return (dp);
}

void
init_dev(struct device *dp)
{

	dp->d_name = "OHNO!!!";
	dp->d_type = DEVICE;
	dp->d_conn = 0;
	dp->d_vec = 0;
	dp->d_addr = dp->d_pri = dp->d_flags = dp->d_dk = 0;
	dp->d_slave = dp->d_drive = dp->d_unit = UNKNOWN;
	if (machine == MACHINE_SUN2 || machine == MACHINE_SUN3
	    || machine == MACHINE_SUN4){
		dp->d_addr = UNKNOWN;
		dp->d_mach = dp->d_bus = 0;
	}
	if (machine == MACHINE_MIPSY || machine == MACHINE_MIPS){
		dp->d_addrmod = 0;
	}
	dp->d_init = 0;
}

/*
 * make certain that this is a reasonable type of thing to connect to a nexus
 */
void
check_nexus(struct device *dev, int num)
{

	switch (machine) {

	case MACHINE_VAX:
		if (!eq(dev->d_name, "uba") && !eq(dev->d_name, "mba"))
			yyerror("only uba's and mba's should be connected to the nexus");
		if (num != QUES)
			yyerror("can't give specific nexus numbers");
		break;

	case MACHINE_SUN:
		if (!eq(dev->d_name, "mb"))
			yyerror("only mb's should be connected to the nexus");
		break;

	case MACHINE_ROMP:
		if (!eq(dev->d_name, "iocc"))
			yyerror("only iocc's should be connected to the nexus");
		break;
        case MACHINE_SUN2:
		if (!eq(dev->d_name, "virtual") &&
		    !eq(dev->d_name, "obmem") &&
		    !eq(dev->d_name, "obio") &&
		    !eq(dev->d_name, "mbmem") &&
		    !eq(dev->d_name, "mbio") &&
		    !eq(dev->d_name, "vme16d16") &&
		    !eq(dev->d_name, "vme24d16")) {
			(void)sprintf(errbuf,
			    "unknown bus type `%s' for nexus connection on %s",
			    dev->d_name, machinename);
			yyerror(errbuf);
		}

	case MACHINE_MMAX:
		yyerror("don't grok 'nexus' on mmax -- try 'slot'.");
		break;
        case MACHINE_SUN3:
        case MACHINE_SUN4:
		if (!eq(dev->d_name, "virtual") &&
		    !eq(dev->d_name, "obmem") &&
		    !eq(dev->d_name, "obio") &&
		    !eq(dev->d_name, "mbmem") &&
		    !eq(dev->d_name, "mbio") &&
		    !eq(dev->d_name, "vme16d16") &&
		    !eq(dev->d_name, "vme24d16") &&
                    !eq(dev->d_name, "vme32d16") &&
		    !eq(dev->d_name, "vme16d32") &&
		    !eq(dev->d_name, "vme24d32") &&
		    !eq(dev->d_name, "vme32d32")) {
			(void)sprintf(errbuf,
			    "unknown bus type `%s' for nexus connection on %s",
			    dev->d_name, machinename);
			yyerror(errbuf);
		}
		break;
	case MACHINE_MIPSY:
	case MACHINE_MIPS:
		if (!eq(dev->d_name, "vme") && !eq(dev->d_name, "mbii"))
			yyerror("only vme's and mbii's should be connected to the nexus");
		if (num != QUES)
			yyerror("can't give specific nexus numbers");
		break;
	}
}

/*
 * make certain that this is a reasonable type of thing to connect to a slot
 */

void
check_slot(struct device *dev, int num)
{

	switch (machine) {

	case MACHINE_MMAX:
		if (!eq(dev->d_name, "emc"))
			yyerror("only emc's plug into backplane slots.");
		if (num == QUES)
			yyerror("specific slot numbers must be given");
		break;

	case MACHINE_SQT:
		if (!eq(dev->d_name, "mbad") &&
		    !eq(dev->d_name, "zdc") &&
		    !eq(dev->d_name, "sec")) {
			(void)sprintf(errbuf,
			    "unknown bus type `%s' for slot on %s",
			    dev->d_name, machinename);
			yyerror(errbuf);
		}
		break;

	default:
		yyerror("don't grok 'slot' for this machine -- try 'nexus'.");
		break;
	}
}

/*
 * Check system specification and apply defaulting
 * rules on root, argument, dump, and swap devices.
 */
void
checksystemspec(struct file_list *fl)
{
	char buf[BUFSIZ];
	register struct file_list *swap;
	int generic;

	if (fl == 0 || fl->f_type != SYSTEMSPEC) {
		yyerror("internal error, bad system specification");
		exit(1);
	}
	swap = fl->f_next;
	generic = swap && swap->f_type == SWAPSPEC && eq(swap->f_fn, "generic");
	if (fl->f_rootdev == NODEV && !generic) {
		yyerror("no root device specified");
		exit(1);
	}
	/*
	 * Default swap area to be in 'b' partition of root's
	 * device.  If root specified to be other than on 'a'
	 * partition, give warning, something probably amiss.
	 */
	if (swap == 0 || swap->f_type != SWAPSPEC) {
		dev_t dev;

		swap = newswap();
		dev = fl->f_rootdev;
		if (minor(dev) & DEV_MASK) {
			(void) sprintf(buf,
"Warning, swap defaulted to 'b' partition with root on '%c' partition",
				(minor(dev) & DEV_MASK) + 'a');
			yyerror(buf);
		}
		swap->f_swapdev =
		   makedev(major(dev), (minor(dev) &~ DEV_MASK) | ('b' - 'a'));
		swap->f_fn = devtoname(swap->f_swapdev);
		mkswap(fl, swap, 0);
	}
	/*
	 * Make sure a generic swap isn't specified, along with
	 * other stuff (user must really be confused).
	 */
	if (generic) {
		if (fl->f_rootdev != NODEV)
			yyerror("root device specified with generic swap");
		if (fl->f_argdev != NODEV)
			yyerror("arg device specified with generic swap");
		if (fl->f_dumpdev != NODEV)
			yyerror("dump device specified with generic swap");
		return;
	}
	/*
	 * Default argument device and check for oddball arrangements.
	 */
	if (fl->f_argdev == NODEV)
		fl->f_argdev = swap->f_swapdev;
	if (fl->f_argdev != swap->f_swapdev)
		yyerror("Warning, arg device different than primary swap");
	/*
	 * Default dump device and warn if place is not a
	 * swap area or the argument device partition.
	 */
	if (fl->f_dumpdev == NODEV)
		fl->f_dumpdev = swap->f_swapdev;
	if (fl->f_dumpdev != swap->f_swapdev && fl->f_dumpdev != fl->f_argdev) {
		struct file_list *p = swap->f_next;

		for (; p && p->f_type == SWAPSPEC; p = p->f_next)
			if (fl->f_dumpdev == p->f_swapdev)
				return;
		(void) sprintf(buf, "Warning, orphaned dump device, %s",
			"do you know what you're doing");
		yyerror(buf);
	}
}

/*
 * Verify all devices specified in the system specification
 * are present in the device specifications.
 */
void
verifysystemspecs(void)
{
	register struct file_list *fl;
	dev_t checked[50];
	register dev_t *pchecked = checked;

	for (fl = conf_list; fl; fl = fl->f_next) {
		if (fl->f_type != SYSTEMSPEC)
			continue;
		if (!finddev(fl->f_rootdev))
			deverror(fl->f_needs, "root");
		*pchecked++ = fl->f_rootdev;
		pchecked = verifyswap(fl->f_next, checked, pchecked);
#define	samedev(dev1, dev2) \
	((minor(dev1) &~ DEV_MASK) != (minor(dev2) &~ DEV_MASK))
		if (!alreadychecked(fl->f_dumpdev, checked, pchecked)) {
			if (!finddev(fl->f_dumpdev))
				deverror(fl->f_needs, "dump");
			*pchecked++ = fl->f_dumpdev;
		}
		if (!alreadychecked(fl->f_argdev, checked, pchecked)) {
			if (!finddev(fl->f_argdev))
				deverror(fl->f_needs, "arg");
			*pchecked++ = fl->f_argdev;
		}
	}
}

/*
 * Do as above, but for swap devices.
 */
dev_t *
verifyswap(struct file_list *fl, dev_t checked[], dev_t *pchecked)
{

	for (;fl && fl->f_type == SWAPSPEC; fl = fl->f_next) {
		if (eq(fl->f_fn, "generic"))
			continue;
		if (alreadychecked(fl->f_swapdev, checked, pchecked))
			continue;
		if (!finddev(fl->f_swapdev))
			fprintf(stderr,
			   "config: swap device %s not configured", fl->f_fn);
		*pchecked++ = fl->f_swapdev;
	}
	return (pchecked);
}

/*
 * Has a device already been checked
 * for it's existence in the configuration?
 */
int
alreadychecked(dev_t dev, dev_t list[], dev_t *last)
{
	register dev_t *p;

	for (p = list; p < last; p++)
		if (samedev(*p, dev))
			return (1);
	return (0);
}

void
deverror(const char *systemname, const char *devtype)
{

	fprintf(stderr, "config: %s: %s device not configured\n",
		systemname, devtype);
}

/*
 * Look for the device in the list of
 * configured hardware devices.  Must
 * take into account stuff wildcarded.
 */
/*ARGSUSED*/
int
finddev(__unused dev_t dev)
{

	/* punt on this right now */
	return (1);
}
