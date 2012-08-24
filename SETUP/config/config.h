/*
 * Copyright (c) 1999-2009 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
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
 * Copyright (c) 1980 Regents of the University of California.
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
 *	@(#)config.h	5.8 (Berkeley) 6/18/88
 */

/*
 * Config.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <string.h>

struct file_list {
	struct	file_list *f_next;	
	char	*f_fn;			/* the name */
	u_char	f_type;			/* see below */
	u_char	f_flags;		/* see below */
	short	f_special;		/* requires special make rule */
	char	*f_needs;
	char	*f_extra;		/* stuff to add to make line */
	/*
	 * Random values:
	 *	swap space parameters for swap areas
	 *	root device, etc. for system specifications
	 */
	union {
		struct {		/* when swap specification */
			dev_t	fuw_swapdev;
			int	fuw_swapsize;
		} fuw;
		struct {		/* when system specification */
			dev_t	fus_rootdev;
			dev_t	fus_argdev;
			dev_t	fus_dumpdev;
		} fus;
	} fun;
#define	f_swapdev	fun.fuw.fuw_swapdev
#define	f_swapsize	fun.fuw.fuw_swapsize
#define	f_rootdev	fun.fus.fus_rootdev
#define	f_argdev	fun.fus.fus_argdev
#define	f_dumpdev	fun.fus.fus_dumpdev
};

/*
 * Types.
 */
#define DRIVER		1
#define NORMAL		2
#define	INVISIBLE	3
#define	PROFILING	4
#define	SYSTEMSPEC	5
#define	SWAPSPEC	6

/*
 * Attributes (flags).
 */
#define	CONFIGDEP	0x01	/* obsolete? */
#define	OPTIONSDEF	0x02	/* options definition entry */
#define ORDERED		0x04	/* don't list in OBJ's, keep "files" order */
#define SEDIT		0x08	/* run sed filter (SQT) */

/*
 * Maximum number of fields for variable device fields (SQT).
 */
#define	NFIELDS		10

struct	idlst {
	char	*id;
	struct	idlst *id_next;
	int	id_vec;		/* Sun interrupt vector number */
};

struct device {
	int	d_type;			/* CONTROLLER, DEVICE, bus adaptor */
	struct	device *d_conn;		/* what it is connected to */
	const char	*d_name;	/* name of device (e.g. rk11) */
	struct	idlst *d_vec;		/* interrupt vectors */
	int	d_pri;			/* interrupt priority */
	int	d_addr;			/* address of csr */
	int	d_unit;			/* unit number */
	int	d_drive;		/* drive number */
	int	d_slave;		/* slave number */
#define QUES	-1	/* -1 means '?' */
#define	UNKNOWN -2	/* -2 means not set yet */
	int	d_dk;			/* if init 1 set to number for iostat */
	int	d_flags;		/* nlags for device init */
	struct	device *d_next;		/* Next one in list */
        u_short d_mach;                 /* Sun - machine type (0 = all)*/
        u_short d_bus;                  /* Sun - bus type (0 = unknown) */
	u_long	d_fields[NFIELDS];	/* fields values (SQT) */
	int	d_bin;			/* interrupt bin (SQT) */
	int	d_addrmod;		/* address modifier (MIPS) */
	char	*d_init;		/* pseudo device init routine name */
};
#define TO_NEXUS	(struct device *)-1
#define TO_SLOT		(struct device *)-1

struct config {
	char	*c_dev;
	char	*s_sysname;
};

/*
 * Config has a global notion of which machine type is
 * being used.  It uses the name of the machine in choosing
 * files and directories.  Thus if the name of the machine is ``vax'',
 * it will build from ``Makefile.vax'' and use ``../vax/inline''
 * in the makerules, etc.
 */
extern int	machine;
extern const char	*machinename;
#define	MACHINE_VAX	1
#define	MACHINE_SUN	2
#define	MACHINE_ROMP	3
#define	MACHINE_SUN2	4
#define	MACHINE_SUN3	5
#define	MACHINE_MMAX	6
#define	MACHINE_SQT	7
#define MACHINE_SUN4	8
#define	MACHINE_I386	9
#define	MACHINE_IX	10
#define MACHINE_MIPSY	11
#define	MACHINE_MIPS	12
#define	MACHINE_I860	13
#define	MACHINE_M68K	14
#define	MACHINE_M88K	15
#define	MACHINE_M98K	16
#define MACHINE_HPPA	17
#define MACHINE_SPARC	18
#define MACHINE_PPC	19
#define MACHINE_ARM	20
#define MACHINE_X86_64	21

/*
 * For each machine, a set of CPU's may be specified as supported.
 * These and the options (below) are put in the C flags in the makefile.
 */
struct cputype {
	char	*cpu_name;
	struct	cputype *cpu_next;
};

extern struct cputype  *cputype;

/*
 * In order to configure and build outside the kernel source tree,
 * we may wish to specify where the source tree lives.
 */
extern const char *source_directory;
extern const char *object_directory;
extern char *config_directory;

FILE *fopenp(const char *fpath, char *file, char *complete, const char *ftype);
const char *get_VPATH(void);
#define VPATH	get_VPATH()

/*
 * A set of options may also be specified which are like CPU types,
 * but which may also specify values for the options.
 * A separate set of options may be defined for make-style options.
 */
struct opt {
	char	*op_name;
	char	*op_value;
	struct	opt *op_next;
};

extern struct opt *opt, *mkopt, *opt_tail, *mkopt_tail;

extern char	*ident;
const char	*get_word(FILE *fp);
char	*ns(const char *str);
char	*qu(int num);
char	*path(const char *file);

extern int	do_trace;

#if	MACHINE_VAX
extern int	seen_mba, seen_uba;
#endif

extern int	seen_vme, seen_mbii;

extern struct	device *dtab;
dev_t	nametodev(char *name, int defunit, char defpartition);
char	*devtoname(dev_t dev);

extern char	errbuf[80];
extern int	yyline;

extern struct	file_list *ftab, *conf_list, **confp;
extern char	*build_directory;

extern int	profiling;

extern int	maxusers;

#define eq(a,b)	(!strcmp(a,b))

#ifdef	mips
#define DEV_MASK 0xf
#define	DEV_SHIFT  4
#else	/* mips */
#define DEV_MASK 0x7
#define	DEV_SHIFT  3
#endif	/* mips */

/* External function references */
char *get_rest(FILE *fp);

int yyparse(void);
void yyerror(const char *s);

void vax_ioconf(void);
void sun_ioconf(void);
void romp_ioconf(void);
void mmax_ioconf(void);
void sqt_ioconf(void);
void i386_ioconf(void);
void mips_ioconf(void);
void m68k_ioconf(void);
void m88k_ioconf(void);
void m98k_ioconf(void);
void hppa_ioconf(void);
void sparc_ioconf(void);
void ppc_ioconf(void);
void arm_ioconf(void);
void x86_64_ioconf(void);

void swapconf(void);

void ubglue(void);
void mbglue(void);

void makefile(void);
void headers(void);
int opteq(const char *cp, const char *dp);

void init_dev(struct device *dp);
void newdev(struct device *dp);
void dev_param(struct device *dp, const char *str, long num);

int searchp(const char *spath, char *file, char *fullname, int (*func)(char *));
