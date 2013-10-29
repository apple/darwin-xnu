/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
 */

#ifndef lint
static char sccsid[] __attribute__((used)) = "@(#)mkmakefile.c	5.21 (Berkeley) 6/18/88";
#endif /* not lint */

/*
 * Build the makefile for the system, from
 * the information in the files files and the
 * additional files for the machine being compiled to.
 */

#include <stdio.h>
#include <unistd.h>	/* for unlink */
#include <ctype.h>
#include "parser.h"
#include "config.h"

void	read_files(void);
void	do_objs(FILE *fp, const char *msg, int ext);
void	do_ordered(FILE *fp);
void	do_files(FILE *fp, const char *msg, char ext);
void	do_machdep(FILE *ofp);
void	do_build(const char *name, void (*format)(FILE *));
void	do_rules(FILE *f);
void	do_load(FILE *f);
struct file_list *do_systemspec(FILE *f, struct file_list *fl, int first);
void	do_swapspec(FILE *f, const char *name, char *sysname);
void	copy_dependencies(FILE *makin, FILE *makout);

void	build_cputypes(FILE *fp);
void	build_confdep(FILE *fp);

struct file_list *fl_lookup(char *file);
struct file_list *fltail_lookup(char *file);
struct file_list *new_fent(void);

void	put_source_file_name(FILE *fp, struct file_list *tp);


#define DO_SWAPFILE	0

#define next_word(fp, wd) \
	{ register const char *word = get_word(fp); \
	  if (word == (char *)EOF) \
		return; \
	  else \
		wd = word; \
	}

static	struct file_list *fcur;
const char *tail(const char *fn);
char *allCaps(char *str);

/*
 * Lookup a file, by name.
 */
struct file_list *
fl_lookup(char *file)
{
	register struct file_list *fp;

	for (fp = ftab ; fp != 0; fp = fp->f_next) {
		if (eq(fp->f_fn, file))
			return (fp);
	}
	return (0);
}

/*
 * Lookup a file, by final component name.
 */
struct file_list *
fltail_lookup(char *file)
{
	register struct file_list *fp;

	for (fp = ftab ; fp != 0; fp = fp->f_next) {
		if (eq(tail(fp->f_fn), tail(file)))
			return (fp);
	}
	return (0);
}

/*
 * Make a new file list entry
 */
struct file_list *
new_fent(void)
{
	register struct file_list *fp;

	fp = (struct file_list *) malloc(sizeof *fp);
	fp->f_needs = 0;
	fp->f_next = 0;
	fp->f_flags = 0;
	fp->f_type = 0;
	fp->f_extra = (char *) 0;
	if (fcur == 0)
		fcur = ftab = fp;
	else
		fcur->f_next = fp;
	fcur = fp;
	return (fp);
}

char	*COPTS;
static	struct users {
	int	u_default;
	int	u_min;
	int	u_max;
} users[] = {
	{ 24, 2, 1024 },		/* MACHINE_VAX */
	{  8, 2, 32 },			/* MACHINE_SUN */
	{ 16, 4, 32 },			/* MACHINE_ROMP */
	{  8, 2, 32 },			/* MACHINE_SUN2 */
	{  8, 2, 32 },			/* MACHINE_SUN3 */
	{ 24, 8, 1024},			/* MACHINE_MMAX */
	{ 32, 8, 1024},			/* MACHINE_SQT */
	{  8, 2, 32 },			/* MACHINE_SUN4 */
	{  2, 2, 1024 },		/* MACHINE_I386 */
	{ 32, 8, 1024 },		/* MACHINE_IX */
	{ 32, 8, 1024 },		/* MACHINE_MIPSY */
	{ 32, 8, 1024 },		/* MACHINE_MIPS*/
	{ 32, 8, 1024 },		/* MACHINE_I860*/
	{  8, 2, 32 },			/* MACHINE_M68K */
	{  8, 2, 32 },			/* MACHINE_M88K */
	{  8, 2, 32 },			/* MACHINE_M98K */
	{  8, 2, 32 },			/* MACHINE_HPPA */
	{  8, 2, 32 },			/* MACHINE_SPARC */
	{  8, 2, 32 },			/* MACHINE_PPC */
	{  8, 2, 32 },			/* MACHINE_ARM */
	{  8, 2, 32 },			/* MACHINE_X86_64 */
};
#define NUSERS	(sizeof (users) / sizeof (users[0]))

const char *
get_VPATH(void)
{
    static char *vpath = NULL;

    if ((vpath == NULL) &&
	((vpath = getenv("VPATH")) != NULL) &&
	(*vpath != ':')) {
	register char *buf = malloc((unsigned)(strlen(vpath) + 2));

	vpath = strcat(strcpy(buf, ":"), vpath);
    }

    return vpath ? vpath : "";
}


/*
 * Build the makefile from the skeleton
 */
void
makefile(void)
{
	FILE *ifp, *ofp;
	FILE *dfp;
	char pname[BUFSIZ];
	char line[BUFSIZ];
	struct opt *op;
	struct users *up;

	read_files();
	(void) sprintf(line, "%s/Makefile.template", config_directory);
	ifp = fopenp(VPATH, line, pname, "r");
	if (ifp == 0) {
		perror(line);
		exit(1);
	}
	dfp = fopen(path("Makefile"), "r");
	rename(path("Makefile"), path("Makefile.old"));
	unlink(path("Makefile.old"));
	unlink(path("M.d"));
	if ((ofp = fopen(path("M.d"), "w")) == NULL) {
		perror(path("M.d"));
		/* We'll let this error go */
	}
	else
	 	fclose(ofp);
	ofp = fopen(path("Makefile"), "w");
	if (ofp == 0) {
		perror(path("Makefile"));
		exit(1);
	}
	fprintf(ofp, "SOURCE_DIR=%s\n", source_directory);

	if (machine == MACHINE_SUN || machine == MACHINE_SUN2 
	    || machine == MACHINE_SUN3 || machine == MACHINE_SUN4)
		fprintf(ofp, "export IDENT=-D%s -D%s", machinename, allCaps(ident));
	else
		fprintf(ofp, "export IDENT=-D%s", allCaps(ident));
	if (profiling)
		fprintf(ofp, " -DGPROF");
	if (cputype == 0) {
		printf("cpu type must be specified\n");
		exit(1);
	}
	do_build("cputypes.h", build_cputypes);
	do_build("platforms.h", build_cputypes);

	for (op = opt; op; op = op->op_next)
		if (op->op_value)
			fprintf(ofp, " -D%s=\"%s\"", op->op_name, op->op_value);
		else
			fprintf(ofp, " -D%s", op->op_name);
	fprintf(ofp, "\n");
	if ((unsigned)machine > NUSERS) {
		printf("maxusers config info isn't present, using vax\n");
		up = &users[MACHINE_VAX-1];
	} else
		up = &users[machine-1];
	if (maxusers < up->u_min) {
		maxusers = up->u_min;
	} else if (maxusers > up->u_max)
		printf("warning: maxusers > %d (%d)\n", up->u_max, maxusers);
	if (maxusers) {
		do_build("confdep.h", build_confdep);
	}
	for (op = mkopt; op; op = op->op_next)
		if (op->op_value)
			fprintf(ofp, "%s=%s\n", op->op_name, op->op_value);
		else
			fprintf(ofp, "%s\n", op->op_name);

	while (fgets(line, BUFSIZ, ifp) != 0) {
		if (*line == '%')
			goto percent;
		if (profiling && strncmp(line, "COPTS=", 6) == 0) {
			register char *cp;
			if (machine != MACHINE_MMAX)
			    fprintf(ofp,
				"GPROF.EX=$(SOURCE_DIR)/machdep/%s/gmon.ex\n", machinename);
			cp = index(line, '\n');
			if (cp)
				*cp = 0;
			cp = line + 6;
			while (*cp && (*cp == ' ' || *cp == '\t'))
				cp++;
			COPTS = malloc((unsigned)(strlen(cp) + 1));
			if (COPTS == 0) {
				printf("config: out of memory\n");
				exit(1);
			}
			strcpy(COPTS, cp);
			if (machine == MACHINE_MIPSY || machine == MACHINE_MIPS) {
				fprintf(ofp, "%s ${CCPROFOPT}\n", line);
				fprintf(ofp, "PCOPTS=%s\n", cp);
			} else if (machine == MACHINE_MMAX)
				fprintf(ofp, "%s -p\n",line);
			else
				fprintf(ofp, "%s -pg\n", line);
			continue;
		}
		fprintf(ofp, "%s", line);
		continue;
	percent:
		if (eq(line, "%OBJS\n")) {
			do_objs(ofp, "OBJS=", -1);
		} else if (eq(line, "%CFILES\n")) {
			do_files(ofp, "CFILES=", 'c');
			do_objs(ofp, "COBJS=", 'c');
		} else if (eq(line, "%SFILES\n")) {
			do_files(ofp, "SFILES=", 's');
			do_objs(ofp, "SOBJS=", 's');
		} else if (eq(line, "%MACHDEP\n")) {
			/*
			 * Move do_machdep() after the mkopt stuff.
			 */
			for (op = mkopt; op; op = op->op_next)
				fprintf(ofp, "%s=%s\n", op->op_name, op->op_value);
			do_machdep(ofp);
		} else if (eq(line, "%RULES\n"))
			do_rules(ofp);
		else if (eq(line, "%LOAD\n"))
			do_load(ofp);
		else
			fprintf(stderr,
			    "Unknown %% construct in generic makefile: %s",
			    line);
	}
	if (dfp != NULL)
	{
		copy_dependencies(dfp, ofp);
		(void) fclose(dfp);
	}
	(void) fclose(ifp);
	(void) fclose(ofp);
}

/*
 * Read in the information about files used in making the system.
 * Store it in the ftab linked list.
 */
void
read_files(void)
{
	FILE *fp;
	register struct file_list *tp, *pf;
	register struct device *dp;
	register struct opt *op;
	const char *wd;
	char *this, *needs;
	const char *devorprof;
	int options;
	int not_option;
	int ordered;
	int sedit;				/* SQT */
	char pname[BUFSIZ];
	char fname[1024];
	char *rest = (char *) 0;
	struct cputype *cp;
	int nreqs, first = 1, isdup;

	ftab = 0;
	(void) sprintf(fname, "%s/files", config_directory);
openit:
	fp = fopenp(VPATH, fname, pname, "r");
	if (fp == 0) {
		perror(fname);
		exit(1);
	}
next:
	options = 0;
	rest = (char *) 0;
	/*
	 * filename	[ standard | optional ]
	 *	[ dev* | profiling-routine ] [ device-driver]
	 */
	/*
	 * MACHINE_SQT ONLY:
	 *
	 * filename	[ standard | optional ] 
	 *	[ ordered | sedit ]
	 *	[ dev* | profiling-routine ] [ device-driver]
	 */
	wd = get_word(fp);
	if (wd == (char *)EOF) {
		(void) fclose(fp);
		if (first == 1) {
			(void) sprintf(fname, "%s/files.%s", config_directory, machinename);
			first++;
			goto openit;
		}
		if (first == 2) {
			(void) sprintf(fname, "files.%s", allCaps(ident));
			first++;
			fp = fopenp(VPATH, fname, pname, "r");
			if (fp != 0)
				goto next;
		}
		return;
	}
	if (wd == 0)
		goto next;
	/*
	 *  Allow comment lines beginning witha '#' character.
	 */
	if (*wd == '#')
	{
		while ((wd=get_word(fp)) && wd != (char *)EOF)
			;
		goto next;
	}

	this = ns(wd);
	next_word(fp, wd);
	if (wd == 0) {
		printf("%s: No type for %s.\n",
		    fname, this);
		exit(1);
	}
	if ((pf = fl_lookup(this)) && (pf->f_type != INVISIBLE || pf->f_flags))
		isdup = 1;
	else
		isdup = 0;
	tp = 0;
	if (first == 3 && (tp = fltail_lookup(this)) != 0)
		printf("%s: Local file %s overrides %s.\n",
		    fname, this, tp->f_fn);
	nreqs = 0;
	devorprof = "";
	ordered = 0;
	sedit = 1;				/* SQT: assume sedit for now */
	needs = 0;
	if (eq(wd, "standard"))
		goto checkdev;
	if (!eq(wd, "optional")) {
		printf("%s: %s must be optional or standard\n", fname, this);
		exit(1);
	}
	if (strncmp(this, "OPTIONS/", 8) == 0)
		options++;
	not_option = 0;
nextopt:
	next_word(fp, wd);
	if (wd == 0)
		goto doneopt;
	if (eq(wd, "ordered")) {
		ordered++;
		goto nextopt;
	}
	if (machine == MACHINE_SQT && eq(wd, "sedit")) {
		sedit++;
		goto nextopt;
	}
	if (eq(wd, "not")) {
		not_option = !not_option;
		goto nextopt;
	}
	devorprof = wd;
	if (eq(wd, "device-driver") || eq(wd, "profiling-routine")) {
		next_word(fp, wd);
		goto save;
	}
	nreqs++;
	if (needs == 0 && nreqs == 1)
		needs = ns(wd);
	if (isdup)
		goto invis;
	if (options)
	{
		struct opt *lop = 0;
		struct device tdev;

		/*
		 *  Allocate a pseudo-device entry which we will insert into
		 *  the device list below.  The flags field is set non-zero to
		 *  indicate an internal entry rather than one generated from
		 *  the configuration file.  The slave field is set to define
		 *  the corresponding symbol as 0 should we fail to find the
		 *  option in the option list.
		 */
		init_dev(&tdev);
		tdev.d_name = ns(wd);
		tdev.d_type = PSEUDO_DEVICE;
		tdev.d_flags++;
		tdev.d_slave = 0;

		for (op=opt; op; lop=op, op=op->op_next)
		{
			char *od = allCaps(ns(wd));

			/*
			 *  Found an option which matches the current device
			 *  dependency identifier.  Set the slave field to
			 *  define the option in the header file.
			 */
			if (strcmp(op->op_name, od) == 0)
			{
				tdev.d_slave = 1;
				if (lop == 0)
					opt = op->op_next;
				else
					lop->op_next = op->op_next;
				free(op);
				op = 0;
			 }
			free(od);
			if (op == 0)
				break;
		}
		newdev(&tdev);
	}
 	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (eq(dp->d_name, wd) && (dp->d_type != PSEUDO_DEVICE || dp->d_slave)) {
			if (not_option)
				goto invis;	/* dont want file if option present */
			else
				goto nextopt;
		}
	}
	if (not_option)
		goto nextopt;		/* want file if option missing */

	for (op = opt; op != 0; op = op->op_next)
		if (op->op_value == 0 && opteq(op->op_name, wd)) {
			if (nreqs == 1) {
				free(needs);
				needs = 0;
			}
			goto nextopt;
		}

	for (cp = cputype; cp; cp = cp->cpu_next)
		if (opteq(cp->cpu_name, wd)) {
			if (nreqs == 1) {
				free(needs);
				needs = 0;
			}
			goto nextopt;
		}

invis:
	while ((wd = get_word(fp)) != 0)
		;
	if (tp == 0)
		tp = new_fent();
	tp->f_fn = this;
	tp->f_type = INVISIBLE;
	tp->f_needs = needs;
	tp->f_flags = isdup;
	goto next;

doneopt:
	if (nreqs == 0) {
		printf("%s: what is %s optional on?\n",
		    fname, this);
		exit(1);
	}

checkdev:
	if (wd) {
		if (*wd == '|')
			goto getrest;
		next_word(fp, wd);
		if (wd) {
			if (eq(wd, "ordered")) {
				ordered++;
				goto checkdev;
			}
			if (machine == MACHINE_SQT && eq(wd, "sedit")) {
				sedit++;
				goto checkdev;
			}
			devorprof = wd;
			next_word(fp, wd);
		}
	}

save:
getrest:
	if (wd) {
		if (*wd == '|') {
			rest = ns(get_rest(fp));
		} else {
			printf("%s: syntax error describing %s\n",
			       fname, this);
			exit(1);
		}
	}
	if (eq(devorprof, "profiling-routine") && profiling == 0)
		goto next;
	if (tp == 0)
		tp = new_fent();
	tp->f_fn = this;
	tp->f_extra = rest;
	if (options)
		tp->f_type = INVISIBLE;
	else
	if (eq(devorprof, "device-driver"))
		tp->f_type = DRIVER;
	else if (eq(devorprof, "profiling-routine"))
		tp->f_type = PROFILING;
	else
		tp->f_type = NORMAL;
	tp->f_flags = 0;
	if (ordered)
		tp->f_flags |= ORDERED;
	if (sedit)				/* SQT */
		tp->f_flags |= SEDIT;
	tp->f_needs = needs;
	if (pf && pf->f_type == INVISIBLE)
		pf->f_flags = 1;		/* mark as duplicate */
	goto next;
}

int
opteq(const char *cp, const char *dp)
{
	char c, d;

	for (; ; cp++, dp++) {
		if (*cp != *dp) {
			c = isupper(*cp) ? tolower(*cp) : *cp;
			d = isupper(*dp) ? tolower(*dp) : *dp;
			if (c != d)
				return (0);
		}
		if (*cp == 0)
			return (1);
	}
}

void
put_source_file_name(FILE *fp, struct file_list *tp)
{
	if ((tp->f_fn[0] == '.') && (tp->f_fn[1] == '/'))
		fprintf(fp, "%s ", tp->f_fn);
	 else
		fprintf(fp, "$(SOURCE_DIR)/%s ", tp->f_fn);
}

void
do_objs(FILE *fp, const char *msg, int ext)
{
	register struct file_list *tp;
	register int lpos, len;
	char *cp;
	char och;
	const char *sp;
#if	DO_SWAPFILE
	register struct file_list *fl;
	char swapname[32];
#endif	/* DO_SWAPFILE */

	fprintf(fp, "%s", msg);
	lpos = strlen(msg);
	for (tp = ftab; tp != 0; tp = tp->f_next) {
		if (tp->f_type == INVISIBLE)
			continue;

		/*
		 *	Check for '.o' file in list
		 */
		cp = tp->f_fn + (len = strlen(tp->f_fn)) - 1;
		if ((ext == -1 && tp->f_flags & ORDERED) ||		/* not in objs */
		    (ext != -1 && *cp != ext))
			continue;
		else if (*cp == 'o') {
			if (len + lpos > 72) {
				lpos = 8;
				fprintf(fp, "\\\n\t");
			}
			put_source_file_name(fp, tp);
			fprintf(fp, " ");
			lpos += len + 1;
			continue;
		}
		sp = tail(tp->f_fn);
#if	DO_SWAPFILE
		for (fl = conf_list; fl; fl = fl->f_next) {
			if (fl->f_type != SWAPSPEC)
				continue;
			(void) sprintf(swapname, "swap%s.c", fl->f_fn);
			if (eq(sp, swapname))
				goto cont;
		}
#endif	/* DO_SWAPFILE */
		cp = (char *)sp + (len = strlen(sp)) - 1;
		och = *cp;
		*cp = 'o';
		if (len + lpos > 72) {
			lpos = 8;
			fprintf(fp, "\\\n\t");
		}
		fprintf(fp, "%s ", sp);
		lpos += len + 1;
		*cp = och;
#if	DO_SWAPFILE
cont:
		;
#endif	/* DO_SWAPFILE */
	}
	if (lpos != 8)
		putc('\n', fp);
}

/* not presently used and probably broken,  use ORDERED instead */
void
do_ordered(FILE *fp)
{
	register struct file_list *tp;
	register int lpos, len;
	char *cp;
	char och;
	const char *sp;

	fprintf(fp, "ORDERED=");
	lpos = 10;
	for (tp = ftab; tp != 0; tp = tp->f_next) {
		if ((tp->f_flags & ORDERED) != ORDERED)
			continue;
		sp = tail(tp->f_fn);
		cp = (char *)sp + (len = strlen(sp)) - 1;
		och = *cp;
		*cp = 'o';
		if (len + lpos > 72) {
			lpos = 8;
			fprintf(fp, "\\\n\t");
		}
		fprintf(fp, "%s ", sp);
		lpos += len + 1;
		*cp = och;
	}
	if (lpos != 8)
		putc('\n', fp);
}

void
do_files(FILE *fp, const char *msg, char ext)
{
	register struct file_list *tp;
	register int lpos, len=0; /* dvw: init to 0 */

	fprintf(fp, "%s", msg);
	lpos = 8;
	for (tp = ftab; tp != 0; tp = tp->f_next) {
		if (tp->f_type == INVISIBLE)
			continue;
		if (tp->f_fn[strlen(tp->f_fn)-1] != ext)
			continue;
		/*
		 * Always generate a newline.
		 * Our Makefile's aren't readable anyway.
		 */

		lpos = 8;
		fprintf(fp, "\\\n\t");
		put_source_file_name(fp, tp);
		lpos += len + 1;
	}
	if (lpos != 8)
		putc('\n', fp);
}

/*
 *  Include machine dependent makefile in output
 */

void
do_machdep(FILE *ofp)
{
	FILE *ifp;
	char pname[BUFSIZ];
	char line[BUFSIZ];

	(void) sprintf(line, "%s/Makefile.%s", config_directory, machinename);
	ifp = fopenp(VPATH, line, pname, "r");
	if (ifp == 0) {
		perror(line);
		exit(1);
	}
	while (fgets(line, BUFSIZ, ifp) != 0) {
		if (profiling && (strncmp(line, "LIBS=", 5) == 0)) 
			fprintf(ofp,"LIBS=${LIBS_P}\n");
		else
			fputs(line, ofp);
	}
	fclose(ifp);
}


/*
 *  Format configuration dependent parameter file.
 */

void
build_confdep(FILE *fp)
{
	fprintf(fp, "#define MAXUSERS %d\n", maxusers);
}

/*
 *  Format cpu types file.
 */

void
build_cputypes(FILE *fp)
{
	struct cputype *cp;

	for (cp = cputype; cp; cp = cp->cpu_next)
		fprintf(fp, "#define\t%s\t1\n", cp->cpu_name);
}



/*
 *  Build a define parameter file.  Create it first in a temporary location and
 *  determine if this new contents differs from the old before actually
 *  replacing the original (so as not to introduce avoidable extraneous
 *  compilations).
 */

void
do_build(const char *name, void (*format)(FILE *))
{
	static char temp[]="#config.tmp";
	FILE *tfp, *ofp;
	int c;

	unlink(path(temp));
	tfp = fopen(path(temp), "w+");
	if (tfp == 0) {
		perror(path(temp));
		exit(1);
	}
	unlink(path(temp));
	(*format)(tfp);
	ofp = fopen(path(name), "r");
	if (ofp != 0)
	{
		fseek(tfp, 0, 0);
		while ((c = fgetc(tfp)) != EOF)
			if (fgetc(ofp) != c)
				goto copy;
		if (fgetc(ofp) == EOF)
			goto same;
		
	}
copy:
	if (ofp)
		fclose(ofp);
	unlink(path(name));
	ofp = fopen(path(name), "w");
	if (ofp == 0) {
		perror(path(name));
		exit(1);
	}
	fseek(tfp, 0, 0);
	while ((c = fgetc(tfp)) != EOF)
		fputc(c, ofp);
same:
	fclose(ofp);
	fclose(tfp);
}

const char *
tail(const char *fn)
{
	register const char *cp;

	cp = rindex(fn, '/');
	if (cp == 0)
		return (fn);
	return (cp+1);
}

/*
 * Create the makerules for each file
 * which is part of the system.
 * Devices are processed with the special c2 option -i
 * which avoids any problem areas with i/o addressing
 * (e.g. for the VAX); assembler files are processed by as.
 */
void
do_rules(FILE *f)
{
	char *cp;
	char *np, och;
	const char *tp;
	register struct file_list *ftp;
	const char *extras = ""; /* dvw: init to "" */
	char *source_dir;
	char och_upper;
	const char *nl = "";

	for (ftp = ftab; ftp != 0; ftp = ftp->f_next) {
		if (ftp->f_type == INVISIBLE)
			continue;
		cp = (np = ftp->f_fn) + strlen(ftp->f_fn) - 1;
		och = *cp;
		/*
			*	Don't compile '.o' files
			*/
		if (och == 'o')
			continue;
		/*
			*	Determine where sources should come from
			*/
		if ((np[0] == '.') && (np[1] == '/')) {
			source_dir = "";
			np += 2;
		} else
			source_dir = "$(SOURCE_DIR)/";
		*cp = '\0';
		tp = tail(np);	/* dvw: init tp before 'if' */
		fprintf(f, "-include %sd\n", tp);
		fprintf(f, "%so: %s%s%c\n", tp, source_dir, np, och);
		if (och == 's') {
			switch (machine) {
			case MACHINE_MIPSY:
			case MACHINE_MIPS:
				break;
			default:
				fprintf(f, "\t${S_RULE_0}\n");
				fprintf(f, "\t${S_RULE_1A}%s%.*s${S_RULE_1B}%s\n",
						source_dir, (int)(tp-np), np, nl);
				fprintf(f, "\t${S_RULE_2}%s\n", nl);
				break;
			}
			continue;
		}
		extras = "";
		switch (ftp->f_type) {
	
		case NORMAL:
			switch (machine) {
	
			case MACHINE_MIPSY:
			case MACHINE_MIPS:
				break;
			default:
				goto common;
			}
			break;
	
		case DRIVER:
			switch (machine) {
	
			case MACHINE_MIPSY:
			case MACHINE_MIPS:
				fprintf(f, "\t@${RM} %so\n", tp);
				fprintf(f, "\t${CC} ${CCDFLAGS}%s %s%s%sc\n\n",
					(ftp->f_extra?ftp->f_extra:""), extras, source_dir, np);
				continue;
			default:
				extras = "_D";
				goto common;
			}
			break;
	
		case PROFILING:
			if (!profiling)
				continue;
			if (COPTS == 0) {
				fprintf(stderr,
					"config: COPTS undefined in generic makefile");
				COPTS = "";
			}
			switch (machine) {
				case MACHINE_MIPSY:
				case MACHINE_MIPS:
					fprintf(f, "\t@${RM} %so\n", tp);
					fprintf(f, "\t${CC} ${CCPFLAGS}%s %s../%sc\n\n",
						(ftp->f_extra?ftp->f_extra:""), extras, np);
					continue;
				case MACHINE_VAX:
				case MACHINE_ROMP:
				case MACHINE_SQT:
				case MACHINE_MMAX:
				case MACHINE_SUN3:
				case MACHINE_SUN4:
				case MACHINE_I386:
				case MACHINE_I860:
				case MACHINE_HPPA:
				case MACHINE_SPARC:
				case MACHINE_PPC:
				case MACHINE_ARM:
				case MACHINE_X86_64:
					extras = "_P";
					goto common;
				default:
				fprintf(stderr,
					"config: don't know how to profile kernel on this cpu\n");
				break;
			}
	
		common:
			och_upper = och + 'A' - 'a';
			fprintf(f, "\t${%c_RULE_0%s}\n", och_upper, extras);
			fprintf(f, "\t${%c_RULE_1A%s}", och_upper, extras);
			if (ftp->f_extra)
				fprintf(f, "%s", ftp->f_extra);
			fprintf(f, "%s%.*s${%c_RULE_1B%s}%s\n",
					source_dir, (int)(tp-np), np, och_upper, extras, nl);

			/* While we are still using CTF, any build that normally does not support CTF will
			 * a "standard" compile done as well that we can harvest CTF information from; do
			 * that here.
			 */
			fprintf(f, "\t${%c_CTFRULE_1A%s}", och_upper, extras);
			if (ftp->f_extra)
				fprintf(f, "%s", ftp->f_extra);
			fprintf(f, "%s%.*s${%c_CTFRULE_1B%s}%s\n",
					source_dir, (int)(tp-np), np, och_upper, extras, nl);

			fprintf(f, "\t${%c_RULE_2%s}%s\n", och_upper, extras, nl);
			fprintf(f, "\t${%c_CTFRULE_2%s}%s\n", och_upper, extras, nl);
			break;
	
		default:
			printf("Don't know rules for %s\n", np);
			break;
		}
		*cp = och;
	}
}

/*
 * Create the load strings
 */
void
do_load(FILE *f)
{
	register struct file_list *fl;
	int first = 1;

	fl = conf_list;
	while (fl) {
		if (fl->f_type != SYSTEMSPEC) {
			fl = fl->f_next;
			continue;
		}
		fl = do_systemspec(f, fl, first);
		if (first)
			first = 0;
	}
	fprintf(f, "LOAD =");
	for (fl = conf_list; fl != 0; fl = fl->f_next)
		if (fl->f_type == SYSTEMSPEC)
			fprintf(f, " %s", fl->f_needs);
#ifdef	multimax
	fprintf(f, "\n\nall .ORDER: includelinks ${LOAD}\n");
#else	/* multimax */
	fprintf(f, "\n\nall: includelinks ${LOAD}\n");
#endif	/* multimax */
	fprintf(f, "\n");
}

struct file_list *
do_systemspec(FILE *f, struct file_list *fl, __unused int first)
{
	/*
	 * Variable for kernel name.
	 */
	fprintf(f, "KERNEL_NAME=%s\n", fl->f_needs);

	fprintf(f, "%s .ORDER: %s.sys ${SYSDEPS}\n",
		fl->f_needs, fl->f_needs);
	fprintf(f, "\t${SYS_RULE_1}\n");
	fprintf(f, "\t${SYS_RULE_2}\n");
	fprintf(f, "\t${SYS_RULE_3}\n");
	fprintf(f, "\t${SYS_RULE_4}\n\n");
	do_swapspec(f, fl->f_fn, fl->f_needs);
	for (fl = fl->f_next; fl != NULL && fl->f_type == SWAPSPEC; fl = fl->f_next)
		continue;
	return (fl);
}

void
do_swapspec(__unused FILE *f, __unused const char *name, __unused char *sysname)
{

#if	DO_SWAPFILE
	char *gdir = eq(name, "generic")?"$(MACHINEDIR)/":"";

	fprintf(f, "%s.sys:${P} ${PRELDDEPS} ${LDOBJS} ${LDDEPS}\n\n", sysname);
	fprintf(f, "%s.swap: swap%s.o\n", sysname, name);
	fprintf(f, "\t@rm -f $@\n");
	fprintf(f, "\t@cp swap%s.o $@\n\n", name);
	fprintf(f, "swap%s.o: %sswap%s.c ${SWAPDEPS}\n", name, gdir, name);
	if (machine == MACHINE_MIPSY || machine == MACHINE_MIPS) {
		fprintf(f, "\t@${RM} swap%s.o\n", name);
		fprintf(f, "\t${CC} ${CCNFLAGS} %sswap%s.c\n\n", gdir, name);
	} else {
		fprintf(f, "\t${C_RULE_1A}%s${C_RULE_1B}\n", gdir);
		fprintf(f, "\t${C_RULE_2}\n");
		fprintf(f, "\t${C_RULE_3}\n");
		fprintf(f, "\t${C_RULE_4}\n\n");
	}
#endif	/* DO_SWAPFILE */
}

char *
allCaps(str)
	register char *str;
{
	register char *cp = str;

	while (*str) {
		if (islower(*str))
			*str = toupper(*str);
		str++;
	}
	return (cp);
}

#define OLDSALUTATION "# DO NOT DELETE THIS LINE"

#define LINESIZE 1024
static char makbuf[LINESIZE];		/* one line buffer for makefile */

void
copy_dependencies(FILE *makin, FILE *makout)
{
	register int oldlen = (sizeof OLDSALUTATION - 1);

	while (fgets(makbuf, LINESIZE, makin) != NULL) {
		if (! strncmp(makbuf, OLDSALUTATION, oldlen))
			break;
	}
	while (fgets(makbuf, LINESIZE, makin) != NULL) {
		if (oldlen != 0)
		{
			if (makbuf[0] == '\n')
				continue;
			else
				oldlen = 0;
		}
		fputs(makbuf, makout);
	}
}
