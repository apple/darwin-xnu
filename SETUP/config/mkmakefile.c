/*
 * Copyright (c) 1999-2016 Apple Inc. All rights reserved.
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
#include <unistd.h>     /* for unlink */
#include <ctype.h>
#include "parser.h"
#include "config.h"

void    read_files(void);
void    do_objs(FILE *fp, const char *msg, int ext);
void    do_files(FILE *fp, const char *msg, char ext);
void    do_machdep(FILE *ofp);
void    do_rules(FILE *f);
void    copy_dependencies(FILE *makin, FILE *makout);

struct file_list *fl_lookup(char *file);
struct file_list *fltail_lookup(char *file);
struct file_list *new_fent(void);

void    put_source_file_name(FILE *fp, struct file_list *tp);


#define next_word(fp, wd) \
	{ const char *word = get_word(fp); \
	  if (word == (char *)EOF) \
	        return; \
	  else \
	        wd = word; \
	}

static  struct file_list *fcur;
const char *tail(const char *fn);
char *allCaps(char *str);

/*
 * Lookup a file, by name.
 */
struct file_list *
fl_lookup(char *file)
{
	struct file_list *fp;

	for (fp = ftab; fp != 0; fp = fp->f_next) {
		if (eq(fp->f_fn, file)) {
			return fp;
		}
	}
	return 0;
}

/*
 * Lookup a file, by final component name.
 */
struct file_list *
fltail_lookup(char *file)
{
	struct file_list *fp;

	for (fp = ftab; fp != 0; fp = fp->f_next) {
		if (eq(tail(fp->f_fn), tail(file))) {
			return fp;
		}
	}
	return 0;
}

/*
 * Make a new file list entry
 */
struct file_list *
new_fent(void)
{
	struct file_list *fp;

	fp = (struct file_list *) malloc(sizeof *fp);
	fp->f_needs = 0;
	fp->f_next = 0;
	fp->f_flags = 0;
	fp->f_type = 0;
	fp->f_extra = (char *) 0;
	if (fcur == 0) {
		fcur = ftab = fp;
	} else {
		fcur->f_next = fp;
	}
	fcur = fp;
	return fp;
}

char    *COPTS;

const char *
get_VPATH(void)
{
	static char *vpath = NULL;

	if ((vpath == NULL) &&
	    ((vpath = getenv("VPATH")) != NULL) &&
	    (*vpath != ':')) {
		char *buf = malloc((unsigned)(strlen(vpath) + 2));

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
	ofp = fopen(path("Makefile"), "w");
	if (ofp == 0) {
		perror(path("Makefile"));
		exit(1);
	}
	fprintf(ofp, "SOURCE_DIR=%s\n", source_directory);

	fprintf(ofp, "export CONFIG_DEFINES =");
	if (profiling) {
		fprintf(ofp, " -DGPROF");
	}

	for (op = opt; op; op = op->op_next) {
		if (op->op_value) {
			fprintf(ofp, " -D%s=\"%s\"", op->op_name, op->op_value);
		} else {
			fprintf(ofp, " -D%s", op->op_name);
		}
	}
	fprintf(ofp, "\n");
	for (op = mkopt; op; op = op->op_next) {
		if (op->op_value) {
			fprintf(ofp, "%s=%s\n", op->op_name, op->op_value);
		} else {
			fprintf(ofp, "%s\n", op->op_name);
		}
	}

	while (fgets(line, BUFSIZ, ifp) != 0) {
		if (*line == '%') {
			goto percent;
		}
		if (profiling && strncmp(line, "COPTS=", 6) == 0) {
			char *cp;
			fprintf(ofp,
			    "GPROF.EX=$(SOURCE_DIR)/machdep/%s/gmon.ex\n", machinename);
			cp = index(line, '\n');
			if (cp) {
				*cp = 0;
			}
			cp = line + 6;
			while (*cp && (*cp == ' ' || *cp == '\t')) {
				cp++;
			}
			COPTS = malloc((unsigned)(strlen(cp) + 1));
			if (COPTS == 0) {
				printf("config: out of memory\n");
				exit(1);
			}
			strcpy(COPTS, cp);
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
		} else if (eq(line, "%CXXFILES\n")) {
			do_files(ofp, "CXXFILES=", 'p');
			do_objs(ofp, "CXXOBJS=", 'p');
		} else if (eq(line, "%SFILES\n")) {
			do_files(ofp, "SFILES=", 's');
			do_objs(ofp, "SOBJS=", 's');
		} else if (eq(line, "%MACHDEP\n")) {
			do_machdep(ofp);
		} else if (eq(line, "%RULES\n")) {
			do_rules(ofp);
		} else {
			fprintf(stderr,
			    "Unknown %% construct in generic makefile: %s",
			    line);
		}
	}
	if (dfp != NULL) {
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
	struct file_list *tp, *pf;
	struct device *dp;
	struct opt *op;
	const char *wd;
	char *this, *needs;
	const char *devorprof;
	int options;
	int not_option;
	char pname[BUFSIZ];
	char fname[1024];
	char *rest = (char *) 0;
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
	wd = get_word(fp);
	if (wd == (char *)EOF) {
		(void) fclose(fp);
		if (first == 1) {
			(void) sprintf(fname, "%s/files.%s", config_directory, machinename);
			first++;
			goto openit;
		}
		return;
	}
	if (wd == 0) {
		goto next;
	}
	/*
	 *  Allow comment lines beginning witha '#' character.
	 */
	if (*wd == '#') {
		while ((wd = get_word(fp)) && wd != (char *)EOF) {
			;
		}
		goto next;
	}

	this = ns(wd);
	next_word(fp, wd);
	if (wd == 0) {
		printf("%s: No type for %s.\n",
		    fname, this);
		exit(1);
	}
	if ((pf = fl_lookup(this)) && (pf->f_type != INVISIBLE || pf->f_flags)) {
		isdup = 1;
	} else {
		isdup = 0;
	}
	tp = 0;
	nreqs = 0;
	devorprof = "";
	needs = 0;
	if (eq(wd, "standard")) {
		goto checkdev;
	}
	if (!eq(wd, "optional")) {
		printf("%s: %s must be optional or standard\n", fname, this);
		exit(1);
	}
	if (strncmp(this, "OPTIONS/", 8) == 0) {
		options++;
	}
	not_option = 0;
nextopt:
	next_word(fp, wd);
	if (wd == 0) {
		goto doneopt;
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
	if (needs == 0 && nreqs == 1) {
		needs = ns(wd);
	}
	if (isdup) {
		goto invis;
	}
	if (options) {
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

		for (op = opt; op; lop = op, op = op->op_next) {
			char *od = allCaps(ns(wd));

			/*
			 *  Found an option which matches the current device
			 *  dependency identifier.  Set the slave field to
			 *  define the option in the header file.
			 */
			if (strcmp(op->op_name, od) == 0) {
				tdev.d_slave = 1;
				if (lop == 0) {
					opt = op->op_next;
				} else {
					lop->op_next = op->op_next;
				}
				free(op);
				op = 0;
			}
			free(od);
			if (op == 0) {
				break;
			}
		}
		newdev(&tdev);
	}
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (eq(dp->d_name, wd) && (dp->d_type != PSEUDO_DEVICE || dp->d_slave)) {
			if (not_option) {
				goto invis;     /* dont want file if option present */
			} else {
				goto nextopt;
			}
		}
	}
	if (not_option) {
		goto nextopt;           /* want file if option missing */
	}
	for (op = opt; op != 0; op = op->op_next) {
		if (op->op_value == 0 && opteq(op->op_name, wd)) {
			if (nreqs == 1) {
				free(needs);
				needs = 0;
			}
			goto nextopt;
		}
	}

invis:
	while ((wd = get_word(fp)) != 0) {
		;
	}
	if (tp == 0) {
		tp = new_fent();
	}
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
		if (*wd == '|') {
			goto getrest;
		}
		next_word(fp, wd);
		if (wd) {
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
	if (eq(devorprof, "profiling-routine") && profiling == 0) {
		goto next;
	}
	if (tp == 0) {
		tp = new_fent();
	}
	tp->f_fn = this;
	tp->f_extra = rest;
	if (options) {
		tp->f_type = INVISIBLE;
	} else if (eq(devorprof, "device-driver")) {
		tp->f_type = DRIVER;
	} else if (eq(devorprof, "profiling-routine")) {
		tp->f_type = PROFILING;
	} else {
		tp->f_type = NORMAL;
	}
	tp->f_flags = 0;
	tp->f_needs = needs;
	if (pf && pf->f_type == INVISIBLE) {
		pf->f_flags = 1;                /* mark as duplicate */
	}
	goto next;
}

int
opteq(const char *cp, const char *dp)
{
	char c, d;

	for (;; cp++, dp++) {
		if (*cp != *dp) {
			c = isupper(*cp) ? tolower(*cp) : *cp;
			d = isupper(*dp) ? tolower(*dp) : *dp;
			if (c != d) {
				return 0;
			}
		}
		if (*cp == 0) {
			return 1;
		}
	}
}

void
put_source_file_name(FILE *fp, struct file_list *tp)
{
	if ((tp->f_fn[0] == '.') && (tp->f_fn[1] == '/')) {
		fprintf(fp, "%s ", tp->f_fn);
	} else {
		fprintf(fp, "$(SOURCE_DIR)/%s ", tp->f_fn);
	}
}

void
do_objs(FILE *fp, const char *msg, int ext)
{
	struct file_list *tp;
	int lpos, len;
	char *cp;
	char och;
	const char *sp;

	fprintf(fp, "%s", msg);
	lpos = strlen(msg);
	for (tp = ftab; tp != 0; tp = tp->f_next) {
		if (tp->f_type == INVISIBLE) {
			continue;
		}

		/*
		 *	Check for '.o' file in list
		 */
		cp = tp->f_fn + (len = strlen(tp->f_fn)) - 1;
		if (ext != -1 && *cp != ext) {
			continue;
		} else if (*cp == 'o') {
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
	putc('\n', fp);
}

void
do_files(FILE *fp, const char *msg, char ext)
{
	struct file_list *tp;
	int lpos, len = 0; /* dvw: init to 0 */

	fprintf(fp, "%s", msg);
	lpos = 8;
	for (tp = ftab; tp != 0; tp = tp->f_next) {
		if (tp->f_type == INVISIBLE) {
			continue;
		}
		if (tp->f_fn[strlen(tp->f_fn) - 1] != ext) {
			continue;
		}
		/*
		 * Always generate a newline.
		 * Our Makefile's aren't readable anyway.
		 */

		lpos = 8;
		fprintf(fp, "\\\n\t");
		put_source_file_name(fp, tp);
		lpos += len + 1;
	}
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
		if (profiling && (strncmp(line, "LIBS=", 5) == 0)) {
			fprintf(ofp, "LIBS=${LIBS_P}\n");
		} else {
			fputs(line, ofp);
		}
	}
	fclose(ifp);
}

const char *
tail(const char *fn)
{
	const char *cp;

	cp = rindex(fn, '/');
	if (cp == 0) {
		return fn;
	}
	return cp + 1;
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
	struct file_list *ftp;
	const char *extras = ""; /* dvw: init to "" */
	char *source_dir;
	char och_upper;
	const char *nl = "";

	for (ftp = ftab; ftp != 0; ftp = ftp->f_next) {
		if (ftp->f_type == INVISIBLE) {
			continue;
		}
		cp = (np = ftp->f_fn) + strlen(ftp->f_fn) - 1;
		och = *cp;
		/*
		 *	Don't compile '.o' files
		 */
		if (och == 'o') {
			continue;
		}
		/*
		 *	Determine where sources should come from
		 */
		if ((np[0] == '.') && (np[1] == '/')) {
			source_dir = "";
			np += 2;
		} else {
			source_dir = "$(SOURCE_DIR)/";
		}
		*cp = '\0';
		tp = tail(np);  /* dvw: init tp before 'if' */
		fprintf(f, "-include %sd\n", tp);
		fprintf(f, "%so: %s%s%c\n", tp, source_dir, np, och);
		if (och == 's') {
			fprintf(f, "\t${S_RULE_0}\n");
			fprintf(f, "\t${S_RULE_1A}%s%.*s${S_RULE_1B}%s\n",
			    source_dir, (int)(tp - np), np, nl);
			fprintf(f, "\t${S_RULE_2}%s\n", nl);
			continue;
		}
		extras = "";
		switch (ftp->f_type) {
		case NORMAL:
			goto common;
			break;

		case DRIVER:
			extras = "_D";
			goto common;
			break;

		case PROFILING:
			if (!profiling) {
				continue;
			}
			if (COPTS == 0) {
				fprintf(stderr,
				    "config: COPTS undefined in generic makefile");
				COPTS = "";
			}
			extras = "_P";
			goto common;

common:
			och_upper = och + 'A' - 'a';
			fprintf(f, "\t${%c_RULE_0%s}\n", och_upper, extras);
			fprintf(f, "\t${%c_RULE_1A%s}", och_upper, extras);
			if (ftp->f_extra) {
				fprintf(f, "%s", ftp->f_extra);
			}
			fprintf(f, "%s%.*s${%c_RULE_1B%s}%s\n",
			    source_dir, (int)(tp - np), np, och_upper, extras, nl);

			/* While we are still using CTF, any build that normally does not support CTF will
			 * a "standard" compile done as well that we can harvest CTF information from; do
			 * that here.
			 */
			fprintf(f, "\t${%c_CTFRULE_1A%s}", och_upper, extras);
			if (ftp->f_extra) {
				fprintf(f, "%s", ftp->f_extra);
			}
			fprintf(f, "%s%.*s${%c_CTFRULE_1B%s}%s\n",
			    source_dir, (int)(tp - np), np, och_upper, extras, nl);

			fprintf(f, "\t${%c_RULE_2%s}%s\n", och_upper, extras, nl);
			fprintf(f, "\t${%c_CTFRULE_2%s}%s\n", och_upper, extras, nl);
			fprintf(f, "\t${%c_RULE_3%s}%s\n", och_upper, extras, nl);
			fprintf(f, "\t${%c_RULE_4A%s}", och_upper, extras);
			if (ftp->f_extra) {
				fprintf(f, "%s", ftp->f_extra);
			}
			fprintf(f, "%s%.*s${%c_RULE_4B%s}%s\n",
			    source_dir, (int)(tp - np), np, och_upper, extras, nl);
			break;

		default:
			printf("Don't know rules for %s\n", np);
			break;
		}
		*cp = och;
	}
}

char *
allCaps(char *str)
{
	char *cp = str;

	while (*str) {
		if (islower(*str)) {
			*str = toupper(*str);
		}
		str++;
	}
	return cp;
}

#define OLDSALUTATION "# DO NOT DELETE THIS LINE"

#define LINESIZE 1024
static char makbuf[LINESIZE];           /* one line buffer for makefile */

void
copy_dependencies(FILE *makin, FILE *makout)
{
	int oldlen = (sizeof OLDSALUTATION - 1);

	while (fgets(makbuf, LINESIZE, makin) != NULL) {
		if (!strncmp(makbuf, OLDSALUTATION, oldlen)) {
			break;
		}
	}
	while (fgets(makbuf, LINESIZE, makin) != NULL) {
		if (oldlen != 0) {
			if (makbuf[0] == '\n') {
				continue;
			} else {
				oldlen = 0;
			}
		}
		fputs(makbuf, makout);
	}
}
