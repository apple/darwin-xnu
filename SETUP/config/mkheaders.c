/*
 * Copyright (c) 1999-2006 Apple Computer, Inc. All rights reserved.
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
static char sccsid[] __attribute__((used)) = "@(#)mkheaders.c	5.5 (Berkeley) 6/18/88";
#endif /* not lint */

/*
 * Make all the .h files for the optional entries
 */

#include <stdio.h>
#include <unistd.h>     /* unlink */
#include <ctype.h>
#include "config.h"
#include "parser.h"

static void     do_count(const char *dev, const char *hname, int search);
static void     do_header(const char *dev, const char *hname, int count);
static char     *toheader(const char *dev);
static char     *tomacro(const char *dev);

void
headers(void)
{
	struct file_list *fl;

	for (fl = ftab; fl != 0; fl = fl->f_next) {
		if (fl->f_needs != 0) {
			do_count(fl->f_needs, fl->f_needs, 1);
		}
	}
}

/*
 * count all the devices of a certain type and recurse to count
 * whatever the device is connected to
 */
void
do_count(const char *dev, const char *hname, int search)
{
	struct device *dp;
	int count;

	for (count = 0, dp = dtab; dp != 0; dp = dp->d_next) {
		if (eq(dp->d_name, dev)) {
			if (dp->d_type == PSEUDO_DEVICE) {
				count =
				    dp->d_slave != UNKNOWN ? dp->d_slave : 1;
				if (dp->d_flags) {
					dev = NULL;
				}
				break;
			}
		}
	}
	do_header(dev, hname, count);
}

static void
do_header(const char *dev, const char *hname, int count)
{
	char *file, *name;
	const char *inw;
	char *inwcopy;
	struct file_list *fl = NULL;    /* may exit for(;;) uninitted */
	struct file_list *fl_head, *fl_prev;
	FILE *inf, *outf;
	int inc, oldcount;

	file = toheader(hname);
	name = tomacro(dev?dev:hname) + (dev == NULL);
	inf = fopen(file, "r");
	oldcount = -1;
	if (inf == 0) {
		(void) unlink(file);
		outf = fopen(file, "w");
		if (outf == 0) {
			perror(file);
			exit(1);
		}
		fprintf(outf, "#define %s %d\n", name, count);
		(void) fclose(outf);
		file = path("meta_features.h");
		outf = fopen(file, "a");
		if (outf == 0) {
			perror(file);
			exit(1);
		}
		fprintf(outf, "#include <%s.h>\n", hname);
		(void) fclose(outf);
		return;
	}
	fl_head = 0;
	for (;;) {
		const char *cp;
		if ((inw = get_word(inf)) == 0 || inw == (char *)EOF) {
			break;
		}
		if ((inw = get_word(inf)) == 0 || inw == (char *)EOF) {
			break;
		}
		inwcopy = ns(inw);
		cp = get_word(inf);
		if (cp == 0 || cp == (char *)EOF) {
			break;
		}
		inc = atoi(cp);
		if (eq(inwcopy, name)) {
			oldcount = inc;
			inc = count;
		}
		cp = get_word(inf);
		if (cp == (char *)EOF) {
			break;
		}
		fl = (struct file_list *) malloc(sizeof *fl);
		fl->f_fn = inwcopy;
		fl->f_type = inc;
		fl->f_next = fl_head;
		fl_head = fl;
	}
	(void) fclose(inf);
	if (count == oldcount) {
		while (fl != 0) {
			fl_prev = fl;
			fl = fl->f_next;
			free((char *)fl_prev);
		}
		return;
	}
	if (oldcount == -1) {
		fl = (struct file_list *) malloc(sizeof *fl);
		fl->f_fn = name;
		fl->f_type = count;
		fl->f_next = fl_head;
		fl_head = fl;
	}
	unlink(file);
	outf = fopen(file, "w");
	if (outf == 0) {
		perror(file);
		exit(1);
	}
	for (fl = fl_head; fl != 0; fl = fl->f_next) {
		fprintf(outf, "#define %s %d\n",
		    fl->f_fn, count ? fl->f_type : 0);
		free((char *)fl);
	}
	(void) fclose(outf);
}

/*
 * convert a dev name to a .h file name
 */
static char *
toheader(const char *dev)
{
	static char hbuf[MAXPATHLEN];
	(void) snprintf(hbuf, sizeof hbuf, "%s.h", path(dev));
	hbuf[MAXPATHLEN - 1] = '\0';
	return hbuf;
}

/*
 * convert a dev name to a macro name
 */
static char *
tomacro(const char *dev)
{
	static char mbuf[FILENAME_MAX];
	char *cp;

	cp = mbuf;
	*cp++ = 'N';
	while (*dev) {
		if (!islower(*dev)) {
			*cp++ = *dev++;
		} else {
			*cp++ = toupper(*dev++);
		}
	}
	*cp++ = 0;
	return mbuf;
}
