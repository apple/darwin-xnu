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
static char sccsid[] __attribute__((used)) = "@(#)mkswapconf.c	5.6 (Berkeley) 6/18/88";
#endif /* not lint */

/*
 * Build a swap configuration file.
 */
#include "config.h"

#include <stdio.h>
#include <unistd.h>	/* for unlink */
#include <ctype.h>

struct file_list *do_swap(struct file_list *fl);
void initdevtable(void);

void
swapconf(void)
{
	register struct file_list *fl;

	fl = conf_list;
	while (fl) {
		if (fl->f_type != SYSTEMSPEC) {
			fl = fl->f_next;
			continue;
		}
		fl = do_swap(fl);
	}
}

struct file_list *
do_swap(struct file_list *fl)
{
	FILE *fp;
	char  swapname[80];
	register struct file_list *swap;
	dev_t dev;

	if (eq(fl->f_fn, "generic")) {
		fl = fl->f_next;
		return (fl->f_next);
	}
	if (machine == MACHINE_MMAX) {
		printf("Error: Multimax must specify swap generic only.\n");
		exit(1);
	}
	(void) sprintf(swapname, "swap%s.c", fl->f_fn);
	fp = fopen(path(swapname), "w");
	if (fp == 0) {
		perror(path(swapname));
		exit(1);
	}
	fprintf(fp, "#include <sys/param.h>\n");
	fprintf(fp, "#include <sys/conf.h>\n");
	fprintf(fp, "\n");
	/*
	 * If there aren't any swap devices
	 * specified, just return, the error
	 * has already been noted.
	 */
	swap = fl->f_next;
	if (swap == 0 || swap->f_type != SWAPSPEC) {
		(void) unlink(path(swapname));
		fclose(fp);
		return (swap);
	}
	fprintf(fp, "dev_t\trootdev = makedev(%d, %d);\n",
		major(fl->f_rootdev), minor(fl->f_rootdev));
	fprintf(fp, "dev_t\targdev  = makedev(%d, %d);\n",
		major(fl->f_argdev), minor(fl->f_argdev));
	fprintf(fp, "dev_t\tdumpdev = makedev(%d, %d);\n",
		major(fl->f_dumpdev), minor(fl->f_dumpdev));
	fprintf(fp, "\n");
	fprintf(fp, "struct\tswdevt swdevt[] = {\n");
	do {
		dev = swap->f_swapdev;
		fprintf(fp, "\t{ makedev(%d, %d),\t0,\t%d },\t/* %s */\n",
		    major(dev), minor(dev), swap->f_swapsize, swap->f_fn);
		swap = swap->f_next;
	} while (swap && swap->f_type == SWAPSPEC);
	fprintf(fp, "\t{ 0, 0, 0 }\n");
	fprintf(fp, "};\n");
	if (machine == MACHINE_MIPSY || machine == MACHINE_MIPS) {
		fprintf(fp, "\nsetconf()\n");
		fprintf(fp, "{\n");
		fprintf(fp, "\t/* resolve reference for non-generic kernels */\n");
		fprintf(fp, "}\n");
	}
	fclose(fp);
	return (swap);
}

static	int devtablenotread = 1;
static	struct devdescription {
	char	*dev_name;
	int	dev_major;
	struct	devdescription *dev_next;
} *devtable;

/*
 * Given a device name specification figure out:
 *	major device number
 *	partition
 *	device name
 *	unit number
 * This is a hack, but the system still thinks in
 * terms of major/minor instead of string names.
 */
dev_t
nametodev(char *name, int defunit, char defpartition)
{
	char *cp, partition;
	int unit;
	register struct devdescription *dp;

	cp = name;
	if (cp == 0) {
		fprintf(stderr, "config: internal error, nametodev\n");
		exit(1);
	}
	while (*cp && !isdigit(*cp))
		cp++;
	unit = *cp ? atoi(cp) : defunit;
	if (unit < 0 || unit > 31) {
		fprintf(stderr,
"config: %s: invalid device specification, unit out of range\n", name);
		unit = defunit;			/* carry on more checking */
	}
	if (*cp) {
		*cp++ = '\0';
		while (*cp && isdigit(*cp))
			cp++;
	}
	partition = *cp ? *cp : defpartition;
	if (partition < 'a' || partition > 'h') {
		fprintf(stderr,
"config: %c: invalid device specification, bad partition\n", *cp);
		partition = defpartition;	/* carry on */
	}
	if (devtablenotread)
		initdevtable();
	for (dp = devtable; dp->dev_next; dp = dp->dev_next)
		if (eq(name, dp->dev_name))
			break;
	if (dp == 0) {
		fprintf(stderr, "config: %s: unknown device\n", name);
		return (NODEV);
	}
	return (makedev(dp->dev_major, (unit << DEV_SHIFT) + (partition - 'a')));
}

char *
devtoname(dev_t dev)
{
	char buf[80]; 
	register struct devdescription *dp;

	if (devtablenotread)
		initdevtable();
	for (dp = devtable; dp->dev_next; dp = dp->dev_next)
		if (major(dev) == dp->dev_major)
			break;
	if (dp == 0)
		dp = devtable;
	(void) sprintf(buf, "%s%d%c", dp->dev_name,
		minor(dev) >> DEV_SHIFT, (minor(dev) & DEV_MASK) + 'a');
	return (ns(buf));
}

void
initdevtable(void)
{
	char buf[BUFSIZ];
	char line[BUFSIZ];
	int maj;
	register struct devdescription **dp = &devtable;
	FILE *fp;

	(void) sprintf(buf, "%s/devices.%s", config_directory, machinename);
	fp = fopenp(VPATH, buf, line, "r");
	if (fp == NULL) {
		fprintf(stderr, "config: can't open %s\n", buf);
		exit(1);
	}
	while (fgets(line, BUFSIZ, fp) != 0) {
		if (*line == '#' || *line == '\n')
			continue;
		if (sscanf(line, "%s\t%d\n", buf, &maj) != 2)
			break;
		*dp = (struct devdescription *)malloc(sizeof (**dp));
		(*dp)->dev_name = ns(buf);
		(*dp)->dev_major = maj;
		dp = &(*dp)->dev_next;
	}
	*dp = 0;
	fclose(fp);
	devtablenotread = 0;
}
