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
static char sccsid[] __attribute__((used)) = "@(#)mkglue.c	5.6 (Berkeley) 6/18/88";
#endif /* not lint */

/*
 * Make the bus adaptor interrupt glue files.
 */
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "parser.h"
#include <ctype.h>

void dump_mb_handler(FILE *fp, struct idlst *vec, int number);
void dump_ubavec(FILE *fp, char *vector, int number);
void dump_std(FILE *fp, FILE *gp);
void dump_intname(FILE *fp, char *vector, int number);
void dump_ctrs(FILE *fp);
void glue(FILE *fp, void (*dump_handler)(FILE *, struct idlst *, int));

/*
 * Create the UNIBUS interrupt vector glue file.
 */
void
ubglue(void)
{
	register FILE *fp, *gp;
	register struct device *dp, *mp;

	fp = fopen(path("ubglue.s"), "w");
	if (fp == 0) {
		perror(path("ubglue.s"));
		exit(1);
	}
	gp = fopen(path("ubvec.s"), "w");
	if (gp == 0) {
		perror(path("ubvec.s"));
		exit(1);
	}
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (mp != 0 && mp != (struct device *)-1 &&
		    !eq(mp->d_name, "mba")) {
			struct idlst *id, *id2;

			for (id = dp->d_vec; id; id = id->id_next) {
				for (id2 = dp->d_vec; id2; id2 = id2->id_next) {
					if (id2 == id) {
						dump_ubavec(fp, id->id,
						    dp->d_unit);
						break;
					}
					if (!strcmp(id->id, id2->id))
						break;
				}
			}
		}
	}
	dump_std(fp, gp);
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (mp != 0 && mp != (struct device *)-1 &&
		    !eq(mp->d_name, "mba")) {
			struct idlst *id, *id2;

			for (id = dp->d_vec; id; id = id->id_next) {
				for (id2 = dp->d_vec; id2; id2 = id2->id_next) {
					if (id2 == id) {
						dump_intname(fp, id->id,
							dp->d_unit);
						break;
					}
					if (!strcmp(id->id, id2->id))
						break;
				}
			}
		}
	}
	dump_ctrs(fp);
	(void) fclose(fp);
	(void) fclose(gp);
}

static int cntcnt = 0;		/* number of interrupt counters allocated */

/*
 * Print a UNIBUS interrupt vector.
 */
void
dump_ubavec(FILE *fp, char *vector, int number)
{
	char nbuf[80];
	register char *v = nbuf;

	switch (machine) {

	case MACHINE_VAX:
		(void) sprintf(v, "%s%d", vector, number);
		fprintf(fp, "\t.globl\t_X%s\n\t.align\t2\n_X%s:\n",
		    v, v);
		fprintf(fp,"\tTIM_PUSHR(0)\n");
		fprintf(fp, "\tincl\t_fltintrcnt+(4*%d)\n", cntcnt++);
		if (strncmp(vector, "dzx", 3) == 0)
			fprintf(fp, "\tmovl\t$%d,r0\n\tjmp\tdzdma\n\n", number);
		else {
			if (strncmp(vector, "uur", 3) == 0) {
				fprintf(fp, "#ifdef UUDMA\n");
				fprintf(fp, "\tmovl\t$%d,r0\n\tjsb\tuudma\n",
					    number);
				fprintf(fp, "#endif\n");
			}
			fprintf(fp, "\tpushl\t$%d\n", number);
			fprintf(fp, "\tcalls\t$1,_%s\n",vector);
			fprintf(fp, "\tCOUNT(V_INTR)\n");
			fprintf(fp, "\tTSREI_POPR\n");
		}
		break;

	case MACHINE_MIPSY:
	case MACHINE_MIPS:
		/*
		 * Actually, we should never get here!
		 * Main does not even call ubglue.
		 */
		if (strncmp(vector, "dzx", 3) == 0)
			fprintf(fp, "\tDZINTR(%s,%d)\n", vector, number);
		else
			fprintf(fp, "\tDEVINTR(%s,%d)\n", vector, number);
		break;
	}

}

static	const char *vaxinames[] = {
	"clock", "cnr", "cnx", "tur", "tux",
	"mba0", "mba1", "mba2", "mba3",
	"uba0", "uba1", "uba2", "uba3"
};
static	struct stdintrs {
	const char	**si_names;	/* list of standard interrupt names */
	int	si_n;		/* number of such names */
} stdintrs[] = {
	{ vaxinames, sizeof (vaxinames) / sizeof (vaxinames[0]) },
};
/*
 * Start the interrupt name table with the names
 * of the standard vectors not directly associated
 * with a bus.  Also, dump the defines needed to
 * reference the associated counters into a separate
 * file which is prepended to locore.s.
 */
void
dump_std(FILE *fp, FILE *gp)
{
	register struct stdintrs *si = &stdintrs[machine-1];
	register const char **cpp;
	register int i;

	fprintf(fp, "\n\t.globl\t_intrnames\n");
	fprintf(fp, "\n\t.globl\t_eintrnames\n");
	fprintf(fp, "\t.data\n");
	fprintf(fp, "_intrnames:\n");
	cpp = si->si_names;
	for (i = 0; i < si->si_n; i++) {
		const char *cp;
		char *tp;
		char buf[80];

		cp = *cpp;
		if (cp[0] == 'i' && cp[1] == 'n' && cp[2] == 't') {
			cp += 3;
			if (*cp == 'r')
				cp++;
		}
		for (tp = buf; *cp; cp++)
			if (islower(*cp))
				*tp++ = toupper(*cp);
			else
				*tp++ = *cp;
		*tp = '\0';
		fprintf(gp, "#define\tI_%s\t%lu\n", buf, i*sizeof (long));
		fprintf(fp, "\t.asciz\t\"%s\"\n", *cpp);
		cpp++;
	}
}

void
dump_intname(FILE *fp, char *vector, int number)
{
	register char *cp = vector;

	fprintf(fp, "\t.asciz\t\"");
	/*
	 * Skip any "int" or "intr" in the name.
	 */
	while (*cp)
		if (cp[0] == 'i' && cp[1] == 'n' &&  cp[2] == 't') {
			cp += 3;
			if (*cp == 'r')
				cp++;
		} else {
			putc(*cp, fp);
			cp++;
		}
	fprintf(fp, "%d\"\n", number);
}

/*
 * Reserve space for the interrupt counters.
 */
void
dump_ctrs(FILE *fp)
{
	struct stdintrs *si = &stdintrs[machine-1];

	fprintf(fp, "_eintrnames:\n");
	fprintf(fp, "\n\t.globl\t_intrcnt\n");
	fprintf(fp, "\n\t.globl\t_eintrcnt\n");
	fprintf(fp, "\t.align 2\n");
	fprintf(fp, "_intrcnt:\n");
	fprintf(fp, "\t.space\t4 * %d\n", si->si_n);
	fprintf(fp, "_fltintrcnt:\n");
	fprintf(fp, "\t.space\t4 * %d\n", cntcnt);
	fprintf(fp, "_eintrcnt:\n\n");
	fprintf(fp, "\t.text\n");
}

/*
 * Routines for making Sun mb interrupt file mbglue.s
 */

/*
 * print an interrupt handler for mainbus
 */
void
dump_mb_handler(FILE *fp, struct idlst *vec, int number)
{
	fprintf(fp, "\tVECINTR(_X%s%d, _%s, _V%s%d)\n",
		vec->id, number, vec->id, vec->id, number);
}

void
mbglue(void)
{
	register FILE *fp;
	const char *name = "mbglue.s";

	fp = fopen(path(name), "w");
	if (fp == 0) {
		perror(path(name));
		exit(1);
	}
	fprintf(fp, "#include <machine/asm_linkage.h>\n\n");
	glue(fp, dump_mb_handler);
	(void) fclose(fp);
}

void
glue(FILE *fp, void (*dump_handler)(FILE *, struct idlst *, int))
{
	register struct device *dp, *mp;

	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (mp != 0 && mp != (struct device *)-1 &&
		    !eq(mp->d_name, "mba")) {
			struct idlst *vd, *vd2;

			for (vd = dp->d_vec; vd; vd = vd->id_next) {
				for (vd2 = dp->d_vec; vd2; vd2 = vd2->id_next) {
					if (vd2 == vd) {
						(void)(*dump_handler)
							(fp, vd, dp->d_unit);
						break;
					}
					if (!strcmp(vd->id, vd2->id))
						break;
				}
			}
		}
	}
}
