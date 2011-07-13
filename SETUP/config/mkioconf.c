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

#include <stdio.h>
#include <unistd.h>	/* for unlink */
#include "parser.h"
#include "config.h"

/*
 * build the ioconf.c file
 */
char	*intv(struct device *dev);
char	*intv2(struct device *dev);
void	i386_pseudo_inits(FILE *fp);	/* XXX function in wrong block */
void	check_vector(struct idlst *vec);
void	nrw_ioconf(void);
void	m88k_pseudo_inits(FILE *fp);
void	m98k_pseudo_inits(FILE *fp);
char	*m88k_dn(char *name);
char	*m98k_dn(char *name);
char	*concat3(char *buf, const char *p1, const char *p2, const char *p3);

#if MACHINE_VAX

void
vax_ioconf(void)
{
	register struct device *dp, *mp, *np;
	register int uba_n, slave;
	FILE *fp;

	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
/*MACH_KERNEL*/
	fprintf(fp, "#ifndef  MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "#include <machine/pte.h>\n");
	fprintf(fp, "#include <sys/param.h>\n");
	fprintf(fp, "#include <sys/buf.h>\n");
	fprintf(fp, "#include <sys/map.h>\n");
	fprintf(fp, "#include <sys/vm.h>\n");
/*MACH_KERNEL*/
	fprintf(fp, "#endif   MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "\n");
	fprintf(fp, "#include <vaxmba/mbavar.h>\n");
	fprintf(fp, "#include <vaxuba/ubavar.h>\n\n");
	fprintf(fp, "\n");
	fprintf(fp, "#define C (caddr_t)\n\n");
	/*
	 * First print the mba initialization structures
	 */
	if (seen_mba) {
		for (dp = dtab; dp != 0; dp = dp->d_next) {
			mp = dp->d_conn;
			if (mp == 0 || mp == TO_NEXUS ||
			    !eq(mp->d_name, "mba"))
				continue;
			fprintf(fp, "extern struct mba_driver %sdriver;\n",
			    dp->d_name);
		}
		fprintf(fp, "\nstruct mba_device mbdinit[] = {\n");
		fprintf(fp, "\t/* Device,  Unit, Mba, Drive, Dk */\n");
		for (dp = dtab; dp != 0; dp = dp->d_next) {
			mp = dp->d_conn;
			if (dp->d_unit == QUES || mp == 0 ||
			    mp == TO_NEXUS || !eq(mp->d_name, "mba"))
				continue;
			if (dp->d_addr) {
				printf("can't specify csr address on mba for %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_vec != 0) {
				printf("can't specify vector for %s%d on mba\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive == UNKNOWN) {
				printf("drive not specified for %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_slave != UNKNOWN) {
				printf("can't specify slave number for %s%d\n", 
				    dp->d_name, dp->d_unit);
				continue;
			}
			fprintf(fp, "\t{ &%sdriver, %d,   %s,",
				dp->d_name, dp->d_unit, qu(mp->d_unit));
			fprintf(fp, "  %s,  %d },\n",
				qu(dp->d_drive), dp->d_dk);
		}
		fprintf(fp, "\t0\n};\n\n");
		/*
		 * Print the mbsinit structure
		 * Driver Controller Unit Slave
		 */
		fprintf(fp, "struct mba_slave mbsinit [] = {\n");
		fprintf(fp, "\t/* Driver,  Ctlr, Unit, Slave */\n");
		for (dp = dtab; dp != 0; dp = dp->d_next) {
			/*
			 * All slaves are connected to something which
			 * is connected to the massbus.
			 */
			if ((mp = dp->d_conn) == 0 || mp == TO_NEXUS)
				continue;
			np = mp->d_conn;
			if (np == 0 || np == TO_NEXUS ||
			    !eq(np->d_name, "mba"))
				continue;
			fprintf(fp, "\t{ &%sdriver, %s",
			    mp->d_name, qu(mp->d_unit));
			fprintf(fp, ",  %2d,    %s },\n",
			    dp->d_unit, qu(dp->d_slave));
		}
		fprintf(fp, "\t0\n};\n\n");
	}
	/*
	 * Now generate interrupt vectors for the unibus
	 */
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_vec != 0) {
			struct idlst *ip;
			mp = dp->d_conn;
			if (mp == 0 || mp == TO_NEXUS ||
			    !eq(mp->d_name, "uba"))
				continue;
			fprintf(fp,
			    "extern struct uba_driver %sdriver;\n",
			    dp->d_name);
			fprintf(fp, "extern ");
			ip = dp->d_vec;
			for (;;) {
				fprintf(fp, "X%s%d()", ip->id, dp->d_unit);
				ip = ip->id_next;
				if (ip == 0)
					break;
				fprintf(fp, ", ");
			}
			fprintf(fp, ";\n");
			fprintf(fp, "int\t (*%sint%d[])() = { ", dp->d_name,
			    dp->d_unit);
			ip = dp->d_vec;
			for (;;) {
				fprintf(fp, "X%s%d", ip->id, dp->d_unit);
				ip = ip->id_next;
				if (ip == 0)
					break;
				fprintf(fp, ", ");
			}
			fprintf(fp, ", 0 } ;\n");
		}
	}
	fprintf(fp, "\nstruct uba_ctlr ubminit[] = {\n");
	fprintf(fp, "/*\t driver,\tctlr,\tubanum,\talive,\tintr,\taddr */\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_type != CONTROLLER || mp == TO_NEXUS || mp == 0 ||
		    !eq(mp->d_name, "uba"))
			continue;
		if (dp->d_vec == 0) {
			printf("must specify vector for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_addr == 0) {
			printf("must specify csr address for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
			printf("drives need their own entries; dont ");
			printf("specify drive or slave for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_flags) {
			printf("controllers (e.g. %s%d) ",
			    dp->d_name, dp->d_unit);
			printf("don't have flags, only devices do\n");
			continue;
		}
		fprintf(fp,
		    "\t{ &%sdriver,\t%d,\t%s,\t0,\t%sint%d, C 0%o },\n",
		    dp->d_name, dp->d_unit, qu(mp->d_unit),
		    dp->d_name, dp->d_unit, dp->d_addr);
	}
	fprintf(fp, "\t0\n};\n");
/* unibus devices */
	fprintf(fp, "\nstruct uba_device ubdinit[] = {\n");
	fprintf(fp,
"\t/* driver,  unit, ctlr,  ubanum, slave,   intr,    addr,    dk, flags*/\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_unit == QUES || dp->d_type != DEVICE || mp == 0 ||
		    mp == TO_NEXUS || mp->d_type == MASTER ||
		    eq(mp->d_name, "mba"))
			continue;
		np = mp->d_conn;
		if (np != 0 && np != TO_NEXUS && eq(np->d_name, "mba"))
			continue;
		np = 0;
		if (eq(mp->d_name, "uba")) {
			if (dp->d_vec == 0) {
				printf("must specify vector for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr == 0) {
				printf("must specify csr for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
				printf("drives/slaves can be specified ");
				printf("only for controllers, ");
				printf("not for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			uba_n = mp->d_unit;
			slave = QUES;
		} else {
			if ((np = mp->d_conn) == 0) {
				printf("%s%d isn't connected to anything ",
				    mp->d_name, mp->d_unit);
				printf(", so %s%d is unattached\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			uba_n = np->d_unit;
			if (dp->d_drive == UNKNOWN) {
				printf("must specify ``drive number'' ");
				printf("for %s%d\n", dp->d_name, dp->d_unit);
				continue;
			}
			/* NOTE THAT ON THE UNIBUS ``drive'' IS STORED IN */
			/* ``SLAVE'' AND WE DON'T WANT A SLAVE SPECIFIED */
			if (dp->d_slave != UNKNOWN) {
				printf("slave numbers should be given only ");
				printf("for massbus tapes, not for %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_vec != 0) {
				printf("interrupt vectors should not be ");
				printf("given for drive %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr != 0) {
				printf("csr addresses should be given only ");
				printf("on controllers, not on %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = dp->d_drive;
		}
		fprintf(fp, "\t{ &%sdriver,  %2d,   %s,",
		    eq(mp->d_name, "uba") ? dp->d_name : mp->d_name, dp->d_unit,
		    eq(mp->d_name, "uba") ? " -1" : qu(mp->d_unit));
		fprintf(fp, "  %s,    %2d,   %s, C 0%-6o,  %d,  0x%x },\n",
		    qu(uba_n), slave, intv(dp), dp->d_addr, dp->d_dk,
		    dp->d_flags);
	}
	fprintf(fp, "\t0\n};\n");
	(void) fclose(fp);
}
#endif

#if MACHINE_SUN
#define SP_OBIO	0x0004	/* on board i/o (for sun/autoconf.h) */

#define	VEC_LO	64
#define	VEC_HI	255

void pseudo_inits(FILE *fp);

void
check_vector(struct idlst *vec)
{

	if (vec->id_vec == 0)
		fprintf(stderr, "vector number for %s not given\n", vec->id);
	else if (vec->id_vec < VEC_LO || vec->id_vec > VEC_HI)
		fprintf(stderr,
			"vector number %d for %s is not between %d and %d\n",
			vec->id_vec, vec->id, VEC_LO, VEC_HI);
}

void
sun_ioconf(void)
{
	register struct device *dp, *mp;
	register int slave;
	register struct idlst *vp;
	FILE *fp;

	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
/*MACH_KERNEL*/
	fprintf(fp, "#ifndef  MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "#include <sys/param.h>\n");
	fprintf(fp, "#include <sys/buf.h>\n");
	fprintf(fp, "#include <sys/map.h>\n");
	fprintf(fp, "#include <sys/vm.h>\n");
/*MACH_KERNEL*/
	fprintf(fp, "#endif   MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "\n");
	fprintf(fp, "#include <sundev/mbvar.h>\n");
	fprintf(fp, "\n");
	fprintf(fp, "#define C (caddr_t)\n\n");
	fprintf(fp, "\n");

	/*
	 * Now generate interrupt vectors for the Mainbus
	 */
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (mp == TO_NEXUS || mp == 0 || mp->d_conn != TO_NEXUS)
			continue;
		fprintf(fp, "extern struct mb_driver %sdriver;\n",
			    dp->d_name);
		if (dp->d_vec != 0) {
			if (dp->d_pri == 0)
				fprintf(stderr,
				    "no priority specified for %s%d\n",
				    dp->d_name, dp->d_unit);
			fprintf(fp, "extern ");
			for (vp = dp->d_vec;;) {
				if (machine == MACHINE_SUN4)
					fprintf(fp, "%s()", vp->id);
				else
					fprintf(fp, "X%s%d()",
						vp->id, dp->d_unit);
				vp = vp->id_next;
				if (vp == 0)
					break;
				fprintf(fp, ", ");
			}
			fprintf(fp, ";\n");

			for (vp = dp->d_vec; vp; vp = vp->id_next) {
				fprintf(fp, "int V%s%d = %d;\n",
				    vp->id, dp->d_unit, dp->d_unit);
			}

			fprintf(fp, "struct vec %s[] = { ", intv(dp));
			for (vp = dp->d_vec; vp != 0; vp = vp->id_next) {
				if (machine == MACHINE_SUN4)
					fprintf(fp, "{ %s, %d, &V%s%d }, ",
						vp->id, vp->id_vec,
						vp->id, dp->d_unit);
				else
				fprintf(fp, "{ X%s%d, %d, &V%s%d }, ",
					vp->id, dp->d_unit, vp->id_vec,
					vp->id, dp->d_unit);
				check_vector(vp);
			}
			fprintf(fp, "0 };\n");
		}
	}

	/*
	 * Now spew forth the mb_ctlr structures
	 */
	fprintf(fp, "\nstruct mb_ctlr mbcinit[] = {\n");
	fprintf(fp,
"/* driver,\tctlr,\talive,\taddress,\tintpri,\t intr,\tspace */\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_type != CONTROLLER || mp == TO_NEXUS || mp == 0 ||
		    mp->d_conn != TO_NEXUS)
			continue;
		if (dp->d_addr == UNKNOWN) {
			printf("must specify csr address for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
			printf("drives need their own entries; ");
			printf("don't specify drive or slave for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_flags) {
			printf("controllers (e.g. %s%d) don't have flags, ",
			    dp->d_name, dp->d_unit);
			printf("only devices do\n");
			continue;
		}
		if (machine == MACHINE_SUN4)
		fprintf(fp,
		"{ &%sdriver,\t%d,\t0,\tC 0x%08x,\t%d,\t%s, 0x%x },\n",
		    dp->d_name, dp->d_unit, dp->d_addr,
		    (dp->d_bus==SP_OBIO) ? (dp->d_pri << 1) : (dp->d_pri<<1)-1,
		    intv(dp), ((dp->d_mach << 16) | dp->d_bus));
		else
			fprintf(fp,
		"{ &%sdriver,\t%d,\t0,\tC 0x%08x,\t%d,\t%s, 0x%x },\n",
		    dp->d_name, dp->d_unit, dp->d_addr,
		    dp->d_pri, intv(dp), ((dp->d_mach << 16) | dp->d_bus));
	}
	fprintf(fp, "\t0\n};\n");

	/*
	 * Now we go for the mb_device stuff
	 */
	fprintf(fp, "\nstruct mb_device mbdinit[] = {\n");
	fprintf(fp,
"/* driver,\tunit, ctlr, slave, address,      pri, dk, flags, intr, space */\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_unit == QUES || dp->d_type != DEVICE || mp == 0 ||
		    mp == TO_NEXUS || mp->d_type == MASTER)
			continue;
		if (mp->d_conn == TO_NEXUS) {
			if (dp->d_addr == UNKNOWN) {
				printf("must specify csr for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
				printf("drives/slaves can be specified only ");
				printf("for controllers, not for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = QUES;
		} else {
			if (mp->d_conn == 0) {
				printf("%s%d isn't connected to anything, ",
				    mp->d_name, mp->d_unit);
				printf("so %s%d is unattached\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive == UNKNOWN) {
				printf("must specify ``drive number'' for %s%d\n",
				   dp->d_name, dp->d_unit);
				continue;
			}
			/* NOTE THAT ON THE UNIBUS ``drive'' IS STORED IN */
			/* ``SLAVE'' AND WE DON'T WANT A SLAVE SPECIFIED */
			if (dp->d_slave != UNKNOWN) {
				printf("slave numbers should be given only ");
				printf("for massbus tapes, not for %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_pri != 0) {
				printf("interrupt priority should not be ");
				printf("given for drive %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr != UNKNOWN) {
				printf("csr addresses should be given only");
				printf(" on controllers, not on %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = dp->d_drive;
		}
		if (machine == MACHINE_SUN4)
		fprintf(fp,
"{ &%sdriver,\t%d,  %s,   %2d,     C 0x%08x, %d,   %d, 0x%x, %s, 0x%x },\n",
		    mp->d_conn == TO_NEXUS? dp->d_name : mp->d_name, dp->d_unit,
		    mp->d_conn == TO_NEXUS? " -1" : qu(mp->d_unit),
		    slave,
		    dp->d_addr == UNKNOWN? 0 : dp->d_addr,
		    dp->d_pri * 2, dp->d_dk, dp->d_flags, intv(dp),
		    ((dp->d_mach << 16) | dp->d_bus));
		else
			fprintf(fp,
"{ &%sdriver,\t%d,  %s,   %2d,     C 0x%08x, %d,   %d, 0x%x, %s, 0x%x },\n",
		    mp->d_conn == TO_NEXUS? dp->d_name : mp->d_name, dp->d_unit,
		    mp->d_conn == TO_NEXUS? " -1" : qu(mp->d_unit),
		    slave,
		    dp->d_addr == UNKNOWN? 0 : dp->d_addr,
		    dp->d_pri, dp->d_dk, dp->d_flags, intv(dp),
		    ((dp->d_mach << 16) | dp->d_bus));
	}
	fprintf(fp, "\t0\n};\n");
	pseudo_inits(fp);
	(void) fclose(fp);
}

void
pseudo_inits(FILE *fp)
{
#ifdef	notdef
	register struct device *dp;
	int count;

	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
#endif	notdef
	fprintf(fp, "struct pseudo_init {\n");
	fprintf(fp, "\tint\tps_count;\n\tint\t(*ps_func)();\n");
	fprintf(fp, "} pseudo_inits[] = {\n");
#ifdef	notdef
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
#endif	notdef
	fprintf(fp, "\t{0,\t0},\n};\n");
}
#endif

#if MACHINE_ROMP
void
romp_ioconf(void)
{
	register struct device *dp, *mp;
	register int slave;
	FILE *fp;

	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
/*MACH_KERNEL*/
	fprintf(fp, "#ifndef  MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "#include <sys/param.h>\n");
	fprintf(fp, "#include <sys/buf.h>\n");
	fprintf(fp, "#include <sys/map.h>\n");
	fprintf(fp, "#include <sys/vm.h>\n");
/*MACH_KERNEL*/
	fprintf(fp, "#endif   MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "\n");
	fprintf(fp, "#include <caio/ioccvar.h>\n");
	fprintf(fp, "\n");
	fprintf(fp, "#define C (caddr_t)\n\n");
	fprintf(fp, "\n");

	fprintf (fp, "struct     iocc_hd iocc_hd[] = {{C 0xF0000000,}};\n");
	/*
	 * Now generate interrupt vectors for the  Winnerbus
	 */
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_pri != 0) {
			mp = dp->d_conn;
			if (mp == 0 || mp == TO_NEXUS ||
			    !eq(mp->d_name, "iocc"))
				continue;
			fprintf(fp, "extern struct iocc_driver %sdriver;\n",
			    dp->d_name);
		}
	}
	/*
	 * Now spew forth the iocc_cinfo structure
	 */
	fprintf(fp, "\nstruct iocc_ctlr iocccinit[] = {\n");
	fprintf(fp, "/*\t driver,\tctlr,\talive,\taddr,\tintpri */\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_type != CONTROLLER)
			continue;
		if (mp == TO_NEXUS || mp == 0 || !eq(mp->d_name, "iocc"))
			continue;
		if (dp->d_unit == QUES && eq(dp->d_name,"hdc"))
			continue;
		if (dp->d_unit == QUES && eq(dp->d_name,"fdc"))
			continue;
		if (dp->d_pri == 0) {
			printf("must specify priority for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_addr == 0) {
			printf("must specify csr address for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
			printf("drives need their own entries; ");
			printf("dont specify drive or slave for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_flags) {
			printf("controllers (e.g. %s%d) don't have flags, ",
			    dp->d_name, dp->d_unit);
			printf("only devices do\n");
			continue;
		}
		fprintf(fp, "\t{ &%sdriver,\t%d,\t0,\tC 0x%x,\t%d },\n",
		    dp->d_name, dp->d_unit, dp->d_addr, dp->d_pri);
	}
	fprintf(fp, "\t0\n};\n");
	/*
	 * Now we go for the iocc_device stuff
	 */
	fprintf(fp, "\nstruct iocc_device ioccdinit[] = {\n");
	fprintf(fp,
"\t/* driver,  unit, ctlr,  slave,   addr,    pri,    dk, flags*/\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_unit == QUES || dp->d_type != DEVICE || mp == 0 ||
		    mp == TO_NEXUS || mp->d_type == MASTER ||
		    eq(mp->d_name, "iocca"))
			continue;
		if (eq(mp->d_name, "iocc")) {
			if (dp->d_pri == 0) {
				printf("must specify vector for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr == 0) {
				printf("must specify csr for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
				printf("drives/slaves can be specified only ");
				printf("for controllers, not for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = QUES;
		} else {
			if (mp->d_conn == 0) {
				printf("%s%d isn't connected to anything, ",
				    mp->d_name, mp->d_unit);
				printf("so %s%d is unattached\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive == UNKNOWN) {
				printf("must specify ``drive number'' for %s%d\n",
				   dp->d_name, dp->d_unit);
				continue;
			}
			/* NOTE THAT ON THE UNIBUS ``drive'' IS STORED IN */
			/* ``SLAVE'' AND WE DON'T WANT A SLAVE SPECIFIED */
			if (dp->d_slave != UNKNOWN) {
				printf("slave numbers should be given only ");
				printf("for massbus tapes, not for %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_pri != 0) {
				printf("interrupt priority should not be ");
				printf("given for drive %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr != 0) {
				printf("csr addresses should be given only");
				printf("on controllers, not on %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = dp->d_drive;
		}
		fprintf(fp,
"\t{ &%sdriver,  %2d,   %s,    %2d,   C 0x%x, %d,  %d,  0x%x },\n",
		    eq(mp->d_name, "iocc") ? dp->d_name : mp->d_name, dp->d_unit,
		    eq(mp->d_name, "iocc") ? " -1" : qu(mp->d_unit),
 		    slave, dp->d_addr, dp->d_pri, dp->d_dk, dp->d_flags);
 	}
 	fprintf(fp, "\t0\n};\n");
 	(void) fclose(fp);
} 

#endif	MACHINE_ROMP

#if	MACHINE_MMAX
void
mmax_ioconf(void)
{
	register struct device *dp, *dp1, *mp;
	FILE *fp;
	int	unit;

	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <mmaxio/io.h>\n\n");

	/*
	 *	Multimax code is a little messy because we have to
	 * 	scan the entire list for each device to generate the
	 * 	structures correctly.  We cheat and use the d->d_pri
	 *	field to avoid doing anything twice.  -1000 is an obvious
	 *	bogus value for this field.
	 */

	for (dp1 = dtab; dp1 != 0; dp1 = dp1->d_next) {
	    /* 
	     *	If pri is not -1000, then haven't seen device yet.
	     */
	    if (dp1->d_pri != -1000) switch (dp1->d_type) {

	    case CONTROLLER:
		fprintf(fp,"struct devaddr %s_devaddr[] = {\n",
			dp1->d_name);
		/*
		 *	Now scan entire list and get all of them.  Use
		 *	unit to make sure unit numbers are right.
		 */
		unit = 0;
		for (dp = dp1; dp != 0; dp = dp->d_next) {
			if (!strcmp(dp->d_name, dp1->d_name)) {
				mp = dp->d_conn;
				if (mp != TO_SLOT) {
		printf("%s%d: controller must be connected to slot.\n",
						dp->d_name, dp->d_unit);
					exit(1);
				}
				if (dp->d_vec != 0) {
		printf("%s%d: cannot configure multimax interrupt vectors.\n",
						dp->d_name, dp->d_unit);
				}
				if (dp->d_pri != 0) {
		printf("%s%d: interrupt priority is nonsense on multimax.\n",
						dp->d_name, dp->d_unit);
				}
				if ((dp->d_drive != UNKNOWN) ||
					(dp->d_slave !=UNKNOWN)) {
		printf("%s%d: don't specify drive or slave for controller.\n",
						dp->d_name, dp->d_unit);
				}
				/*
				 *	Fix unit number if bogus
				 */
				if(dp->d_unit != unit) {
	printf("Warning: %s%d configured as %s%d -- fix config file.\n",
		dp->d_name,dp->d_unit,dp->d_name,unit);
					dp->d_unit = unit;
				}
				unit++;
				fprintf(fp,"\t{ %d, 0, 0},\n",dp->d_addr);
				dp->d_pri = -1000; /* done this one */
			}
		}
		fprintf(fp,"} ;\n\n");
		break;

	    case DEVICE:
		fprintf(fp,"struct subdevaddr %s_subdevaddr[] = {\n",
			dp1->d_name);
		/*
		 *	Now scan entire list and get all of them.  Use
		 *	unit to make sure unit numbers are right.
		 */
		unit = 0;
		for (dp = dp1; dp != 0; dp = dp->d_next) {
			if (!strcmp(dp->d_name, dp1->d_name)) {
				mp = dp->d_conn;
				if ( (mp == 0) || (mp == TO_SLOT) ||
					(mp->d_type != CONTROLLER)) {
				printf("%s%d: device has no controller.\n",
						dp->d_name, dp->d_unit);
					exit(1);
				}
				if (dp->d_vec != 0) {
		printf("%s%d: cannot configure multimax interrupt vectors.\n",
						dp->d_name, dp->d_unit);
				}
				if (dp->d_pri != 0) {
		printf("%s%d: interrupt priority is nonsense on multimax.\n",
						dp->d_name, dp->d_unit);
				}
				if ((dp->d_drive != UNKNOWN) ||
					(dp->d_slave !=UNKNOWN)) {
		printf("%s%d: use 'unit' instead of 'drive' or 'slave'.\n",
						dp->d_name, dp->d_unit);
				}
				/*
				 *	Fix unit number if bogus
				 */
				if(dp->d_unit != unit) {
	printf("Warning: %s%d configured as %s%d -- fix config file.\n",
				dp->d_name,dp->d_unit,dp->d_name,unit);
					dp->d_unit = unit;
				}
				unit++;
				if((dp->d_addr == 0) || (dp->d_addr == QUES)){
			printf("%s%d: must specify logical unit number.\n",
					dp->d_name,dp->d_unit);
					exit(1);
				}
				fprintf(fp,"\t{ %d, %d, 0},\n",mp->d_unit,
					dp->d_addr);
				dp->d_pri = -1000; /* don't do this again */
			}
		}
		fprintf(fp,"} ;\n\n");
		break;

	    case PSEUDO_DEVICE:
		/*
		 *	Doesn't exist as far as ioconf.c is concerned.
		 */
		break;

	    default:
		printf("Bogus device type for %s\n", dp1->d_name);
		exit(1);
		break;
	    }
	}
	
	(void) fclose(fp);
}

#endif	MACHINE_MMAX

#if	MACHINE_SQT

/*
 * Define prototype device spec lines.
 *
 * For now, have static set of controller prototypes.  This should be
 * upgraded to using (eg) controllers.balance (ala Sequent /etc/config)
 * to support custom boards without need to edit this file.
 */

/*
 *  flags for indicating presence of upper and lower bound values
 */

#define	P_LB	1
#define	P_UB	2

struct p_entry {
	const char 	*p_name;		/* name of field */
	long	p_def;				/* default value */
	long 	p_lb;				/* lower bound for field */
	long	p_ub;				/* upper bound of field */ 
	char	p_flags;			/* bound valid flags */
};

struct proto {
	const char	*p_name;		/* name of controller type */
	struct  p_entry	p_fields[NFIELDS];	/* ordered list of fields */
	int	p_seen;				/* any seen? */
};

/*
 * MULTIBUS Adapter:
 *	type mbad  index csr flags maps[0,256] bin[0,7] intr[0,7]
 */

static	struct	proto	mbad_proto = {
	"mbad",
       {{ "index",	0,	0,	0,	0 },
	{ "csr",	0,	0,	0,	0 },
	{ "flags",	0,	0,	0,	0 },
	{ "maps",	0,	0,	256,	P_LB|P_UB },
	{ "bin",	0,	0,	7,	P_LB|P_UB },
	{ "intr",	0,	0,	7,	P_LB|P_UB },},
	0
};

/*
 * SCSI/Ether Controller:
 *	type sec   flags bin[0,7] req doneq index target[0,7]=-1 unit
 */

static	struct	proto	sec_proto = {
	"sec",
       {{ "flags",	0,	0,	0,	0 },
	{ "bin",	0,	0,	7,	P_LB|P_UB } ,
	{ "req",	0,	0,	0,	0 },
	{ "doneq",	0,	0,	0,	0 },
	{ "index",	0,	0,	0,	0 },
	{ "target",	-1,	0,	7,	P_LB|P_UB },
	{ "unit",	0,	0,	0,	0 },},
	0
};

/*
 * "Zeke" (FAST) Disk Controller (Dual-Channel Disk Controller):
 *	type zdc index[0,31] drive[-1,7] drive_type[-1,1]
 *
 * Levgal values for drive_type:
 *	M2333K = 0	(swallow)
 *	M2351A = 1	(eagle)
 *	wildcard = -1	(run-time determined)
 */

static	struct	proto	zdc_proto = {
	"zdc",
       {{ "index",	0,	0,	31,	P_LB|P_UB },
	{ "drive",	0,	-1,	7,	P_LB|P_UB },
	{ "drive_type",	0,	-1,	1,	P_LB|P_UB },},
	0
};

static	struct	proto	*ptab[] = {
	&mbad_proto,
	&sec_proto,
	&zdc_proto,
	(struct proto *) 0
};

/*
 * locate a prototype structure in the queue of such structures.
 * return NULL if not found.
 */

static struct proto *
find_proto(const char *str)
{
	register struct proto *ptp;
	register int	ptbx;

	for (ptbx = 0; (ptp = ptab[ptbx]) != NULL; ptbx++) {
		if (eq(str, ptp->p_name))
			return(ptp);
	}
	return(NULL);
}

void
dev_param(struct device *dp, const char *str, long num)
{
	register struct p_entry *entry;
	register struct proto *ptp;

	ptp = find_proto(dp->d_conn->d_name);
	if (ptp == NULL) {
		fprintf(stderr,"dev %s cont %s", dp->d_name, dp->d_conn->d_name);
		yyerror("invalid controller");
		return;
	}

	for (entry = ptp->p_fields; entry->p_name != NULL; entry++) {
		if (eq(entry->p_name, str)) {
			if ((entry->p_flags & P_LB) && (num < entry->p_lb)) {
				yyerror("parameter below range");
				return;
			}
			if ((entry->p_flags & P_UB) && (num > entry->p_ub)) {
				yyerror("parameter above range");
				return;
			}
			dp->d_fields[entry-ptp->p_fields] = num;
			return;
		}
	}

	yyerror("invalid parameter");
}

void
sqt_ioconf(void)
{
	register struct device *dp, *mp;
	register int count;
	const char *namep;
	register struct proto *ptp;
	register struct p_entry *entry;
	FILE	*fp;
	int	bin_table[8];
	int	ptbx;
	int	found;

	for (count = 0; count < 8; count++)
		bin_table[count] = 0;
	fp = fopen(path("ioconf.c"), "w");
	if (fp == NULL) {
		perror(path("ioconf.c"));
		exit(1);
	}
/*MACH_KERNEL*/
	fprintf(fp, "#ifndef  MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "#include <sys/param.h>\n");
	fprintf(fp, "#include <sys/systm.h>\n");
/*MACH_KERNEL*/
	fprintf(fp, "#endif   MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "\n");
	fprintf(fp, "#include <machine/ioconf.h>\n");

	fprintf(fp, "\nu_long\tMBAd_IOwindow =\t\t3*256*1024;\t/* top 1/4 Meg */\n\n");

	for (ptbx = 0; (ptp = ptab[ptbx]) != NULL; ptbx++) {

		fprintf(fp, "/*\n");
		fprintf(fp, " * %s device configuration.\n", ptp->p_name);
		fprintf(fp, " */\n\n");
		fprintf(fp, "\n");
		fprintf(fp, "#include <sqt%s/ioconf.h>\n", ptp->p_name);
		fprintf(fp, "\n");

		/*
		 * Generate dev structures for this controller
		 */
		for (dp = dtab, namep = NULL; dp != 0; dp = dp->d_next) {
			mp = dp->d_conn;
			if (mp == 0 || mp == TO_NEXUS ||
			   !eq(mp->d_name, ptp->p_name) ||
			   (namep != NULL && eq(dp->d_name, namep)) )
				continue;
			fprintf(fp, "extern\tstruct\t%s_driver\t%s_driver;\n",
			    ptp->p_name, namep = dp->d_name);
			ptp->p_seen = 1;
		}

		found = 0;
		for (dp = dtab, namep = NULL; dp != 0; dp = dp->d_next) {
			mp = dp->d_conn;
			if (mp == 0 || mp == TO_NEXUS ||
			   !eq(mp->d_name, ptp->p_name))
				continue;
			if (namep == NULL || !eq(namep, dp->d_name)) {
				count = 0;
				if (namep != NULL) 
					fprintf(fp, "};\n");
				found = 1;
				fprintf(fp, "\nstruct\t%s_dev %s_%s[] = {\n",
						ptp->p_name,
						ptp->p_name,
						namep = dp->d_name);
				fprintf(fp, "/*");
				entry = ptp->p_fields;
				for (; entry->p_name != NULL; entry++)
					fprintf(fp, "\t%s",entry->p_name);
				fprintf(fp, " */\n");
			}
			if (dp->d_bin != UNKNOWN)
				bin_table[dp->d_bin]++;
			fprintf(fp, "{");
			for (entry = ptp->p_fields; entry->p_name != NULL; entry++) {
				if (eq(entry->p_name,"index"))
					fprintf(fp, "\t%d,", mp->d_unit);
				else
					fprintf(fp, "\t%lu,",
						dp->d_fields[entry-ptp->p_fields]);
			}
			fprintf(fp, "\t},\t/* %s%d */\n", dp->d_name, count++);
		}
		if (found)
			fprintf(fp, "};\n\n");

		/*
	 	* Generate conf array
	 	*/
		fprintf(fp, "/*\n");
		fprintf(fp, " * %s_conf array collects all %s devices\n", 
			ptp->p_name, ptp->p_name);
		fprintf(fp, " */\n\n");
		fprintf(fp, "struct\t%s_conf %s_conf[] = {\n", 
			ptp->p_name, ptp->p_name);
		fprintf(fp, "/*\tDriver\t\t#Entries\tDevices\t\t*/\n");
		for (dp = dtab, namep = NULL; dp != 0; dp = dp->d_next) {
			mp = dp->d_conn;
			if (mp == 0 || mp == TO_NEXUS ||
			   !eq(mp->d_name, ptp->p_name))
				continue;
			if (namep == NULL || !eq(namep, dp->d_name)) {
				if (namep != NULL)
					fprintf(fp, 
			"{\t&%s_driver,\t%d,\t\t%s_%s,\t},\t/* %s */\n",
			namep, count, ptp->p_name, namep, namep);
				count = 0;
				namep = dp->d_name;
			}
			++count;
		}
		if (namep != NULL) {
			fprintf(fp, 
			  "{\t&%s_driver,\t%d,\t\t%s_%s,\t},\t/* %s */\n",
			  namep, count, ptp->p_name, namep, namep);
		}
		fprintf(fp, "\t{ 0 },\n");
		fprintf(fp, "};\n\n");

	}

	/*
	 * Pseudo's
	 */

	fprintf(fp, "/*\n");
	fprintf(fp, " * Pseudo-device configuration\n");
	fprintf(fp, " */\n\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type == PSEUDO_DEVICE) {
			fprintf(fp, "extern\tint\t%sboot();\n", dp->d_name);
		}
	}
	fprintf(fp, "\nstruct\tpseudo_dev pseudo_dev[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type == PSEUDO_DEVICE) {
			fprintf(fp, "\t{ \"%s\",\t%d,\t%sboot,\t},\n",
				dp->d_name, 
				dp->d_slave == UNKNOWN ? 32 : dp->d_slave, 
				dp->d_name);
		}
	}
	fprintf(fp, "\t{ 0 },\n");
	fprintf(fp, "};\n\n");

	/*
	 * Bin interrupt table and misc
	 */

	fprintf(fp, "/*\n");
	fprintf(fp, " * Interrupt table\n");
	fprintf(fp, " */\n\n");
	fprintf(fp, "int\tbin_intr[8] = {\n");
	fprintf(fp, "\t\t0,\t\t\t\t/* bin 0, always zero */\n");
	for (count=1; count < 8; count++) {
		fprintf(fp, "\t\t%d,\t\t\t\t/* bin %d */\n", 
			bin_table[count], count);
	}
	fprintf(fp, "};\n");

	/*
	 * b8k_cntlrs[]
	 */

	fprintf(fp, "/*\n");
	fprintf(fp, " * b8k_cntlrs array collects all controller entries\n");
	fprintf(fp, " */\n\n");
	for (ptbx = 0; (ptp = ptab[ptbx]) != NULL; ptbx++) {
		if (ptp->p_seen)
			fprintf(fp, "extern int  conf_%s(),\tprobe_%s_devices(),\t%s_map();\n",
				ptp->p_name, ptp->p_name, ptp->p_name);
	}
	fprintf(fp, "\n\nstruct\tcntlrs b8k_cntlrs[] = {\n");
	fprintf(fp, "/*\tconf\t\tprobe_devs\t\tmap\t*/\n");

	for (ptbx = 0; (ptp = ptab[ptbx]) != NULL; ptbx++) {
		if (ptp->p_seen)
			fprintf(fp, "{\tconf_%s,\tprobe_%s_devices,\t%s_map\t}, \n",
				ptp->p_name, ptp->p_name, ptp->p_name);
	}
	fprintf(fp, "{\t0,\t},\n");
	fprintf(fp, "};\n");

	(void) fclose(fp);
}

#endif	MACHINE_SQT
#if	MACHINE_I386
void
i386_ioconf(void)
{
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/busvar.h>\n");
	fprintf(fp, "\n");
	fprintf(fp, "#define C (void *)\n");
	fprintf(fp, "\n");

	i386_pseudo_inits (fp);
	(void) fclose(fp);
}
#endif	MACHINE_I386

#if MACHINE_MIPSY || MACHINE_MIPS

void declare(const char *cp);
int is_declared(const char *cp);

void
mips_ioconf(void)
{
	register struct device *dp, *mp, *np;
	register int slave;
	FILE *fp;
	char buf1[64], buf2[64];

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
/*MACH_KERNEL*/
	fprintf(fp, "#ifndef  MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "#include <sys/param.h>\n");
	fprintf(fp, "#include <sys/buf.h>\n");
	fprintf(fp, "#include <sys/map.h>\n");
	fprintf(fp, "#include <sys/vm.h>\n");
/*MACH_KERNEL*/
	fprintf(fp, "#endif   MACH_KERNEL\n");
/*MACH_KERNEL*/
	fprintf(fp, "\n");
	if (seen_mbii && seen_vme) {
		printf("can't have both vme and mbii devices\n");
		exit(1);
	}
	if (seen_mbii)
		fprintf(fp, "#include <mipsmbii/mbiivar.h>\n");
	if (seen_vme)
		fprintf(fp, "#include <mipsvme/vmevar.h>\n");
	fprintf(fp, "\n");
	fprintf(fp, "#define C	(caddr_t)\n");
	fprintf(fp, "#define NULL	0\n\n");
	if (!seen_mbii)
		goto checkvme;
	/*
	 * MBII stuff should go here
	 */

checkvme:
	if (!seen_vme)
		goto closefile;
	/*
	 * Now generate interrupt vectors for the vme bus
	 */
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_vec != 0) {
			struct idlst *ip;
			mp = dp->d_conn;
			if (mp == 0 || mp == TO_NEXUS || !eq(mp->d_name, "vme"))
				continue;
			if (is_declared(dp->d_name))
				continue;
			declare(dp->d_name);
			fprintf(fp, "extern struct vme_driver %sdriver;\n",
			    dp->d_name);
			fprintf(fp, "extern ");
			ip = dp->d_vec;
			for (;;) {
				fprintf(fp, "%s()", ip->id);
				ip = ip->id_next;
				if (ip == 0)
					break;
				fprintf(fp, ", ");
			}
			fprintf(fp, ";\n");
			fprintf(fp, "int (*_%sint%d[])() = { ", dp->d_name,
			    dp->d_unit);
			ip = dp->d_vec;
			for (;;) {
				fprintf(fp, "%s", ip->id);
				ip = ip->id_next;
				if (ip == 0)
					break;
				fprintf(fp, ", ");
			}
			fprintf(fp, ", 0 } ;\n\n");
		}
	}
	fprintf(fp, "\nstruct vme_ctlr vmminit[] = {\n");
	fprintf(fp,
"  /*          driver  ctlr alive        intr          addr    am */\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_type != CONTROLLER || mp == TO_NEXUS || mp == 0 ||
		    !eq(mp->d_name, "vme"))
			continue;
		if (dp->d_vec == 0) {
			printf("must specify vector for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_addr == 0) {
			printf("must specify csr address for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_addrmod == 0) {
			printf("must specify address modifier for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
			printf("drives need their own entries; dont ");
			printf("specify drive or slave for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_flags) {
			printf("controllers (e.g. %s%d) ",
			    dp->d_name, dp->d_unit);
			printf("don't have flags, only devices do\n");
			continue;
		}
		fprintf(fp,
"  {   %14s, %3d,    0, %11s, C 0x%08x, 0x%02x },\n",
		     concat3(buf1, "&", dp->d_name, "driver"),
		     dp->d_unit,
		     concat3(buf2, "_", dp->d_name, "int"),
		     dp->d_addr,
		     dp->d_addrmod);
	}
	fprintf(fp, "  {             NULL }\n};\n");
	/*
	 * vme devices
	 */
	fprintf(fp, "\nstruct vme_device vmdinit[] = {\n");
	fprintf(fp,
"/*       driver  unit ctlr slave      intr          addr    am dk       flags */\n"
	);
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_unit == QUES || dp->d_type != DEVICE || mp == 0 ||
		    mp == TO_NEXUS || mp->d_type == MASTER)
			continue;
		for (np = mp; np && np != TO_NEXUS; np = np->d_conn)
			if (eq(np->d_name, "vme"))
				break;
		if (np != 0 && np != TO_NEXUS && !eq(np->d_name, "vme"))
			continue;
		np = 0;
		if (eq(mp->d_name, "vme")) {
			if (dp->d_vec == 0) {
				printf("must specify vector for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr == 0) {
				printf("must specify csr for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addrmod == 0) {
				printf(
			"must specify address modifier for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
				printf("drives/slaves can be specified ");
				printf("only for controllers, ");
				printf("not for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = QUES;
		} else {
			if ((np = mp->d_conn) == 0) {
				printf("%s%d isn't connected to anything ",
				    mp->d_name, mp->d_unit);
				printf(", so %s%d is unattached\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive == UNKNOWN) {
				printf("must specify ``drive number'' ");
				printf("for %s%d\n", dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_slave != UNKNOWN) {
				printf("slave numbers should be given only ");
				printf("for massbus tapes, not for %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_vec != 0) {
				printf("interrupt vectors should not be ");
				printf("given for drive %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr != 0) {
				printf("csr addresses should be given only ");
				printf("on controllers, not on %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addrmod != 0) {
				printf("address modifiers should be given only ");
				printf("on controllers, not on %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = dp->d_drive;
		}
		fprintf(fp,
"{%14s, %3d, %3s, %4d,%10s, C 0x%08x, 0x%02x, %1d, 0x%08x },\n",
		    concat3(buf1, "&",
		        eq(mp->d_name, "vme") ? dp->d_name : mp->d_name,
			"driver"),
		    dp->d_unit,
		    eq(mp->d_name, "vme") ? "-1" : qu(mp->d_unit),
		    slave,
		    intv2(dp),
		    dp->d_addr,
		    dp->d_addrmod,
		    dp->d_dk,
		    dp->d_flags);
	}
	fprintf(fp, "{          NULL }\n};\n");
closefile:
	(void) fclose(fp);
}

char *
intv2(struct device *dev)
{
	static char buf[20];

	if (dev->d_vec == 0) {
		strcpy(buf, "NULL");
	} else {
		(void) sprintf(buf, "_%sint", dev->d_name);
	}
	return (buf);
}

char *
concat3(char *buf, const char *p1, const char *p2, const char *p3)
{
	(void) sprintf(buf, "%s%s%s", p1, p2, p3);
	return (buf);
}

#define	MAXDEVS	100
#define	DEVLEN	10
char decl_devices[MAXDEVS][DEVLEN];

void
declare(const char *cp)
{
	register int i;

	for (i = 0; i < MAXDEVS; i++)
		if (decl_devices[i][0] == 0) {
			strncpy(decl_devices[i], cp, DEVLEN);
			return;
		}
	printf("device table full, fix mkioconf.c\n");
	exit(1);
}

int
is_declared(const char *cp)
{
	register int i;

	for (i = 0; i < MAXDEVS; i++) {
		if (decl_devices[i][0] == 0)
			return(0);
		if (strncmp(decl_devices[i], cp, DEVLEN) == 0)
			return(1);
	}
	return(0);
}
#endif MACHINE_MIPSY || MACHINE_MIPS

#if	MACHINE_M68K
char	*m68k_dn(const char *name);
void	m68k_pseudo_inits(FILE *fp);

void
m68k_ioconf(void)
{
	register struct device *dp, *mp;
	register int slave;
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/m68k/busvar.h>\n");
	fprintf(fp, "\n");
	fprintf(fp, "#define C (void *)\n");
	fprintf(fp, "\n");

	/*
	 * Now generate interrupt vectors for the bus
	 */
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (mp == TO_NEXUS || mp == 0 || mp->d_conn != TO_NEXUS)
			continue;
		fprintf(fp, "extern struct bus_driver %sdriver;\n",
			    dp->d_name);
	}

	/*
	 * Now spew forth the bus_ctrl structures
	 */
	fprintf(fp, "\nstruct bus_ctrl bus_cinit[] = {\n");
	fprintf(fp,
"  /* driver        ctrl   ipl         address */\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_type != CONTROLLER || mp == TO_NEXUS || mp == 0 ||
		    mp->d_conn != TO_NEXUS || dp->d_unit == QUES)
			continue;
		if (dp->d_addr == UNKNOWN) {
			printf("must specify csr address for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
			printf("drives need their own entries; ");
			printf("don't specify drive or slave for %s%d\n",
			    dp->d_name, dp->d_unit);
			continue;
		}
		if (dp->d_flags) {
			printf("controllers (e.g. %s%d) don't have flags, ",
			    dp->d_name, dp->d_unit);
			printf("only devices do\n");
			continue;
		}
		fprintf(fp,
"  {  %-12s, %5d, %4d,   C 0x%08x },\n",
		    m68k_dn(dp->d_name), dp->d_unit, dp->d_pri, dp->d_addr);
	}
	fprintf(fp, "  0\n};\n");

	/*
	 * Now we go for the bus_device stuff
	 */
	fprintf(fp, "\nstruct bus_device bus_dinit[] = {\n");
	fprintf(fp,
"  /* driver      unit ctrl slave ipl  dk       flags       address  name */\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		mp = dp->d_conn;
		if (dp->d_unit == QUES || dp->d_type != DEVICE || mp == 0 ||
		    mp == TO_NEXUS || mp->d_type == MASTER)
			continue;
		if (mp->d_conn == TO_NEXUS) {
			if (dp->d_addr == UNKNOWN) {
				printf("must specify csr for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive != UNKNOWN || dp->d_slave != UNKNOWN) {
				printf("drives/slaves can be specified only ");
				printf("for controllers, not for device %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = UNKNOWN;
		} else {
			if (mp->d_conn == 0) {
				printf("%s%d isn't connected to anything, ",
				    mp->d_name, mp->d_unit);
				printf("so %s%d is unattached\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_drive == UNKNOWN) {
				printf("must specify ``drive number'' for %s%d\n",
				   dp->d_name, dp->d_unit);
				continue;
			}
			/* NOTE THAT ON THE UNIBUS ``drive'' IS STORED IN */
			/* ``SLAVE'' AND WE DON'T WANT A SLAVE SPECIFIED */
			if (dp->d_slave != UNKNOWN) {
				printf("slave numbers should be given only ");
				printf("for massbus tapes, not for %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_pri != 0) {
				printf("interrupt priority should not be ");
				printf("given for drive %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			if (dp->d_addr != 0) {
				printf("csr addresses should be given only");
				printf(" on controllers, not on %s%d\n",
				    dp->d_name, dp->d_unit);
				continue;
			}
			slave = dp->d_drive;
		}
		fprintf(fp,
"  {  %-12s, %3d, %s,  %s,%3d,%3d, %#10x, C 0x%08x, \"%s\" },\n",
		    m68k_dn(mp->d_conn == TO_NEXUS? dp->d_name : mp->d_name),
		    dp->d_unit,
		    mp->d_conn == TO_NEXUS? " -1" : qu(mp->d_unit),
		    qu(slave),
		    dp->d_pri, -dp->d_dk, dp->d_flags,
		    dp->d_addr == UNKNOWN? 0 : dp->d_addr,
		    dp->d_name);
	}
	fprintf(fp, "  0\n};\n");
	m68k_pseudo_inits (fp);
	(void) fclose(fp);
}

void
m68k_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

void
i386_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

char *
m68k_dn(const char *name)
{
	sprintf(errbuf, "&%sdriver", name); return ns(errbuf);
}
#endif	MACHINE_M68K

#if	MACHINE_M88K || MACHINE_M98K
char	*nrw_dn(char *name);
void	nrw_pseudo_inits(FILE *fp);

void
nrw_ioconf(void)
{
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/nrw/busvar.h>\n");
	fprintf(fp, "\n");
	nrw_pseudo_inits (fp);
	(void) fclose(fp);
}

void
nrw_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

char *
nrw_dn(char *name)
{
	sprintf(errbuf, "&%sdriver,", name);
	return(errbuf);
}

void
m88k_ioconf(void)
{
	nrw_ioconf();
}

void
m98k_ioconf(void)
{
	nrw_ioconf();
}

void
m88k_pseudo_inits(FILE *fp)
{
	nrw_pseudo_inits(fp);
}

void
m98k_pseudo_inits(FILE *fp)
{
	nrw_pseudo_inits(fp);
}

char *
m88k_dn(char *name)
{
	return(nrw_dn(name));
}

char *
m98k_dn(char *name)
{
	return(nrw_dn(name));
}


#endif	MACHINE_M88K || MACHINE_M98K

#ifdef MACHINE_HPPA
char	*hppa_dn(char *name);
void	hppa_pseudo_inits(FILE *fp);

void
hppa_ioconf(void)
{
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/hppa/busvar.h>\n");
	fprintf(fp, "\n");
	hppa_pseudo_inits (fp);
	(void) fclose(fp);
}

void
hppa_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

char *
hppa_dn(char *name)
{
	sprintf(errbuf, "&%sdriver,", name);

	return (errbuf);
}

#endif MACHINE_HPPA

#ifdef MACHINE_SPARC
char	*sparc_dn(char *name);
void	sparc_pseudo_inits(FILE *fp);

void
sparc_ioconf(void)
{
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/busvar.h>\n");
	fprintf(fp, "\n");
	sparc_pseudo_inits (fp);
	(void) fclose(fp);
}

void
sparc_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

char *
sparc_dn(char *name)
{
	sprintf(errbuf, "&%sdriver,", name);
	return (errbuf);
}

#endif MACHINE_SPARC

#ifdef MACHINE_PPC
char	*ppc_dn(char *name);
void	ppc_pseudo_inits(FILE *fp);

void
ppc_ioconf(void)
{
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/busvar.h>\n");
	fprintf(fp, "\n");
	ppc_pseudo_inits (fp);
	(void) fclose(fp);
}

void
ppc_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

char *
ppc_dn(name)
	char *name;
{
	sprintf(errbuf, "&%sdriver,", name);
	return (errbuf);
}

#endif MACHINE_PPC

#ifdef MACHINE_ARM
void	arm_pseudo_inits(FILE *fp);

void
arm_ioconf(void)
{
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/busvar.h>\n");
	fprintf(fp, "\n");
	arm_pseudo_inits (fp);
	(void) fclose(fp);
}

void
arm_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

#endif /* MACHINE_ARM */

#ifdef MACHINE_X86_64
void	x86_64_pseudo_inits(FILE *fp);

void
x86_64_ioconf(void)
{
	FILE *fp;

	unlink(path("ioconf.c"));
	fp = fopen(path("ioconf.c"), "w");
	if (fp == 0) {
		perror(path("ioconf.c"));
		exit(1);
	}
	fprintf(fp, "#include <dev/busvar.h>\n");
	fprintf(fp, "\n");
	x86_64_pseudo_inits (fp);
	(void) fclose(fp);
}

void
x86_64_pseudo_inits(FILE *fp)
{
	register struct device *dp;
	int count;

	fprintf(fp, "\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		fprintf(fp, "extern int %s(int);\n", dp->d_init);
	}
	fprintf(fp, "\nstruct pseudo_init pseudo_inits[] = {\n");
	for (dp = dtab; dp != 0; dp = dp->d_next) {
		if (dp->d_type != PSEUDO_DEVICE || dp->d_init == 0)
			continue;
		count = dp->d_slave;
		if (count <= 0)
			count = 1;
		fprintf(fp, "\t{%d,\t%s},\n", count, dp->d_init);
	}
	fprintf(fp, "\t{0,\t0},\n};\n");
}

#endif /* MACHINE_X86_64 */

char *
intv(struct device *dev)
{
	static char buf[20];

	if (dev->d_vec == 0) {
		strcpy(buf, "     0");
	} else {
		(void) sprintf(buf, "%sint%d", dev->d_name, dev->d_unit);
	}
	return ns(buf);
}

char *
qu(int num)
{

	if (num == QUES) {
		strcpy(errbuf, "'?'");
	} else if (num == UNKNOWN) {
		strcpy(errbuf, " -1");
	} else {
		(void) sprintf(errbuf, "%3d", num);
	}
	return ns(errbuf);
}
