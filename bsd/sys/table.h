/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Mach Operating System
 * Copyright (c) 1986 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#ifndef	_SYS_TABLE_
#define _SYS_TABLE_

#include <sys/appleapiopts.h>

#warning obsolete header! Please delete the include from your sources.

#ifdef	KERNEL_PRIVATE

#ifdef __APPLE_API_OBSOLETE
#include <sys/dkstat.h>
#include <machine/table.h>

#define	TBL_LOADAVG		3	/* (no index) */
#define	TBL_ARGUMENTS		6	/* index by process ID */
#define	TBL_PROCINFO		10	/* index by proc table slot */
#define	TBL_MACHFACTOR		11	/* index by cpu number */
#define TBL_CPUINFO		12	/* (no index), generic CPU info */

/*
 * Machine specific table id base
 */
#define TBL_MACHDEP_BASE	0x4000	/* Machine dependent codes start here */

/*
 * Return codes from machine dependent calls
 */
#define TBL_MACHDEP_NONE	0	/* Not handled by machdep code */
#define	TBL_MACHDEP_OKAY	1	/* Handled by machdep code */
#define	TBL_MACHDEP_BAD		-1	/* Bad status from machdep code */



/*
 *  TBL_LOADAVG data layout
 *  (used by TBL_MACHFACTOR too)
 */
struct tbl_loadavg
{
    long   tl_avenrun[3];
    int    tl_lscale;		/* 0 scale when floating point */
};

/*
 *	TBL_PROCINFO data layout
 */
#define	PI_COMLEN	19	/* length of command string */
struct tbl_procinfo
{
    int		pi_uid;		/* user ID */
    int		pi_pid;		/* proc ID */
    int		pi_ppid;	/* parent proc ID */
    int		pi_pgrp;	/* proc group ID */
    int		pi_ttyd;	/* controlling terminal number */
    int		pi_status;	/* process status: */
#define	PI_EMPTY	0	    /* no process */
#define	PI_ACTIVE	1	    /* active process */
#define	PI_EXITING	2	    /* exiting */
#define	PI_ZOMBIE	3	    /* zombie */
    int		pi_flag;	/* other random flags */
    char	pi_comm[PI_COMLEN+1];
				/* short command name */
};

/*
 * TBL_CPUINFO data layout
 */
struct tbl_cpuinfo
{
    int		ci_swtch;		/* # context switches */
    int		ci_intr;		/* # interrupts */
    int		ci_syscall;		/* # system calls */
    int		ci_traps;		/* # system traps */
    int		ci_hz;			/* # ticks per second */
    int		ci_phz;			/* profiling hz */
    int		ci_cptime[CPUSTATES];	/* cpu state times */
};



#ifdef KERNEL
/*
 * Machine specific procedure prototypes.
 */
int machine_table(int id, int index, caddr_t addr, int nel, u_int lel, int set);
int machine_table_setokay(int id);
#endif /* KERNEL */

#endif /* __APPLE_API_OBSOLETE */

#endif	/* KERNEL_PRIVATE */
#endif	/* _SYS_TABLE_ */

