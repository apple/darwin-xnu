/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 * 
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:49  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:08  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.8.1  1996/12/09  16:57:22  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	[1996/12/09  11:13:16  stephen]
 *
 * Revision 1.1.6.1  1996/04/11  11:20:35  emcmanus
 * 	Copied from mainline.ppc.
 * 	[1996/04/11  08:26:36  emcmanus]
 * 
 * 	hppa merge
 * 	[1995/03/15  09:47:27  bruel]
 * 
 * Revision 1.1.4.1  1995/11/23  17:37:28  stephen
 * 	first powerpc checkin to mainline.ppc
 * 	[1995/11/23  16:46:29  stephen]
 * 
 * Revision 1.1.2.1  1995/08/25  06:50:17  stephen
 * 	Initial checkin of files for PowerPC port
 * 	[1995/08/23  15:05:31  stephen]
 * 
 * Revision 1.1.2.1  1995/02/14  14:25:16  bruel
 * 	First Revision.
 * 	[95/01/27            bruel]
 * 
 * $EndLog$
 */

#ifndef _PROFILE_MD_H
#define _PROFILE_MD_H

/*
 * Define the interfaces between the assembly language profiling support
 * that is common between the kernel, mach servers, and user space library.
 */

/*
 * Integer types used.
 */

typedef	long		prof_ptrint_t;	/* hold either pointer or signed int */
typedef	unsigned long	prof_uptrint_t;	/* hold either pointer or unsigned int */
typedef	long		prof_lock_t;	/* lock word type */
typedef unsigned char	prof_flag_t;	/* type for boolean flags */

/*
 * Double precision counter.
 */

typedef struct prof_cnt_t {
	prof_uptrint_t	low;		/* low 32 bits of counter */
	prof_uptrint_t	high;		/* high 32 bits of counter */
} prof_cnt_t;

#define PROF_CNT_INC(cnt)	((++((cnt).low) == 0) ? ++((cnt).high) : 0)
#define PROF_CNT_ADD(cnt,val)	(((((cnt).low + (val)) < (val)) ? ((cnt).high++) : 0), ((cnt).low += (val)))
#define PROF_CNT_LADD(cnt,val)	(PROF_CNT_ADD(cnt,(val).low), (cnt).high += (val).high)
#define PROF_CNT_SUB(cnt,val)	(((((cnt).low - (val)) > (cnt).low) ? ((cnt).high--) : 0), ((cnt).low -= (val)))
#define PROF_CNT_LSUB(cnt,val)	(PROF_CNT_SUB(cnt,(val).low), (cnt).high -= (val).high)

#define LPROF_ULONG_TO_CNT(cnt,val)	PROF_ULONG_TO_CNT(cnt,val)
#define LPROF_CNT_INC(lp)		PROF_CNT_INC(lp)
#define LPROF_CNT_ADD(lp,val)		PROF_CNT_ADD(lp,val)
#define LPROF_CNT_LADD(lp,val)		PROF_CNT_LADD(lp,val)
#define LPROF_CNT_SUB(lp,val)		PROF_CNT_SUB(lp,val)
#define LPROF_CNT_LSUB(lp,val)		PROF_CNT_LSUB(lp,val)
#define	LPROF_CNT_OVERFLOW(lp,high,low)	PROF_CNT_OVERFLOW(lp,high,low)
#define LPROF_CNT_TO_ULONG(lp)		PROF_CNT_TO_ULONG(lp)
#define LPROF_CNT_TO_LDOUBLE(lp)	PROF_CNT_TO_LDOUBLE(lp)
#define LPROF_CNT_TO_DECIMAL(buf,cnt)	PROF_CNT_TO_DECIMAL(buf,cnt)
#define LPROF_CNT_EQ_0(cnt)		PROF_CNT_EQ_0(cnt)
#define LPROF_CNT_NE_0(cnt)		PROF_CNT_NE_0(cnt)
#define LPROF_CNT_EQ(cnt1,cnt2)		PROF_CNT_EQ(cnt1,cnt2)
#define LPROF_CNT_NE(cnt1,cnt2)		PROF_CNT_NE(cnt1,cnt2)
#define LPROF_CNT_GT(cnt1,cnt2)		PROF_CNT_GT(cnt1,cnt2)
#define LPROF_CNT_LT(cnt1,cnt2)		PROF_CNT_LT(cnt1,cnt2)
#define LPROF_CNT_DIGITS		PROF_CNT_DIGITS


/*
 * Types of the profil counter.
 */

typedef unsigned short	HISTCOUNTER;		/* profil */
typedef prof_cnt_t	LHISTCOUNTER;		/* lprofil */

struct profile_stats {			/* Debugging counters */
	prof_uptrint_t major_version;	/* major version number */
	prof_uptrint_t minor_version;	/* minor version number */
};

struct profile_md {
	int major_version;		/* major version number */
	int minor_version;		/* minor version number */
};

#define PROFILE_MAJOR_VERSION 1
#define PROFILE_MINOR_VERSION 1

#endif /* _PROFILE_MD_H */






