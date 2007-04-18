/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 *      Copyright (c) 1988, 1989, 1997 Apple Computer, Inc.
 */

/* netat/debug.h */

#ifndef _NETAT_DEBUG_H_
#define _NETAT_DEBUG_H_
#include <sys/appleapiopts.h>
#ifdef __APPLE_API_OBSOLETE
#ifdef PRIVATE

#define D_L_FATAL		0x00000001
#define D_L_ERROR		0x00000002
#define D_L_WARNING		0x00000004
#define D_L_INFO		0x00000008
#define D_L_VERBOSE		0x00000010
#define D_L_STARTUP     	0x00000020
#define D_L_STARTUP_LOW		0x00000040
#define D_L_SHUTDN		0x00000080
#define D_L_SHUTDN_LOW		0x00000100
#define D_L_INPUT		0x00000200
#define D_L_OUTPUT		0x00000400
#define D_L_STATS		0x00000800
#define D_L_STATE_CHG		0x00001000	/* re-aarp, ifState etc. */
#define D_L_ROUTING		0x00002000
#define D_L_DNSTREAM		0x00004000
#define D_L_UPSTREAM		0x00008000
#define D_L_STARTUP_INFO	0x00010000
#define D_L_SHUTDN_INFO		0x00020000
#define D_L_ROUTING_AT		0x00040000	/* atalk address routing */
#define D_L_USR1		0x01000000
#define D_L_USR2		0x02000000
#define D_L_USR3		0x04000000
#define D_L_USR4		0x08000000
#define D_L_TRACE		0x10000000


#define D_M_PAT			0x00000001
#define D_M_PAT_LOW		0x00000002
#define D_M_ELAP		0x00000004
#define D_M_ELAP_LOW		0x00000008
#define D_M_DDP			0x00000010
#define D_M_DDP_LOW		0x00000020
#define D_M_NBP			0x00000040
#define D_M_NBP_LOW		0x00000080
#define D_M_ZIP			0x00000100
#define D_M_ZIP_LOW		0x00000200
#define D_M_RTMP		0x00000400
#define D_M_RTMP_LOW		0x00000800
#define D_M_ATP			0x00001000
#define D_M_ATP_LOW		0x00002000
#define D_M_ADSP		0x00004000
#define D_M_ADSP_LOW		0x00008000
#define D_M_AEP			0x00010000
#define D_M_AARP		0x00020000
#define D_M_ASP			0x00040000
#define D_M_ASP_LOW		0x00080000
#define D_M_AURP		0x00100000
#define D_M_AURP_LOW		0x00200000
#define D_M_TRACE		0x10000000

	/* macros for working with atp data at the lap level. 
	 * These are for tracehook performance measurements only!!!
	 * It is assumed that the ddp & atp headers are at the top of the
	 * mblk, occupy contiguous memory and the atp headers are of the
	 * extended type only.
	 */

typedef struct dbgBits {
	unsigned long 	dbgMod;	/* debug module bitmap (used in dPrintf) */
	unsigned long 	dbgLev;	/* debug level bitmap */
} dbgBits_t;

extern dbgBits_t 	dbgBits;

	/* macros for debugging */
#ifdef DEBUG
#define dPrintf(mod, lev, p) \
	if (((mod) & dbgBits.dbgMod) && ((lev) & dbgBits.dbgLev)) {\
		 kprintf p;  \
	}
#else
#define dPrintf(mod, lev, p)
#endif

/* 8/5/98 LD: Adds MacOSX kernel debugging facility */
/* note: kdebug must be added to the "RELEASE" config in conf/MASTER.ppc */

#include <sys/kdebug.h>
#if KDEBUG
/*
  Strings for the "trace/codes" file:

0x02650004      AT_DDPinput

0x02680000      AT_ADSP_Misc
0x02680004      AT_ADSP_RxData
0x02680008      AT_ADSP_SndData
0x0268000C      AT_ADSP_Read
0x02680010      AT_ADSP_Write
0x02680014      AT_ADSP_mbuf
0x02680018      AT_ADSP_putnext
0x0268001c      AT_ADSP_ATrw

*/

/* usage:
      KERNEL_DEBUG(DBG_AT_DDP_INPUT | DBG_FUNC_START, 0,0,0,0,0);
      KERNEL_DEBUG(DBG_AT_DDP_INPUT, 0,0,0,0,0);
      KERNEL_DEBUG(DBG_AT_DDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
*/

#define DBG_AT_DDP_INPUT NETDBG_CODE(DBG_NETDDP, 1)
#define DBG_AT_DDP_OUTPUT NETDBG_CODE(DBG_NETDDP, 2)

#define DBG_ADSP_MISC	NETDBG_CODE(DBG_NETADSP, 0)
#define DBG_ADSP_RCV	NETDBG_CODE(DBG_NETADSP, 1)
#define DBG_ADSP_SND	NETDBG_CODE(DBG_NETADSP, 2)
#define DBG_ADSP_READ	NETDBG_CODE(DBG_NETADSP, 3)
#define DBG_ADSP_WRITE	NETDBG_CODE(DBG_NETADSP, 4)
#define DBG_ADSP_MBUF	NETDBG_CODE(DBG_NETADSP, 5)
#define DBG_ADSP_PNEXT	NETDBG_CODE(DBG_NETADSP, 6)
#define DBG_ADSP_ATRW	NETDBG_CODE(DBG_NETADSP, 7)
#endif

#define trace_mbufs(pri, str, start)\
{ if (start)\
{   int i; gbuf_t *tmp;\
    for (tmp=start, i=0; tmp && i < 10; tmp = gbuf_cont(tmp), i++) {\
	dPrintf(pri, D_L_TRACE, ("%s=0x%x, len=%d %s\n",\
                                 str, tmp, gbuf_len(tmp),\
                                 (((struct mbuf *)tmp)->m_flags & M_EXT)?"CL":""));\
	KERNEL_DEBUG(DBG_ADSP_MBUF,  0, tmp, gbuf_len(tmp), gbuf_next(tmp), \
		((struct mbuf *)tmp)->m_flags & M_EXT);\
}}}

/* from h/atlog.h */

/* These pointers are non-NULL if logging or tracing are activated. */
#ifndef LOG_DRIVER
extern char *log_errp;	
extern char *log_trcp;
#endif  /* LOG_DRIVER */

/* ATTRACE() macro.  Use this routine for calling 
 * streams tracing and logging.  If `log' is TRUE, then
 * this event will also be logged if logging is on.
 */
#if !defined(lint) && defined(AT_DEBUG)
#define	ATTRACE(mid,sid,level,log,fmt,arg1,arg2,arg3)		\
	if (log_trcp || (log && log_errp)) {			\
		strlog(mid,sid,level,SL_TRACE |			\
			(log ? SL_ERROR : 0)  |			\
			(level <= AT_LV_FATAL ? SL_FATAL : 0),	\
			fmt,arg1,arg2,arg3);			\
	}
#else
#define	ATTRACE(mid,sid,level,log,fmt,arg1,arg2,arg3)		\
/*	printf(fmt, arg1, arg2, arg3); */

#endif


/* Levels for AppleTalk tracing */

#define	AT_LV_FATAL	1
#define	AT_LV_ERROR	3
#define	AT_LV_WARNING	5
#define	AT_LV_INFO	7
#define	AT_LV_VERBOSE	9


/* Sub-ids for AppleTalk tracing, add more if you can't figure
 * out where your event belongs.
 */

#define	AT_SID_INPUT	1	/* Network incoming packets */
#define	AT_SID_OUTPUT	2	/* Network outgoing packets */
#define	AT_SID_TIMERS	3	/* Protocol timers */
#define	AT_SID_FLOWCTRL	4	/* Protocol flow control */
#define	AT_SID_USERREQ	5	/* User requests */
#define	AT_SID_RESOURCE	6	/* Resource limitations */



/* Module ID's for AppleTalk subsystems */

#define	AT_MID(n)	(200+n)

/* 
#define	AT_MID_MISC	AT_MID(0)	not used
#define	AT_MID_LLAP	AT_MID(1)	not_used
#define	AT_MID_ELAP	202		moved to lap.h
#define	AT_MID_DDP	203		moved to ddp.h
#define	AT_MID_RTMP	AT_MID(4)	not used
#define	AT_MID_NBP	AT_MID(5)	not used
#define	AT_MID_EP	AT_MID(6)	not used
#define	AT_MID_ATP	AT_MID(7)	not used
#define	AT_MID_ZIP	AT_MID(8)	not needed
#define	AT_MID_PAP	AT_MID(9)	not used
#define	AT_MID_ASP	AT_MID(10)	redefined in adsp.h
#define	AT_MID_AFP	AT_MID(11)	not used
#define	AT_MID_ADSP	212		moved to adsp.h
#define	AT_MID_NBPD	AT_MID(13)	not used
#define	AT_MID_LAP	214		moved to lap.h
#define	AT_MID_LAST	214
*/

#ifdef	AT_MID_STRINGS
static char *at_mid_strings[] = {
	"misc",
	"LLAP",
	"ELAP",
	"DDP",
	"RTMP",
	"NBP",
	"EP",
	"ATP",
	"ZIP",
	"PAP",
	"ASP",
	"AFP",
	"ADSP",
	"NBPD",
	"LAP"
};
#endif


#ifndef SL_FATAL
/* Don't define these if they're already defined */

/* Flags for log messages */

#define SL_FATAL	01	/* indicates fatal error */
#define SL_NOTIFY	02	/* logger must notify administrator */
#define SL_ERROR	04	/* include on the error log */
#define SL_TRACE	010	/* include on the trace log */

#endif

#endif /* PRIVATE */
#endif /* __APPLE_API_OBSOLETE */
#endif /* _NETAT_DEBUG_H_ */

