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

/* 	Copyright (c) 1997 Apple Computer, Inc.  All rights reserved. 
 *
 * kdebug.h -   kernel_debug definitions
 *
 */

#ifndef BSD_SYS_KDEBUG_H
#define BSD_SYS_KDEBUG_H

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <mach/clock_types.h>
#if	defined(KERNEL_BUILD)
#include <kdebug.h>
#endif /* KERNEL_BUILD */

/*
 * types of faults that vm_fault handles
 * and creates trace entries for
 */
#define DBG_ZERO_FILL_FAULT   1
#define DBG_PAGEIN_FAULT      2
#define DBG_COW_FAULT         3
#define DBG_CACHE_HIT_FAULT   4


/* The debug code consists of the following 
*
* ----------------------------------------------------------------------
*|              |               |                               |Func   |
*| Class (8)    | SubClass (8)  |          Code (14)            |Qual(2)|
* ----------------------------------------------------------------------
* The class specifies the higher level 
*/

/* The Function qualifiers  */
#define DBG_FUNC_START		1
#define DBG_FUNC_END		2
#define DBG_FUNC_NONE		0


/* The Kernel Debug Classes  */
#define DBG_MACH		1
#define DBG_NETWORK		2	
#define DBG_FSYSTEM		3
#define DBG_BSD			4
#define DBG_IOKIT		5
#define DBG_DRIVERS		6
#define DBG_TRACE               7
#define DBG_DLIL	        8
#define DBG_MISC		20
#define DBG_MIG			255

/* **** The Kernel Debug Sub Classes for Mach (DBG_MACH) **** */
#define	DBG_MACH_EXCP_DFLT	0x03	/* Data Translation Fault */
#define	DBG_MACH_EXCP_IFLT	0x04	/* Inst Translation Fault */
#define	DBG_MACH_EXCP_INTR	0x05	/* Interrupts */
#define	DBG_MACH_EXCP_ALNG	0x06	/* Alignment Exception */
#define	DBG_MACH_EXCP_TRAP	0x07	/* Traps */
#define	DBG_MACH_EXCP_FP	0x08	/* FP Unavail */
#define	DBG_MACH_EXCP_DECI	0x09	/* Decrementer Interrupt */
#define	DBG_MACH_EXCP_SC	0x0C	/* System Calls */
#define	DBG_MACH_EXCP_TRACE	0x0D	/* Trace exception */
#define	DBG_MACH_IHDLR		0x10	/* Interrupt Handlers */
#define	DBG_MACH_IPC		0x20	/* Inter Process Comm */
#define	DBG_MACH_VM		0x30	/* Virtual Memory */
#define	DBG_MACH_SCHED		0x40	/* Scheduler */
#define	DBG_MACH_MSGID_INVALID	0x50	/* Messages - invalid */

/* Codes for Scheduler (DBG_MACH_SCHED) */     
#define MACH_SCHED              0x0     /* Scheduler */
#define MACH_STACK_ATTACH       0x1     /* stack_attach() */
#define MACH_STACK_HANDOFF      0x2     /* stack_handoff() */
#define MACH_CALL_CONT          0x3     /* call_continuation() */
#define MACH_CALLOUT            0x4     /* callouts */
#define MACH_STACK_DETACH       0x5
#define MACH_MAKE_RUNNABLE      0x6     /* make thread runnable */

/* **** The Kernel Debug Sub Classes for Network (DBG_NETWORK) **** */
#define DBG_NETIP	1	/* Internet Protocol */
#define DBG_NETARP	2	/* Address Resolution Protocol */
#define	DBG_NETUDP	3	/* User Datagram Protocol */
#define	DBG_NETTCP	4	/* Transmission Control Protocol */
#define	DBG_NETICMP	5	/* Internet Control Message Protocol */
#define	DBG_NETIGMP	6	/* Internet Group Management Protocol */
#define	DBG_NETRIP	7	/* Routing Information Protocol */
#define	DBG_NETOSPF	8	/* Open Shortest Path First */
#define	DBG_NETISIS	9	/* Intermediate System to Intermediate System */
#define	DBG_NETSNMP	10	/* Simple Network Management Protocol */
#define DBG_NETSOCK	11	/* Socket Layer */

/* For Apple talk */
#define	DBG_NETAARP	100	/* Apple ARP */
#define	DBG_NETDDP	101	/* Datagram Delivery Protocol */
#define	DBG_NETNBP	102	/* Name Binding Protocol */
#define	DBG_NETZIP	103	/* Zone Information Protocol */
#define	DBG_NETADSP	104	/* Name Binding Protocol */
#define	DBG_NETATP	105	/* Apple Transaction Protocol */
#define	DBG_NETASP	106	/* Apple Session Protocol */
#define	DBG_NETAFP	107	/* Apple Filing Protocol */
#define	DBG_NETRTMP	108	/* Routing Table Maintenance Protocol */
#define	DBG_NETAURP	109	/* Apple Update Routing Protocol */

/* **** The Kernel Debug Sub Classes for IOKIT (DBG_IOKIT) **** */
#define DBG_IOSCSI	1	/* SCSI */
#define DBG_IODISK	2	/* Disk layers */
#define	DBG_IONETWORK	3	/* Network layers */
#define	DBG_IOKEYBOARD	4	/* Keyboard */
#define	DBG_IOPOINTING	5	/* Pointing Devices */
#define	DBG_IOAUDIO	6	/* Audio */
#define	DBG_IOFLOPPY	7	/* Floppy */
#define	DBG_IOSERIAL	8	/* Serial */
#define	DBG_IOTTY	9	/* TTY layers */
#define DBG_IOWORKLOOP	10	/* Work from work loop */
#define DBG_IOINTES	11	/* Interrupt event source */
#define DBG_IOCLKES	12	/* Clock event source */
#define DBG_IOCMDQ	13	/* Command queue latencies */
#define DBG_IOMCURS	14	/* Memory Cursor */
#define DBG_IOMDESC	15	/* Memory Descriptors */

/* **** The Kernel Debug Sub Classes for Device Drivers (DBG_DRIVERS) **** */
#define DBG_DRVSCSI	1	/* SCSI */
#define DBG_DRVDISK	2	/* Disk layers */
#define	DBG_DRVNETWORK	3	/* Network layers */
#define	DBG_DRVKEYBOARD	4	/* Keyboard */
#define	DBG_DRVPOINTING	5	/* Pointing Devices */
#define	DBG_DRVAUDIO	6	/* Audio */
#define	DBG_DRVFLOPPY	7	/* Floppy */
#define	DBG_DRVSERIAL	8	/* Serial */
#define DBG_DRVSPLT     9

/* **** The Kernel Debug Sub Classes for the DLIL Layer (DBG_DLIL) **** */
#define DBG_DLIL_STATIC 1       /* Static DLIL code */
#define DBG_DLIL_PR_MOD 2       /* DLIL Protocol Module */
#define DBG_DLIL_IF_MOD 3       /* DLIL Interface Module */
#define DBG_DLIL_PR_FLT 4       /* DLIL Protocol Filter */
#define DBG_DLIL_IF_FLT 5       /* DLIL Interface FIlter */

/* The Kernel Debug Sub Classes for File System */
#define DBG_FSRW      1       /* reads and writes to the filesystem */

/* The Kernel Debug Sub Classes for BSD */
#define	DBG_BSD_EXCP_SC	0x0C	/* System Calls */

/* The Kernel Debug Sub Classes for DBG_TRACE */
#define DBG_TRACE_DATA      0
#define DBG_TRACE_STRING    1

/**********************************************************************/

#define KDBG_CODE(Class, SubClass, code) (((Class & 0xff) << 24) | ((SubClass & 0xff) << 16) | ((code & 0x3fff)  << 2))

#define KDBG_MIGCODE(msgid) ((DBG_MIG << 24) | (((msgid) & 0x3fffff)  << 2))

#define MACHDBG_CODE(SubClass, code) KDBG_CODE(DBG_MACH, SubClass, code)
#define NETDBG_CODE(SubClass, code) KDBG_CODE(DBG_NETWORK, SubClass, code)
#define FSDBG_CODE(SubClass, code) KDBG_CODE(DBG_FSYSTEM, SubClass, code)
#define BSDDBG_CODE(SubClass, code) KDBG_CODE(DBG_BSD, SubClass, code)
#define IOKDBG_CODE(SubClass, code) KDBG_CODE(DBG_IOKIT, SubClass, code)
#define DRVDBG_CODE(SubClass, code) KDBG_CODE(DBG_DRIVERS, SubClass, code)
#define TRACEDBG_CODE(SubClass,code) KDBG_CODE(DBG_TRACE, SubClass, code)
#define MISCDBG_CODE(SubClass,code) KDBG_CODE(DBG_MISC, SubClass, code)
#define DLILDBG_CODE(SubClass,code) KDBG_CODE(DBG_DLIL, SubClass, code)

/*   Usage:
* kernel_debug((KDBG_CODE(DBG_NETWORK, DNET_PROTOCOL, 51) | DBG_FUNC_START), 
*	offset, 0, 0, 0,0) 
* 
* For ex, 
* 
* #include <sys/kdebug.h>
* 
* #define DBG_NETIPINIT NETDBG_CODE(DBG_NETIP,1)
* 
* 
* void
* ip_init()
* {
*	register struct protosw *pr;
*	register int i;
* 	
*	KERNEL_DEBUG(DBG_NETIPINIT | DBG_FUNC_START, 0,0,0,0,0)
* 	--------
*	KERNEL_DEBUG(DBG_NETIPINIT, 0,0,0,0,0)
* 	--------
*	KERNEL_DEBUG(DBG_NETIPINIT | DBG_FUNC_END, 0,0,0,0,0)
* }
*

*/

extern unsigned int kdebug_enable;
#define KERNEL_DEBUG_CONSTANT(x,a,b,c,d,e)    \
do {					\
    if (kdebug_enable)			\
        kernel_debug(x,a,b,c,d,e);	\
} while(0)

#define KERNEL_DEBUG_CONSTANT1(x,a,b,c,d,e)    \
do {					\
    if (kdebug_enable)			\
        kernel_debug1(x,a,b,c,d,e);	\
} while(0)

extern void kernel_debug(unsigned int debugid, unsigned int arg1, unsigned int arg2, unsigned int arg3,  unsigned int arg4, unsigned int arg5);

extern void kernel_debug1(unsigned int debugid, unsigned int arg1, unsigned int arg2, unsigned int arg3,  unsigned int arg4, unsigned int arg5);

#if	KDEBUG

#define KERNEL_DEBUG(x,a,b,c,d,e)	\
do {					\
    if (kdebug_enable)			\
        kernel_debug(x,a,b,c,d,e);	\
} while(0)

#define KERNEL_DEBUG1(x,a,b,c,d,e)	\
do {					\
    if (kdebug_enable)			\
        kernel_debug1(x,a,b,c,d,e);	\
} while(0)

#else

#define KERNEL_DEBUG(x,a,b,c,d,e)
#define KERNEL_DEBUG1(x,a,b,c,d,e)

#endif

__END_DECLS


#ifdef KERNEL_PRIVATE
/*
 * private kernel_debug definitions
 */

typedef struct {
mach_timespec_t	timestamp;
unsigned int	arg1;
unsigned int	arg2;
unsigned int	arg3;
unsigned int	arg4;
unsigned int	arg5;       /* will hold current thread */
unsigned int	debugid;
} kd_buf;

#define KDBG_THREAD_MASK 0x7fffffff
#define KDBG_CPU_MASK    0x80000000

/* Debug Flags */
#define	KDBG_INIT	0x1
#define	KDBG_NOWRAP	0x2
#define	KDBG_FREERUN	0x4
#define	KDBG_WRAPPED	0x8
#define	KDBG_USERFLAGS	(KDBG_FREERUN|KDBG_NOWRAP|KDBG_INIT)
#define KDBG_PIDCHECK   0x10
#define KDBG_MAPINIT    0x20
#define KDBG_PIDEXCLUDE 0x40

typedef struct {
	unsigned int	type;
	unsigned int	value1;
	unsigned int	value2;
	unsigned int	value3;
	unsigned int	value4;
	
} kd_regtype;

typedef struct
{
    int nkdbufs;
    int nolog;
    int flags;
    int nkdthreads;
} kbufinfo_t;

typedef struct
{
  unsigned int thread;
  int          valid;
  char         command[20];
} kd_threadmap;

#define	KDBG_CLASSTYPE		0x10000
#define	KDBG_SUBCLSTYPE		0x20000
#define	KDBG_RANGETYPE		0x40000
#define	KDBG_TYPENONE		0x80000
#define KDBG_CKTYPES		0xF0000

#define	KDBG_RANGECHECK	0x100000
#define	KDBG_VALCHECK	0x200000        /* Check up to 4 individual values */

#define	KDBG_BUFINIT	0x80000000

/* Control operations */
#define	KDBG_EFLAGS	1
#define	KDBG_DFLAGS	2
#define KDBG_ENABLE	3
#define KDBG_SETNUMBUF	4
#define KDBG_GETNUMBUF	5
#define KDBG_SETUP	6
#define KDBG_REMOVE	7
#define	KDBG_SETREGCODE	8
#define	KDBG_GETREGCODE	9
#define	KDBG_READTRACE	10
#define KDBG_PIDTR      11
#define KDBG_THRMAP     12
#define KDBG_PIDEX      14
#define KDBG_SETRTCDEC  15

/* Minimum value allowed when setting decrementer ticks */
#define KDBG_MINRTCDEC  2500


/* PCSAMPLES control operations */
#define PCSAMPLE_DISABLE   1
#define PCSAMPLE_SETNUMBUF 2
#define PCSAMPLE_GETNUMBUF 3
#define PCSAMPLE_SETUP	   4
#define PCSAMPLE_REMOVE	   5
#define	PCSAMPLE_READBUF   6
#define	PCSAMPLE_SETREG    7
#define PCSAMPLE_COMM      8

#define MAX_PCSAMPLES    1000000     /* Maximum number of pc's in a single buffer */


extern unsigned int pcsample_enable;

typedef struct
{
    int npcbufs;
    int bufsize;
    int enable;
    unsigned long pcsample_beg;
    unsigned long pcsample_end;
} pcinfo_t;

#endif /* KERNEL_PRIVATE */

#endif /* !BSD_SYS_KDEBUG_H */
