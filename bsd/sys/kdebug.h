/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>
__BEGIN_DECLS

#ifdef __APPLE_API_UNSTABLE

#include <mach/clock_types.h>
#include <stdint.h>
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
#define DBG_MACH			1
#define DBG_NETWORK			2	
#define DBG_FSYSTEM			3
#define DBG_BSD				4
#define DBG_IOKIT			5
#define DBG_DRIVERS			6
#define DBG_TRACE           7
#define DBG_DLIL	        8
#define DBG_SECURITY		9
#define DBG_MISC			20
#define DBG_DYLD            31
#define DBG_QT              32
#define DBG_APPS            33
#define DBG_MIG				255

/* **** The Kernel Debug Sub Classes for Mach (DBG_MACH) **** */
#define	DBG_MACH_EXCP_KTRAP_x86	0x02	/* Kernel Traps on x86 */
#define	DBG_MACH_EXCP_DFLT	0x03	/* Data Translation Fault */
#define	DBG_MACH_EXCP_IFLT	0x04	/* Inst Translation Fault */
#define	DBG_MACH_EXCP_INTR	0x05	/* Interrupts */
#define	DBG_MACH_EXCP_ALNG	0x06	/* Alignment Exception */
#define	DBG_MACH_EXCP_UTRAP_x86	0x07	/* User Traps on x86 */
#define	DBG_MACH_EXCP_FP	0x08	/* FP Unavail */
#define	DBG_MACH_EXCP_DECI	0x09	/* Decrementer Interrupt */
#define	DBG_MACH_CHUD		0x0A	/* CHUD */
#define	DBG_MACH_EXCP_SC	0x0C	/* System Calls */
#define	DBG_MACH_EXCP_TRACE	0x0D	/* Trace exception */
#define	DBG_MACH_EXCP_EMUL	0x0E	/* Instruction emulated */
#define	DBG_MACH_IHDLR		0x10	/* Interrupt Handlers */
#define	DBG_MACH_IPC		0x20	/* Inter Process Comm */
#define	DBG_MACH_VM		0x30	/* Virtual Memory */
#define	DBG_MACH_SCHED		0x40	/* Scheduler */
#define	DBG_MACH_MSGID_INVALID	0x50	/* Messages - invalid */
#define DBG_MACH_LOCKS		0x60	/* new lock APIs */

/* Codes for Scheduler (DBG_MACH_SCHED) */     
#define MACH_SCHED              0x0     /* Scheduler */
#define MACH_STACK_ATTACH       0x1     /* stack_attach() */
#define MACH_STACK_HANDOFF      0x2     /* stack_handoff() */
#define MACH_CALL_CONT          0x3     /* call_continuation() */
#define MACH_CALLOUT            0x4     /* callouts */
#define MACH_STACK_DETACH       0x5
#define MACH_MAKE_RUNNABLE      0x6     /* make thread runnable */
#define	MACH_PROMOTE			0x7		/* promoted due to resource */
#define	MACH_DEMOTE				0x8		/* promotion undone */
#define MACH_PREBLOCK_MUTEX		0x9		/* preblocking on mutex */

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
#define	DBG_NETIPSEC	128	/* IPsec Protocol  */

/* **** The Kernel Debug Sub Classes for IOKIT (DBG_IOKIT) **** */
#define DBG_IOWORKLOOP		1	/* Work from work loop */
#define DBG_IOINTES			2	/* Interrupt event source */
#define DBG_IOCLKES			3	/* Clock event source */
#define DBG_IOCMDQ			4	/* Command queue latencies */
#define DBG_IOMCURS			5	/* Memory Cursor */
#define DBG_IOMDESC			6	/* Memory Descriptors */
#define DBG_IOPOWER			7	/* Power Managerment */

/* **** 8-32 reserved for internal IOKit usage **** */

#define DBG_IOSTORAGE		32	/* Storage layers */
#define	DBG_IONETWORK		33	/* Network layers */
#define	DBG_IOKEYBOARD		34	/* Keyboard */
#define	DBG_IOHID			35	/* HID Devices */
#define	DBG_IOAUDIO			36	/* Audio */
#define	DBG_IOSERIAL		37	/* Serial */
#define	DBG_IOTTY			38	/* TTY layers */
#define DBG_IOSAM			39	/* SCSI Architecture Model layers */
#define DBG_IOPARALLELATA   40	/* Parallel ATA */
#define DBG_IOPARALLELSCSI	41	/* Parallel SCSI */
#define DBG_IOSATA			42	/* Serial-ATA */
#define DBG_IOSAS			43	/* SAS */
#define DBG_IOFIBRECHANNEL	44	/* FiberChannel */
#define DBG_IOUSB			45	/* USB */
#define DBG_IOBLUETOOTH		46	/* Bluetooth */
#define DBG_IOFIREWIRE		47	/* FireWire */
#define DBG_IOINFINIBAND	48	/* Infiniband */

/* Backwards compatibility */
#define	DBG_IOPOINTING		DBG_IOHID			/* OBSOLETE: Use DBG_IOHID instead */
#define DBG_IODISK			DBG_IOSTORAGE		/* OBSOLETE: Use DBG_IOSTORAGE instead */

/* **** The Kernel Debug Sub Classes for Device Drivers (DBG_DRIVERS) **** */
#define DBG_DRVSTORAGE		1	/* Storage layers */
#define	DBG_DRVNETWORK		2	/* Network layers */
#define	DBG_DRVKEYBOARD		3	/* Keyboard */
#define	DBG_DRVHID			4	/* HID Devices */
#define	DBG_DRVAUDIO		5	/* Audio */
#define	DBG_DRVSERIAL		7	/* Serial */
#define DBG_DRVSAM			8	/* SCSI Architecture Model layers */
#define DBG_DRVPARALLELATA  9	/* Parallel ATA */
#define DBG_DRVPARALLELSCSI	10	/* Parallel SCSI */
#define DBG_DRVSATA			11	/* Serial ATA */
#define DBG_DRVSAS			12	/* SAS */
#define DBG_DRVFIBRECHANNEL	13	/* FiberChannel */
#define DBG_DRVUSB			14	/* USB */
#define DBG_DRVBLUETOOTH	15	/* Bluetooth */
#define DBG_DRVFIREWIRE		16	/* FireWire */
#define DBG_DRVINFINIBAND	17	/* Infiniband */

/* Backwards compatibility */
#define	DBG_DRVPOINTING		DBG_DRVHID		/* OBSOLETE: Use DBG_DRVHID instead */
#define DBG_DRVDISK			DBG_DRVSTORAGE	/* OBSOLETE: Use DBG_DRVSTORAGE instead */

/* **** The Kernel Debug Sub Classes for the DLIL Layer (DBG_DLIL) **** */
#define DBG_DLIL_STATIC 1       /* Static DLIL code */
#define DBG_DLIL_PR_MOD 2       /* DLIL Protocol Module */
#define DBG_DLIL_IF_MOD 3       /* DLIL Interface Module */
#define DBG_DLIL_PR_FLT 4       /* DLIL Protocol Filter */
#define DBG_DLIL_IF_FLT 5       /* DLIL Interface FIlter */

/* The Kernel Debug Sub Classes for File System */
#define DBG_FSRW      1       /* reads and writes to the filesystem */
#define DBG_DKRW      2       /* reads and writes to the disk */
#define DBG_FSVN      3       /* vnode operations (inc. locking/unlocking) */
#define DBG_FSLOOOKUP 4       /* namei and other lookup-related operations */

/* The Kernel Debug Sub Classes for BSD */
#define	DBG_BSD_EXCP_SC	0x0C	/* System Calls */
#define	DBG_BSD_AIO		0x0D	/* aio (POSIX async IO) */
#define DBG_BSD_SC_EXTENDED_INFO 0x0E    /* System Calls, extended info */

/* The Kernel Debug Sub Classes for DBG_TRACE */
#define DBG_TRACE_DATA      0
#define DBG_TRACE_STRING    1

/* The Kernel Debug Sub Classes for DBG_MISC */
#define DBG_EVENT	0x10
#define	DBG_BUFFER	0x20

/* The Kernel Debug Sub Classes for DBG_DYLD */
#define DBG_DYLD_STRING   5

/* The Kernel Debug modifiers for the DBG_DKRW sub class */
#define DKIO_DONE 	0x01
#define DKIO_READ	0x02
#define DKIO_ASYNC	0x04
#define DKIO_META	0x08
#define DKIO_PAGING	0x10

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
#define SECURITYDBG_CODE(SubClass,code) KDBG_CODE(DBG_SECURITY, SubClass, code)
#define DYLDDBG_CODE(SubClass,code) KDBG_CODE(DBG_DYLD, SubClass, code)
#define QTDBG_CODE(SubClass,code) KDBG_CODE(DBG_QT, SubClass, code)
#define APPSDBG_CODE(SubClass,code) KDBG_CODE(DBG_APPS, SubClass, code)

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
#define KDEBUG_ENABLE_TRACE   0x1
#define KDEBUG_ENABLE_ENTROPY 0x2
#define KDEBUG_ENABLE_CHUD    0x4

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

/*
 * LP64todo - for some reason these are problematic
 */
struct proc;
extern void kdbg_trace_data(struct proc *proc, long *arg_pid);

extern void kdbg_trace_string(struct proc *proc, long *arg1, long *arg2, long *arg3, long *arg4);

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

#define __kdebug_only

#else

#define KERNEL_DEBUG(x,a,b,c,d,e)
#define KERNEL_DEBUG1(x,a,b,c,d,e)

#define __kdebug_only __unused
#endif

#endif /* __APPLE_API_UNSTABLE */
__END_DECLS


#ifdef	PRIVATE
#ifdef __APPLE_API_PRIVATE
/*
 * private kernel_debug definitions
 */

typedef struct {
uint64_t	timestamp;
unsigned int	arg1;
unsigned int	arg2;
unsigned int	arg3;
unsigned int	arg4;
unsigned int	arg5;       /* will hold current thread */
unsigned int	debugid;
} kd_buf;

#define KDBG_TIMESTAMP_MASK 0x00ffffffffffffffULL
#define KDBG_CPU_MASK       0x0f00000000000000ULL
#define KDBG_CPU_SHIFT	56

/* Debug Flags */
#define	KDBG_INIT	0x1
#define	KDBG_NOWRAP	0x2
#define	KDBG_FREERUN	0x4
#define	KDBG_WRAPPED	0x8
#define	KDBG_USERFLAGS	(KDBG_FREERUN|KDBG_NOWRAP|KDBG_INIT)
#define KDBG_PIDCHECK   0x10
#define KDBG_MAPINIT    0x20
#define KDBG_PIDEXCLUDE 0x40
#define KDBG_LOCKINIT	0x80

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
    int bufid;
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
#define KDBG_KDGETENTROPY 16

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
	unsigned int pcsample_beg;
	unsigned int pcsample_end;
} pcinfo_t;

#endif /* __APPLE_API_PRIVATE */
#endif	/* PRIVATE */

#endif /* !BSD_SYS_KDEBUG_H */
