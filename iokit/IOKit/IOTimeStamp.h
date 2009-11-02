/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#ifndef IOKIT_IOTIMESTAMP_H
#define IOKIT_IOTIMESTAMP_H

#include <sys/kdebug.h>

static inline void
IOTimeStampStartConstant(unsigned int csc,
			 unsigned int a = 0, unsigned int b = 0,
			 unsigned int c = 0, unsigned int d = 0)
{
    KERNEL_DEBUG_CONSTANT(csc | DBG_FUNC_START, a, b, c, d, 0);
}

static inline void
IOTimeStampEndConstant(unsigned int csc,
		       unsigned int a = 0, unsigned int b = 0,
		       unsigned int c = 0, unsigned int d = 0)
{
    KERNEL_DEBUG_CONSTANT(csc | DBG_FUNC_END, a, b, c, d, 0);
}

static inline void
IOTimeStampConstant(unsigned int csc,
		    unsigned int a = 0, unsigned int b = 0,
		    unsigned int c = 0, unsigned int d = 0)
{
    KERNEL_DEBUG_CONSTANT(csc | DBG_FUNC_NONE, a, b, c, d, 0);
}

#if KDEBUG

static inline void
IOTimeStampStart(unsigned int csc,
                 unsigned int a = 0, unsigned int b = 0,
                 unsigned int c = 0, unsigned int d = 0)
{
    KERNEL_DEBUG(csc | DBG_FUNC_START, a, b, c, d, 0);
}

static inline void
IOTimeStampEnd(unsigned int csc,
               unsigned int a = 0, unsigned int b = 0,
               unsigned int c = 0, unsigned int d = 0)
{
    KERNEL_DEBUG(csc | DBG_FUNC_END, a, b, c, d, 0);
}

static inline void
IOTimeStamp(unsigned int csc,
            unsigned int a = 0, unsigned int b = 0,
            unsigned int c = 0, unsigned int d = 0)
{
    KERNEL_DEBUG(csc | DBG_FUNC_NONE, a, b, c, d, 0);
}

#endif /* KDEBUG */

#define IODBG_SCSI(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOSCSI, code))
#define IODBG_DISK(code)	(KDBG_CODE(DBG_IOKIT, DBG_IODISK, code))
#define IODBG_NETWORK(code)	(KDBG_CODE(DBG_IOKIT, DBG_IONETWORK, code))
#define IODBG_KEYBOARD(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOKEYBOARD, code))
#define IODBG_POINTING(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOPOINTING, code))
#define IODBG_AUDIO(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOAUDIO, code))
#define IODBG_FLOPPY(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOFLOPPY, code))
#define IODBG_SERIAL(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOSERIAL, code))
#define IODBG_TTY(code)		(KDBG_CODE(DBG_IOKIT, DBG_IOTTY, code))

/* IOKit infrastructure subclasses */
#define IODBG_WORKLOOP(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOWORKLOOP, code))
#define IODBG_INTES(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOINTES, code))
#define IODBG_TIMES(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOCLKES, code))
#define IODBG_CMDQ(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOCMDQ, code))
#define IODBG_MCURS(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOMCURS, code))
#define IODBG_MDESC(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOMDESC, code))
#define IODBG_POWER(code)	(KDBG_CODE(DBG_IOKIT, DBG_IOPOWER, code))

/* IOKit specific codes - within each subclass */

/* DBG_IOKIT/DBG_IOSCSI codes */

/* DBG_IOKIT/DBG_IODISK codes */

/* DBG_IOKIT/DBG_IONETWORK codes */

/* DBG_IOKIT/DBG_IOKEYBOARD codes */

/* DBG_IOKIT/DBG_IOPOINTING codes */

/* DBG_IOKIT/DBG_IOAUDIO codes */

/* DBG_IOKIT/DBG_IOFLOPPY codes */

/* DBG_IOKIT/DBG_IOSERIAL codes */

/* DBG_IOKIT/DBG_IOTTY codes */

/* DBG_IOKIT/DBG_IOWORKLOOP codes */
#define IOWL_CLIENT	1	/* 0x050a0004 */
#define IOWL_WORK	2	/* 0x050a0008 */

/* DBG_IOKIT/DBG_IOINTES codes */
#define IOINTES_CLIENT	1	/* 0x050b0004 */
#define IOINTES_LAT	2	/* 0x050b0008 */
#define IOINTES_SEMA	3	/* 0x050b000c */
#define IOINTES_INTCTXT 4	/* 0x050b0010 */
#define IOINTES_INTFLTR 5	/* 0x050b0014 */
#define IOINTES_ACTION	6	/* 0x050b0018 */
#define IOINTES_FILTER	7	/* 0x050b001c */

/* DBG_IOKIT/DBG_IOTIMES codes */
#define IOTIMES_CLIENT	1	/* 0x050c0004 */
#define IOTIMES_LAT	2	/* 0x050c0008 */
#define IOTIMES_SEMA	3	/* 0x050c000c */
#define IOTIMES_ACTION	4	/* 0x050c0010 */

/* DBG_IOKIT/DBG_IOCMDQ codes */
#define IOCMDQ_CLIENT	1	/* 0x050d0004 */
#define IOCMDQ_LAT	2	/* 0x050d0008 */
#define IOCMDQ_SEMA	3	/* 0x050d000c */
#define IOCMDQ_PSEMA	4	/* 0x050d0010 */
#define IOCMDQ_PLOCK	5	/* 0x050d0014 */
#define IOCMDQ_ACTION	6	/* 0x050d0018 */

/* DBG_IOKIT/DBG_IOMCURS codes */

/* DBG_IOKIT/DBG_IOMDESC codes */

/* DBG_IOKIT/DBG_IOPOWER codes */
// See IOKit/pwr_mgt/IOPMlog.h for the power management codes

#endif /* ! IOKIT_IOTIMESTAMP_H */
