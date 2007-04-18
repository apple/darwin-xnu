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
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:39  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:40  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1994/09/23  01:47:30  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:20:22  ezf]
 *
 * Revision 1.1.2.3  1993/08/09  19:39:04  dswartz
 * 	Add ANSI prototypes - CR#9523
 * 	[1993/08/06  17:51:17  dswartz]
 * 
 * Revision 1.1.2.2  1993/06/02  23:21:32  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:03:17  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:27:20  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.7  91/05/14  16:30:03  mrt
 * 	Correcting copyright
 * 
 * Revision 2.6  91/03/16  14:47:03  rpd
 * 	Fixed ioctl definitions for ANSI C.
 * 	[91/02/20            rpd]
 * 
 * Revision 2.5  91/02/05  17:20:25  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:47:16  mrt]
 * 
 * Revision 2.4  90/11/26  14:51:02  rvb
 * 	jsb bet me to XMK34, sigh ...
 * 	[90/11/26            rvb]
 * 	Synched 2.5 & 3.0 at I386q (r1.5.1.3) & XMK35 (r2.4)
 * 	[90/11/15            rvb]
 * 
 * Revision 1.5.1.2  90/07/27  11:27:06  rvb
 * 	Fix Intel Copyright as per B. Davies authorization.
 * 	[90/07/27            rvb]
 * 
 * Revision 2.2  90/05/03  15:46:11  dbg
 * 	First checkin.
 * 
 * Revision 1.5.1.1  90/01/08  13:29:46  rvb
 * 	Add Intel copyright.
 * 	[90/01/08            rvb]
 * 
 * Revision 1.5  89/09/25  12:27:37  rvb
 * 	File was provided by Intel 9/18/89.
 * 	[89/09/23            rvb]
 * 
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/* 
 */

/*
 *   Copyright 1988, 1989 by Intel Corporation, Santa Clara, California.
 * 
 * 		All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appears in all
 * copies and that both the copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Intel
 * not be used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * 
 * INTEL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 * IN NO EVENT SHALL INTEL BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define RTC_ADDR	0x70	/* I/O port address for register select */
#define RTC_DATA	0x71	/* I/O port address for data read/write */

/*
 * Register A definitions
 */
#define RTC_A		0x0a	/* register A address */
#define RTC_UIP		0x80	/* Update in progress bit */
#define RTC_DIV0	0x00	/* Time base of 4.194304 MHz */
#define RTC_DIV1	0x10	/* Time base of 1.048576 MHz */
#define RTC_DIV2	0x20	/* Time base of 32.768 KHz */
#define RTC_RATE6	0x06	/* interrupt rate of 976.562 */

/*
 * Register B definitions
 */
#define RTC_B		0x0b	/* register B address */
#define RTC_SET		0x80	/* stop updates for time set */
#define RTC_PIE		0x40	/* Periodic interrupt enable */
#define RTC_AIE		0x20	/* Alarm interrupt enable */
#define RTC_UIE		0x10	/* Update ended interrupt enable */
#define RTC_SQWE	0x08	/* Square wave enable */
#define RTC_DM		0x04	/* Date mode, 1 = binary, 0 = BCD */
#define RTC_HM		0x02	/* hour mode, 1 = 24 hour, 0 = 12 hour */
#define RTC_DSE		0x01	/* Daylight savings enable */

/* 
 * Register C definitions
 */
#define RTC_C		0x0c	/* register C address */
#define RTC_IRQF	0x80	/* IRQ flag */
#define RTC_PF		0x40	/* PF flag bit */
#define RTC_AF		0x20	/* AF flag bit */
#define RTC_UF		0x10	/* UF flag bit */

/*
 * Register D definitions
 */
#define RTC_D		0x0d	/* register D address */
#define RTC_VRT		0x80	/* Valid RAM and time bit */

#define RTC_NREG	0x0e	/* number of RTC registers */
#define RTC_NREGP	0x0a	/* number of RTC registers to set time */

#define RTCRTIME	_IOR('c', 0x01, struct rtc_st) /* Read time from RTC */
#define RTCSTIME	_IOW('c', 0x02, struct rtc_st) /* Set time into RTC */

struct rtc_st {
	char	rtc_sec;
	char	rtc_asec;
	char	rtc_min;
	char	rtc_amin;
	char	rtc_hr;
	char	rtc_ahr;
	char	rtc_dow;
	char	rtc_dom;
	char	rtc_mon;
	char	rtc_yr;
	char	rtc_statusa;
	char	rtc_statusb;
	char	rtc_statusc;
	char	rtc_statusd;
};

/*
 * this macro reads contents of real time clock to specified buffer 
 */
#define load_rtc(regs) \
{\
	register int i; \
	\
	for (i = 0; i < RTC_NREG; i++) { \
		outb(RTC_ADDR, i); \
		(regs)[i] = inb(RTC_DATA); \
	} \
}

/*
 * this macro writes contents of specified buffer to real time clock 
 */ 
#define save_rtc(regs) \
{ \
	register int i; \
	for (i = 0; i < RTC_NREGP; i++) { \
		outb(RTC_ADDR, i); \
		outb(RTC_DATA, (regs)[i]);\
	} \
}	


