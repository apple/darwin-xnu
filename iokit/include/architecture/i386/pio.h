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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.2.1  1998/10/13 00:40:44  ehewitt
 * Added support for Intel.
 *
 * Revision 1.1.1.1  1998/09/22 21:05:37  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:38  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.8.2  1996/07/31  09:46:36  paire
 * 	Merged with nmk20b7_shared (1.1.11.2 -> 1.1.11.1)
 * 	[96/06/10            paire]
 *
 * Revision 1.1.11.2  1996/06/13  12:38:25  bernadat
 * 	Do not use inline macros when MACH_ASSERT is configured.
 * 	[96/05/24            bernadat]
 * 
 * Revision 1.1.11.1  1996/05/14  13:50:23  paire
 * 	Added new linl and loutl __inline__.
 * 	Added conditional compilation for [l]{in|oub}[bwl]() __inline__.
 * 	[95/11/24            paire]
 * 
 * Revision 1.1.8.1  1994/09/23  02:00:28  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:25:52  ezf]
 * 
 * Revision 1.1.4.5  1993/08/09  19:40:41  dswartz
 * 	Add ANSI prototypes - CR#9523
 * 	[1993/08/06  17:45:57  dswartz]
 * 
 * Revision 1.1.4.4  1993/06/11  15:17:37  jeffc
 * 	CR9176 - ANSI C violations: inb/outb macros must be changed from
 * 	({ ... }) to inline functions, with proper type definitions. Callers
 * 	must pass proper types to these functions: 386 I/O port addresses
 * 	are unsigned shorts (not pointers).
 * 	[1993/06/10  14:26:10  jeffc]
 * 
 * Revision 1.1.4.3  1993/06/07  22:09:28  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  19:00:26  jeffc]
 * 
 * Revision 1.1.4.2  1993/06/04  15:28:45  jeffc
 * 	CR9176 - ANSI problems -
 * 	Added casts to get macros to take caddr_t as an I/O space address.
 * 	[1993/06/04  13:45:55  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:25:51  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/05/14  16:14:20  mrt
 * 	Correcting copyright
 * 
 * Revision 2.4  91/02/05  17:13:56  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:37:08  mrt]
 * 
 * Revision 2.3  90/12/20  16:36:37  jeffreyh
 * 	changes for __STDC__
 * 	[90/12/07            jeffreyh]
 * 
 * Revision 2.2  90/11/26  14:48:41  rvb
 * 	Pulled from 2.5
 * 	[90/11/22  10:09:38  rvb]
 * 
 * 	[90/08/14            mg32]
 * 
 * 	Now we know how types are factor in.
 * 	Cleaned up a bunch: eliminated ({ for output and flushed unused
 * 	output variables.
 * 	[90/08/14            rvb]
 * 
 * 	This is how its done in gcc:
 * 		Created.
 * 	[90/03/26            rvb]
 * 
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
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
#ifndef I386_PIO_H
#define I386_PIO_H
//#include <cpus.h>
//#include <mach_assert.h>
#define MACH_ASSERT 0

typedef unsigned short i386_ioport_t;

/* read a longword */
extern unsigned long	inl(
				i386_ioport_t	port);
/* read a shortword */
extern unsigned short	inw(
				i386_ioport_t	port);
/* read a byte */
extern unsigned char	inb(
				i386_ioport_t	port);
/* write a longword */
extern void		outl(
				i386_ioport_t	port,
				unsigned long	datum);
/* write a word */
extern void		outw(
				i386_ioport_t	port,
				unsigned short	datum);
/* write a longword */
extern void		outb(
				i386_ioport_t	port,
				unsigned char	datum);

/* input an array of longwords */
extern void		linl(
				i386_ioport_t	port,
				int		* data,
				int		count);
/* output an array of longwords */
extern void		loutl(
				i386_ioport_t	port,
				int		* data,
				int		count);

/* input an array of words */
extern void		linw(
				i386_ioport_t	port,
				int		* data,
				int		count);
/* output an array of words */
extern void		loutw(
				i386_ioport_t	port,
				int		* data,
				int		count);

/* input an array of bytes */
extern void		linb(
				i386_ioport_t	port,
				char		* data,
				int		count);
/* output an array of bytes */
extern void		loutb(
				i386_ioport_t	port,
				char		* data,
				int		count);

#if defined(__GNUC__) && (!MACH_ASSERT)
extern __inline__ unsigned long	inl(
				i386_ioport_t port)
{
	unsigned long datum;
	__asm__ volatile("inl %1, %0" : "=a" (datum) : "d" (port));
	return(datum);
}

extern __inline__ unsigned short inw(
				i386_ioport_t port)
{
	unsigned short datum;
	__asm__ volatile(".byte 0x66; inl %1, %0" : "=a" (datum) : "d" (port));
	return(datum);
}

extern __inline__ unsigned char inb(
				i386_ioport_t port)
{
	unsigned char datum;
	__asm__ volatile("inb %1, %0" : "=a" (datum) : "d" (port));
	return(datum);
}

extern __inline__ void outl(
				i386_ioport_t port,
				unsigned long datum)
{
	__asm__ volatile("outl %0, %1" : : "a" (datum), "d" (port));
}

extern __inline__ void outw(
				i386_ioport_t port,
				unsigned short datum)
{
	__asm__ volatile(".byte 0x66; outl %0, %1" : : "a" (datum), "d" (port));
}

extern __inline__ void outb(
				i386_ioport_t port,
				unsigned char datum)
{
	__asm__ volatile("outb %0, %1" : : "a" (datum), "d" (port));
}
#endif /* defined(__GNUC__) && (!MACH_ASSERT) */
#endif /* I386_PIO_H */
