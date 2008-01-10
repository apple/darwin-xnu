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
 */
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
#include <mach_assert.h>

#if !MACH_ASSERT
#include <architecture/i386/pio.h>
#else
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
#endif /* !MACH_ASSERT */

#endif /* I386_PIO_H */
