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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * The NEXTSTEP Software License Agreement specifies the terms
 * and conditions for redistribution.
 */

#ifndef _SYS_CHIO_H_
#define _SYS_CHIO_H_

/*
 * Structures and definitions for changer io control commands
 */

#define CH_INVERT		0x10000
#define CH_ADDR_MASK		0xffff
struct chop {
	short	ch_op;		/* operations defined below */
	short	result;		/* the result */
	union {
		struct {
			int chm;		/* Transport element */
			int from;
			int to;
		} move;
		struct {
			int chm;		/* Transport element */
			int to;
		} position; 
		struct {
			short   chmo;		/* Offset of first CHM */
			short   chms;		/* No. of CHM */
			short   slots;		/* No. of Storage Elements */
			short   sloto;		/* Offset of first SE */
			short   imexs;		/* No. of Import/Export Slots */
			short   imexo;		/* Offset of first IM/EX */
			short   drives;		/* No. of CTS */
			short   driveo;		/* Offset of first CTS */
			short   rot;		/* CHM can rotate */
		} getparam;
		struct {
			int type;
#define CH_CHM	1
#define CH_STOR	2
#define CH_IMEX	3
#define CH_CTS	4
			int from;
			struct {
				u_char elema_1;
				u_char elema_0;
				u_char full:1;
				u_char rsvd:1;
				u_char except:1;
				u_char :5;
				u_char rsvd2;
				union {
					struct {
						u_char add_sense_code;
						u_char add_sense_code_qualifier;
					} specs;
					short add_sense;
/* WARINING LSB only */
#define CH_CHOLDER	0x0290	/* Cartridge holder is missing */
#define CH_STATUSQ	0x0390	/* Status is questionable */
#define CH_CTS_CLOSED	0x0490	/* CTS door is closed */
				} ch_add_sense;
				u_char rsvd3[3];
				u_char :6;
				u_char invert:1;
				u_char svalid:1;
				u_char source_1;
				u_char source_0;
				u_char rsvd4[4];
			} elem_data;
		} get_elem_stat;
	} u;
};

/* operations */
#define CHMOVE				1
#define CHPOSITION			2
#define CHGETPARAM			3
#define CHGETELEM			4


/* Changer IO control command */
#define	CHIOOP	_IOWR('c', 1, struct chop)	/* do a mag tape op */

#endif /* !_SYS_CHIO_H_ */
