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
/*-
 * Copyright (c) University of British Columbia, 1984
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by the
 * Laboratory for Computation Vision and the Computer Science Department
 * of the University of British Columbia.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)hdlc.h	8.1 (Berkeley) 6/10/93
 */

#ifndef ORDER4
#define FALSE   0
#define TRUE    1
typedef u_char octet;
typedef char    bool;

/*
 *  HDLC Packet format definitions
 *  This will eventually have to be rewritten without reference
 *  to bit fields, to be compliant with ANSI C and alignment safe.
 */

#if BYTE_ORDER == BIG_ENDIAN
#define ORDER4(a, b, c, d) a , b , c , d
#define ORDER5(a, b, c, d, e) a , b , c , d , e
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define ORDER4(a, b, c, d) d , c , b , a
#define ORDER5(a, b, c, d, e) e , d , c , b , a
#endif
#endif

#define MAX_INFO_LEN    4096+3+4
#define ADDRESS_A       3	/* B'00000011' */
#define ADDRESS_B       1	/* B'00000001' */

struct Hdlc_iframe {
	octet	address;
	octet	ORDER4(nr:3, pf:1, ns:3, hdlc_0:1);
	octet    i_field[MAX_INFO_LEN];
};

struct Hdlc_sframe {
	octet	address;
	octet	ORDER4(nr:3, pf:1, s2:2, hdlc_01:2);
};

struct	Hdlc_uframe {
	octet	address;
	octet	ORDER4(m3:3, pf:1, m2:2, hdlc_11:2);
};

struct	Frmr_frame {
	octet	address;
	octet	control;
	octet	frmr_control;
	octet	ORDER4(frmr_nr:3, frmr_f1_0:1, frmr_ns:3, frmr_f2_0:1);
	octet	ORDER5(frmr_0000:4, frmr_z:1, frmr_y:1, frmr_x:1, frmr_w:1);
};

#define HDHEADERLN	2
#define MINFRLN		2		/* Minimum frame length. */

struct	Hdlc_frame {
	octet	address;
	octet	control;
	octet	info[3];	/* min for FRMR */
};

#define SABM_CONTROL 057	/* B'00101111' */
#define UA_CONTROL   0143	/* B'01100011' */
#define DISC_CONTROL 0103	/* B'01000011' */
#define DM_CONTROL   017	/* B'00001111' */
#define FRMR_CONTROL 0207	/* B'10000111' */
#define RR_CONTROL   01		/* B'00000001' */
#define RNR_CONTROL  05		/* B'00000101' */
#define REJ_CONTROL  011	/* B'00001001' */

#define POLLOFF  0
#define POLLON   1

/* Define Link State constants. */

#define INIT		0
#define DM_SENT		1
#define SABM_SENT	2
#define ABM		3
#define WAIT_SABM	4
#define WAIT_UA		5
#define DISC_SENT	6
#define DISCONNECTED	7
#define MAXSTATE	8

/* The following constants are used in a switch statement to process
   frames read from the communications line. */

#define SABM     0 * MAXSTATE
#define DM       1 * MAXSTATE
#define DISC     2 * MAXSTATE
#define UA       3 * MAXSTATE
#define FRMR     4 * MAXSTATE
#define RR       5 * MAXSTATE
#define RNR      6 * MAXSTATE
#define REJ      7 * MAXSTATE
#define IFRAME   8 * MAXSTATE
#define ILLEGAL  9 * MAXSTATE

#define T1	(3 * PR_SLOWHZ)		/*  IFRAME TIMEOUT - 3 seconds */
#define T3	(T1 / 2)		/*  RR generate timeout - 1.5 seconds */
#define N2	10
#define MODULUS 8
#define MAX_WINDOW_SIZE 7

#define Z  0
#define Y  1
#define X  2
#define W  3
#define A  4

#define TX 0
#define RX 1

bool	range_check ();
bool	valid_nr ();
struct	mbuf *hd_remove ();
