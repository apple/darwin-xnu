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
 * Copyright (c) University of British Columbia, 1984
 * Copyright (c) 1990, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 * 		 University of Erlangen-Nuremberg, Germany, 1992
 * 
 * This code is derived from software contributed to Berkeley by the
 * Laboratory for Computation Vision and the Computer Science Department
 * of the the University of British Columbia and the Computer Science
 * Department (IV) of the University of Erlangen-Nuremberg, Germany.
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
 *	@(#)x25.h	8.1 (Berkeley) 6/10/93
 */

#ifdef KERNEL
#define PRC_IFUP	3
#define PRC_LINKUP	4
#define PRC_LINKDOWN	5
#define PRC_LINKRESET	6
#define PRC_LINKDONTCOPY	7
#ifndef PRC_DISCONNECT_REQUEST  
#define PRC_DISCONNECT_REQUEST 10
#endif
#endif

#define CCITTPROTO_HDLC		1
#define CCITTPROTO_X25		2	/* packet level protocol */
#define IEEEPROTO_802LLC	3	/* doesn't belong here */

#define HDLCPROTO_LAP		1
#define HDLCPROTO_LAPB		2
#define HDLCPROTO_UNSET		3
#define HDLCPROTO_LAPD		4

/* socket options */
#define PK_ACCTFILE		1	/* use level = CCITTPROTO_X25 */
#define PK_FACILITIES		2	/* use level = CCITTPROTO_X25 */
#define PK_RTATTACH		3	/* use level = CCITTPROTO_X25 */
#define PK_PRLISTEN		4	/* use level = CCITTPROTO_X25 */

#define MAX_FACILITIES		109     /* maximum size for facilities */

/*
 *  X.25 Socket address structure.  It contains the  X.121 or variation of
 *  X.121, facilities information, higher level protocol value (first four
 *  bytes of the User Data field), and the last  12 characters of the User
 *  Data field.
 */

struct x25_sockaddr {		/* obsolete - use sockaddr_x25 */
    short  xaddr_len;		/* Length of xaddr_addr.		*/
    u_char xaddr_addr[15];	/* Network dependent or X.121 address.	*/
    u_char xaddr_facilities;	/* Facilities information.		*/
#define XS_REVERSE_CHARGE	0x01
#define XS_HIPRIO		0x02
    u_char xaddr_proto[4];	/* Protocol ID (4 bytes of user data).	*/
    u_char xaddr_userdata[12];	/* Remaining User data field.		*/
};

/*
 *  X.25 Socket address structure.  It contains the network id, X.121
 *  address, facilities information, higher level protocol value (first four
 *  bytes of the User Data field), and up to 12 characters of User Data.
 */

struct	sockaddr_x25 {
	u_char	x25_len;
	u_char	x25_family;	/* must be AF_CCITT */
	short	x25_net;	/* network id code (usually a dnic) */
	char	x25_addr[16];	/* X.121 address (null terminated) */
	struct	x25opts {
		char	op_flags;	/* miscellaneous options */
					/* pk_var.h defines other lcd_flags */
#define X25_REVERSE_CHARGE	0x01	/* remote DTE pays for call */
#define X25_DBIT		0x02	/* not yet supported */
#define X25_MQBIT		0x04	/* prepend M&Q bit status byte to packet data */
#define X25_OLDSOCKADDR		0x08	/* uses old sockaddr structure */
#define X25_DG_CIRCUIT		0x10	/* lcd_flag: used for datagrams */
#define X25_DG_ROUTING		0x20	/* lcd_flag: peer addr not yet known */
#define X25_MBS_HOLD		0x40	/* lcd_flag: collect m-bit sequences */
		char	op_psize;	/* requested packet size */
#define X25_PS128		7
#define X25_PS256		8
#define X25_PS512		9
		char	op_wsize;	/* window size (1 .. 7) */
		char	op_speed;	/* throughput class */
	} x25_opts;
	short	x25_udlen;	/* user data field length */
	char	x25_udata[16];	/* user data field */
};

/*
 * network configuration info
 * this structure must be 16 bytes long
 */

struct	x25config {
	struct	sockaddr_x25 xc_addr;
	/* link level parameters */
	u_short	xc_lproto:4,	/* link level protocol eg. CCITTPROTO_HDLC */
		xc_lptype:4,	/* protocol type eg. HDLCPROTO_LAPB */
		xc_ltrace:1,	/* link level tracing flag */
		xc_lwsize:7;	/* link level window size */
	u_short	xc_lxidxchg:1,  /* link level XID exchange flag - NOT YET */
	/* packet level parameters */
	        xc_rsvd1:2,
                xc_pwsize:3,	/* default window size */
		xc_psize:4,	/* default packet size 7=128, 8=256, ... */
		xc_type:3,	/* network type */
#define X25_1976	0
#define X25_1980	1
#define X25_1984	2
#define X25_DDN		3
#define X25_BASIC	4
		xc_ptrace:1,	/* packet level tracing flag */
		xc_nodnic:1,	/* remove our dnic when calling on net */
		xc_prepnd0:1;	/* prepend 0 when making offnet calls */
	u_short	xc_maxlcn;	/* max logical channels */
	u_short	xc_dg_idletimo;	/* timeout for idle datagram circuits. */
};

#ifdef IFNAMSIZ
struct ifreq_x25 {
	char	ifr_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	struct	x25config ifr_xc;
};
#define	SIOCSIFCONF_X25	_IOW('i', 12, struct ifreq_x25)	/* set ifnet config */
#define	SIOCGIFCONF_X25	_IOWR('i',13, struct ifreq_x25)	/* get ifnet config */
#endif
