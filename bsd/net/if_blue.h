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
/* Copyright (c) 1997, 1998 Apple Computer, Inc. All Rights Reserved */
/*
 *	@(#)if_blue.h	1.1 (MacOSX) 6/10/43
 * Justin Walker
 * 970520 - First version
 * 980130 - Second version - performance improvements
 */

#ifndef _IF_BLUE_H
#define _IF_BLUE_H

#define BLUE_DEBUG 0

/*
 * Y-adapter filter mechanism.
 * Specifies the Atalk or IP network address of this node.
 * If BF_ALLOC is set and BF_VALID is not, the corresponding
 * protocol type should be captured.
 */
struct BlueFilter
{
#define	IFNAMSIZ	16
	char	ifr_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	short BF_flags;
	unsigned long  BF_address;	/* IP address or Atalk Network # */
	unsigned char  BF_node;		/* Atalk node # */
#ifdef notyet
	struct ifnet *BF_if;		/* Destination of "passed" pkts */
#endif
};

#define BF_ALLOC	0x01	/* Entry in use */
#define BF_DEALLOC	0x02	/* Clear matching entry */
#define BF_VALID	0x04	/* Address is valid */
#define BF_ATALK	0x08	/* Appletalk network address */
#define BF_IP		0x10	/* IP network address */

struct Ystats
{	char YS_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	struct BlueFilter YS_filter[2];
	pid_t YS_blue_pid;
	int YS_pkts_up;
	int YS_pkts_out;
	int YS_pkts_looped_r2b;
	int YS_pkts_looped_b2r;
	int YS_no_bufs1;
	int YS_no_bufs2;
	int YS_full_sockbuf;
};

struct ifnet_blue
{	struct ifnet ifb_ifn;
	struct socket *ifb_so;
	pid_t blue_pid;
	int sig_to_send;
	int sig_sent;		/* Set when new pkt arrives; cleared when mt */
	struct BlueFilter filter[2];	/* Only need to check IP, A/talk */
	/* Stats */
	int pkts_up;
	int pkts_out;
	int pkts_looped_r2b;
	int pkts_looped_b2r;
	int no_bufs1;		/* splitter_input got null mbuf */
	int no_bufs2;		/* ndrv_output couldn't dup mbuf */
	int full_sockbuf;
};

/* Preallocate slots in blue_if to simplify filtering */
#define BFS_ATALK	0x0	/* The Atalk filter */
#define BFS_IP		0x1	/* The IP filter */

#define SIOCSSPLITTER	_IOW('i', 123, struct ifreq)	/* set 'splitter' */
#define SIOCGSPLITTER	_IOR('i', 122, struct ifreq)	/* get 'splitter' */
#define SIOCGSPLTSTAT	_IOWR('i', 121, struct Ystats)
#define SIOCSSPLTFILT	_IOW('i', 120, struct BlueFilter)
#define SIOCZSPLTSTAT	_IO('i', 119)		/* Clear stats */

/*
 * Config structure for the Y adapter - NYI
 */
struct if_splitter
{	char ifs_on;		/* 1=>on */
	char ifs_qmax;		/* !0 => maxqlen */
	short ifs_wait;		/* Time to wait for signal */
	short ifs_sig;		/* Signal to send */
	short ifs_pad;		/* Extra space */
};

#ifdef KERNEL
extern struct ifqueue blueq;		/* Place to put incoming BB packets */

#define BFCount 10
extern struct BlueFilter RhapFilter[]; /* Filters for MacOSX side */
extern int BFIx;
#endif
#endif /* _IF_BLUE_H */
