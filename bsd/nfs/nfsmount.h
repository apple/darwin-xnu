/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfsmount.h	8.3 (Berkeley) 3/30/95
 * FreeBSD-Id: nfsmount.h,v 1.13 1997/08/16 19:16:05 wollman Exp $
 */


#ifndef _NFS_NFSMOUNT_H_
#define _NFS_NFSMOUNT_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
/*
 * Mount structure.
 * One allocated on every NFS mount.
 * Holds NFS specific information for mount.
 */
struct	nfsmount {
	int	nm_flag;		/* Flags for soft/hard... */
	int	nm_state;		/* Internal state flags */
	struct	mount *nm_mountp;	/* Vfs structure for this filesystem */
	int	nm_numgrps;		/* Max. size of groupslist */
	struct vnode *nm_dvp;		/* root directory vnode pointer */
	struct	socket *nm_so;		/* Rpc socket */
	int	nm_sotype;		/* Type of socket */
	int	nm_soproto;		/* and protocol */
	int	nm_soflags;		/* pr_flags for socket protocol */
	struct	mbuf *nm_nam;		/* Addr of server */
	int	nm_timeo;		/* Init timer for NFSMNT_DUMBTIMR */
	int	nm_retry;		/* Max retries */
	int	nm_srtt[4];		/* Timers for rpcs */
	int	nm_sdrtt[4];
	int	nm_sent;		/* Request send count */
	int	nm_cwnd;		/* Request send window */
	int	nm_timeouts;		/* Request timeouts */
	int	nm_deadthresh;		/* Threshold of timeouts-->dead server*/
	int	nm_rsize;		/* Max size of read rpc */
	int	nm_wsize;		/* Max size of write rpc */
	int	nm_readdirsize;		/* Size of a readdir rpc */
	int	nm_readahead;		/* Num. of blocks to readahead */
	int	nm_leaseterm;		/* Term (sec) for NQNFS lease */
	CIRCLEQ_HEAD(, nfsnode) nm_timerhead; /* Head of lease timer queue */
	struct vnode *nm_inprog;	/* Vnode in prog by nqnfs_clientd() */
	uid_t	nm_authuid;		/* Uid for authenticator */
	int	nm_authtype;		/* Authenticator type */
	int	nm_authlen;		/* and length */
	char	*nm_authstr;		/* Authenticator string */
	char	*nm_verfstr;		/* and the verifier */
	int	nm_verflen;
	u_char	nm_verf[NFSX_V3WRITEVERF]; /* V3 write verifier */
	NFSKERBKEY_T nm_key;		/* and the session key */
	int	nm_numuids;		/* Number of nfsuid mappings */
	TAILQ_HEAD(, nfsuid) nm_uidlruhead; /* Lists of nfsuid mappings */
	LIST_HEAD(, nfsuid) nm_uidhashtbl[NFS_MUIDHASHSIZ];
	TAILQ_HEAD(, nfsbuf) nm_bufq;	/* async io buffer queue */
	short	nm_bufqlen;		/* number of buffers in queue */
	short	nm_bufqwant;		/* process wants to add to the queue */
	int	nm_bufqiods;		/* number of iods processing queue */
	int	nm_tprintf_initial_delay;	/* delay first "server down" */
	int	nm_tprintf_delay;	/* delay between "server down" */
};


#if defined(KERNEL)
/*
 * Convert mount ptr to nfsmount ptr.
 */
#define VFSTONFS(mp)	((mp) ? ((struct nfsmount *)((mp)->mnt_data)) : NULL)

#ifndef NFS_TPRINTF_INITIAL_DELAY
#define NFS_TPRINTF_INITIAL_DELAY	12
#endif

#ifndef NFS_TPRINTF_DELAY
#define NFS_TPRINTF_DELAY		30
#endif

#endif /* KERNEL */

#endif /* __APPLE_API_PRIVATE */
#endif /* _NFS_NFSMOUNT_H_ */
