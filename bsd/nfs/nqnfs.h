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
 * Copyright (c) 1992, 1993
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
 *	@(#)nqnfs.h	8.3 (Berkeley) 3/30/95
 * FreeBSD-Id: nqnfs.h,v 1.14 1997/08/16 19:16:05 wollman Exp $
 */


#ifndef _NFS_NQNFS_H_
#define _NFS_NQNFS_H_

/*
 * Definitions for NQNFS (Not Quite NFS) cache consistency protocol.
 */

/* Tunable constants */
#define	NQ_CLOCKSKEW	3	/* Clock skew factor (sec) */
#define	NQ_WRITESLACK	5	/* Delay for write cache flushing */
#define	NQ_MAXLEASE	60	/* Max lease duration (sec) */
#define	NQ_MINLEASE	5	/* Min lease duration (sec) */
#define	NQ_DEFLEASE	30	/* Default lease duration (sec) */
#define	NQ_RENEWAL	3	/* Time before expiry (sec) to renew */
#define	NQ_TRYLATERDEL	15	/* Initial try later delay (sec) */
#define	NQ_MAXNUMLEASE	2048	/* Upper bound on number of server leases */
#define	NQ_DEADTHRESH	NQ_NEVERDEAD	/* Default nm_deadthresh */
#define	NQ_NEVERDEAD	9	/* Greater than max. nm_timeouts */
#define	NQLCHSZ		256	/* Server hash table size */

#define	NQNFS_PROG	300105	/* As assigned by Sun */
#define	NQNFS_VER3	3
#define	NQNFS_EVICTSIZ	156	/* Size of eviction request in bytes */

/*
 * Definitions used for saving the "last lease expires" time in Non-volatile
 * RAM on the server. The default definitions below assume that NOVRAM is not
 * available.
 */
#ifdef HASNVRAM
#  undef HASNVRAM
#endif
#define	NQSTORENOVRAM(t)
#define	NQLOADNOVRAM(t)

/*
 * Defn and structs used on the server to maintain state for current leases.
 * The list of host(s) that hold the lease are kept as nqhost structures.
 * The first one lives in nqlease and any others are held in a linked
 * list of nqm structures hanging off of nqlease.
 *
 * Each nqlease structure is chained into two lists. The first is a list
 * ordered by increasing expiry time for nqsrv_timer() and the second is a chain
 * hashed on lc_fh.
 */
#define	LC_MOREHOSTSIZ	10

struct nqhost {
	union {
		struct {
			u_short udp_flag;
			u_short	udp_port;
			union nethostaddr udp_haddr;
		} un_udp;
		struct {
			u_short connless_flag;
			u_short connless_spare;
			union nethostaddr connless_haddr;
		} un_connless;
		struct {
			u_short conn_flag;
			u_short conn_spare;
			struct nfssvc_sock *conn_slp;
		} un_conn;
	} lph_un;
};
#define	lph_flag	lph_un.un_udp.udp_flag
#define	lph_port	lph_un.un_udp.udp_port
#define	lph_haddr	lph_un.un_udp.udp_haddr
#define	lph_inetaddr	lph_un.un_udp.udp_haddr.had_inetaddr
#define	lph_claddr	lph_un.un_connless.connless_haddr
#define	lph_nam		lph_un.un_connless.connless_haddr.had_nam
#define	lph_slp		lph_un.un_conn.conn_slp

struct nqlease {
	LIST_ENTRY(nqlease) lc_hash;	/* Fhandle hash list */
	CIRCLEQ_ENTRY(nqlease) lc_timer; /* Timer queue list */
	time_t		lc_expiry;	/* Expiry time (sec) */
	struct nqhost	lc_host;	/* Host that got lease */
	struct nqm	*lc_morehosts;	/* Other hosts that share read lease */
	fsid_t		lc_fsid;	/* Fhandle */
	char		lc_fiddata[MAXFIDSZ];
	struct vnode	*lc_vp;		/* Soft reference to associated vnode */
};
#define	lc_flag		lc_host.lph_un.un_udp.udp_flag

/* lc_flag bits */
#define	LC_VALID	0x0001	/* Host address valid */
#define	LC_WRITE	0x0002	/* Write cache */
#define	LC_NONCACHABLE	0x0004	/* Non-cachable lease */
#define	LC_LOCKED	0x0008	/* Locked */
#define	LC_WANTED	0x0010	/* Lock wanted */
#define	LC_EXPIREDWANTED 0x0020	/* Want lease when expired */
#define	LC_UDP		0x0040	/* Host address for udp socket */
#define	LC_CLTP		0x0080	/* Host address for other connectionless */
#define	LC_LOCAL	0x0100	/* Host is server */
#define	LC_VACATED	0x0200	/* Host has vacated lease */
#define	LC_WRITTEN	0x0400	/* Recently wrote to the leased file */
#define	LC_SREF		0x0800	/* Holds a nfssvc_sock reference */

struct nqm {
	struct nqm	*lpm_next;
	struct nqhost	lpm_hosts[LC_MOREHOSTSIZ];
};

/*
 * Special value for slp for local server calls.
 */
#define	NQLOCALSLP	((struct nfssvc_sock *) -1)

/*
 * Server side macros.
 */
#define	nqsrv_getl(v, l) \
		(void) nqsrv_getlease((v), &nfsd->nd_duration, \
		 ((nfsd->nd_flag & ND_LEASE) ? (nfsd->nd_flag & ND_LEASE) : \
		 ((l) | ND_CHECK)), \
		 slp, procp, nfsd->nd_nam, &cache, &frev, cred)

/*
 * Client side macros that check for a valid lease.
 */
#define	NQNFS_CKINVALID(v, n, f) \
 ((time.tv_sec > (n)->n_expiry && \
 VFSTONFS((v)->v_mount)->nm_timeouts < VFSTONFS((v)->v_mount)->nm_deadthresh) \
  || ((f) == ND_WRITE && ((n)->n_flag & NQNFSWRITE) == 0))

#define	NQNFS_CKCACHABLE(v, f) \
 ((time.tv_sec <= VTONFS(v)->n_expiry || \
  VFSTONFS((v)->v_mount)->nm_timeouts >= VFSTONFS((v)->v_mount)->nm_deadthresh) \
   && (VTONFS(v)->n_flag & NQNFSNONCACHE) == 0 && \
   ((f) == ND_READ || (VTONFS(v)->n_flag & NQNFSWRITE)))

#define	NQNFS_NEEDLEASE(v, p) \
		(time.tv_sec > VTONFS(v)->n_expiry ? \
		 ((VTONFS(v)->n_flag & NQNFSEVICTED) ? 0 : nqnfs_piggy[p]) : \
		 (((time.tv_sec + NQ_RENEWAL) > VTONFS(v)->n_expiry && \
		   nqnfs_piggy[p]) ? \
		   ((VTONFS(v)->n_flag & NQNFSWRITE) ? \
		    ND_WRITE : nqnfs_piggy[p]) : 0))

/*
 * List head for timer queue.
 */
extern CIRCLEQ_HEAD(nqtimerhead, nqlease) nqtimerhead;

/*
 * List head for the file handle hash table.
 */
#define	NQFHHASH(f) \
	(&nqfhhashtbl[(*((u_long *)(f))) & nqfhhash])
extern LIST_HEAD(nqfhhashhead, nqlease) *nqfhhashtbl;
extern u_long nqfhhash;

/*
 * Nqnfs return status numbers.
 */
#define	NQNFS_EXPIRED	500
#define	NQNFS_TRYLATER	501

#if defined(KERNEL)
void	nqnfs_lease_check __P((struct vnode *, struct proc *, struct ucred *, int));
void	nqnfs_lease_updatetime __P((int));
int	nqsrv_getlease __P((struct vnode *, u_long *, int,
			    struct nfssvc_sock *, struct proc *,
			    struct mbuf *, int *, u_quad_t *,
			    struct ucred *));
int	nqnfs_getlease __P((struct vnode *,int,struct ucred *,struct proc *));
int	nqnfs_callback __P((struct nfsmount *,struct mbuf *,struct mbuf *,caddr_t));
int	nqnfs_clientd __P((struct nfsmount *,struct ucred *,struct nfsd_cargs *,int,caddr_t,struct proc *));
struct nfsnode;
void	nqnfs_clientlease __P((struct nfsmount *, struct nfsnode *, int, int, time_t, u_quad_t));
void	nqnfs_serverd __P((void));
int	nqnfsrv_getlease __P((struct nfsrv_descript *, struct nfssvc_sock *, struct proc *, struct mbuf **));
int	nqnfsrv_vacated __P((struct nfsrv_descript *, struct nfssvc_sock *, struct proc *, struct mbuf **));
#endif

#endif
