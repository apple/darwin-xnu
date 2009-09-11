/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 * NFS mount file system attributes
 */
struct nfs_fsattr {
	uint32_t	nfsa_flags;		/* file system flags */
	uint32_t	nfsa_lease;		/* lease time in seconds */
	uint32_t	nfsa_maxname;		/* maximum filename size */
	uint32_t	nfsa_maxlink;		/* maximum # links */
	uint32_t	nfsa_bsize;		/* block size */
	uint32_t	nfsa_pad;		/* UNUSED */
	uint64_t	nfsa_maxfilesize;	/* maximum file size */
	uint64_t	nfsa_maxread;		/* maximum read size */
	uint64_t	nfsa_maxwrite;		/* maximum write size */
	uint64_t	nfsa_files_avail;	/* file slots available */
	uint64_t	nfsa_files_free;	/* file slots free */
	uint64_t	nfsa_files_total;	/* file slots total */
	uint64_t	nfsa_space_avail;	/* disk space available */
	uint64_t	nfsa_space_free;	/* disk space free */
	uint64_t	nfsa_space_total;	/* disk space total */
	uint32_t	nfsa_supp_attr[NFS_ATTR_BITMAP_LEN]; /* attributes supported on this file system */
	uint32_t	nfsa_bitmap[NFS_ATTR_BITMAP_LEN]; /* valid attributes */
};
#define NFS_FSFLAG_LINK			0x00000001
#define NFS_FSFLAG_SYMLINK		0x00000002
#define NFS_FSFLAG_UNIQUE_FH		0x00000004
#define NFS_FSFLAG_ACL			0x00000008
#define NFS_FSFLAG_SET_TIME		0x00000010
#define NFS_FSFLAG_CASE_INSENSITIVE	0x00000020
#define NFS_FSFLAG_CASE_PRESERVING	0x00000040
#define NFS_FSFLAG_CHOWN_RESTRICTED	0x00000080
#define NFS_FSFLAG_HOMOGENEOUS		0x00000100
#define NFS_FSFLAG_NO_TRUNC		0x00000200
#define NFS_FSFLAG_FHTYPE_MASK		0xFF000000
#define NFS_FSFLAG_FHTYPE_SHIFT		24

/*
 * function table for calling version-specific NFS functions
 */
struct nfs_funcs {
	int	(*nf_mount)(struct nfsmount *, vfs_context_t, struct user_nfs_args *, nfsnode_t *);
	int	(*nf_update_statfs)(struct nfsmount *, vfs_context_t);
	int	(*nf_getquota)(struct nfsmount *, vfs_context_t, uid_t, int, struct dqblk *);
	int	(*nf_access_rpc)(nfsnode_t, u_int32_t *, vfs_context_t);
	int	(*nf_getattr_rpc)(nfsnode_t, mount_t, u_char *, size_t, vfs_context_t, struct nfs_vattr *, u_int64_t *);
	int	(*nf_setattr_rpc)(nfsnode_t, struct vnode_attr *, vfs_context_t);
	int	(*nf_read_rpc_async)(nfsnode_t, off_t, size_t, thread_t, kauth_cred_t, struct nfsreq_cbinfo *, struct nfsreq **);
	int	(*nf_read_rpc_async_finish)(nfsnode_t, struct nfsreq *, uio_t, size_t *, int *);
	int	(*nf_readlink_rpc)(nfsnode_t, char *, uint32_t *, vfs_context_t);
	int	(*nf_write_rpc_async)(nfsnode_t, uio_t, size_t, thread_t, kauth_cred_t, int, struct nfsreq_cbinfo *, struct nfsreq **);
	int	(*nf_write_rpc_async_finish)(nfsnode_t, struct nfsreq *, int *, size_t *, uint64_t *);
	int	(*nf_commit_rpc)(nfsnode_t, uint64_t, uint64_t, kauth_cred_t);
	int	(*nf_lookup_rpc_async)(nfsnode_t, char *, int, vfs_context_t, struct nfsreq **);
	int	(*nf_lookup_rpc_async_finish)(nfsnode_t, vfs_context_t, struct nfsreq *, u_int64_t *, fhandle_t *, struct nfs_vattr *);
	int	(*nf_remove_rpc)(nfsnode_t, char *, int, thread_t, kauth_cred_t);
	int	(*nf_rename_rpc)(nfsnode_t, char *, int, nfsnode_t, char *, int, vfs_context_t);
};

/*
 * The long form of the NFSv4 client ID.
 */
struct nfs_client_id {
	TAILQ_ENTRY(nfs_client_id)	nci_link;	/* list of client IDs */
	char				*nci_id;	/* client id buffer */
	int				nci_idlen;	/* length of client id buffer */
};
TAILQ_HEAD(nfsclientidlist, nfs_client_id);
__private_extern__ struct nfsclientidlist nfsclientids;

/*
 * Mount structure.
 * One allocated on every NFS mount.
 * Holds NFS specific information for mount.
 */
struct nfsmount {
	lck_mtx_t nm_lock;		/* nfs mount lock */
	int	nm_flag;		/* Flags for soft/hard... */
	int	nm_state;		/* Internal state flags */
	int	nm_vers;		/* NFS version */
	struct nfs_funcs *nm_funcs;	/* version-specific functions */
	mount_t	nm_mountp;		/* VFS structure for this filesystem */
	nfsnode_t nm_dnp;		/* root directory nfsnode pointer */
	int	nm_numgrps;		/* Max. size of groupslist */
	TAILQ_HEAD(, nfs_gss_clnt_ctx) nm_gsscl; /* GSS user contexts */
	int	nm_timeo;		/* Init timer for NFSMNT_DUMBTIMR */
	int	nm_retry;		/* Max retries */
	uint32_t nm_rsize;		/* Max size of read rpc */
	uint32_t nm_wsize;		/* Max size of write rpc */
	uint32_t nm_biosize;		/* buffer I/O size */
	uint32_t nm_readdirsize;	/* Size of a readdir rpc */
	int	nm_readahead;		/* Num. of blocks to readahead */
	int	nm_acregmin;		/* reg file min attr cache timeout */
	int	nm_acregmax;		/* reg file max attr cache timeout */
	int	nm_acdirmin;		/* dir min attr cache timeout */
	int	nm_acdirmax;		/* dir max attr cache timeout */
	uint32_t nm_auth;		/* security mechanism flavor */
	/* mount info */
	uint32_t nm_fsattrstamp;	/* timestamp for fs attrs */
	struct nfs_fsattr nm_fsattr;	/* file system attributes */
	uint64_t nm_verf;		/* v3/v4 write verifier */
	union {
	    struct {			/* v2/v3 specific fields */
		u_short rqport;		/* cached rquota port */
		uint32_t rqportstamp;	/* timestamp of rquota port */
	    } v3;
	    struct {			/* v4 specific fields */
		struct nfs_client_id *longid; /* client ID, long form */
		uint64_t mounttime;	/* used as client ID verifier */
		uint64_t clientid;	/* client ID, short form */
		thread_call_t renew_timer; /* RENEW timer call */
		TAILQ_HEAD(, nfs_open_owner) open_owners; /* list of open owners */
		TAILQ_HEAD(, nfsnode) recallq; /* list of nodes with recalled delegations */
		TAILQ_ENTRY(nfsmount) cblink; /* chain of mounts registered for callbacks */
		uint32_t stateinuse;	/* state in use counter */
		uint32_t stategenid;	/* state generation counter */
		kauth_cred_t mcred;	/* credential used for the mount */
		uint32_t cbid;		/* callback channel identifier */
		uint32_t cbrefs;	/* # callbacks using this mount */
	    } v4;
	} nm_un;
	/* async I/O queue */
	struct nfs_reqqhead nm_resendq;	/* async I/O resend queue */
	struct nfs_reqqhead nm_iodq;	/* async I/O request queue */
	struct nfsiod *nm_niod;		/* nfsiod processing this mount */
	TAILQ_ENTRY(nfsmount) nm_iodlink; /* chain of mounts awaiting nfsiod */
	int	nm_asyncwrites;		/* outstanding async I/O writes */
	/* socket state */
	int	nm_sotype;		/* Type of socket */
	int	nm_soproto;		/* and protocol */
	mbuf_t	nm_nam;			/* Address of server */
	u_short nm_sockflags;		/* socket state flags */
	socket_t nm_so;			/* RPC socket */
	time_t	nm_deadto_start;	/* dead timeout start time */
	time_t	nm_reconnect_start;	/* reconnect start time */
	int	nm_tprintf_initial_delay;	/* delay first "server down" */
	int	nm_tprintf_delay;	/* delay between "server down" */
	int	nm_deadtimeout;		/* delay between first "server down" and dead */
	int	nm_srtt[4];		/* Timers for RPCs */
	int	nm_sdrtt[4];
	int	nm_timeouts;		/* Request timeouts */
	int	nm_jbreqs;		/* # R_JBTPRINTFMSG requests */
	union {
		struct {
			int sent;	/* Request send count */
			int cwnd;	/* Request congestion window */
			struct nfs_reqqhead cwndq; /* requests waiting on cwnd */
		} udp;
		struct {
			u_int32_t mleft;/* marker bytes remaining */
			u_int32_t fleft;/* fragment bytes remaining */
			u_int32_t len;	/* length of RPC record */
			mbuf_t m;	/* mbufs for current record */
			mbuf_t mlast;
		} tcp;
	} nm_sockstate;
	TAILQ_ENTRY(nfsmount) nm_pokeq;	/* mount poke queue chain */
	thread_t nm_sockthd;		/* socket thread for this mount */
};

/*
 * NFS mount state flags (nm_state)
 */
#define NFSSTA_BIGCOOKIES	0x00000800  /* have seen >32bit dir cookies */
#define NFSSTA_JUKEBOXTIMEO	0x00001000  /* experienced a jukebox timeout */
#define NFSSTA_LOCKTIMEO	0x00002000  /* experienced a lock req timeout */
#define NFSSTA_MOUNTED		0x00004000  /* completely mounted */
#define NFSSTA_LOCKSWORK	0x00008000  /* lock ops have worked. */
#define NFSSTA_TIMEO		0x00010000  /* experienced a timeout. */
#define NFSSTA_FORCE		0x00020000  /* doing a forced unmount. */
#define NFSSTA_HASWRITEVERF	0x00040000  /* Has write verifier for V3 */
#define NFSSTA_GOTPATHCONF	0x00080000  /* Got the V3 pathconf info */
#define NFSSTA_GOTFSINFO	0x00100000  /* Got the V3 fsinfo */
#define NFSSTA_SNDLOCK		0x01000000  /* Send socket lock */
#define NFSSTA_WANTSND		0x02000000  /* Want above */
#define NFSSTA_DEAD		0x04000000  /* mount is dead */
#define NFSSTA_RECOVER		0x08000000  /* mount state needs to be recovered */

/* flags for nm_sockflags */
#define NMSOCK_READY		0x0001	/* socket is ready for use */
#define NMSOCK_CONNECTING	0x0002	/* socket is being connect()ed */
#define NMSOCK_SETUP		0x0004	/* socket/connection is being set up */
#define NMSOCK_UNMOUNT		0x0008	/* unmounted, no more socket activity */
#define NMSOCK_LASTFRAG		0x0010	/* on last fragment of RPC record */
#define NMSOCK_POKE		0x0020	/* socket needs to be poked */
#define NMSOCK_UPCALL		0x0040	/* socket upcall in progress */

/* aliases for socket state variables */
#define nm_sent		nm_sockstate.udp.sent
#define nm_cwnd		nm_sockstate.udp.cwnd
#define nm_cwndq	nm_sockstate.udp.cwndq
#define nm_markerleft	nm_sockstate.tcp.mleft
#define nm_fragleft	nm_sockstate.tcp.fleft
#define nm_reclen	nm_sockstate.tcp.len
#define nm_m		nm_sockstate.tcp.m
#define nm_mlast	nm_sockstate.tcp.mlast

/* aliases for version-specific fields */
#define nm_rqport	nm_un.v3.rqport
#define nm_rqportstamp	nm_un.v3.rqportstamp
#define nm_longid	nm_un.v4.longid
#define nm_clientid	nm_un.v4.clientid
#define nm_mounttime	nm_un.v4.mounttime
#define nm_renew_timer	nm_un.v4.renew_timer
#define nm_open_owners	nm_un.v4.open_owners
#define nm_stateinuse	nm_un.v4.stateinuse
#define nm_stategenid	nm_un.v4.stategenid
#define nm_mcred	nm_un.v4.mcred
#define nm_cbid		nm_un.v4.cbid
#define nm_cblink	nm_un.v4.cblink
#define nm_cbrefs	nm_un.v4.cbrefs
#define nm_recallq	nm_un.v4.recallq

#if defined(KERNEL)
/*
 * Macros to convert from various things to mount structures.
 */
#define VFSTONFS(mp)	((mp) ? ((struct nfsmount *)vfs_fsprivate(mp)) : NULL)
#define VTONMP(vp)	VFSTONFS(vnode_mount(vp))
#define NFSTONMP(np)	VTONMP(NFSTOV(np))
#define NFSTOMP(np)	(vnode_mount(NFSTOV(np)))

#endif /* KERNEL */

#endif /* __APPLE_API_PRIVATE */
#endif /* _NFS_NFSMOUNT_H_ */
