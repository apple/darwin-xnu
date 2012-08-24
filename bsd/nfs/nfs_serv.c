/*
 * Copyright (c) 2000-2011 Apple Inc.  All rights reserved.
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
 *	@(#)nfs_serv.c	8.7 (Berkeley) 5/14/95
 * FreeBSD-Id: nfs_serv.c,v 1.52 1997/10/28 15:59:05 bde Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/unistd.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/mount_internal.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kpi_mbuf.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/kernel.h>
#include <sys/ubc.h>
#include <sys/vnode_internal.h>
#include <sys/uio_internal.h>
#include <libkern/OSAtomic.h>
#include <sys/fsevents.h>
#include <kern/thread_call.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#include <netinet/in.h>

#include <nfs/nfsproto.h>
#include <nfs/rpcv2.h>
#include <nfs/nfs.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsrvcache.h>
#include <nfs/nfs_gss.h>

#if NFSSERVER

/*
 * NFS server globals
 */

int nfsd_thread_count = 0;
int nfsd_thread_max = 0;
lck_grp_t *nfsd_lck_grp;
lck_mtx_t *nfsd_mutex;
struct nfsd_head nfsd_head, nfsd_queue;

lck_grp_t *nfsrv_slp_rwlock_group;
lck_grp_t *nfsrv_slp_mutex_group;
struct nfsrv_sockhead nfsrv_socklist, nfsrv_deadsocklist, nfsrv_sockwg,
			nfsrv_sockwait, nfsrv_sockwork;
struct nfsrv_sock *nfsrv_udpsock = NULL;
struct nfsrv_sock *nfsrv_udp6sock = NULL;

/* NFS exports */
struct nfsrv_expfs_list nfsrv_exports;
struct nfsrv_export_hashhead *nfsrv_export_hashtbl = NULL;
int nfsrv_export_hash_size = NFSRVEXPHASHSZ;
u_long nfsrv_export_hash;
lck_grp_t *nfsrv_export_rwlock_group;
lck_rw_t nfsrv_export_rwlock;

#if CONFIG_FSE
/* NFS server file modification event generator */
struct nfsrv_fmod_hashhead *nfsrv_fmod_hashtbl;
u_long nfsrv_fmod_hash;
lck_grp_t *nfsrv_fmod_grp;
lck_mtx_t *nfsrv_fmod_mutex;
static int nfsrv_fmod_timer_on = 0;
int nfsrv_fsevents_enabled = 1;
#endif

/* NFS server timers */
#if CONFIG_FSE
thread_call_t	nfsrv_fmod_timer_call;
#endif
thread_call_t	nfsrv_deadsock_timer_call;
thread_call_t	nfsrv_wg_timer_call;
int nfsrv_wg_timer_on;

/* globals for the active user list */
uint32_t nfsrv_user_stat_enabled = 1;
uint32_t nfsrv_user_stat_node_count = 0;
uint32_t nfsrv_user_stat_max_idle_sec = NFSRV_USER_STAT_DEF_IDLE_SEC;
uint32_t nfsrv_user_stat_max_nodes = NFSRV_USER_STAT_DEF_MAX_NODES;
lck_grp_t *nfsrv_active_user_mutex_group;

int nfsrv_wg_delay = NFSRV_WGATHERDELAY * 1000;
int nfsrv_wg_delay_v3 = 0;

int nfsrv_async = 0;

int nfsrv_authorize(vnode_t,vnode_t,kauth_action_t,vfs_context_t,struct nfs_export_options*,int);
int nfsrv_wg_coalesce(struct nfsrv_descript *, struct nfsrv_descript *);
void nfsrv_modified(vnode_t, vfs_context_t);

extern void IOSleep(int);
extern int safe_getpath(struct vnode *dvp, char *leafname, char *path, int _len, int *truncated_path);

/*
 * Initialize the data structures for the server.
 */

#define NFSRV_NOT_INITIALIZED	0
#define NFSRV_INITIALIZING	1
#define NFSRV_INITIALIZED	2
static volatile UInt32 nfsrv_initted = NFSRV_NOT_INITIALIZED;

int
nfsrv_is_initialized(void)
{
	return (nfsrv_initted == NFSRV_INITIALIZED);
}

void
nfsrv_init(void)
{
	/* make sure we init only once */
	if (!OSCompareAndSwap(NFSRV_NOT_INITIALIZED, NFSRV_INITIALIZING, &nfsrv_initted)) {
		/* wait until initialization is complete */
		while (!nfsrv_is_initialized())
			IOSleep(500);
		return;
	}

	if (sizeof (struct nfsrv_sock) > NFS_SVCALLOC)
		printf("struct nfsrv_sock bloated (> %dbytes)\n",NFS_SVCALLOC);

	/* init nfsd mutex */
	nfsd_lck_grp = lck_grp_alloc_init("nfsd", LCK_GRP_ATTR_NULL);
	nfsd_mutex = lck_mtx_alloc_init(nfsd_lck_grp, LCK_ATTR_NULL);

	/* init slp rwlock */
	nfsrv_slp_rwlock_group = lck_grp_alloc_init("nfsrv-slp-rwlock", LCK_GRP_ATTR_NULL);
	nfsrv_slp_mutex_group  = lck_grp_alloc_init("nfsrv-slp-mutex", LCK_GRP_ATTR_NULL);

	/* init export data structures */
	LIST_INIT(&nfsrv_exports);
	nfsrv_export_rwlock_group = lck_grp_alloc_init("nfsrv-export-rwlock", LCK_GRP_ATTR_NULL);
	lck_rw_init(&nfsrv_export_rwlock, nfsrv_export_rwlock_group, LCK_ATTR_NULL);

	/* init active user list mutex structures */
	nfsrv_active_user_mutex_group = lck_grp_alloc_init("nfs-active-user-mutex", LCK_GRP_ATTR_NULL);

	/* init nfs server request cache mutex */
	nfsrv_reqcache_lck_grp = lck_grp_alloc_init("nfsrv_reqcache", LCK_GRP_ATTR_NULL);
	nfsrv_reqcache_mutex = lck_mtx_alloc_init(nfsrv_reqcache_lck_grp, LCK_ATTR_NULL);

#if CONFIG_FSE
	/* init NFS server file modified event generation */
	nfsrv_fmod_hashtbl = hashinit(NFSRVFMODHASHSZ, M_TEMP, &nfsrv_fmod_hash);
	nfsrv_fmod_grp = lck_grp_alloc_init("nfsrv_fmod", LCK_GRP_ATTR_NULL);
	nfsrv_fmod_mutex = lck_mtx_alloc_init(nfsrv_fmod_grp, LCK_ATTR_NULL);
#endif

	/* initialize NFS server timer callouts */
#if CONFIG_FSE
	nfsrv_fmod_timer_call = thread_call_allocate(nfsrv_fmod_timer, NULL);
#endif
	nfsrv_deadsock_timer_call = thread_call_allocate(nfsrv_deadsock_timer, NULL);
	nfsrv_wg_timer_call = thread_call_allocate(nfsrv_wg_timer, NULL);

	/* Init server data structures */
	TAILQ_INIT(&nfsrv_socklist);
	TAILQ_INIT(&nfsrv_sockwait);
	TAILQ_INIT(&nfsrv_sockwork);
	TAILQ_INIT(&nfsrv_deadsocklist);
	TAILQ_INIT(&nfsrv_sockwg);
	TAILQ_INIT(&nfsd_head);
	TAILQ_INIT(&nfsd_queue);
	nfsrv_udpsock = NULL;
	nfsrv_udp6sock = NULL;

	/* Setup the up-call handling */
	nfsrv_uc_init();
	
	/* initialization complete */
	nfsrv_initted = NFSRV_INITIALIZED;
}


/*
 *
 * NFS version 2 and 3 server request processing functions
 *
 * These functions take the following parameters:
 *
 *      struct nfsrv_descript *nd - the NFS request descriptor
 *      struct nfsrv_sock *slp    - the NFS socket the request came in on
 *      vfs_context_t ctx         - VFS context
 *      mbuf_t *mrepp             - pointer to hold the reply mbuf list
 *
 * These routines generally have 3 phases:
 *
 *   1 - break down and validate the RPC request in the mbuf chain
 *       provided in nd->nd_nmreq.
 *   2 - perform the vnode operations for the request
 *       (many are very similar to syscalls in vfs_syscalls.c and
 *       should therefore be kept in sync with those implementations)
 *   3 - build the RPC reply in an mbuf chain (nmrep) and return the mbuf chain
 *
 */

/*
 * nfs v3 access service
 */
int
nfsrv_access(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct nfsm_chain *nmreq, nmrep;
	vnode_t vp;
	int error, attrerr;
	struct vnode_attr vattr;
	struct nfs_filehandle nfh;
	u_int32_t nfsmode;
	kauth_action_t testaction;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;

	error = 0;
	attrerr = ENOENT;
	nfsmode = 0;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	*mrepp = NULL;
	vp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, NFS_VER3, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, nfsmode);
	nfsmerr_if(error);
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	/*
	 * Each NFS mode bit is tested separately.
	 *
	 * XXX this code is nominally correct, but returns a pessimistic
	 *     rather than optimistic result.  It will be necessary to add
	 *     an NFS-specific interface to the vnode_authorize code to
	 *     obtain good performance in the optimistic mode.
	 */
	if (nfsmode & NFS_ACCESS_READ) {
		testaction = vnode_isdir(vp) ? KAUTH_VNODE_LIST_DIRECTORY : KAUTH_VNODE_READ_DATA;
		if (nfsrv_authorize(vp, NULL, testaction, ctx, nxo, 0))
			nfsmode &= ~NFS_ACCESS_READ;
	}
	if ((nfsmode & NFS_ACCESS_LOOKUP) &&
	    (!vnode_isdir(vp) ||
	    nfsrv_authorize(vp, NULL, KAUTH_VNODE_SEARCH, ctx, nxo, 0)))
		nfsmode &= ~NFS_ACCESS_LOOKUP;
	if (nfsmode & NFS_ACCESS_MODIFY) {
		if (vnode_isdir(vp)) {
			testaction =
			    KAUTH_VNODE_ADD_FILE |
			    KAUTH_VNODE_ADD_SUBDIRECTORY |
			    KAUTH_VNODE_DELETE_CHILD;
		} else {
			testaction =
			    KAUTH_VNODE_WRITE_DATA;
		}
		if (nfsrv_authorize(vp, NULL, testaction, ctx, nxo, 0))
			nfsmode &= ~NFS_ACCESS_MODIFY;
	}
	if (nfsmode & NFS_ACCESS_EXTEND) {
		if (vnode_isdir(vp)) {
			testaction =
			    KAUTH_VNODE_ADD_FILE |
			    KAUTH_VNODE_ADD_SUBDIRECTORY;
		} else {
			testaction =
			    KAUTH_VNODE_WRITE_DATA |
			    KAUTH_VNODE_APPEND_DATA;
		}
		if (nfsrv_authorize(vp, NULL, testaction, ctx, nxo, 0))
			nfsmode &= ~NFS_ACCESS_EXTEND;
	}

	/*
	 * Note concerning NFS_ACCESS_DELETE:
	 * For hard links, the answer may be wrong if the vnode
	 * has multiple parents with different permissions.
	 * Also, some clients (e.g. MacOSX 10.3) may incorrectly
	 * interpret the missing/cleared DELETE bit.
	 * So we'll just leave the DELETE bit alone.  At worst,
	 * we're telling the client it might be able to do
	 * something it really can't.
	 */

	if ((nfsmode & NFS_ACCESS_EXECUTE) &&
	    (vnode_isdir(vp) ||
	    nfsrv_authorize(vp, NULL, KAUTH_VNODE_EXECUTE, ctx, nxo, 0)))
		nfsmode &= ~NFS_ACCESS_EXECUTE;

	/* get postop attributes */
	nfsm_srv_vattr_init(&vattr, NFS_VER3);
	attrerr = vnode_getattr(vp, &vattr, ctx);

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPATTR(NFS_VER3) + NFSX_UNSIGNED);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &vattr);
	if (!nd->nd_repstat)
		nfsm_chain_add_32(error, &nmrep, nfsmode);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (vp)
		vnode_put(vp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs getattr service
 */
int
nfsrv_getattr(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct nfsm_chain *nmreq, nmrep;
	struct vnode_attr vattr;
	vnode_t vp;
	int error;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;

	error = 0;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	*mrepp = NULL;
	vp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	nfsm_srv_vattr_init(&vattr, nd->nd_vers);
	error = vnode_getattr(vp, &vattr, ctx);
	vnode_put(vp);
	vp = NULL;

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_FATTR(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_if(nd->nd_repstat);
	error = nfsm_chain_add_fattr(nd, &nmrep, &vattr);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (vp)
		vnode_put(vp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs setattr service
 */
int
nfsrv_setattr(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct nfsm_chain *nmreq, nmrep;
	struct vnode_attr preattr, postattr;
	struct vnode_attr vattr, *vap = &vattr;
	vnode_t vp;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	int error, preattrerr, postattrerr, gcheck;
	struct nfs_filehandle nfh;
	struct timespec guard = { 0, 0 };
	kauth_action_t action;
	uid_t saved_uid;

	error = 0;
	preattrerr = postattrerr = ENOENT;
	gcheck = 0;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	*mrepp = NULL;
	vp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);

	VATTR_INIT(vap);
	error = nfsm_chain_get_sattr(nd, nmreq, vap);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_get_32(error, nmreq, gcheck);
		if (gcheck)
			nfsm_chain_get_time(error, nmreq, nd->nd_vers, guard.tv_sec, guard.tv_nsec);
	}
	nfsmerr_if(error);

	/*
	 * Save the original credential UID in case they are
	 * mapped and we need to map the IDs in the attributes.
	 */
	saved_uid = kauth_cred_getuid(nd->nd_cr);

	/*
	 * Now that we have all the fields, lets do it.
	 */
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	if (nd->nd_vers == NFS_VER3) {
		nfsm_srv_pre_vattr_init(&preattr);
		error = preattrerr = vnode_getattr(vp, &preattr, ctx);
		if (!error && gcheck && VATTR_IS_SUPPORTED(&preattr, va_change_time) &&
			(preattr.va_change_time.tv_sec != guard.tv_sec ||
			 preattr.va_change_time.tv_nsec != guard.tv_nsec))
			error = NFSERR_NOT_SYNC;
		if (!preattrerr && !VATTR_ALL_SUPPORTED(&preattr))
			preattrerr = ENOENT;
		nfsmerr_if(error);
	}

	/*
	 * If the credentials were mapped, we should
	 * map the same values in the attributes.
	 */
	if ((vap->va_uid == saved_uid) && (kauth_cred_getuid(nd->nd_cr) != saved_uid)) {
		int ismember;
		VATTR_SET(vap, va_uid, kauth_cred_getuid(nd->nd_cr));
		if (kauth_cred_ismember_gid(nd->nd_cr, vap->va_gid, &ismember) || !ismember)
			VATTR_SET(vap, va_gid, kauth_cred_getgid(nd->nd_cr));
	}

	/* Authorize the attribute changes.  */
	error = vnode_authattr(vp, vap, &action, ctx);
	if (!error)
		error = nfsrv_authorize(vp, NULL, action, ctx, nxo, 0);

	/* set the new attributes */
	if (!error)
		error = vnode_setattr(vp, vap, ctx);

	if (!error || (nd->nd_vers == NFS_VER3)) {
		nfsm_srv_vattr_init(&postattr, nd->nd_vers);
		postattrerr = vnode_getattr(vp, &postattr, ctx);
		if (!error)
			error = postattrerr;
	}

nfsmerr:
	if (vp)
		vnode_put(vp);

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_WCCORFATTR(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			preattrerr, &preattr, postattrerr, &postattr);
	else
		error = nfsm_chain_add_fattr(nd, &nmrep, &postattr);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs lookup rpc
 */
int
nfsrv_lookup(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct nameidata ni;
	vnode_t vp, dirp = NULL;
	struct nfs_filehandle dnfh, nfh;
	struct nfs_export *nx = NULL;
	struct nfs_export_options *nxo;
	int error, attrerr, dirattrerr, isdotdot;
	uint32_t len = 0;
	uid_t saved_uid;
	struct vnode_attr va, dirattr, *vap = &va;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	attrerr = dirattrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	saved_uid = kauth_cred_getuid(nd->nd_cr);

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, dnfh.nfh_fhp, dnfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);

	ni.ni_cnd.cn_nameiop = LOOKUP;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_LOOKUP;
#endif
	ni.ni_cnd.cn_flags = LOCKLEAF;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	isdotdot = ((len == 2) && (ni.ni_cnd.cn_pnbuf[0] == '.') && (ni.ni_cnd.cn_pnbuf[1] == '.'));
	if (!error) {
		error = nfsrv_namei(nd, ctx, &ni, &dnfh, &dirp, &nx, &nxo);
		if (nx != NULL) {
			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);
		}
	}

	if (dirp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_vattr_init(&dirattr, NFS_VER3);
			dirattrerr = vnode_getattr(dirp, &dirattr, ctx);
		}
		vnode_put(dirp);
	}
	nfsmerr_if(error);

	nameidone(&ni);

	vp = ni.ni_vp;
	error = nfsrv_vptofh(nx, nd->nd_vers, (isdotdot ? &dnfh : NULL), vp, ctx, &nfh);
	if (!error) {
		nfsm_srv_vattr_init(vap, nd->nd_vers);
		attrerr = vnode_getattr(vp, vap, ctx);
	}
	vnode_put(vp);

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_SRVFH(nd->nd_vers, &nfh) +
			NFSX_POSTOPORFATTR(nd->nd_vers) + NFSX_POSTOPATTR(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	if (nd->nd_repstat) {
		if (nd->nd_vers == NFS_VER3)
			nfsm_chain_add_postop_attr(error, nd, &nmrep, dirattrerr, &dirattr);
		goto nfsmout;
	}
	nfsm_chain_add_fh(error, &nmrep, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, vap);
		nfsm_chain_add_postop_attr(error, nd, &nmrep, dirattrerr, &dirattr);
	} else if (!error) {
		error = nfsm_chain_add_fattr(nd, &nmrep, vap);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs readlink service
 */
int
nfsrv_readlink(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	int error, mpcnt, tlen, len, attrerr;
	vnode_t vp;
	struct vnode_attr vattr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct nfsm_chain *nmreq, nmrep;
	mbuf_t mpath, mp;
	uio_t auio = NULL;
	char uio_buf[ UIO_SIZEOF(4) ];
	char *uio_bufp = &uio_buf[0];
	int uio_buflen = UIO_SIZEOF(4);

	error = 0;
	attrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	mpath = NULL;
	vp = NULL;
	len = NFS_MAXPATHLEN;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);

	/* get mbuf list to hold symlink path */
	error = nfsm_mbuf_get_list(len, &mpath, &mpcnt);
	nfsmerr_if(error);
	if (mpcnt > 4) {
		uio_buflen = UIO_SIZEOF(mpcnt);
		MALLOC(uio_bufp, char*, uio_buflen, M_TEMP, M_WAITOK);
		if (!uio_bufp)
			error = ENOMEM;
		nfsmerr_if(error);
	}
	auio = uio_createwithbuffer(mpcnt, 0, UIO_SYSSPACE, UIO_READ, uio_bufp, uio_buflen);
	if (!auio)
		error = ENOMEM;
	nfsmerr_if(error);

	for (mp = mpath; mp; mp = mbuf_next(mp))
		uio_addiov(auio, CAST_USER_ADDR_T((caddr_t)mbuf_data(mp)), mbuf_len(mp));

	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	if (vnode_vtype(vp) != VLNK) {
		if (nd->nd_vers == NFS_VER3)
			error = EINVAL;
		else
			error = ENXIO;
	}

	if (!error)
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, ctx, nxo, 0);
	if (!error)
		error = VNOP_READLINK(vp, auio, ctx);
	if (vp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_vattr_init(&vattr, NFS_VER3);
			attrerr = vnode_getattr(vp, &vattr, ctx);
		}
		vnode_put(vp);
		vp = NULL;
	}
	if (error) {
		mbuf_freem(mpath);
		mpath = NULL;
	}

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPATTR(nd->nd_vers) + NFSX_UNSIGNED);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &vattr);
	if (error || nd->nd_repstat) {
		nfsm_chain_build_done(error, &nmrep);
		goto nfsmout;
	}
	if (auio && (uio_resid(auio) > 0)) {
		len -= uio_resid(auio);
		tlen = nfsm_rndup(len);
		nfsm_adj(mpath, NFS_MAXPATHLEN-tlen, tlen-len);
	}
	nfsm_chain_add_32(error, &nmrep, len);
	nfsm_chain_build_done(error, &nmrep);
	nfsmout_if(error);
	error = mbuf_setnext(nmrep.nmc_mcur, mpath);
	if (!error)
		mpath = NULL;
nfsmout:
	if (vp)
		vnode_put(vp);
	if (mpath)
		mbuf_freem(mpath);
	if (uio_bufp != &uio_buf[0])
		FREE(uio_bufp, M_TEMP);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs read service
 */
int
nfsrv_read(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	int error, attrerr, mreadcnt;
	uint32_t reqlen, maxlen, count, len, tlen, left;
	mbuf_t mread, m;
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t auio = NULL;
	char *uio_bufp = NULL;
	struct vnode_attr vattr, *vap = &vattr;
	off_t off;
	uid_t saved_uid;
	char uio_buf[ UIO_SIZEOF(0) ];
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	attrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	mread = NULL;
	vp = NULL;
	len = reqlen = 0;
	saved_uid = kauth_cred_getuid(nd->nd_cr);

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_get_64(error, nmreq, off);
	else
		nfsm_chain_get_32(error, nmreq, off);
	nfsm_chain_get_32(error, nmreq, reqlen);
	maxlen = NFSRV_NDMAXDATA(nd);
	if (reqlen > maxlen)
		reqlen = maxlen;
	nfsmerr_if(error);
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	if (vnode_vtype(vp) != VREG) {
		if (nd->nd_vers == NFS_VER3)
			error = EINVAL;
		else
			error = (vnode_vtype(vp) == VDIR) ? EISDIR : EACCES;
	}

	if (!error) {
	    if ((error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, ctx, nxo, 1)))
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_EXECUTE, ctx, nxo, 1);
	}
	nfsm_srv_vattr_init(vap, nd->nd_vers);
	attrerr = vnode_getattr(vp, vap, ctx);
	if (!error)
		error = attrerr;
	nfsmerr_if(error);

	if ((u_quad_t)off >= vap->va_data_size)
		count = 0;
	else if (((u_quad_t)off + reqlen) > vap->va_data_size)
		count = nfsm_rndup(vap->va_data_size - off);
	else
		count = reqlen;

	len = left = count;
	if (count > 0) {
		/* get mbuf list to hold read data */
		error = nfsm_mbuf_get_list(count, &mread, &mreadcnt);
		nfsmerr_if(error);
		MALLOC(uio_bufp, char *, UIO_SIZEOF(mreadcnt), M_TEMP, M_WAITOK);
		if (uio_bufp)
			auio = uio_createwithbuffer(mreadcnt, off, UIO_SYSSPACE,
					UIO_READ, uio_bufp, UIO_SIZEOF(mreadcnt));
		if (!uio_bufp || !auio) {
			error = ENOMEM;
			goto errorexit;
		}
		for (m = mread; m; m = mbuf_next(m))
			uio_addiov(auio, CAST_USER_ADDR_T((caddr_t)mbuf_data(m)), mbuf_len(m));
		error = VNOP_READ(vp, auio, IO_NODELOCKED, ctx);
	} else {
		auio = uio_createwithbuffer(0, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
		if (!auio) {
			error = ENOMEM;
			goto errorexit;
		}
	}

errorexit:
	if (!error || (nd->nd_vers == NFS_VER3)) {
		nfsm_srv_vattr_init(vap, nd->nd_vers);
		attrerr = vnode_getattr(vp, vap, ctx);
		if (!error && (nd->nd_vers == NFS_VER2))
			error = attrerr; /* NFSv2 must have attributes to return */
	}
	nfsmerr_if(error);

	vnode_put(vp);
	vp = NULL;

	/* trim off any data not actually read */
	len -= uio_resid(auio);
	tlen = nfsm_rndup(len);
	if (count != tlen || tlen != len)
		nfsm_adj(mread, count - tlen, tlen - len);

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPORFATTR(nd->nd_vers) + 3 * NFSX_UNSIGNED);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, vap);
	if (error || nd->nd_repstat) {
		nfsm_chain_build_done(error, &nmrep);
		goto nfsmout;
	}
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_32(error, &nmrep, len);
		nfsm_chain_add_32(error, &nmrep, (len < reqlen) ? TRUE : FALSE);
	} else {
		error = nfsm_chain_add_fattr(nd, &nmrep, vap);
	}
	nfsm_chain_add_32(error, &nmrep, len);
	nfsm_chain_build_done(error, &nmrep);
	nfsmout_if(error);
	error = mbuf_setnext(nmrep.nmc_mcur, mread);
	if (!error)
		mread = NULL;

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.bytes_read, len);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, saved_uid, 1, len, 0);
nfsmout:
	if (vp)
		vnode_put(vp);
	if (mread)
		mbuf_freem(mread);
	if (uio_bufp != NULL)
		FREE(uio_bufp, M_TEMP);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

#if CONFIG_FSE
/*
 * NFS File modification reporting
 *
 * When the contents of a file are changed, a "content modified"
 * fsevent needs to be issued.  Normally this would be done at
 * file close time.  This is difficult for NFS because the protocol
 * has no "close" operation.  The client sends a stream of write
 * requests that just stop.  So we keep a hash table full of
 * vnodes that have been written to recently, and issue a
 * "content modified" fsevent only if there are no writes to
 * a vnode for nfsrv_fmod_pendtime milliseconds.
 */
int nfsrv_fmod_pending;		/* count of vnodes being written to */
int nfsrv_fmod_pendtime = 1000;	/* msec to wait */
int nfsrv_fmod_min_interval = 100;	/* msec min interval between callbacks */

/*
 * This function is called via the kernel's callout
 * mechanism.  Calls are made only when there are
 * vnodes pending a fsevent creation, and no more
 * frequently than every nfsrv_fmod_min_interval ms.
 */
void
nfsrv_fmod_timer(__unused void *param0, __unused void *param1)
{
	struct nfsrv_fmod_hashhead *headp, firehead;
	struct nfsrv_fmod *fp, *nfp, *pfp;
	uint64_t timenow, next_deadline;
	int interval = 0, i, fmod_fire;

	LIST_INIT(&firehead);
	lck_mtx_lock(nfsrv_fmod_mutex);
again:
	clock_get_uptime(&timenow);
	clock_interval_to_deadline(nfsrv_fmod_pendtime, 1000 * 1000,
		&next_deadline);

	/*
	 * Scan all the hash chains
	 */
	fmod_fire = 0;
	for (i = 0; i < NFSRVFMODHASHSZ; i++) {
		/*
		 * For each hash chain, look for an entry
		 * that has exceeded the deadline.
		 */
		headp = &nfsrv_fmod_hashtbl[i];
		LIST_FOREACH(fp, headp, fm_link) {
			if (timenow >= fp->fm_deadline)
				break;
			if (fp->fm_deadline < next_deadline)
				next_deadline = fp->fm_deadline;
		}

		/*
		 * If we have an entry that's exceeded the
		 * deadline, then the same is true for all
		 * following entries in the chain, since they're
		 * sorted in time order.
		 */
		pfp = NULL;
		while (fp) {
			/* move each entry to the fire list */
			nfp = LIST_NEXT(fp, fm_link);
			LIST_REMOVE(fp, fm_link);
			fmod_fire++;
			if (pfp)
				LIST_INSERT_AFTER(pfp, fp, fm_link);
			else
				LIST_INSERT_HEAD(&firehead, fp, fm_link);
			pfp = fp;
			fp = nfp;
		}
	}

	if (fmod_fire) {
		lck_mtx_unlock(nfsrv_fmod_mutex);
		/*
		 * Fire off the content modified fsevent for each
		 * entry and free it.
		 */
		LIST_FOREACH_SAFE(fp, &firehead, fm_link, nfp) {
			if (nfsrv_fsevents_enabled) {
				fp->fm_context.vc_thread = current_thread();
				add_fsevent(FSE_CONTENT_MODIFIED, &fp->fm_context,
					FSE_ARG_VNODE, fp->fm_vp,
					FSE_ARG_DONE);
			}
			vnode_put(fp->fm_vp);
			kauth_cred_unref(&fp->fm_context.vc_ucred);
			LIST_REMOVE(fp, fm_link);
			FREE(fp, M_TEMP);
		}
		lck_mtx_lock(nfsrv_fmod_mutex);
		nfsrv_fmod_pending -= fmod_fire;
		goto again;
	}

	/*
	 * If there are still pending entries, set up another
	 * callout to handle them later. Set the timeout deadline
	 * so that the callout happens when the oldest pending
	 * entry is ready to send its fsevent.
	 */
	if (nfsrv_fmod_pending > 0) {
		interval = (next_deadline - timenow) / (1000 * 1000);
		if (interval < nfsrv_fmod_min_interval)
			interval = nfsrv_fmod_min_interval;
	}

	nfsrv_fmod_timer_on = interval > 0;
	if (nfsrv_fmod_timer_on)
		nfs_interval_timer_start(nfsrv_fmod_timer_call, interval);

	lck_mtx_unlock(nfsrv_fmod_mutex);
}

/*
 * When a vnode has been written to, enter it in the hash
 * table of vnodes pending creation of an fsevent. If the
 * callout timer isn't already running, schedule a callback
 * for nfsrv_fmod_pendtime msec from now.
 */
void
nfsrv_modified(vnode_t vp, vfs_context_t ctx)
{
	uint64_t deadline;
	struct nfsrv_fmod *fp;
	struct nfsrv_fmod_hashhead *head;

	lck_mtx_lock(nfsrv_fmod_mutex);

	/*
	 * Compute the time in the future when the
	 * content modified fsevent is to be issued.
	 */
	clock_interval_to_deadline(nfsrv_fmod_pendtime, 1000 * 1000, &deadline);

	/*
	 * Check if there's already a file content change fsevent
	 * pending for this vnode.  If there is, update its
	 * timestamp and make sure it's at the front of the hash chain.
	 */
	head = &nfsrv_fmod_hashtbl[NFSRVFMODHASH(vp)];
	LIST_FOREACH(fp, head, fm_link) {
		if (vp == fp->fm_vp) {
			fp->fm_deadline = deadline;
			if (fp != LIST_FIRST(head)) {
				LIST_REMOVE(fp, fm_link);
				LIST_INSERT_HEAD(head, fp, fm_link);
			}
			lck_mtx_unlock(nfsrv_fmod_mutex);
			return;
		}
	}

	/*
	 * First content change fsevent for this vnode.
	 * Allocate a new file mod entry and add it
	 * on the front of the hash chain.
	 */
	if (vnode_get(vp) != 0)
		goto done;
	MALLOC(fp, struct nfsrv_fmod *, sizeof(*fp), M_TEMP, M_WAITOK);
	if (fp == NULL) {
		vnode_put(vp);
		goto done;
	}
	fp->fm_vp = vp;
	kauth_cred_ref(vfs_context_ucred(ctx));
	fp->fm_context = *ctx;
	fp->fm_deadline = deadline;
	LIST_INSERT_HEAD(head, fp, fm_link);

	/*
	 * If added to an empty hash table, then set the
	 * callout timer to go off after nfsrv_fmod_pendtime.
	 */
	nfsrv_fmod_pending++;
	if (!nfsrv_fmod_timer_on) {
		nfsrv_fmod_timer_on = 1;
		nfs_interval_timer_start(nfsrv_fmod_timer_call,
			nfsrv_fmod_pendtime);
	}
done:
	lck_mtx_unlock(nfsrv_fmod_mutex);
	return;
}
#endif /* CONFIG_FSE */

/*
 * nfs write service
 */
int
nfsrv_write(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct vnode_attr preattr, postattr;
	int error, preattrerr, postattrerr;
	int ioflags, len, retlen;
	int mlen, mcount;
	int stable = NFS_WRITE_FILESYNC;
	mbuf_t m;
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t auio = NULL;
	char *uio_bufp = NULL;
	off_t off;
	uid_t saved_uid;
	struct nfsm_chain *nmreq, nmrep;

	if (nd->nd_nmreq.nmc_mhead == NULL) {
		*mrepp = NULL;
		return (0);
	}

	error = 0;
	preattrerr = postattrerr = ENOENT;
	saved_uid = kauth_cred_getuid(nd->nd_cr);
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	vp = NULL;
	len = retlen = 0;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_get_64(error, nmreq, off);
		nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
		nfsm_chain_get_32(error, nmreq, stable);
	} else {
		nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
		nfsm_chain_get_32(error, nmreq, off);
		nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
		if (nfsrv_async)
	    		stable = NFS_WRITE_UNSTABLE;
	}
	nfsm_chain_get_32(error, nmreq, len);
	nfsmerr_if(error);
	retlen = len;

	/*
	 * For NFS Version 2, it is not obvious what a write of zero length
	 * should do, but I might as well be consistent with Version 3,
	 * which is to return ok so long as there are no permission problems.
	 */

	if (len > 0) {
		error = nfsm_chain_trim_data(nmreq, len, &mlen);
		nfsmerr_if(error);
	} else {
		mlen = 0;
	}
	if ((len > NFSRV_MAXDATA) || (len < 0) || (mlen < len)) {
		error = EIO;
		goto nfsmerr;
	}
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	if (nd->nd_vers == NFS_VER3) {
		nfsm_srv_pre_vattr_init(&preattr);
		preattrerr = vnode_getattr(vp, &preattr, ctx);
	}
	if (vnode_vtype(vp) != VREG) {
		if (nd->nd_vers == NFS_VER3)
			error = EINVAL;
		else
			error = (vnode_vtype(vp) == VDIR) ? EISDIR : EACCES;
	}
	if (!error)
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA, ctx, nxo, 1);
	nfsmerr_if(error);

	if (len > 0) {
		for (mcount=0, m=nmreq->nmc_mcur; m; m = mbuf_next(m))
			if (mbuf_len(m) > 0)
				mcount++;
		MALLOC(uio_bufp, char *, UIO_SIZEOF(mcount), M_TEMP, M_WAITOK);
		if (uio_bufp)
			auio = uio_createwithbuffer(mcount, off, UIO_SYSSPACE, UIO_WRITE, uio_bufp, UIO_SIZEOF(mcount));
		if (!uio_bufp || !auio)
			error = ENOMEM;
		nfsmerr_if(error);
		for (m = nmreq->nmc_mcur; m; m = mbuf_next(m))
			if ((mlen = mbuf_len(m)) > 0)
				uio_addiov(auio, CAST_USER_ADDR_T((caddr_t)mbuf_data(m)), mlen);
		/*
		 * XXX The IO_METASYNC flag indicates that all metadata (and not just
		 * enough to ensure data integrity) mus be written to stable storage
		 * synchronously.  (IO_METASYNC is not yet implemented in 4.4BSD-Lite.)
		 */
		if (stable == NFS_WRITE_UNSTABLE)
			ioflags = IO_NODELOCKED;
		else if (stable == NFS_WRITE_DATASYNC)
			ioflags = (IO_SYNC | IO_NODELOCKED);
		else
			ioflags = (IO_METASYNC | IO_SYNC | IO_NODELOCKED);

		error = VNOP_WRITE(vp, auio, ioflags, ctx);
		OSAddAtomic64(1, &nfsstats.srvvop_writes);

		/* update export stats */
		NFSStatAdd64(&nx->nx_stats.bytes_written, len);

		/* update active user stats */
		nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, len);

#if CONFIG_FSE
		if (nfsrv_fsevents_enabled && !error && need_fsevent(FSE_CONTENT_MODIFIED, vp))
			nfsrv_modified(vp, ctx);
#endif
	}
	nfsm_srv_vattr_init(&postattr, nd->nd_vers);
	postattrerr = vnode_getattr(vp, &postattr, ctx);
	if (!error && (nd->nd_vers == NFS_VER2))
		error = postattrerr; /* NFSv2 must have attributes to return */
	vnode_put(vp);
	vp = NULL;

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_PREOPATTR(nd->nd_vers) +
			NFSX_POSTOPORFATTR(nd->nd_vers) + 2 * NFSX_UNSIGNED +
			NFSX_WRITEVERF(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			preattrerr, &preattr, postattrerr, &postattr);
		nfsmout_if(error || nd->nd_repstat);
		nfsm_chain_add_32(error, &nmrep, retlen);
		/* If nfsrv_async is set, then pretend the write was FILESYNC. */
		if ((stable == NFS_WRITE_UNSTABLE) && !nfsrv_async)
			nfsm_chain_add_32(error, &nmrep, stable);
		else
			nfsm_chain_add_32(error, &nmrep, NFS_WRITE_FILESYNC);
		/* write verifier */
		nfsm_chain_add_32(error, &nmrep, nx->nx_exptime.tv_sec);
		nfsm_chain_add_32(error, &nmrep, nx->nx_exptime.tv_usec);
	} else {
		error = nfsm_chain_add_fattr(nd, &nmrep, &postattr);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (vp)
		vnode_put(vp);
	if (uio_bufp != NULL)
		FREE(uio_bufp, M_TEMP);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * NFS write service with write gathering support. Called when
 * nfsrv_wg_delay > 0.
 * See: Chet Juszczak, "Improving the Write Performance of an NFS Server",
 * in Proc. of the Winter 1994 Usenix Conference, pg. 247-259, San Franscisco,
 * Jan. 1994.
 */

#define	NWDELAYHASH(sock, f) \
	(&(sock)->ns_wdelayhashtbl[(*((u_int32_t *)(f))) % NFS_WDELAYHASHSIZ])
/* These macros compare nfsrv_descript structures.  */
#define NFSW_CONTIG(o, n) \
		(((o)->nd_eoff >= (n)->nd_off) && nfsrv_fhmatch(&(o)->nd_fh, &(n)->nd_fh))
/*
 * XXX The following is an incorrect comparison; it fails to take into account
 * XXX scoping of MAC labels, but we currently lack KPI for credential
 * XXX comparisons.
 */
#define NFSW_SAMECRED(o, n) \
	(!bcmp((caddr_t)(o)->nd_cr, (caddr_t)(n)->nd_cr, \
		sizeof (struct ucred)))

int
nfsrv_writegather(
	struct nfsrv_descript **ndp,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct nfsrv_descript *nd, *wp, *owp, *swp;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct nfsrv_wg_delayhash *wpp;
	uid_t saved_uid;
	struct vnode_attr preattr, postattr;
	int error, mlen, i, ioflags, tlen;
	int preattrerr, postattrerr;
	vnode_t vp;
	mbuf_t m;
	uio_t auio = NULL;
	char *uio_bufp = NULL;
	u_quad_t cur_usec;
	struct timeval now;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	preattrerr = postattrerr = ENOENT;
	nfsm_chain_null(&nmrep);
	vp = NULL;

	*mrepp = NULL;
	if (*ndp) {
	    nd = *ndp;
	    *ndp = NULL;
	    nmreq = &nd->nd_nmreq;
	    LIST_INIT(&nd->nd_coalesce);
	    nd->nd_mrep = NULL;
	    nd->nd_stable = NFS_WRITE_FILESYNC;
	    microuptime(&now);
	    cur_usec = (u_quad_t)now.tv_sec * 1000000 + (u_quad_t)now.tv_usec;
	    nd->nd_time = cur_usec +
		((nd->nd_vers == NFS_VER3) ? nfsrv_wg_delay_v3 : nfsrv_wg_delay);

	    /* Now, get the write header... */
	    nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nd->nd_fh.nfh_fhp, nd->nd_fh.nfh_len);
	    /* XXX shouldn't we be checking for invalid FHs before doing any more work? */
	    nfsmerr_if(error);
	    if (nd->nd_vers == NFS_VER3) {
		    nfsm_chain_get_64(error, nmreq, nd->nd_off);
		    nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
		    nfsm_chain_get_32(error, nmreq, nd->nd_stable);
	    } else {
		    nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
		    nfsm_chain_get_32(error, nmreq, nd->nd_off);
		    nfsm_chain_adv(error, nmreq, NFSX_UNSIGNED);
		    if (nfsrv_async)
			    nd->nd_stable = NFS_WRITE_UNSTABLE;
	    }
	    nfsm_chain_get_32(error, nmreq, nd->nd_len);
	    nfsmerr_if(error);
	    nd->nd_eoff = nd->nd_off + nd->nd_len;

	    if (nd->nd_len > 0) {
		    error = nfsm_chain_trim_data(nmreq, nd->nd_len, &mlen);
		    nfsmerr_if(error);
	    } else {
		mlen = 0;
	    }

	    if ((nd->nd_len > NFSRV_MAXDATA) || (nd->nd_len < 0)  || (mlen < nd->nd_len)) {
		error = EIO;
nfsmerr:
		nd->nd_repstat = error;
		error = nfsrv_rephead(nd, slp, &nmrep, NFSX_WCCDATA(nd->nd_vers));
		if (!error) {
		    nd->nd_mrep = nmrep.nmc_mhead;
		    if (nd->nd_vers == NFS_VER3)
			nfsm_chain_add_wcc_data(error, nd, &nmrep,
				preattrerr, &preattr, postattrerr, &postattr);
		}
		nfsm_chain_build_done(error, &nmrep);
		nd->nd_time = 1;
	    }

	    /*
	     * Add this entry to the hash and time queues.
	     */
	    lck_mtx_lock(&slp->ns_wgmutex);
	    owp = NULL;
	    wp = slp->ns_tq.lh_first;
	    while (wp && wp->nd_time < nd->nd_time) {
		owp = wp;
		wp = wp->nd_tq.le_next;
	    }
	    if (owp) {
		LIST_INSERT_AFTER(owp, nd, nd_tq);
	    } else {
		LIST_INSERT_HEAD(&slp->ns_tq, nd, nd_tq);
	    }
	    if (!error) {
		wpp = NWDELAYHASH(slp, nd->nd_fh.nfh_fid);
		owp = NULL;
		wp = wpp->lh_first;
		while (wp && !nfsrv_fhmatch(&nd->nd_fh, &wp->nd_fh)) {
		    owp = wp;
		    wp = wp->nd_hash.le_next;
		}
		while (wp && (wp->nd_off < nd->nd_off) &&
		    nfsrv_fhmatch(&nd->nd_fh, &wp->nd_fh)) {
		    owp = wp;
		    wp = wp->nd_hash.le_next;
		}
		if (owp) {
		    LIST_INSERT_AFTER(owp, nd, nd_hash);
		    /*
		     * Search the hash list for overlapping entries and
		     * coalesce.
		     */
		    for(; nd && NFSW_CONTIG(owp, nd); nd = wp) {
			wp = nd->nd_hash.le_next;
			if (NFSW_SAMECRED(owp, nd))
			    nfsrv_wg_coalesce(owp, nd);
		    }
		} else {
		    LIST_INSERT_HEAD(wpp, nd, nd_hash);
		}
	    }
	} else {
	    lck_mtx_lock(&slp->ns_wgmutex);
	}

	/*
	 * Now, do VNOP_WRITE()s for any one(s) that need to be done now
	 * and generate the associated reply mbuf list(s).
	 */
loop1:
	microuptime(&now);
	cur_usec = (u_quad_t)now.tv_sec * 1000000 + (u_quad_t)now.tv_usec;
	for (nd = slp->ns_tq.lh_first; nd; nd = owp) {
		owp = nd->nd_tq.le_next;
		if (nd->nd_time > cur_usec)
		    break;
		if (nd->nd_mrep)
		    continue;
		LIST_REMOVE(nd, nd_tq);
		LIST_REMOVE(nd, nd_hash);
		nmreq = &nd->nd_nmreq;
		preattrerr = postattrerr = ENOENT;

		/* save the incoming uid before mapping, */	
		/* for updating active user stats later */
		saved_uid = kauth_cred_getuid(nd->nd_cr);

		error = nfsrv_fhtovp(&nd->nd_fh, nd, &vp, &nx, &nxo);
		if (!error) {
		    /* update per-export stats */
		    NFSStatAdd64(&nx->nx_stats.ops, 1);

		    error = nfsrv_credcheck(nd, ctx, nx, nxo);
		    if (error)
		    	vnode_put(vp);
		}
		if (!error) {
		    if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&preattr);
			preattrerr = vnode_getattr(vp, &preattr, ctx);
		    }
		    if (vnode_vtype(vp) != VREG) {
			if (nd->nd_vers == NFS_VER3)
			    error = EINVAL;
			else
			    error = (vnode_vtype(vp) == VDIR) ? EISDIR : EACCES;
		    }
		} else
		    vp = NULL;
		if (!error)
		    error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA, ctx, nxo, 1);

		if (nd->nd_stable == NFS_WRITE_UNSTABLE)
		    ioflags = IO_NODELOCKED;
		else if (nd->nd_stable == NFS_WRITE_DATASYNC)
		    ioflags = (IO_SYNC | IO_NODELOCKED);
		else
		    ioflags = (IO_METASYNC | IO_SYNC | IO_NODELOCKED);

		if (!error && ((nd->nd_eoff - nd->nd_off) > 0)) {
		    for (i=0, m=nmreq->nmc_mhead; m; m = mbuf_next(m))
			if (mbuf_len(m) > 0)
			    i++;

		    MALLOC(uio_bufp, char *, UIO_SIZEOF(i), M_TEMP, M_WAITOK);
		    if (uio_bufp)
			auio = uio_createwithbuffer(i, nd->nd_off, UIO_SYSSPACE,
						UIO_WRITE, uio_bufp, UIO_SIZEOF(i));
		    if (!uio_bufp || !auio)
			error = ENOMEM;
		    if (!error) {
			for (m = nmreq->nmc_mhead; m; m = mbuf_next(m))
			    if ((tlen = mbuf_len(m)) > 0)
				uio_addiov(auio, CAST_USER_ADDR_T((caddr_t)mbuf_data(m)), tlen);
			error = VNOP_WRITE(vp, auio, ioflags, ctx);
			OSAddAtomic64(1, &nfsstats.srvvop_writes);

			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.bytes_written, nd->nd_len);
			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, nd->nd_len);

#if CONFIG_FSE
			if (nfsrv_fsevents_enabled && !error && need_fsevent(FSE_CONTENT_MODIFIED, vp))
				nfsrv_modified(vp, ctx);
#endif
		    }
		    if (uio_bufp) {
			FREE(uio_bufp, M_TEMP);
			uio_bufp = NULL;
		    }
		}
		if (vp) {
		    nfsm_srv_vattr_init(&postattr, nd->nd_vers);
		    postattrerr = vnode_getattr(vp, &postattr, ctx);
		    vnode_put(vp);
		}

		/*
		 * Loop around generating replies for all write rpcs that have
		 * now been completed.
		 */
		swp = nd;
		do {
		    if (error) {
			nd->nd_repstat = error;
			error = nfsrv_rephead(nd, slp, &nmrep, NFSX_WCCDATA(nd->nd_vers));
			if (!error && (nd->nd_vers == NFS_VER3)) {
			    nfsm_chain_add_wcc_data(error, nd, &nmrep,
				    preattrerr, &preattr, postattrerr, &postattr);
			}
		    } else {
			nd->nd_repstat = error;
			error = nfsrv_rephead(nd, slp, &nmrep, NFSX_PREOPATTR(nd->nd_vers) +
			    NFSX_POSTOPORFATTR(nd->nd_vers) + 2 * NFSX_UNSIGNED +
			    NFSX_WRITEVERF(nd->nd_vers));
			if (!error && (nd->nd_vers == NFS_VER3)) {
			    nfsm_chain_add_wcc_data(error, nd, &nmrep,
				    preattrerr, &preattr, postattrerr, &postattr);
			    nfsm_chain_add_32(error, &nmrep, nd->nd_len);
			    nfsm_chain_add_32(error, &nmrep, nd->nd_stable);
			    /* write verifier */
			    nfsm_chain_add_32(error, &nmrep, nx->nx_exptime.tv_sec);
			    nfsm_chain_add_32(error, &nmrep, nx->nx_exptime.tv_usec);
			} else if (!error) {
			    error = nfsm_chain_add_fattr(nd, &nmrep, &postattr);
			}
		    }
		    nfsm_chain_build_done(error, &nmrep);
		    nfsmerr_if(error);
		    nd->nd_mrep = nmrep.nmc_mhead;

		    /*
		     * Done. Put it at the head of the timer queue so that
		     * the final phase can return the reply.
		     */
		    if (nd != swp) {
			nd->nd_time = 1;
			LIST_INSERT_HEAD(&slp->ns_tq, nd, nd_tq);
		    }
		    nd = swp->nd_coalesce.lh_first;
		    if (nd) {
			LIST_REMOVE(nd, nd_tq);
		    }
		} while (nd);
		swp->nd_time = 1;
		LIST_INSERT_HEAD(&slp->ns_tq, swp, nd_tq);
		goto loop1;
	}

	/*
	 * Search for a reply to return.
	 */
	for (nd = slp->ns_tq.lh_first; nd; nd = nd->nd_tq.le_next)
		if (nd->nd_mrep) {
		    LIST_REMOVE(nd, nd_tq);
		    *mrepp = nd->nd_mrep;
		    *ndp = nd;
		    break;
		}
	slp->ns_wgtime = slp->ns_tq.lh_first ? slp->ns_tq.lh_first->nd_time : 0;
	lck_mtx_unlock(&slp->ns_wgmutex);

	/*
	 * If we've just created a write pending gather,
	 * start the timer to check on it soon to make sure
	 * the write will be completed.
	 *
	 * Add/Remove the socket in the nfsrv_sockwg queue as needed.
	 */
	lck_mtx_lock(nfsd_mutex);
	if (slp->ns_wgtime) {
		if (slp->ns_wgq.tqe_next == SLPNOLIST) {
			TAILQ_INSERT_HEAD(&nfsrv_sockwg, slp, ns_wgq);
		}
		if (!nfsrv_wg_timer_on) {
			nfsrv_wg_timer_on = 1;
			nfs_interval_timer_start(nfsrv_wg_timer_call,
				NFSRV_WGATHERDELAY);
		}
	} else if (slp->ns_wgq.tqe_next != SLPNOLIST) {
		TAILQ_REMOVE(&nfsrv_sockwg, slp, ns_wgq);
		slp->ns_wgq.tqe_next = SLPNOLIST;
	}
	lck_mtx_unlock(nfsd_mutex);

	return (0);
}

/*
 * Coalesce the write request nd into owp. To do this we must:
 * - remove nd from the queues
 * - merge nd->nd_nmreq into owp->nd_nmreq
 * - update the nd_eoff and nd_stable for owp
 * - put nd on owp's nd_coalesce list
 */
int
nfsrv_wg_coalesce(struct nfsrv_descript *owp, struct nfsrv_descript *nd)
{
	int overlap, error;
	mbuf_t mp, mpnext;
	struct nfsrv_descript *p;

	LIST_REMOVE(nd, nd_hash);
	LIST_REMOVE(nd, nd_tq);
	if (owp->nd_eoff < nd->nd_eoff) {
		overlap = owp->nd_eoff - nd->nd_off;
		if (overlap < 0)
			return (EIO);
		if (overlap > 0)
			mbuf_adj(nd->nd_nmreq.nmc_mhead, overlap);
		mp = owp->nd_nmreq.nmc_mhead;
		while ((mpnext = mbuf_next(mp)))
			mp = mpnext;
		error = mbuf_setnext(mp, nd->nd_nmreq.nmc_mhead);
		if (error)
			return (error);
		owp->nd_eoff = nd->nd_eoff;
	} else {
		mbuf_freem(nd->nd_nmreq.nmc_mhead);
	}
	nd->nd_nmreq.nmc_mhead = NULL;
	nd->nd_nmreq.nmc_mcur = NULL;
	if (nd->nd_stable == NFS_WRITE_FILESYNC)
		owp->nd_stable = NFS_WRITE_FILESYNC;
	else if ((nd->nd_stable == NFS_WRITE_DATASYNC) &&
		 (owp->nd_stable == NFS_WRITE_UNSTABLE))
		owp->nd_stable = NFS_WRITE_DATASYNC;
	LIST_INSERT_HEAD(&owp->nd_coalesce, nd, nd_tq);

	/*
	 * If nd had anything else coalesced into it, transfer them
	 * to owp, otherwise their replies will never get sent.
	 */
	while ((p = nd->nd_coalesce.lh_first)) {
		LIST_REMOVE(p, nd_tq);
		LIST_INSERT_HEAD(&owp->nd_coalesce, p, nd_tq);
	}
	return (0);
}

/*
 * Scan the write gathering queues for writes that need to be
 * completed now.
 */
void
nfsrv_wg_timer(__unused void *param0, __unused void *param1)
{
	struct timeval now;
	uint64_t cur_usec, next_usec;
	int interval;
	struct nfsrv_sock *slp;
	int writes_pending = 0;

	microuptime(&now);
	cur_usec = (uint64_t)now.tv_sec * 1000000 + (uint64_t)now.tv_usec;
	next_usec = cur_usec + (NFSRV_WGATHERDELAY * 1000);

	lck_mtx_lock(nfsd_mutex);
	TAILQ_FOREACH(slp, &nfsrv_sockwg, ns_wgq) {
		if (slp->ns_wgtime) {
			writes_pending++;
			if (slp->ns_wgtime <= cur_usec) {
				lck_rw_lock_exclusive(&slp->ns_rwlock);
				slp->ns_flag |= SLP_DOWRITES;
				lck_rw_done(&slp->ns_rwlock);
				nfsrv_wakenfsd(slp);
				continue;
			}
			if (slp->ns_wgtime < next_usec)
				next_usec = slp->ns_wgtime;
		}
	}

	if (writes_pending == 0) {
		nfsrv_wg_timer_on = 0;
		lck_mtx_unlock(nfsd_mutex);
		return;
	}
	lck_mtx_unlock(nfsd_mutex);

	/*
	 * Return the number of msec to wait again
	 */
	interval = (next_usec - cur_usec) / 1000;
	if (interval < 1)
		interval = 1;
	nfs_interval_timer_start(nfsrv_wg_timer_call, interval);
}

/*
 * Sort the group list in increasing numerical order.
 * (Insertion sort by Chris Torek, who was grossed out by the bubble sort
 *  that used to be here.)
 */
void
nfsrv_group_sort(gid_t *list, int num)
{
	int i, j;
	gid_t v;

	/* Insertion sort. */
	for (i = 1; i < num; i++) {
		v = list[i];
		/* find correct slot for value v, moving others up */
		for (j = i; --j >= 0 && v < list[j];)
			list[j + 1] = list[j];
		list[j + 1] = v;
	}
}

/*
 * nfs create service
 * now does a truncate to 0 length via. setattr if it already exists
 */
int
nfsrv_create(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct vnode_attr dpreattr, dpostattr, postattr;
	struct vnode_attr va, *vap = &va;
	struct nameidata ni;
	int error, rdev, dpreattrerr, dpostattrerr, postattrerr;
	int how, exclusive_flag;
	uint32_t len = 0, cnflags;
	vnode_t vp, dvp, dirp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx = NULL;
	struct nfs_export_options *nxo;
	u_quad_t tempsize;
	u_char cverf[NFSX_V3CREATEVERF];
	uid_t saved_uid;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	dpreattrerr = dpostattrerr = postattrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	vp = dvp = dirp = NULL;
	exclusive_flag = 0;
	ni.ni_cnd.cn_nameiop = 0;
	rdev = 0;

	saved_uid = kauth_cred_getuid(nd->nd_cr);

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);

	ni.ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_LINK;
#endif
	ni.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	if (!error) {
		error = nfsrv_namei(nd, ctx, &ni, &nfh, &dirp, &nx, &nxo);
		if (nx != NULL) {
			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);
		}
	}
	if (dirp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&dpreattr);
			dpreattrerr = vnode_getattr(dirp, &dpreattr, ctx);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}

	if (error) {
		ni.ni_cnd.cn_nameiop = 0;
		goto nfsmerr;
	}

	dvp = ni.ni_dvp;
	vp = ni.ni_vp;
	VATTR_INIT(vap);

	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_get_32(error, nmreq, how);
		nfsmerr_if(error);
		switch (how) {
		case NFS_CREATE_GUARDED:
			if (vp) {
				error = EEXIST;
				break;
			}
		case NFS_CREATE_UNCHECKED:
			error = nfsm_chain_get_sattr(nd, nmreq, vap);
			break;
		case NFS_CREATE_EXCLUSIVE:
			nfsm_chain_get_opaque(error, nmreq, NFSX_V3CREATEVERF, cverf);
			exclusive_flag = 1;
			if (vp == NULL)
				VATTR_SET(vap, va_mode, 0);
			break;
		};
		VATTR_SET(vap, va_type, VREG);
	} else {
	        enum vtype v_type;

		error = nfsm_chain_get_sattr(nd, nmreq, vap);
		nfsmerr_if(error);
		v_type = vap->va_type;
		if (v_type == VNON)
			v_type = VREG;
		VATTR_SET(vap, va_type, v_type);

		switch (v_type) {
		case VCHR:
		case VBLK:
		case VFIFO:
			rdev = vap->va_data_size;
			VATTR_CLEAR_ACTIVE(vap, va_data_size);
			break;
		default:
			break;
		};
	}
	nfsmerr_if(error);

	/*
	 * If it doesn't exist, create it
	 * otherwise just truncate to 0 length
	 *   should I set the mode too ??
	 */
	if (vp == NULL) {
	        kauth_acl_t xacl = NULL;

		/* authorize before creating */
		error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx, nxo, 0);

		/* construct ACL and handle inheritance */
		if (!error) {
			error = kauth_acl_inherit(dvp,
			    NULL,
			    &xacl,
			    0 /* !isdir */,
			    ctx);

			if (!error && xacl != NULL)
			        VATTR_SET(vap, va_acl, xacl);
		}
		VATTR_CLEAR_ACTIVE(vap, va_data_size);
		VATTR_CLEAR_ACTIVE(vap, va_access_time);
		/*
		 * Server policy is to alway use the mapped rpc credential for 
		 * file system object creation. This has the nice side effect of
		 * enforcing BSD creation semantics
		 */
		VATTR_CLEAR_ACTIVE(vap, va_uid);
		VATTR_CLEAR_ACTIVE(vap, va_gid);

		/* validate new-file security information */
		if (!error) 
			error = vnode_authattr_new(dvp, vap, 0, ctx);

		if (vap->va_type == VREG || vap->va_type == VSOCK) {

			if (!error)
				error = VNOP_CREATE(dvp, &vp, &ni.ni_cnd, vap, ctx);

			if (!error && !VATTR_ALL_SUPPORTED(vap))
			        /*
				 * If some of the requested attributes weren't handled by the VNOP,
				 * use our fallback code.
				 */
				error = vnode_setattr_fallback(vp, vap, ctx);

			if (xacl != NULL)
				kauth_acl_free(xacl);

			if (!error) {
				if (exclusive_flag) {
					exclusive_flag = 0;
					VATTR_INIT(vap);
					bcopy(cverf, (caddr_t)&vap->va_access_time,
						NFSX_V3CREATEVERF);
					VATTR_SET_ACTIVE(vap, va_access_time);
					// skip authorization, as this is an
					// NFS internal implementation detail.
					error = vnode_setattr(vp, vap, ctx);
				}

#if CONFIG_FSE
				if (nfsrv_fsevents_enabled && need_fsevent(FSE_CREATE_FILE, vp)) {
				        add_fsevent(FSE_CREATE_FILE, ctx,
						    FSE_ARG_VNODE, vp,
						    FSE_ARG_DONE);
				}
#endif
			}

		} else if (vap->va_type == VCHR || vap->va_type == VBLK ||
			vap->va_type == VFIFO) {
			if (vap->va_type == VCHR && rdev == (int)0xffffffff)
				VATTR_SET(vap, va_type, VFIFO);
			if (vap->va_type != VFIFO) {
				error = suser(nd->nd_cr, NULL);
				nfsmerr_if(error);
			}
			VATTR_SET(vap, va_rdev, (dev_t)rdev);

			error = VNOP_MKNOD(dvp, &vp, &ni.ni_cnd, vap, ctx);

			if (xacl != NULL)
				kauth_acl_free(xacl);

			nfsmerr_if(error);

			if (vp) {
				vnode_recycle(vp);
				vnode_put(vp);
				vp = NULL;
			}
			ni.ni_cnd.cn_nameiop = LOOKUP;
#if CONFIG_TRIGGERS
			ni.ni_op = OP_LOOKUP;
#endif
			ni.ni_cnd.cn_flags &= ~LOCKPARENT;
			ni.ni_cnd.cn_context = ctx;
			ni.ni_startdir = dvp;
			ni.ni_usedvp   = dvp;
			cnflags = ni.ni_cnd.cn_flags; /* store in case we have to restore */
			while ((error = lookup(&ni)) == ERECYCLE) {
				ni.ni_cnd.cn_flags = cnflags;
				ni.ni_cnd.cn_nameptr = ni.ni_cnd.cn_pnbuf;
				ni.ni_usedvp = ni.ni_dvp = ni.ni_startdir = dvp;
			}
			if (!error) {
				if (ni.ni_cnd.cn_flags & ISSYMLINK)
					error = EINVAL;
				vp = ni.ni_vp;
			}
			nfsmerr_if(error);
		} else {
			error = ENXIO;
		}
		/*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&ni);
		ni.ni_cnd.cn_nameiop = 0;

		vnode_put(dvp);
	} else {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
	        nameidone(&ni);
		ni.ni_cnd.cn_nameiop = 0;

		vnode_put(dvp);

		if (!error && VATTR_IS_ACTIVE(vap, va_data_size)) {
			error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA,
			    ctx, nxo, 0);
			if (!error) {
				tempsize = vap->va_data_size;
				VATTR_INIT(vap);
				VATTR_SET(vap, va_data_size, tempsize);
				error = vnode_setattr(vp, vap, ctx);
			}
		}
	}
	if (!error) {
		error = nfsrv_vptofh(nx, nd->nd_vers, NULL, vp, ctx, &nfh);
		if (!error) {
			nfsm_srv_vattr_init(&postattr, nd->nd_vers);
			postattrerr = vnode_getattr(vp, &postattr, ctx);
			if (nd->nd_vers == NFS_VER2)
				error = postattrerr;
		}
	}
	if (vp)
	        vnode_put(vp);

	if (nd->nd_vers == NFS_VER3) {
		if (exclusive_flag && !error &&
		    bcmp(cverf, &postattr.va_access_time, NFSX_V3CREATEVERF))
			error = EEXIST;
		nfsm_srv_vattr_init(&dpostattr, NFS_VER3);
		dpostattrerr = vnode_getattr(dirp, &dpostattr, ctx);
		vnode_put(dirp);
		dirp = NULL;
	}

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_SRVFH(nd->nd_vers, &nfh) +
			NFSX_FATTR(nd->nd_vers) + NFSX_WCCDATA(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3) {
		if (!nd->nd_repstat) {
			nfsm_chain_add_postop_fh(error, &nmrep, nfh.nfh_fhp, nfh.nfh_len);
			nfsm_chain_add_postop_attr(error, nd, &nmrep, postattrerr, &postattr);
		}
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			dpreattrerr, &dpreattr, dpostattrerr, &dpostattr);
	} else {
		nfsm_chain_add_fh(error, &nmrep, NFS_VER2, nfh.nfh_fhp, nfh.nfh_len);
		if (!error)
			error = nfsm_chain_add_fattr(nd, &nmrep, &postattr);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (ni.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&ni);

		if (vp)
			vnode_put(vp);
		vnode_put(dvp);
	}
	if (dirp)
		vnode_put(dirp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs v3 mknod service
 */
int
nfsrv_mknod(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct vnode_attr dpreattr, dpostattr, postattr;
	struct vnode_attr va, *vap = &va;
	struct nameidata ni;
	int error, dpreattrerr, dpostattrerr, postattrerr;
	uint32_t len = 0, cnflags;
	u_int32_t major = 0, minor = 0;
	enum vtype vtyp;
	nfstype nvtype;
	vnode_t vp, dvp, dirp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx = NULL;
	struct nfs_export_options *nxo;
	uid_t saved_uid;
	kauth_acl_t xacl = NULL;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	dpreattrerr = dpostattrerr = postattrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	vp = dvp = dirp = NULL;
	ni.ni_cnd.cn_nameiop = 0;

	saved_uid = kauth_cred_getuid(nd->nd_cr);

	nfsm_chain_get_fh_ptr(error, nmreq, NFS_VER3, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);

	ni.ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_LINK;
#endif
	ni.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	if (!error) {
		error = nfsrv_namei(nd, ctx, &ni, &nfh, &dirp, &nx, &nxo);
		if (nx != NULL) {
			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);
		}
	}
	if (dirp) {
		nfsm_srv_pre_vattr_init(&dpreattr);
		dpreattrerr = vnode_getattr(dirp, &dpreattr, ctx);
	}
	if (error) {
		ni.ni_cnd.cn_nameiop = 0;
		goto nfsmerr;
	}

	dvp = ni.ni_dvp;
	vp = ni.ni_vp;

	nfsm_chain_get_32(error, nmreq, nvtype);
	nfsmerr_if(error);
	vtyp = nfstov_type(nvtype, NFS_VER3);
	if (!error && (vtyp != VCHR) && (vtyp != VBLK) && (vtyp != VSOCK) && (vtyp != VFIFO)) {
		error = NFSERR_BADTYPE;
		goto out;
	}

	VATTR_INIT(vap);
	error = nfsm_chain_get_sattr(nd, nmreq, vap);
	if ((vtyp == VCHR) || (vtyp == VBLK)) {
		nfsm_chain_get_32(error, nmreq, major);
		nfsm_chain_get_32(error, nmreq, minor);
		nfsmerr_if(error);
		VATTR_SET(vap, va_rdev, makedev(major, minor));
	}
	nfsmerr_if(error);

	/*
	 * If it doesn't exist, create it.
	 */
	if (vp) {
		error = EEXIST;
		goto out;
	}
	VATTR_SET(vap, va_type, vtyp);

	/* authorize before creating */
	error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx, nxo, 0);

	/* construct ACL and handle inheritance */
	if (!error) {
		error = kauth_acl_inherit(dvp,
		    NULL,
		    &xacl,
		    0 /* !isdir */,
		    ctx);

		if (!error && xacl != NULL)
		        VATTR_SET(vap, va_acl, xacl);
	}
	VATTR_CLEAR_ACTIVE(vap, va_data_size);
	VATTR_CLEAR_ACTIVE(vap, va_access_time);
	/*
	 * Server policy is to alway use the mapped rpc credential for 
	 * file system object creation. This has the nice side effect of
	 * enforcing BSD creation semantics
	 */
	VATTR_CLEAR_ACTIVE(vap, va_uid);
	VATTR_CLEAR_ACTIVE(vap, va_gid);

	/* validate new-file security information */
	if (!error) 
		error = vnode_authattr_new(dvp, vap, 0, ctx);

	if (error)
		goto out1;

	if (vtyp == VSOCK) {
		error = VNOP_CREATE(dvp, &vp, &ni.ni_cnd, vap, ctx);

		if (!error && !VATTR_ALL_SUPPORTED(vap))
		        /*
			 * If some of the requested attributes weren't handled by the VNOP,
			 * use our fallback code.
			 */
			error = vnode_setattr_fallback(vp, vap, ctx);
	} else {
		if (vtyp != VFIFO && (error = suser(nd->nd_cr, (u_short *)0)))
			goto out1;
		if ((error = VNOP_MKNOD(dvp, &vp, &ni.ni_cnd, vap, ctx)))
			goto out1;
		if (vp) {
			vnode_recycle(vp);
			vnode_put(vp);
			vp = NULL;
		}
		ni.ni_cnd.cn_nameiop = LOOKUP;
#if CONFIG_TRIGGERS
		ni.ni_op = OP_LOOKUP;
#endif
		ni.ni_cnd.cn_flags &= ~LOCKPARENT;
		ni.ni_cnd.cn_context = vfs_context_current();
		ni.ni_startdir = dvp;
		ni.ni_usedvp   = dvp;
		cnflags = ni.ni_cnd.cn_flags; /* store in case we have to restore */
		while ((error = lookup(&ni)) == ERECYCLE) {
			ni.ni_cnd.cn_flags = cnflags;
			ni.ni_cnd.cn_nameptr = ni.ni_cnd.cn_pnbuf;
			ni.ni_usedvp = ni.ni_dvp = ni.ni_startdir = dvp;
		}
		if (!error) {
		        vp = ni.ni_vp;
			if (ni.ni_cnd.cn_flags & ISSYMLINK)
			        error = EINVAL;
		}
	}
out1:
	if (xacl != NULL)
		kauth_acl_free(xacl);
out:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&ni);
	ni.ni_cnd.cn_nameiop = 0;

	vnode_put(dvp);
	dvp = NULL;

	if (!error) {
		error = nfsrv_vptofh(nx, NFS_VER3, NULL, vp, ctx, &nfh);
		if (!error) {
			nfsm_srv_vattr_init(&postattr, NFS_VER3);
			postattrerr = vnode_getattr(vp, &postattr, ctx);
		}
	}
	if (vp) {
		vnode_put(vp);
		vp = NULL;
	}

	nfsm_srv_vattr_init(&dpostattr, NFS_VER3);
	dpostattrerr = vnode_getattr(dirp, &dpostattr, ctx);
	vnode_put(dirp);
	dirp = NULL;

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_SRVFH(NFS_VER3, &nfh) +
			NFSX_POSTOPATTR(NFS_VER3) + NFSX_WCCDATA(NFS_VER3));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (!nd->nd_repstat) {
		nfsm_chain_add_postop_fh(error, &nmrep, nfh.nfh_fhp, nfh.nfh_len);
		nfsm_chain_add_postop_attr(error, nd, &nmrep, postattrerr, &postattr);
	}
	nfsm_chain_add_wcc_data(error, nd, &nmrep,
		dpreattrerr, &dpreattr, dpostattrerr, &dpostattr);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (ni.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&ni);

		if (vp)
			vnode_put(vp);
		vnode_put(dvp);
	}
	if (dvp)
		vnode_put(dvp);
	if (vp)
		vnode_put(vp);
	if (dirp)
		vnode_put(dirp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs remove service
 */
int
nfsrv_remove(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct nameidata ni;
	int error, dpreattrerr, dpostattrerr;
	uint32_t len = 0;
	uid_t saved_uid;
	vnode_t vp, dvp, dirp = NULL;
	struct vnode_attr dpreattr, dpostattr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx = NULL;
	struct nfs_export_options *nxo;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	dpreattrerr = dpostattrerr = ENOENT;
	saved_uid = kauth_cred_getuid(nd->nd_cr);
	dvp = vp = dirp = NULL;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);

	ni.ni_cnd.cn_nameiop = DELETE;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_UNLINK;
#endif
	ni.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	if (!error) {
		error = nfsrv_namei(nd, ctx, &ni, &nfh, &dirp, &nx, &nxo);
		if (nx != NULL) {
			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);
		}
	}
	if (dirp) {
	        if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&dpreattr);
			dpreattrerr = vnode_getattr(dirp, &dpreattr, ctx);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}

	if (!error) {
		dvp = ni.ni_dvp;
		vp = ni.ni_vp;

		if (vnode_vtype(vp) == VDIR)
			error = EPERM;		/* POSIX */
		else if (vnode_isvroot(vp))
		        /*
			 * The root of a mounted filesystem cannot be deleted.
			 */
			error = EBUSY;
		else
			error = nfsrv_authorize(vp, dvp, KAUTH_VNODE_DELETE, ctx, nxo, 0);

		if (!error) {
#if CONFIG_FSE
			char     *path = NULL;
			int       plen;
			fse_info  finfo;
	
			if (nfsrv_fsevents_enabled && need_fsevent(FSE_DELETE, dvp)) {
				plen = MAXPATHLEN;
				if ((path = get_pathbuff()) && !vn_getpath(vp, path, &plen)) {
					get_fse_info(vp, &finfo, ctx);
				} else if (path) {
					release_pathbuff(path);
					path = NULL;
				}
			}
#endif
		    	error = VNOP_REMOVE(dvp, vp, &ni.ni_cnd, 0, ctx);
	
#if CONFIG_FSE
			if (path) {
				if (!error)
					add_fsevent(FSE_DELETE, ctx,
						    FSE_ARG_STRING, plen, path,
						    FSE_ARG_FINFO, &finfo,
						    FSE_ARG_DONE);
			        release_pathbuff(path);
			}
#endif
		}

		/*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&ni);

		vnode_put(vp);
	        vnode_put(dvp);
	}

nfsmerr:
	if (dirp) {
		nfsm_srv_vattr_init(&dpostattr, nd->nd_vers);
	        dpostattrerr = vnode_getattr(dirp, &dpostattr, ctx);
		vnode_put(dirp);
	}

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_WCCDATA(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			dpreattrerr, &dpreattr, dpostattrerr, &dpostattr);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs rename service
 */
int
nfsrv_rename(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	kauth_cred_t saved_cred = NULL;
	uid_t saved_uid;
	int error;
	uint32_t fromlen, tolen;
	int fdpreattrerr, fdpostattrerr;
	int tdpreattrerr, tdpostattrerr;
	char *frompath = NULL, *topath = NULL;
	struct nameidata fromni, toni;
	vnode_t fvp, tvp, tdvp, fdvp, fdirp, tdirp;
	struct vnode_attr fdpreattr, fdpostattr;
	struct vnode_attr tdpreattr, tdpostattr;
	struct nfs_filehandle fnfh, tnfh;
	struct nfs_export *fnx, *tnx;
	struct nfs_export_options *fnxo, *tnxo;
	enum vtype fvtype, tvtype;
	int holding_mntlock;
	mount_t locked_mp;
	struct nfsm_chain *nmreq, nmrep;
	char *from_name, *to_name;
#if CONFIG_FSE
	int from_len=0, to_len=0;
	fse_info from_finfo, to_finfo;
#endif
	u_char didstats = 0;
	const char *oname;

	error = 0;
	fdpreattrerr = fdpostattrerr = ENOENT;
	tdpreattrerr = tdpostattrerr = ENOENT;
	saved_uid = kauth_cred_getuid(nd->nd_cr);
	fromlen = tolen = 0;
	frompath = topath = NULL;
	fdirp = tdirp = NULL;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);

	/*
	 * these need to be set before calling any code
	 * that they may take us out through the error path.
	 */
	holding_mntlock = 0;
	fvp = tvp = NULL;
	fdvp = tdvp = NULL;
	locked_mp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, fnfh.nfh_fhp, fnfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, fromlen);
	nfsm_name_len_check(error, nd, fromlen);
	nfsmerr_if(error);
	error = nfsm_chain_get_path_namei(nmreq, fromlen, &fromni);
	nfsmerr_if(error);
	frompath = fromni.ni_cnd.cn_pnbuf;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, tnfh.nfh_fhp, tnfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, tolen);
	nfsm_name_len_check(error, nd, tolen);
	nfsmerr_if(error);
	error = nfsm_chain_get_path_namei(nmreq, tolen, &toni);
	nfsmerr_if(error);
	topath = toni.ni_cnd.cn_pnbuf;

	/*
	 * Remember our original uid so that we can reset cr_uid before
	 * the second nfsrv_namei() call, in case it is remapped.
	 */
	saved_cred = nd->nd_cr;
	kauth_cred_ref(saved_cred);
retry:
	fromni.ni_cnd.cn_nameiop = DELETE;
#if CONFIG_TRIGGERS
	fromni.ni_op = OP_UNLINK;
#endif
	fromni.ni_cnd.cn_flags = WANTPARENT;

	fromni.ni_cnd.cn_pnbuf = frompath;
	frompath = NULL;
	fromni.ni_cnd.cn_pnlen = MAXPATHLEN;
	fromni.ni_cnd.cn_flags |= HASBUF;

	error = nfsrv_namei(nd, ctx, &fromni, &fnfh, &fdirp, &fnx, &fnxo);
	if (error)
		goto out;
	fdvp = fromni.ni_dvp;
	fvp  = fromni.ni_vp;

	if (fdirp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&fdpreattr);
			fdpreattrerr = vnode_getattr(fdirp, &fdpreattr, ctx);
		} else {
			vnode_put(fdirp);
			fdirp = NULL;
		}
	}
	fvtype = vnode_vtype(fvp);

	/* reset credential if it was remapped */
	if (nd->nd_cr != saved_cred) {
		kauth_cred_ref(saved_cred);
		kauth_cred_unref(&nd->nd_cr);
		ctx->vc_ucred = nd->nd_cr = saved_cred;
	}

	toni.ni_cnd.cn_nameiop = RENAME;
#if CONFIG_TRIGGERS
	toni.ni_op = OP_RENAME;
#endif
	toni.ni_cnd.cn_flags = WANTPARENT;

	toni.ni_cnd.cn_pnbuf = topath;
	topath = NULL;
	toni.ni_cnd.cn_pnlen = MAXPATHLEN;
	toni.ni_cnd.cn_flags |= HASBUF;

	if (fvtype == VDIR)
		toni.ni_cnd.cn_flags |= WILLBEDIR;

	tnx = NULL;
	error = nfsrv_namei(nd, ctx, &toni, &tnfh, &tdirp, &tnx, &tnxo);
	if (error) {
		/*
		 * Translate error code for rename("dir1", "dir2/.").
		 */
	        if (error == EISDIR && fvtype == VDIR) {
		        if (nd->nd_vers == NFS_VER3)
			        error = EINVAL;
			else
			        error = ENOTEMPTY;
		}
		goto out;
	}
	tdvp = toni.ni_dvp;
	tvp  = toni.ni_vp;

	if (!didstats) {
		/* update export stats once only */
		if (tnx != NULL) {
			/* update export stats */
			NFSStatAdd64(&tnx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(tnx, nd, saved_uid, 1, 0, 0);
			didstats = 1;
		}
	}

	if (tdirp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&tdpreattr);
			tdpreattrerr = vnode_getattr(tdirp, &tdpreattr, ctx);
		} else {
			vnode_put(tdirp);
			tdirp = NULL;
		}
	}

	if (tvp != NULL) {
		tvtype = vnode_vtype(tvp);

		if (fvtype == VDIR && tvtype != VDIR) {
			if (nd->nd_vers == NFS_VER3)
				error = EEXIST;
			else
				error = EISDIR;
			goto out;
		} else if (fvtype != VDIR && tvtype == VDIR) {
			if (nd->nd_vers == NFS_VER3)
				error = EEXIST;
			else
				error = ENOTDIR;
			goto out;
		}
		if (tvtype == VDIR && vnode_mountedhere(tvp)) {
			if (nd->nd_vers == NFS_VER3)
				error = EXDEV;
			else
				error = ENOTEMPTY;
			goto out;
		}
	}
	if (fvp == tdvp) {
		if (nd->nd_vers == NFS_VER3)
			error = EINVAL;
		else
			error = ENOTEMPTY;
		goto out;
	}

	/*
	 * Authorization.
	 *
	 * If tvp is a directory and not the same as fdvp, or tdvp is not the same as fdvp,
	 * the node is moving between directories and we need rights to remove from the
	 * old and add to the new.
	 *
	 * If tvp already exists and is not a directory, we need to be allowed to delete it.
	 *
	 * Note that we do not inherit when renaming.  XXX this needs to be revisited to
	 * implement the deferred-inherit bit.
	 */
	{
		int moving = 0;

		error = 0;
		if ((tvp != NULL) && vnode_isdir(tvp)) {
			if (tvp != fdvp)
				moving = 1;
		} else if (tdvp != fdvp) {
			moving = 1;
		}
		if (moving) {
			/* moving out of fdvp, must have delete rights */
			if ((error = nfsrv_authorize(fvp, fdvp, KAUTH_VNODE_DELETE, ctx, fnxo, 0)) != 0)
				goto auth_exit;
			/* moving into tdvp or tvp, must have rights to add */
			if ((error = nfsrv_authorize(((tvp != NULL) && vnode_isdir(tvp)) ? tvp : tdvp,
				 NULL,
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE,
				 ctx, tnxo, 0)) != 0)
				goto auth_exit;
		} else {
			/* node staying in same directory, must be allowed to add new name */
			if ((error = nfsrv_authorize(fdvp, NULL,
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE,
				 ctx, fnxo, 0)) != 0)
				goto auth_exit;
		}
		/* overwriting tvp */
		if ((tvp != NULL) && !vnode_isdir(tvp) &&
		    ((error = nfsrv_authorize(tvp, tdvp, KAUTH_VNODE_DELETE, ctx, tnxo, 0)) != 0))
			goto auth_exit;

		/* XXX more checks? */

auth_exit:
		/* authorization denied */
		if (error != 0)
			goto out;
	}

	if ((vnode_mount(fvp) != vnode_mount(tdvp)) ||
	    (tvp && (vnode_mount(fvp) != vnode_mount(tvp)))) {
		if (nd->nd_vers == NFS_VER3)
			error = EXDEV;
		else
			error = ENOTEMPTY;
		goto out;
	}
	/*
	 * The following edge case is caught here:
	 * (to cannot be a descendent of from)
	 *
	 *       o fdvp
	 *      /
	 *     /
	 *    o fvp
	 *     \
	 *      \
	 *       o tdvp
	 *      /
	 *     /
	 *    o tvp
	 */
	if (tdvp->v_parent == fvp) {
		if (nd->nd_vers == NFS_VER3)
			error = EXDEV;
		else
			error = ENOTEMPTY;
		goto out;
	}
	if (fvtype == VDIR && vnode_mountedhere(fvp)) {
		if (nd->nd_vers == NFS_VER3)
			error = EXDEV;
		else
			error = ENOTEMPTY;
		goto out;
	}
	/*
	 * If source is the same as the destination (that is the
	 * same vnode) then there is nothing to do...
	 * EXCEPT if the underlying file system supports case
	 * insensitivity and is case preserving.  In this case
	 * the file system needs to handle the special case of
	 * getting the same vnode as target (fvp) and source (tvp).
	 *
	 * Only file systems that support pathconf selectors _PC_CASE_SENSITIVE
	 * and _PC_CASE_PRESERVING can have this exception, and they need to
	 * handle the special case of getting the same vnode as target and
	 * source.  NOTE: Then the target is unlocked going into vnop_rename,
	 * so not to cause locking problems. There is a single reference on tvp.
	 *
	 * NOTE - that fvp == tvp also occurs if they are hard linked - NOTE
	 * that correct behaviour then is just to remove the source (link)
	 */
	if ((fvp == tvp) && (fdvp == tdvp)) {
		if (fromni.ni_cnd.cn_namelen == toni.ni_cnd.cn_namelen &&
	       	    !bcmp(fromni.ni_cnd.cn_nameptr, toni.ni_cnd.cn_nameptr,
			  fromni.ni_cnd.cn_namelen)) {
			goto out;
		}
	}

	if (holding_mntlock && vnode_mount(fvp) != locked_mp) {
	        /*
		 * we're holding a reference and lock
		 * on locked_mp, but it no longer matches
		 * what we want to do... so drop our hold
		 */
		mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
	        holding_mntlock = 0;
	}
	if (tdvp != fdvp && fvtype == VDIR) {
	        /*
		 * serialize renames that re-shape
		 * the tree... if holding_mntlock is
		 * set, then we're ready to go...
		 * otherwise we
		 * first need to drop the iocounts
		 * we picked up, second take the
		 * lock to serialize the access,
		 * then finally start the lookup
		 * process over with the lock held
		 */
	        if (!holding_mntlock) {
		        /*
			 * need to grab a reference on
			 * the mount point before we
			 * drop all the iocounts... once
			 * the iocounts are gone, the mount
			 * could follow
			 */
			locked_mp = vnode_mount(fvp);
			mount_ref(locked_mp, 0);

			/* make a copy of to path to pass to nfsrv_namei() again */
			MALLOC_ZONE(topath, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
			if (topath)
				bcopy(toni.ni_cnd.cn_pnbuf, topath, tolen + 1);

			/*
			 * nameidone has to happen before we vnode_put(tdvp)
			 * since it may need to release the fs_nodelock on the tdvp
			 */
			nameidone(&toni);

			if (tvp)
			        vnode_put(tvp);
			vnode_put(tdvp);

			/* make a copy of from path to pass to nfsrv_namei() again */
			MALLOC_ZONE(frompath, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
			if (frompath)
				bcopy(fromni.ni_cnd.cn_pnbuf, frompath, fromlen + 1);

			/*
			 * nameidone has to happen before we vnode_put(fdvp)
			 * since it may need to release the fs_nodelock on the fdvp
			 */
			nameidone(&fromni);

			vnode_put(fvp);
			vnode_put(fdvp);

			if (fdirp) {
			        vnode_put(fdirp);
				fdirp = NULL;
			}
			if (tdirp) {
			        vnode_put(tdirp);
				tdirp = NULL;
			}
			mount_lock_renames(locked_mp);
			holding_mntlock = 1;

			fvp = tvp = NULL;
			fdvp = tdvp = NULL;

			fdpreattrerr = tdpreattrerr = ENOENT;

			if (!topath || !frompath) {
				/* we couldn't allocate a path, so bail */
				error = ENOMEM;
				goto out;
			}

			/* reset credential if it was remapped */
			if (nd->nd_cr != saved_cred) {
				kauth_cred_ref(saved_cred);
				kauth_cred_unref(&nd->nd_cr);
				ctx->vc_ucred = nd->nd_cr = saved_cred;
			}

			goto retry;
		}
	} else {
	        /*
		 * when we dropped the iocounts to take
		 * the lock, we allowed the identity of
		 * the various vnodes to change... if they did,
		 * we may no longer be dealing with a rename
		 * that reshapes the tree... once we're holding
		 * the iocounts, the vnodes can't change type
		 * so we're free to drop the lock at this point
		 * and continue on
		 */
	        if (holding_mntlock) {
			mount_unlock_renames(locked_mp);
			mount_drop(locked_mp, 0);
		        holding_mntlock = 0;
		}
	}

	// save these off so we can later verify that fvp is the same
	vnode_t oparent;
	oname   = fvp->v_name;
	oparent = fvp->v_parent;

	/*
	 * If generating an fsevent, then
	 * stash any pre-rename info we may need.
	 */
#if CONFIG_FSE
	if (nfsrv_fsevents_enabled && need_fsevent(FSE_RENAME, fvp)) {
		int from_truncated = 0, to_truncated = 0;
		
	        get_fse_info(fvp, &from_finfo, ctx);
		if (tvp)
		        get_fse_info(tvp, &to_finfo, ctx);

	        from_name = get_pathbuff();
		if (from_name) {
			from_len = safe_getpath(fdvp, fromni.ni_cnd.cn_nameptr, from_name, MAXPATHLEN, &from_truncated);
		}
		
		to_name = from_name ? get_pathbuff() : NULL;
		if (to_name) {
			to_len = safe_getpath(tdvp, toni.ni_cnd.cn_nameptr, to_name, MAXPATHLEN, &to_truncated);
		}

		if (from_truncated || to_truncated) {
			from_finfo.mode |= FSE_TRUNCATED_PATH;
		}

	} else {
	        from_name = NULL;
	        to_name   = NULL;
	}
#else /* CONFIG_FSE */
	from_name = NULL;
	to_name   = NULL;
#endif /* CONFIG_FSE */

	error = VNOP_RENAME(fromni.ni_dvp, fromni.ni_vp, &fromni.ni_cnd,
			    toni.ni_dvp, toni.ni_vp, &toni.ni_cnd, ctx);
	/*
	 * fix up name & parent pointers.  note that we first	
	 * check that fvp has the same name/parent pointers it
	 * had before the rename call... this is a 'weak' check
	 * at best...
	 */
	if (oname == fvp->v_name && oparent == fvp->v_parent) {
		int update_flags;
		update_flags = VNODE_UPDATE_NAME;
		if (fdvp != tdvp)
			update_flags |= VNODE_UPDATE_PARENT;
		vnode_update_identity(fvp, tdvp, toni.ni_cnd.cn_nameptr,
			toni.ni_cnd.cn_namelen, toni.ni_cnd.cn_hash, update_flags);
	}

	/*
	 * If the rename is OK and we've got the paths
	 * then add an fsevent.
	 */
#if CONFIG_FSE
	if (nfsrv_fsevents_enabled && !error && from_name && to_name) {
	        if (tvp) {
		        add_fsevent(FSE_RENAME, ctx,
				    FSE_ARG_STRING, from_len, from_name,
				    FSE_ARG_FINFO, &from_finfo,
				    FSE_ARG_STRING, to_len, to_name,
				    FSE_ARG_FINFO, &to_finfo,
				    FSE_ARG_DONE);
		} else {
		        add_fsevent(FSE_RENAME, ctx,
				    FSE_ARG_STRING, from_len, from_name,
				    FSE_ARG_FINFO, &from_finfo,
				    FSE_ARG_STRING, to_len, to_name,
				    FSE_ARG_DONE);
		}
	}
	if (from_name)
	        release_pathbuff(from_name);
	if (to_name)
	        release_pathbuff(to_name);
#endif /* CONFIG_FSE */
	from_name = to_name = NULL;
		
out:
	if (holding_mntlock) {
	        mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
		holding_mntlock = 0;
	}
	if (tdvp) {
	        /*
		 * nameidone has to happen before we vnode_put(tdvp)
		 * since it may need to release the fs_nodelock on the tdvp
		 */
		nameidone(&toni);
		if (tvp)
		        vnode_put(tvp);
	        vnode_put(tdvp);

		tdvp = NULL;
	}
	if (fdvp) {
		/*
		 * nameidone has to happen before we vnode_put(fdvp)
		 * since it may need to release the fs_nodelock on the fdvp
		 */
		nameidone(&fromni);

		if (fvp)
		        vnode_put(fvp);
	        vnode_put(fdvp);

		fdvp = NULL;
	}
	if (fdirp) {
		nfsm_srv_vattr_init(&fdpostattr, nd->nd_vers);
		fdpostattrerr = vnode_getattr(fdirp, &fdpostattr, ctx);
		vnode_put(fdirp);
		fdirp = NULL;
	}
	if (tdirp) {
		nfsm_srv_vattr_init(&tdpostattr, nd->nd_vers);
		tdpostattrerr = vnode_getattr(tdirp, &tdpostattr, ctx);
		vnode_put(tdirp);
		tdirp = NULL;
	}

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, 2 * NFSX_WCCDATA(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			fdpreattrerr, &fdpreattr, fdpostattrerr, &fdpostattr);
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			tdpreattrerr, &tdpreattr, tdpostattrerr, &tdpostattr);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (holding_mntlock) {
	        mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
	}
	if (tdvp) {
		/*
		 * nameidone has to happen before we vnode_put(tdvp)
		 * since it may need to release the fs_nodelock on the tdvp
		 */
		nameidone(&toni);

		if (tvp)
		        vnode_put(tvp);
	        vnode_put(tdvp);
	}
	if (fdvp) {
		/*
		 * nameidone has to happen before we vnode_put(fdvp)
		 * since it may need to release the fs_nodelock on the fdvp
		 */
		nameidone(&fromni);

		if (fvp)
		        vnode_put(fvp);
	        vnode_put(fdvp);
	}
	if (fdirp)
		vnode_put(fdirp);
	if (tdirp)
		vnode_put(tdirp);
	if (frompath)
		FREE_ZONE(frompath, MAXPATHLEN, M_NAMEI);
	if (topath)
		FREE_ZONE(topath, MAXPATHLEN, M_NAMEI);
	if (saved_cred)
		kauth_cred_unref(&saved_cred);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs link service
 */
int
nfsrv_link(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct nameidata ni;
	int error, dpreattrerr, dpostattrerr, attrerr;
	uint32_t len = 0;
	vnode_t vp, xp, dvp, dirp;
	struct vnode_attr dpreattr, dpostattr, attr;
	struct nfs_filehandle nfh, dnfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	dpreattrerr = dpostattrerr = attrerr = ENOENT;
	vp = xp = dvp = dirp = NULL;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, dnfh.nfh_fhp, dnfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	/* we're not allowed to link to directories... */
	if (vnode_vtype(vp) == VDIR) {
		error = EPERM;		/* POSIX */
		goto out;
	}

	/* ...or to anything that kauth doesn't want us to (eg. immutable items) */
	if ((error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_LINKTARGET, ctx, nxo, 0)) != 0)
		goto out;

	ni.ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_LINK;
#endif
	ni.ni_cnd.cn_flags = LOCKPARENT;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	if (!error)
		error = nfsrv_namei(nd, ctx, &ni, &dnfh, &dirp, &nx, &nxo);
	if (dirp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&dpreattr);
			dpreattrerr = vnode_getattr(dirp, &dpreattr, ctx);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error)
		goto out;
	dvp = ni.ni_dvp;
	xp = ni.ni_vp;

	if (xp != NULL)
		error = EEXIST;
	else if (vnode_mount(vp) != vnode_mount(dvp))
		error = EXDEV;
	else
		error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx, nxo, 0);

	if (!error)
		error = VNOP_LINK(vp, dvp, &ni.ni_cnd, ctx);

#if CONFIG_FSE
	if (nfsrv_fsevents_enabled && !error && need_fsevent(FSE_CREATE_FILE, dvp)) {
		char *target_path = NULL;
		int plen, truncated=0;
		fse_info finfo;

		/* build the path to the new link file */
		target_path = get_pathbuff();
		if (target_path) {
			plen = safe_getpath(dvp, ni.ni_cnd.cn_nameptr, target_path, MAXPATHLEN, &truncated);

			if (get_fse_info(vp, &finfo, ctx) == 0) {
				if (truncated) {
					finfo.mode |= FSE_TRUNCATED_PATH;
				}
				add_fsevent(FSE_CREATE_FILE, ctx,
					    FSE_ARG_STRING, plen, target_path,
					    FSE_ARG_FINFO, &finfo,
					    FSE_ARG_DONE);
			}

			release_pathbuff(target_path);
		}
	}
#endif

	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&ni);

	if (xp)
		vnode_put(xp);
	vnode_put(dvp);
out:
	if (nd->nd_vers == NFS_VER3) {
		nfsm_srv_vattr_init(&attr, NFS_VER3);
		attrerr = vnode_getattr(vp, &attr, ctx);
	}
	if (dirp) {
		nfsm_srv_vattr_init(&dpostattr, nd->nd_vers);
		dpostattrerr = vnode_getattr(dirp, &dpostattr, ctx);
		vnode_put(dirp);
		dirp = NULL;
	}
	vnode_put(vp);
	vp = NULL;

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPATTR(nd->nd_vers) + NFSX_WCCDATA(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			dpreattrerr, &dpreattr, dpostattrerr, &dpostattr);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (vp)
		vnode_put(vp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs symbolic link service
 */
int
nfsrv_symlink(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct vnode_attr dpreattr, dpostattr, postattr;
	struct vnode_attr va, *vap = &va;
	struct nameidata ni;
	int error, dpreattrerr, dpostattrerr, postattrerr;
	uint32_t len = 0, linkdatalen, cnflags;
	uid_t saved_uid;
	char *linkdata;
	vnode_t vp, dvp, dirp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx = NULL;
	struct nfs_export_options *nxo;
	uio_t auio = NULL;
	char uio_buf[ UIO_SIZEOF(1) ];
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	dpreattrerr = dpostattrerr = postattrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	linkdata = NULL;
	dirp = NULL;

	saved_uid = kauth_cred_getuid(nd->nd_cr);

	ni.ni_cnd.cn_nameiop = 0;
	vp = dvp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);

	ni.ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_LINK;
#endif
	ni.ni_cnd.cn_flags = LOCKPARENT;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	if (!error) {
		error = nfsrv_namei(nd, ctx, &ni, &nfh, &dirp, &nx, &nxo);
		if (nx != NULL) {
			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);
		}
	}
	if (dirp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&dpreattr);
			dpreattrerr = vnode_getattr(dirp, &dpreattr, ctx);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error) {
		ni.ni_cnd.cn_nameiop = 0;
		goto out1;
	}
	dvp = ni.ni_dvp;
	vp = ni.ni_vp;

	VATTR_INIT(vap);
	if (nd->nd_vers == NFS_VER3)
		error = nfsm_chain_get_sattr(nd, nmreq, vap);
	nfsm_chain_get_32(error, nmreq, linkdatalen);
	if (!error && (((nd->nd_vers == NFS_VER2) && (linkdatalen > NFS_MAXPATHLEN)) ||
			((nd->nd_vers == NFS_VER3) && (linkdatalen > MAXPATHLEN))))
		error = NFSERR_NAMETOL;
	nfsmerr_if(error);
	MALLOC(linkdata, caddr_t, linkdatalen + 1, M_TEMP, M_WAITOK);
	if (linkdata)
		auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ,
					&uio_buf[0], sizeof(uio_buf));
	if (!linkdata || !auio) {
		error = ENOMEM;
		goto out;
	}
	uio_addiov(auio, CAST_USER_ADDR_T(linkdata), linkdatalen);
	error = nfsm_chain_get_uio(nmreq, linkdatalen, auio);
	if (!error && (nd->nd_vers == NFS_VER2))
		error = nfsm_chain_get_sattr(nd, nmreq, vap);
	nfsmerr_if(error);
	*(linkdata + linkdatalen) = '\0';
	if (vp) {
		error = EEXIST;
		goto out;
	}

	VATTR_SET(vap, va_type, VLNK);
	VATTR_CLEAR_ACTIVE(vap, va_data_size);
	VATTR_CLEAR_ACTIVE(vap, va_access_time);
	/*
	 * Server policy is to alway use the mapped rpc credential for 
	 * file system object creation. This has the nice side effect of
	 * enforcing BSD creation semantics
	 */
	VATTR_CLEAR_ACTIVE(vap, va_uid);
	VATTR_CLEAR_ACTIVE(vap, va_gid);

	/* authorize before creating */
	error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx, nxo, 0);

	/* validate given attributes */
	if (!error)
		error = vnode_authattr_new(dvp, vap, 0, ctx);

	if (!error)
		error = VNOP_SYMLINK(dvp, &vp, &ni.ni_cnd, vap, linkdata, ctx);

	if (!error && (nd->nd_vers == NFS_VER3)) {
		if (vp == NULL) {
			ni.ni_cnd.cn_nameiop = LOOKUP;
#if CONFIG_TRIGGERS
			ni.ni_op = OP_LOOKUP;
#endif
			ni.ni_cnd.cn_flags &= ~(LOCKPARENT | FOLLOW);
			ni.ni_cnd.cn_flags |= (NOFOLLOW | LOCKLEAF);
			ni.ni_cnd.cn_context = ctx;
			ni.ni_startdir = dvp;
			ni.ni_usedvp   = dvp;
			cnflags = ni.ni_cnd.cn_flags; /* store in case we have to restore */
			while ((error = lookup(&ni)) == ERECYCLE) {
				ni.ni_cnd.cn_flags = cnflags;
				ni.ni_cnd.cn_nameptr = ni.ni_cnd.cn_pnbuf;
				ni.ni_usedvp = ni.ni_dvp = ni.ni_startdir = dvp;
			}
			if (!error)
			        vp = ni.ni_vp;
		}
		if (!error) {
			error = nfsrv_vptofh(nx, NFS_VER3, NULL, vp, ctx, &nfh);
			if (!error) {
				nfsm_srv_vattr_init(&postattr, NFS_VER3);
				postattrerr = vnode_getattr(vp, &postattr, ctx);
			}
		}
	}

#if CONFIG_FSE
	if (nfsrv_fsevents_enabled && !error && vp) {
		add_fsevent(FSE_CREATE_FILE, ctx,
			    FSE_ARG_VNODE, vp,
			    FSE_ARG_DONE);
	}
#endif
out:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&ni);
	ni.ni_cnd.cn_nameiop = 0;
	if (vp)
	        vnode_put(vp);
	vnode_put(dvp);
out1:
	if (linkdata) {
		FREE(linkdata, M_TEMP);
		linkdata = NULL;
	}
	if (dirp) {
		nfsm_srv_vattr_init(&dpostattr, nd->nd_vers);
		dpostattrerr = vnode_getattr(dirp, &dpostattr, ctx);
		vnode_put(dirp);
		dirp = NULL;
	}

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_SRVFH(nd->nd_vers, &nfh) +
			NFSX_POSTOPATTR(nd->nd_vers) + NFSX_WCCDATA(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3) {
		if (!nd->nd_repstat) {
			nfsm_chain_add_postop_fh(error, &nmrep, nfh.nfh_fhp, nfh.nfh_len);
			nfsm_chain_add_postop_attr(error, nd, &nmrep, postattrerr, &postattr);
		}
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			dpreattrerr, &dpreattr, dpostattrerr, &dpostattr);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (ni.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&ni);

		if (vp)
			vnode_put(vp);
		vnode_put(dvp);
	}
	if (dirp)
		vnode_put(dirp);
	if (linkdata)
		FREE(linkdata, M_TEMP);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs mkdir service
 */
 
int
nfsrv_mkdir(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct vnode_attr dpreattr, dpostattr, postattr;
	struct vnode_attr va, *vap = &va;
	struct nameidata ni;
	int error, dpreattrerr, dpostattrerr, postattrerr;
	uint32_t len = 0;
	vnode_t vp, dvp, dirp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx = NULL;
	struct nfs_export_options *nxo;
	uid_t saved_uid;
	kauth_acl_t xacl = NULL;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	dpreattrerr = dpostattrerr = postattrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);

	saved_uid = kauth_cred_getuid(nd->nd_cr);

	ni.ni_cnd.cn_nameiop = 0;
	vp = dvp = dirp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);

	ni.ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_LINK;
#endif
	ni.ni_cnd.cn_flags = LOCKPARENT;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	if (!error) {
		error = nfsrv_namei(nd, ctx, &ni, &nfh, &dirp, &nx, &nxo);
		if (nx != NULL) {
			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);
		}
	}
	if (dirp) {
		if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&dpreattr);
			dpreattrerr = vnode_getattr(dirp, &dpreattr, ctx);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error) {
		ni.ni_cnd.cn_nameiop = 0;
		goto nfsmerr;
	}
	dvp = ni.ni_dvp;
	vp = ni.ni_vp;

	VATTR_INIT(vap);
	error = nfsm_chain_get_sattr(nd, nmreq, vap);
	nfsmerr_if(error);
	VATTR_SET(vap, va_type, VDIR);

	if (vp != NULL) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
	        nameidone(&ni);
		vnode_put(dvp);
		vnode_put(vp);
		error = EEXIST;
		goto out;
	}

	error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_SUBDIRECTORY, ctx, nxo, 0);

	/* construct ACL and handle inheritance */
	if (!error) {
		error = kauth_acl_inherit(dvp,
		    NULL,
		    &xacl,	/* isdir */
		    1,
		    ctx);
		
		if (!error && xacl != NULL)
		        VATTR_SET(vap, va_acl, xacl);
	}

	VATTR_CLEAR_ACTIVE(vap, va_data_size);
	VATTR_CLEAR_ACTIVE(vap, va_access_time);
	/*
	 * We don't support the S_ISGID bit for directories. Solaris and other
	 * SRV4 derived systems might set this to get BSD semantics, which we enforce
	 * any ways. 
	 */
	if (VATTR_IS_ACTIVE(vap, va_mode))
		vap->va_mode &= ~S_ISGID;
	/*
	 * Server policy is to alway use the mapped rpc credential for 
	 * file system object creation. This has the nice side effect of
	 * enforcing BSD creation semantics
	 */
	VATTR_CLEAR_ACTIVE(vap, va_uid);
	VATTR_CLEAR_ACTIVE(vap, va_gid);

	/* validate new-file security information */
	if (!error)
		error = vnode_authattr_new(dvp, vap, 0, ctx);
	/*
	 * vnode_authattr_new can return errors other than EPERM, but that's not going to 
	 * sit well with our clients so we map all errors to EPERM.
         */
	if (error)
		error = EPERM;

	if (!error)
		error = VNOP_MKDIR(dvp, &vp, &ni.ni_cnd, vap, ctx);

#if CONFIG_FSE
	if (nfsrv_fsevents_enabled && !error)
		add_fsevent(FSE_CREATE_DIR, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
#endif

	if (!error && !VATTR_ALL_SUPPORTED(vap))
	        /*
		 * If some of the requested attributes weren't handled by the VNOP,
		 * use our fallback code.
		 */
		error = vnode_setattr_fallback(vp, vap, ctx);

	if (xacl != NULL)
		kauth_acl_free(xacl);
	
	if (!error) {
		error = nfsrv_vptofh(nx, nd->nd_vers, NULL, vp, ctx, &nfh);
		if (!error) {
			nfsm_srv_vattr_init(&postattr, nd->nd_vers);
			postattrerr = vnode_getattr(vp, &postattr, ctx);
			if (nd->nd_vers == NFS_VER2)
				error = postattrerr;
		}
		vnode_put(vp);
		vp = NULL;
	}
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&ni);
	vnode_put(dvp);
out:
	ni.ni_cnd.cn_nameiop = 0;

	if (dirp) {
		nfsm_srv_vattr_init(&dpostattr, nd->nd_vers);
		dpostattrerr = vnode_getattr(dirp, &dpostattr, ctx);
		vnode_put(dirp);
		dirp = NULL;
	}

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_SRVFH(nd->nd_vers, &nfh) +
			NFSX_POSTOPATTR(nd->nd_vers) + NFSX_WCCDATA(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3) {
		if (!nd->nd_repstat) {
			nfsm_chain_add_postop_fh(error, &nmrep, nfh.nfh_fhp, nfh.nfh_len);
			nfsm_chain_add_postop_attr(error, nd, &nmrep, postattrerr, &postattr);
		}
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			dpreattrerr, &dpreattr, dpostattrerr, &dpostattr);
	} else {
		nfsm_chain_add_fh(error, &nmrep, NFS_VER2, nfh.nfh_fhp, nfh.nfh_len);
		if (!error)
			error = nfsm_chain_add_fattr(nd, &nmrep, &postattr);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (ni.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&ni);
		vnode_put(dvp);
		if (vp)
			vnode_put(vp);
	}
	if (dirp)
		vnode_put(dirp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs rmdir service
 */
int
nfsrv_rmdir(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	int error, dpreattrerr, dpostattrerr;
	uint32_t len = 0;
	uid_t saved_uid;
	vnode_t vp, dvp, dirp;
	struct vnode_attr dpreattr, dpostattr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx = NULL;
	struct nfs_export_options *nxo;
	struct nameidata ni;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	dpreattrerr = dpostattrerr = ENOENT;
	saved_uid = kauth_cred_getuid(nd->nd_cr);
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);

	vp = dvp = dirp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_32(error, nmreq, len);
	nfsm_name_len_check(error, nd, len);
	nfsmerr_if(error);

	ni.ni_cnd.cn_nameiop = DELETE;
#if CONFIG_TRIGGERS
	ni.ni_op = OP_UNLINK;
#endif
	ni.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_chain_get_path_namei(nmreq, len, &ni);
	if (!error) {
		error = nfsrv_namei(nd, ctx, &ni, &nfh, &dirp, &nx, &nxo);
		if (nx != NULL) {
			/* update export stats */
			NFSStatAdd64(&nx->nx_stats.ops, 1);

			/* update active user stats */
			nfsrv_update_user_stat(nx, nd, saved_uid, 1, 0, 0);
		}
	}
	if (dirp) {
	        if (nd->nd_vers == NFS_VER3) {
			nfsm_srv_pre_vattr_init(&dpreattr);
			dpreattrerr = vnode_getattr(dirp, &dpreattr, ctx);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	nfsmerr_if(error);

	dvp = ni.ni_dvp;
	vp = ni.ni_vp;

	if (vnode_vtype(vp) != VDIR) {
		error = ENOTDIR;
		goto out;
	}
	/*
	 * No rmdir "." please.
	 */
	if (dvp == vp) {
		error = EINVAL;
		goto out;
	}
	/*
	 * The root of a mounted filesystem cannot be deleted.
	 */
	if (vnode_isvroot(vp))
		error = EBUSY;
	if (!error)
		error = nfsrv_authorize(vp, dvp, KAUTH_VNODE_DELETE, ctx, nxo, 0);
	if (!error) {
#if CONFIG_FSE
		char     *path = NULL;
		int       plen;
		fse_info  finfo;
		
		if (nfsrv_fsevents_enabled && need_fsevent(FSE_DELETE, dvp)) {
			plen = MAXPATHLEN;
		        if ((path = get_pathbuff()) && !vn_getpath(vp, path, &plen)) {
				get_fse_info(vp, &finfo, ctx);
			} else if (path) {
				release_pathbuff(path);
				path = NULL;
			}
		}
#endif /* CONFIG_FSE */

		error = VNOP_RMDIR(dvp, vp, &ni.ni_cnd, ctx);

#if CONFIG_FSE
		if (path) {
			if (!error)
				add_fsevent(FSE_DELETE, ctx,
					FSE_ARG_STRING, plen, path,
					FSE_ARG_FINFO, &finfo,
					FSE_ARG_DONE);
		        release_pathbuff(path);
		}
#endif /* CONFIG_FSE */
	}
out:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&ni);

	vnode_put(dvp);
	vnode_put(vp);

	if (dirp) {
		nfsm_srv_vattr_init(&dpostattr, nd->nd_vers);
		dpostattrerr = vnode_getattr(dirp, &dpostattr, ctx);
		vnode_put(dirp);
		dirp = NULL;
	}

nfsmerr:
	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_WCCDATA(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_add_wcc_data(error, nd, &nmrep,
			dpreattrerr, &dpreattr, dpostattrerr, &dpostattr);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (dirp)
		vnode_put(dirp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs readdir service
 * - mallocs what it thinks is enough to read
 *	count rounded up to a multiple of NFS_DIRBLKSIZ <= NFS_MAXREADDIR
 * - calls VNOP_READDIR()
 * - loops around building the reply
 *	if the output generated exceeds count break out of loop
 *	The nfsm_clget macro is used here so that the reply will be packed
 *	tightly in mbuf clusters.
 * - it only knows that it has encountered eof when the VNOP_READDIR()
 *	reads nothing
 * - as such one readdir rpc will return eof false although you are there
 *	and then the next will return eof
 * - it trims out records with d_fileno == 0
 *	this doesn't matter for Unix clients, but they might confuse clients
 *	for other os'.
 * NB: It is tempting to set eof to true if the VNOP_READDIR() reads less
 *	than requested, but this may not apply to all filesystems. For
 *	example, client NFS does not { although it is never remote mounted
 *	anyhow }
 *     The alternate call nfsrv_readdirplus() does lookups as well.
 * PS:  The XNFS protocol spec clearly describes what the "count"s arguments
 *      are supposed to cover.  For readdir, the count is the total number of
 *      bytes included in everything from the directory's postopattr through
 *      the EOF flag.  For readdirplus, the maxcount is the same, and the
 *      dircount includes all that except for the entry attributes and handles.
 */
int
nfsrv_readdir(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct direntry *dp;
	char *cpos, *cend, *rbuf;
	vnode_t vp;
	struct vnode_attr attr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t auio = NULL;
	char uio_buf[ UIO_SIZEOF(1) ];
	int len, nlen, rem, xfer, error, attrerr;
	int siz, count, fullsiz, eofflag, nentries;
	u_quad_t off, toff, verf;
	int vnopflag;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	attrerr = ENOENT;
	count = nentries = 0;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	rbuf = NULL;
	vp = NULL;

	vnopflag = VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_get_64(error, nmreq, toff);
		nfsm_chain_get_64(error, nmreq, verf);
	} else {
		nfsm_chain_get_32(error, nmreq, toff);
	}
	nfsm_chain_get_32(error, nmreq, count);
	nfsmerr_if(error);

	off = toff;
	siz = ((count + DIRBLKSIZ - 1) & ~(DIRBLKSIZ - 1));
	xfer = NFSRV_NDMAXDATA(nd);
	if (siz > xfer)
		siz = xfer;
	fullsiz = siz;

	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	if (nxo->nxo_flags & NX_MANGLEDNAMES || nd->nd_vers == NFS_VER2)
		vnopflag |= VNODE_READDIR_NAMEMAX;

	if ((nd->nd_vers == NFS_VER2) || (nxo->nxo_flags & NX_32BITCLIENTS))
		vnopflag |= VNODE_READDIR_SEEKOFF32;

	if (nd->nd_vers == NFS_VER3) {
		nfsm_srv_vattr_init(&attr, NFS_VER3);
		error = attrerr = vnode_getattr(vp, &attr, ctx);
		if (!error && toff && verf && (verf != attr.va_filerev))
			error = NFSERR_BAD_COOKIE;
	}
	if (!error)
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_LIST_DIRECTORY, ctx, nxo, 0);
	nfsmerr_if(error);

	MALLOC(rbuf, caddr_t, siz, M_TEMP, M_WAITOK);
	if (rbuf)
		auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ,
				    &uio_buf[0], sizeof(uio_buf));
	if (!rbuf || !auio) {
		error = ENOMEM;
		goto nfsmerr;
	}
again:
	uio_reset(auio, off, UIO_SYSSPACE, UIO_READ);
	uio_addiov(auio, CAST_USER_ADDR_T(rbuf), fullsiz);
	eofflag = 0;
	error = VNOP_READDIR(vp, auio, vnopflag, &eofflag, &nentries, ctx);
	off = uio_offset(auio);

	if (nd->nd_vers == NFS_VER3) {
		nfsm_srv_vattr_init(&attr, NFS_VER3);
		attrerr = vnode_getattr(vp, &attr, ctx);
	}
	nfsmerr_if(error);

	if (uio_resid(auio) != 0) {
		siz -= uio_resid(auio);

		/* If nothing read, return empty reply with eof set */
		if (siz == 0) {
			vnode_put(vp);
			vp = NULL;
			FREE(rbuf, M_TEMP);
			/* assemble reply */
			nd->nd_repstat = error;
			error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPATTR(nd->nd_vers) +
					NFSX_COOKIEVERF(nd->nd_vers) + 2 * NFSX_UNSIGNED);
			nfsmout_if(error);
			*mrepp = nmrep.nmc_mhead;
			nfsmout_on_status(nd, error);
			if (nd->nd_vers == NFS_VER3) {
				nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
				nfsm_chain_add_64(error, &nmrep, attr.va_filerev);
			}
			nfsm_chain_add_32(error, &nmrep, FALSE);
			nfsm_chain_add_32(error, &nmrep, TRUE);
			nfsm_chain_build_done(error, &nmrep);
			return (error);
		}
	}

	/*
	 * Check for degenerate cases of nothing useful read.
	 * If so go try again
	 */
	cpos = rbuf;
	cend = rbuf + siz;
	dp = (struct direntry *)cpos;
	while ((dp->d_fileno == 0) && (cpos < cend) && (nentries > 0)) {
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	if ((cpos >= cend) || (nentries == 0)) {
		toff = off;
		siz = fullsiz;
		goto again;
	}

	vnode_put(vp);
	vp = NULL;

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPATTR(nd->nd_vers) +
			NFSX_COOKIEVERF(nd->nd_vers) + siz);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	nmrep.nmc_flags |= NFSM_CHAIN_FLAG_ADD_CLUSTERS;

	len = 2 * NFSX_UNSIGNED;
	if (nd->nd_vers == NFS_VER3) {
		len += NFSX_V3POSTOPATTR + NFSX_V3COOKIEVERF;
		nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
		nfsm_chain_add_64(error, &nmrep, attr.va_filerev);
		nfsmerr_if(error);
	}

	/* Loop through the records and build reply */
	while ((cpos < cend) && (nentries > 0)) {
		if (dp->d_fileno != 0) {
			nlen = dp->d_namlen;
			if ((nd->nd_vers == NFS_VER2) && (nlen > NFS_MAXNAMLEN))
				nlen = NFS_MAXNAMLEN;
			rem = nfsm_rndup(nlen)-nlen;
			len += (4 * NFSX_UNSIGNED + nlen + rem);
			if (nd->nd_vers == NFS_VER3)
				len += 2 * NFSX_UNSIGNED;
			if (len > count) {
				eofflag = 0;
				break;
			}
			/* Build the directory record xdr from the direntry. */
			nfsm_chain_add_32(error, &nmrep, TRUE);
			if (nd->nd_vers == NFS_VER3) {
				nfsm_chain_add_64(error, &nmrep, dp->d_fileno);
			} else {
				nfsm_chain_add_32(error, &nmrep, dp->d_fileno);
			}
			nfsm_chain_add_string(error, &nmrep, dp->d_name, nlen);
			if (nd->nd_vers == NFS_VER3) {
				if (vnopflag & VNODE_READDIR_SEEKOFF32)
					dp->d_seekoff &= 0x00000000ffffffffULL;
				nfsm_chain_add_64(error, &nmrep, dp->d_seekoff);
			} else {
				nfsm_chain_add_32(error, &nmrep, dp->d_seekoff);
			}
			nfsmerr_if(error);
		}
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	nfsm_chain_add_32(error, &nmrep, FALSE);
	nfsm_chain_add_32(error, &nmrep, eofflag ? TRUE : FALSE);
	FREE(rbuf, M_TEMP);
	goto nfsmout;
nfsmerr:
	if (rbuf)
		FREE(rbuf, M_TEMP);
	if (vp)
		vnode_put(vp);
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPATTR(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

int
nfsrv_readdirplus(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct direntry *dp;
	char *cpos, *cend, *rbuf;
	vnode_t vp, nvp;
	struct nfs_filehandle dnfh, nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t auio = NULL;
	char uio_buf[ UIO_SIZEOF(1) ];
	struct vnode_attr attr, va, *vap = &va;
	int len, nlen, rem, xfer, error, attrerr, gotfh, gotattr;
	int siz, dircount, maxcount, fullsiz, eofflag, dirlen, nentries, isdotdot;
	u_quad_t off, toff, verf;
	int vnopflag;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	attrerr = ENOENT;
	nentries = 0;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	rbuf = NULL;
	vp = NULL;
	dircount = maxcount = 0;

	vnopflag = VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, dnfh.nfh_fhp, dnfh.nfh_len);
	nfsm_chain_get_64(error, nmreq, toff);
	nfsm_chain_get_64(error, nmreq, verf);
	nfsm_chain_get_32(error, nmreq, dircount);
	nfsm_chain_get_32(error, nmreq, maxcount);
	nfsmerr_if(error);

	off = toff;
	xfer = NFSRV_NDMAXDATA(nd);
	dircount = ((dircount + DIRBLKSIZ - 1) & ~(DIRBLKSIZ - 1));
	if (dircount > xfer)
		dircount = xfer;
	fullsiz = siz = dircount;
	maxcount = ((maxcount + DIRBLKSIZ - 1) & ~(DIRBLKSIZ - 1));
	if (maxcount > xfer)
		maxcount = xfer;

	error = nfsrv_fhtovp(&dnfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	if (nxo->nxo_flags & NX_32BITCLIENTS)
		vnopflag |= VNODE_READDIR_SEEKOFF32;

	if (nxo->nxo_flags & NX_MANGLEDNAMES)
		vnopflag |= VNODE_READDIR_NAMEMAX;

	nfsm_srv_vattr_init(&attr, NFS_VER3);
	error = attrerr = vnode_getattr(vp, &attr, ctx);
	if (!error && toff && verf && (verf != attr.va_filerev))
		error = NFSERR_BAD_COOKIE;
	if (!error)
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_LIST_DIRECTORY, ctx, nxo, 0);
	nfsmerr_if(error);

	MALLOC(rbuf, caddr_t, siz, M_TEMP, M_WAITOK);
	if (rbuf)
		auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ,
				    &uio_buf[0], sizeof(uio_buf));
	if (!rbuf || !auio) {
		error = ENOMEM;
		goto nfsmerr;
	}

again:
	uio_reset(auio, off, UIO_SYSSPACE, UIO_READ);
	uio_addiov(auio, CAST_USER_ADDR_T(rbuf), fullsiz);
	eofflag = 0;
	error = VNOP_READDIR(vp, auio, vnopflag, &eofflag, &nentries, ctx);
	off = uio_offset(auio);
	nfsm_srv_vattr_init(&attr, NFS_VER3);
	attrerr = vnode_getattr(vp, &attr, ctx);
	nfsmerr_if(error);

	if (uio_resid(auio) != 0) {
		siz -= uio_resid(auio);

		/* If nothing read, return empty reply with eof set */
		if (siz == 0) {
			vnode_put(vp);
			vp = NULL;
			FREE(rbuf, M_TEMP);
			/* assemble reply */
			nd->nd_repstat = error;
			error = nfsrv_rephead(nd, slp, &nmrep, NFSX_V3POSTOPATTR +
					NFSX_V3COOKIEVERF + 2 * NFSX_UNSIGNED);
			nfsmout_if(error);
			*mrepp = nmrep.nmc_mhead;
			nfsmout_on_status(nd, error);
			nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
			nfsm_chain_add_64(error, &nmrep, attr.va_filerev);
			nfsm_chain_add_32(error, &nmrep, FALSE);
			nfsm_chain_add_32(error, &nmrep, TRUE);
			nfsm_chain_build_done(error, &nmrep);
			return (error);
		}
	}

	/*
	 * Check for degenerate cases of nothing useful read.
	 * If so go try again
	 */
	cpos = rbuf;
	cend = rbuf + siz;
	dp = (struct direntry *)cpos;
	while ((dp->d_fileno == 0) && (cpos < cend) && (nentries > 0)) {
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	if ((cpos >= cend) || (nentries == 0)) {
		toff = off;
		siz = fullsiz;
		goto again;
	}

	/*
	 * Probe one of the directory entries to see if the filesystem
	 * supports VGET.
	 */
	if ((error = VFS_VGET(vnode_mount(vp), (ino64_t)dp->d_fileno, &nvp, ctx))) {
		if (error == ENOTSUP) /* let others get passed back */
			error = NFSERR_NOTSUPP;
		goto nfsmerr;
	}
	vnode_put(nvp);

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, maxcount);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	nmrep.nmc_flags |= NFSM_CHAIN_FLAG_ADD_CLUSTERS;

	dirlen = len = NFSX_V3POSTOPATTR + NFSX_V3COOKIEVERF + 2 * NFSX_UNSIGNED;
	nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
	nfsm_chain_add_64(error, &nmrep, attr.va_filerev);
	nfsmerr_if(error);

	/* Loop through the records and build reply */
	while ((cpos < cend) && (nentries > 0)) {
		if (dp->d_fileno != 0) {
			nlen = dp->d_namlen;
			rem = nfsm_rndup(nlen)-nlen;
			gotfh = gotattr = 1;

			/* Got to get the vnode for lookup per entry. */
			if (VFS_VGET(vnode_mount(vp), (ino64_t)dp->d_fileno, &nvp, ctx)) {
				/* Can't get the vnode... so no fh or attrs */
				gotfh = gotattr = 0;
			} else {
				isdotdot = ((dp->d_namlen == 2) &&
					    (dp->d_name[0] == '.') && (dp->d_name[1] == '.'));
				if (nfsrv_vptofh(nx, 0, (isdotdot ? &dnfh : NULL), nvp, ctx, &nfh))
					gotfh = 0;
				nfsm_srv_vattr_init(vap, NFS_VER3);
				if (vnode_getattr(nvp, vap, ctx))
					gotattr = 0;
				vnode_put(nvp);
			}

			/*
			 * If either the dircount or maxcount will be
			 * exceeded, get out now. Both of these lengths
			 * are calculated conservatively, including all
			 * XDR overheads.
			 */
			len += 8 * NFSX_UNSIGNED + nlen + rem;
			if (gotattr)
				len += NFSX_V3FATTR;
			if (gotfh)
				len += NFSX_UNSIGNED + nfsm_rndup(nfh.nfh_len);
			dirlen += 6 * NFSX_UNSIGNED + nlen + rem;
			if ((len > maxcount) || (dirlen > dircount)) {
				eofflag = 0;
				break;
			}

			/* Build the directory record xdr from the direntry. */
			nfsm_chain_add_32(error, &nmrep, TRUE);
			nfsm_chain_add_64(error, &nmrep, dp->d_fileno);
			nfsm_chain_add_string(error, &nmrep, dp->d_name, nlen);
			if (vnopflag & VNODE_READDIR_SEEKOFF32)
				dp->d_seekoff &= 0x00000000ffffffffULL;
			nfsm_chain_add_64(error, &nmrep, dp->d_seekoff);
			nfsm_chain_add_postop_attr(error, nd, &nmrep, (gotattr ? 0 : ENOENT), vap);
			if (gotfh)
				nfsm_chain_add_postop_fh(error, &nmrep, nfh.nfh_fhp, nfh.nfh_len);
			else
				nfsm_chain_add_32(error, &nmrep, FALSE);
			nfsmerr_if(error);
		}
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	vnode_put(vp);
	vp = NULL;
	nfsm_chain_add_32(error, &nmrep, FALSE);
	nfsm_chain_add_32(error, &nmrep, eofflag ? TRUE : FALSE);
	FREE(rbuf, M_TEMP);
	goto nfsmout;
nfsmerr:
	if (rbuf)
		FREE(rbuf, M_TEMP);
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_V3POSTOPATTR);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (vp)
		vnode_put(vp);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs commit service
 */
int
nfsrv_commit(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	int error, preattrerr, postattrerr, count;
	struct vnode_attr preattr, postattr;
	u_quad_t off;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	preattrerr = postattrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	vp = NULL;

	/*
	 * XXX At this time VNOP_FSYNC() does not accept offset and byte
	 * count parameters, so those arguments are useless (someday maybe).
	 */

	nfsm_chain_get_fh_ptr(error, nmreq, NFS_VER3, nfh.nfh_fhp, nfh.nfh_len);
	nfsm_chain_get_64(error, nmreq, off);
	nfsm_chain_get_32(error, nmreq, count);
	nfsmerr_if(error);

	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	nfsm_srv_pre_vattr_init(&preattr);
	preattrerr = vnode_getattr(vp, &preattr, ctx);

	error = VNOP_FSYNC(vp, MNT_WAIT, ctx);

	nfsm_srv_vattr_init(&postattr, 1);
	postattrerr = vnode_getattr(vp, &postattr, ctx);

nfsmerr:
	if (vp)
		vnode_put(vp);

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_V3WCCDATA + NFSX_V3WRITEVERF);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	nfsm_chain_add_wcc_data(error, nd, &nmrep,
		preattrerr, &preattr, postattrerr, &postattr);
	if (!nd->nd_repstat) {
		nfsm_chain_add_32(error, &nmrep, nx->nx_exptime.tv_sec);
		nfsm_chain_add_32(error, &nmrep, nx->nx_exptime.tv_usec);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs statfs service
 */
int
nfsrv_statfs(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	struct vfs_attr va;
	int error, attrerr;
	vnode_t vp;
	struct vnode_attr attr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	off_t blksize;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	attrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	vp = NULL;
	blksize = 512;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	VFSATTR_INIT(&va);
	VFSATTR_WANTED(&va, f_blocks);
	VFSATTR_WANTED(&va, f_bavail);
	VFSATTR_WANTED(&va, f_files);
	VFSATTR_WANTED(&va, f_ffree);
	error = vfs_getattr(vnode_mount(vp), &va, ctx);
	blksize = vnode_mount(vp)->mnt_vfsstat.f_bsize;

	if (nd->nd_vers == NFS_VER3) {
		nfsm_srv_vattr_init(&attr, nd->nd_vers);
		attrerr = vnode_getattr(vp, &attr, ctx);
	}

nfsmerr:
	if (vp)
		vnode_put(vp);

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_POSTOPATTR(nd->nd_vers) + NFSX_STATFS(nd->nd_vers));
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	if (nd->nd_vers == NFS_VER3)
		nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
	nfsmout_if(nd->nd_repstat);

	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_64(error, &nmrep, va.f_blocks * blksize);
		nfsm_chain_add_64(error, &nmrep, va.f_bfree * blksize);
		nfsm_chain_add_64(error, &nmrep, va.f_bavail * blksize);
		nfsm_chain_add_64(error, &nmrep, va.f_files);
		nfsm_chain_add_64(error, &nmrep, va.f_ffree);
		nfsm_chain_add_64(error, &nmrep, va.f_ffree);
		nfsm_chain_add_32(error, &nmrep, 0); /* invarsec */
	} else {
		nfsm_chain_add_32(error, &nmrep, NFS_V2MAXDATA);
		nfsm_chain_add_32(error, &nmrep, blksize);
		nfsm_chain_add_32(error, &nmrep, va.f_blocks);
		nfsm_chain_add_32(error, &nmrep, va.f_bfree);
		nfsm_chain_add_32(error, &nmrep, va.f_bavail);
	}
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs fsinfo service
 */
int
nfsrv_fsinfo(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	int error, attrerr, prefsize, maxsize;
	vnode_t vp;
	struct vnode_attr attr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	attrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	vp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	nfsm_srv_vattr_init(&attr, NFS_VER3);
	attrerr = vnode_getattr(vp, &attr, ctx);

nfsmerr:
	if (vp)
		vnode_put(vp);

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_V3POSTOPATTR + NFSX_V3FSINFO);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
	nfsmout_if(nd->nd_repstat);

	/*
	 * XXX There should be file system VFS OP(s) to get this information.
	 * For now, assume our usual NFS defaults.
	 */
	if (slp->ns_sotype == SOCK_DGRAM) {
		maxsize = NFS_MAXDGRAMDATA;
		prefsize = NFS_PREFDGRAMDATA;
	} else
		maxsize = prefsize = NFSRV_MAXDATA;

	nfsm_chain_add_32(error, &nmrep, maxsize);
	nfsm_chain_add_32(error, &nmrep, prefsize);
	nfsm_chain_add_32(error, &nmrep, NFS_FABLKSIZE);
	nfsm_chain_add_32(error, &nmrep, maxsize);
	nfsm_chain_add_32(error, &nmrep, prefsize);
	nfsm_chain_add_32(error, &nmrep, NFS_FABLKSIZE);
	nfsm_chain_add_32(error, &nmrep, prefsize);
	nfsm_chain_add_64(error, &nmrep, 0xffffffffffffffffULL);
	nfsm_chain_add_32(error, &nmrep, 0);
	nfsm_chain_add_32(error, &nmrep, 1);
	/* XXX link/symlink support should be taken from volume capabilities */
	nfsm_chain_add_32(error, &nmrep,
		NFSV3FSINFO_LINK | NFSV3FSINFO_SYMLINK |
		NFSV3FSINFO_HOMOGENEOUS | NFSV3FSINFO_CANSETTIME);

nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * nfs pathconf service
 */
int
nfsrv_pathconf(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	vfs_context_t ctx,
	mbuf_t *mrepp)
{
	int error, attrerr, linkmax, namemax;
	int chownres, notrunc, case_sensitive, case_preserving;
	vnode_t vp;
	struct vnode_attr attr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct nfsm_chain *nmreq, nmrep;

	error = 0;
	attrerr = ENOENT;
	nmreq = &nd->nd_nmreq;
	nfsm_chain_null(&nmrep);
	vp = NULL;

	nfsm_chain_get_fh_ptr(error, nmreq, nd->nd_vers, nfh.nfh_fhp, nfh.nfh_len);
	nfsmerr_if(error);
	error = nfsrv_fhtovp(&nfh, nd, &vp, &nx, &nxo);
	nfsmerr_if(error);

	/* update export stats */
	NFSStatAdd64(&nx->nx_stats.ops, 1);

	/* update active user stats */
	nfsrv_update_user_stat(nx, nd, kauth_cred_getuid(nd->nd_cr), 1, 0, 0);

	error = nfsrv_credcheck(nd, ctx, nx, nxo);
	nfsmerr_if(error);

	error = VNOP_PATHCONF(vp, _PC_LINK_MAX, &linkmax, ctx);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_NAME_MAX, &namemax, ctx);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_CHOWN_RESTRICTED, &chownres, ctx);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_NO_TRUNC, &notrunc, ctx);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_CASE_SENSITIVE, &case_sensitive, ctx);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_CASE_PRESERVING, &case_preserving, ctx);

	nfsm_srv_vattr_init(&attr, NFS_VER3);
	attrerr = vnode_getattr(vp, &attr, ctx);

nfsmerr:
	if (vp)
		vnode_put(vp);

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, NFSX_V3POSTOPATTR + NFSX_V3PATHCONF);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
	nfsmout_on_status(nd, error);
	nfsm_chain_add_postop_attr(error, nd, &nmrep, attrerr, &attr);
	nfsmout_if(nd->nd_repstat);

	nfsm_chain_add_32(error, &nmrep, linkmax);
	nfsm_chain_add_32(error, &nmrep, namemax);
	nfsm_chain_add_32(error, &nmrep, notrunc);
	nfsm_chain_add_32(error, &nmrep, chownres);
	nfsm_chain_add_32(error, &nmrep, !case_sensitive);
	nfsm_chain_add_32(error, &nmrep, case_preserving);

nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * Null operation, used by clients to ping server
 */
/* ARGSUSED */
int
nfsrv_null(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	__unused vfs_context_t ctx,
	mbuf_t *mrepp)
{
	int error = NFSERR_RETVOID;
	struct nfsm_chain nmrep;

	/*
	 * RPCSEC_GSS context setup ?
	 */
	if (nd->nd_gss_context)
		return(nfs_gss_svc_ctx_init(nd, slp, mrepp));

	nfsm_chain_null(&nmrep);

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, 0);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

/*
 * No operation, used for obsolete procedures
 */
/* ARGSUSED */
int
nfsrv_noop(
	struct nfsrv_descript *nd,
	struct nfsrv_sock *slp,
	__unused vfs_context_t ctx,
	mbuf_t *mrepp)
{
	int error;
	struct nfsm_chain nmrep;

	nfsm_chain_null(&nmrep);

	if (nd->nd_repstat)
		error = nd->nd_repstat;
	else
		error = EPROCUNAVAIL;

	/* assemble reply */
	nd->nd_repstat = error;
	error = nfsrv_rephead(nd, slp, &nmrep, 0);
	nfsmout_if(error);
	*mrepp = nmrep.nmc_mhead;
nfsmout:
	nfsm_chain_build_done(error, &nmrep);
	if (error) {
		nfsm_chain_cleanup(&nmrep);
		*mrepp = NULL;
	}
	return (error);
}

int (*nfsrv_procs[NFS_NPROCS])(struct nfsrv_descript *nd,
				    struct nfsrv_sock *slp,
				    vfs_context_t ctx,
				    mbuf_t *mrepp) = {
	nfsrv_null,
	nfsrv_getattr,
	nfsrv_setattr,
	nfsrv_lookup,
	nfsrv_access,
	nfsrv_readlink,
	nfsrv_read,
	nfsrv_write,
	nfsrv_create,
	nfsrv_mkdir,
	nfsrv_symlink,
	nfsrv_mknod,
	nfsrv_remove,
	nfsrv_rmdir,
	nfsrv_rename,
	nfsrv_link,
	nfsrv_readdir,
	nfsrv_readdirplus,
	nfsrv_statfs,
	nfsrv_fsinfo,
	nfsrv_pathconf,
	nfsrv_commit,
	nfsrv_noop
};

/*
 * Perform access checking for vnodes obtained from file handles that would
 * refer to files already opened by a Unix client. You cannot just use
 * vnode_authorize() for two reasons.
 * 1 - You must check for exported rdonly as well as MNT_RDONLY for the write case
 * 2 - The owner is to be given access irrespective of mode bits so that
 *     processes that chmod after opening a file don't break. I don't like
 *     this because it opens a security hole, but since the nfs server opens
 *     a security hole the size of a barn door anyhow, what the heck.
 * 
 * The exception to rule 2 is EPERM. If a file is IMMUTABLE, vnode_authorize()
 * will return EPERM instead of EACCESS. EPERM is always an error.
 */

int
nfsrv_authorize(
	vnode_t vp,
	vnode_t dvp,
	kauth_action_t action,
	vfs_context_t ctx,
	struct nfs_export_options *nxo,
	int override)
{
	struct vnode_attr vattr;
	int error;

	if (action & KAUTH_VNODE_WRITE_RIGHTS) {
		/*
		 * Disallow write attempts on read-only exports;
		 * unless the file is a socket or a block or character
		 * device resident on the file system.
		 */
		if (nxo->nxo_flags & NX_READONLY) {
			switch (vnode_vtype(vp)) {
			case VREG: case VDIR: case VLNK: case VCPLX:
				return (EROFS);
			default:
				break;
			}
		}
	}
	error = vnode_authorize(vp, dvp, action, ctx);
	/*
	 * Allow certain operations for the owner (reads and writes
	 * on files that are already open). Picking up from FreeBSD.
	 */
	if (override && (error == EACCES)) {
		VATTR_INIT(&vattr);
		VATTR_WANTED(&vattr, va_uid);
		if ((vnode_getattr(vp, &vattr, ctx) == 0) &&
		    (kauth_cred_getuid(vfs_context_ucred(ctx)) == vattr.va_uid))
			error = 0;
	}
	return error;
}

#endif /* NFSSERVER */

