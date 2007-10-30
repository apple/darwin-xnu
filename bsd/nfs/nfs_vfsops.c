/*
 * Copyright (c) 2000-2007 Apple Inc.  All rights reserved.
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
 * Copyright (c) 1989, 1993, 1995
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
 *	@(#)nfs_vfsops.c	8.12 (Berkeley) 5/20/95
 * FreeBSD-Id: nfs_vfsops.c,v 1.52 1997/11/12 05:42:21 julian Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/proc_internal.h> /* for fs rooting to update rootdir in fdp */
#include <sys/kauth.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mount_internal.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/fcntl.h>
#include <sys/quota.h>
#include <libkern/OSAtomic.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#if !defined(NO_MOUNT_PRIVATE)
#include <sys/filedesc.h>
#endif /* NO_MOUNT_PRIVATE */

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <nfs/rpcv2.h>
#include <nfs/krpc.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsdiskless.h>
#include <nfs/nfs_lock.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <pexpert/pexpert.h>

/*
 * NFS client globals
 */

int nfs_ticks;
static lck_grp_t *nfs_mount_grp;
uint32_t nfs_fs_attr_bitmap[NFS_ATTR_BITMAP_LEN];
uint32_t nfs_object_attr_bitmap[NFS_ATTR_BITMAP_LEN];
uint32_t nfs_getattr_bitmap[NFS_ATTR_BITMAP_LEN];

/* NFS requests */
struct nfs_reqqhead nfs_reqq;
lck_grp_t *nfs_request_grp;
lck_mtx_t *nfs_request_mutex;
thread_call_t nfs_request_timer_call;
int nfs_request_timer_on;
u_long nfs_xid = 0;
u_long nfs_xidwrap = 0;		/* to build a (non-wrapping) 64 bit xid */

thread_call_t nfs_buf_timer_call;

/* nfsiod */
lck_grp_t *nfsiod_lck_grp;
lck_mtx_t *nfsiod_mutex;
struct nfsiodlist nfsiodfree, nfsiodwork;
struct nfsiodmountlist nfsiodmounts;
int nfsiod_thread_count = 0;
int nfsiod_thread_max = NFS_DEFASYNCTHREAD;
int nfs_max_async_writes = NFS_DEFMAXASYNCWRITES;

int nfs_iosize = NFS_IOSIZE;
int nfs_access_cache_timeout = NFS_MAXATTRTIMO;
int nfs_allow_async = 0;
int nfs_statfs_rate_limit = NFS_DEFSTATFSRATELIMIT;
int nfs_lockd_mounts = 0;
int nfs_lockd_request_sent = 0;

int nfs_tprintf_initial_delay = NFS_TPRINTF_INITIAL_DELAY;
int nfs_tprintf_delay = NFS_TPRINTF_DELAY;


static int	mountnfs(struct user_nfs_args *,mount_t,mbuf_t,vfs_context_t,vnode_t *);
static int	nfs_mount_diskless(struct nfs_dlmount *, const char *, int, vnode_t *, mount_t *, vfs_context_t);
#if !defined(NO_MOUNT_PRIVATE)
static int	nfs_mount_diskless_private(struct nfs_dlmount *, const char *, int, vnode_t *, mount_t *, vfs_context_t);
#endif /* NO_MOUNT_PRIVATE */

/*
 * NFS VFS operations.
 */
static int	nfs_vfs_mount(mount_t, vnode_t, user_addr_t, vfs_context_t);
static int	nfs_vfs_start(mount_t, int, vfs_context_t);
static int	nfs_vfs_unmount(mount_t, int, vfs_context_t);
static int	nfs_vfs_root(mount_t, vnode_t *, vfs_context_t);
static int	nfs_vfs_quotactl(mount_t, int, uid_t, caddr_t, vfs_context_t);
static int	nfs_vfs_getattr(mount_t, struct vfs_attr *, vfs_context_t);
static int	nfs_vfs_sync(mount_t, int, vfs_context_t);
static int	nfs_vfs_vget(mount_t, ino64_t, vnode_t *, vfs_context_t);
static int	nfs_vfs_vptofh(vnode_t, int *, unsigned char *, vfs_context_t);
static int	nfs_vfs_fhtovp(mount_t, int, unsigned char *, vnode_t *, vfs_context_t);
static int	nfs_vfs_init(struct vfsconf *);
static int	nfs_vfs_sysctl(int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t);

struct vfsops nfs_vfsops = {
	nfs_vfs_mount,
	nfs_vfs_start,
	nfs_vfs_unmount,
	nfs_vfs_root,
	nfs_vfs_quotactl,
	nfs_vfs_getattr,
	nfs_vfs_sync,
	nfs_vfs_vget,
	nfs_vfs_fhtovp,
	nfs_vfs_vptofh,
	nfs_vfs_init,
	nfs_vfs_sysctl,
	NULL,		/* setattr */
	{ NULL,		/* reserved */
	  NULL,		/* reserved */
	  NULL,		/* reserved */
	  NULL,		/* reserved */
	  NULL,		/* reserved */
	  NULL,		/* reserved */
	  NULL }	/* reserved */
};


/*
 * version-specific NFS functions
 */
static int nfs3_mount(struct nfsmount *, vfs_context_t, struct user_nfs_args *, nfsnode_t *);
static int nfs4_mount(struct nfsmount *, vfs_context_t, struct user_nfs_args *, nfsnode_t *);
static int nfs3_update_statfs(struct nfsmount *, vfs_context_t);
static int nfs4_update_statfs(struct nfsmount *, vfs_context_t);
#if !QUOTA
#define nfs3_getquota	NULL
#define nfs4_getquota	NULL
#else
static int nfs3_getquota(struct nfsmount *, vfs_context_t, u_long, int, struct dqblk *);
static int nfs4_getquota(struct nfsmount *, vfs_context_t, u_long, int, struct dqblk *);
#endif

struct nfs_funcs nfs3_funcs = {
	nfs3_mount,
	nfs3_update_statfs,
	nfs3_getquota,
	nfs3_access_rpc,
	nfs3_getattr_rpc,
	nfs3_setattr_rpc,
	nfs3_read_rpc_async,
	nfs3_read_rpc_async_finish,
	nfs3_readlink_rpc,
	nfs3_write_rpc_async,
	nfs3_write_rpc_async_finish,
	nfs3_commit_rpc,
	nfs3_lookup_rpc_async,
	nfs3_lookup_rpc_async_finish,
	nfs3_remove_rpc,
	nfs3_rename_rpc
	};
struct nfs_funcs nfs4_funcs = {
	nfs4_mount,
	nfs4_update_statfs,
	nfs4_getquota,
	nfs4_access_rpc,
	nfs4_getattr_rpc,
	nfs4_setattr_rpc,
	nfs4_read_rpc_async,
	nfs4_read_rpc_async_finish,
	nfs4_readlink_rpc,
	nfs4_write_rpc_async,
	nfs4_write_rpc_async_finish,
	nfs4_commit_rpc,
	nfs4_lookup_rpc_async,
	nfs4_lookup_rpc_async_finish,
	nfs4_remove_rpc,
	nfs4_rename_rpc
	};

/*
 * Called once to initialize data structures...
 */
static int
nfs_vfs_init(struct vfsconf *vfsp)
{
	int i;

	/*
	 * Check to see if major data structures haven't bloated.
	 */
	if (sizeof (struct nfsnode) > NFS_NODEALLOC) {
		printf("struct nfsnode bloated (> %dbytes)\n", NFS_NODEALLOC);
		printf("Try reducing NFS_SMALLFH\n");
	}
	if (sizeof (struct nfsmount) > NFS_MNTALLOC) {
		printf("struct nfsmount bloated (> %dbytes)\n", NFS_MNTALLOC);
		printf("Try reducing NFS_MUIDHASHSIZ\n");
	}

	nfs_ticks = (hz * NFS_TICKINTVL + 500) / 1000;
	if (nfs_ticks < 1)
		nfs_ticks = 1;

	/* init async I/O thread pool state */
	TAILQ_INIT(&nfsiodfree);
	TAILQ_INIT(&nfsiodwork);
	TAILQ_INIT(&nfsiodmounts);
	nfsiod_lck_grp = lck_grp_alloc_init("nfsiod", LCK_GRP_ATTR_NULL);
	nfsiod_mutex = lck_mtx_alloc_init(nfsiod_lck_grp, LCK_ATTR_NULL);

	/* init mount lock group */
	nfs_mount_grp = lck_grp_alloc_init("nfs_mount", LCK_GRP_ATTR_NULL);

	/* init request list mutex */
	nfs_request_grp = lck_grp_alloc_init("nfs_request", LCK_GRP_ATTR_NULL);
	nfs_request_mutex = lck_mtx_alloc_init(nfs_request_grp, LCK_ATTR_NULL);

	/* initialize NFS request list */
	TAILQ_INIT(&nfs_reqq);

	nfs_nbinit();			/* Init the nfsbuf table */
	nfs_nhinit();			/* Init the nfsnode table */
	nfs_lockinit();			/* Init the nfs lock state */
	nfs_gss_init();			/* Init RPCSEC_GSS security */

	/* NFSv4 stuff */
	NFS4_PER_FS_ATTRIBUTES(nfs_fs_attr_bitmap);
	NFS4_PER_OBJECT_ATTRIBUTES(nfs_object_attr_bitmap);
	NFS4_DEFAULT_ATTRIBUTES(nfs_getattr_bitmap);
	for (i=0; i < NFS_ATTR_BITMAP_LEN; i++)
		nfs_getattr_bitmap[i] &= nfs_object_attr_bitmap[i];

	/* initialize NFS timer callouts */
	nfs_request_timer_call = thread_call_allocate(nfs_request_timer, NULL);
	nfs_buf_timer_call = thread_call_allocate(nfs_buf_timer, NULL);

	vfsp->vfc_refcount++; /* make us non-unloadable */
	return (0);
}

/*
 * nfs statfs call
 */
static int
nfs3_update_statfs(struct nfsmount *nmp, vfs_context_t ctx)
{
	nfsnode_t np;
	int error = 0, lockerror, status, nfsvers;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	uint32_t val;

	nfsvers = nmp->nm_vers;
	np = nmp->nm_dnp;
	if ((error = vnode_get(NFSTOV(np))))
		return(error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(nfsvers));
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC_FSSTAT, ctx,
		   &nmrep, &xid, &status);
	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	if (nfsvers == NFS_VER3)
		nfsm_chain_postop_attr_update(error, &nmrep, np, &xid);
	if (!lockerror)
		nfs_unlock(np);
	if (!error)
		error = status;
	nfsm_assert(error, NFSTONMP(np), ENXIO);
	nfsmout_if(error);
	lck_mtx_lock(&nmp->nm_lock);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_TOTAL);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_FREE);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_AVAIL);
	if (nfsvers == NFS_VER3) {
		NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_FILES_AVAIL);
		NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_FILES_TOTAL);
		NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_FILES_FREE);
		nmp->nm_fsattr.nfsa_bsize = NFS_FABLKSIZE;
		nfsm_chain_get_64(error, &nmrep, nmp->nm_fsattr.nfsa_space_total);
		nfsm_chain_get_64(error, &nmrep, nmp->nm_fsattr.nfsa_space_free);
		nfsm_chain_get_64(error, &nmrep, nmp->nm_fsattr.nfsa_space_avail);
		nfsm_chain_get_64(error, &nmrep, nmp->nm_fsattr.nfsa_files_total);
		nfsm_chain_get_64(error, &nmrep, nmp->nm_fsattr.nfsa_files_free);
		nfsm_chain_get_64(error, &nmrep, nmp->nm_fsattr.nfsa_files_avail);
		// skip invarsec
	} else {
		nfsm_chain_adv(error, &nmrep, NFSX_UNSIGNED); // skip tsize?
		nfsm_chain_get_32(error, &nmrep, nmp->nm_fsattr.nfsa_bsize);
		nfsm_chain_get_32(error, &nmrep, val);
		nfsmout_if(error);
		if (nmp->nm_fsattr.nfsa_bsize <= 0)
			nmp->nm_fsattr.nfsa_bsize = NFS_FABLKSIZE;
		nmp->nm_fsattr.nfsa_space_total = (uint64_t)val * nmp->nm_fsattr.nfsa_bsize;
		nfsm_chain_get_32(error, &nmrep, val);
		nfsmout_if(error);
		nmp->nm_fsattr.nfsa_space_free = (uint64_t)val * nmp->nm_fsattr.nfsa_bsize;
		nfsm_chain_get_32(error, &nmrep, val);
		nfsmout_if(error);
		nmp->nm_fsattr.nfsa_space_avail = (uint64_t)val * nmp->nm_fsattr.nfsa_bsize;
	}
	lck_mtx_unlock(&nmp->nm_lock);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	vnode_put(NFSTOV(np));
	return (error);
}

static int
nfs4_update_statfs(struct nfsmount *nmp, vfs_context_t ctx)
{
	nfsnode_t np;
	int error = 0, lockerror, status, nfsvers, numops;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN];
	struct nfs_vattr nvattr;

	nfsvers = nmp->nm_vers;
	np = nmp->nm_dnp;
	if ((error = vnode_get(NFSTOV(np))))
		return(error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH + GETATTR
	numops = 2;
	nfsm_chain_build_alloc_init(error, &nmreq, 15 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "statfs", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	NFS_COPY_ATTRIBUTES(nfs_getattr_bitmap, bitmap);
	NFS4_STATFS_ATTRIBUTES(bitmap);
	nfsm_chain_add_bitmap_masked(error, &nmreq, bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_assert(error, NFSTONMP(np), ENXIO);
	nfsmout_if(error);
	lck_mtx_lock(&nmp->nm_lock);
	NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
	error = nfs4_parsefattr(&nmrep, &nmp->nm_fsattr, &nvattr, NULL, NULL);
	lck_mtx_unlock(&nmp->nm_lock);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	if (!error)
		nfs_loadattrcache(np, &nvattr, &xid, 0);
	if (!lockerror)
		nfs_unlock(np);
	nfsm_assert(error, NFSTONMP(np), ENXIO);
	nfsmout_if(error);
	nmp->nm_fsattr.nfsa_bsize = NFS_FABLKSIZE;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	vnode_put(NFSTOV(np));
	return (error);
}


/*
 * The NFS VFS_GETATTR function: "statfs"-type information is retrieved
 * using the nf_update_statfs() function, and other attributes are cobbled
 * together from whatever sources we can (getattr, fsinfo, pathconf).
 */
static int
nfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t ctx)
{
	struct nfsmount *nmp;
	uint32_t bsize;
	int error = 0, nfsvers;

	if (!(nmp = VFSTONFS(mp)))
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if (VFSATTR_IS_ACTIVE(fsap, f_bsize)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_iosize) ||
	    VFSATTR_IS_ACTIVE(fsap, f_blocks) ||
	    VFSATTR_IS_ACTIVE(fsap, f_bfree)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_bavail) ||
	    VFSATTR_IS_ACTIVE(fsap, f_bused)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_files)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_ffree)) {
		int statfsrate = nfs_statfs_rate_limit;
		int refresh = 1;

		/*
		 * Are we rate-limiting statfs RPCs?
		 * (Treat values less than 1 or greater than 1,000,000 as no limit.)
		 */
		if ((statfsrate > 0) && (statfsrate < 1000000)) {
			struct timeval now;
			uint32_t stamp;

			microuptime(&now);
			lck_mtx_lock(&nmp->nm_lock);
			stamp = (now.tv_sec * statfsrate) + (now.tv_usec / (1000000/statfsrate));
			if (stamp != nmp->nm_fsattrstamp) {
				refresh = 1;
				nmp->nm_fsattrstamp = stamp;
			} else {
				refresh = 0;
			}
			lck_mtx_unlock(&nmp->nm_lock);
		}

		if (refresh)
			error = nmp->nm_funcs->nf_update_statfs(nmp, ctx);
		if ((error == ESTALE) || (error == ETIMEDOUT))
			error = 0;
		if (error)
			return (error);

		lck_mtx_lock(&nmp->nm_lock);
		VFSATTR_RETURN(fsap, f_iosize, nfs_iosize);
		VFSATTR_RETURN(fsap, f_bsize, nmp->nm_fsattr.nfsa_bsize);
		bsize = nmp->nm_fsattr.nfsa_bsize;
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_TOTAL))
			VFSATTR_RETURN(fsap, f_blocks, nmp->nm_fsattr.nfsa_space_total / bsize);
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_FREE))
			VFSATTR_RETURN(fsap, f_bfree, nmp->nm_fsattr.nfsa_space_free / bsize);
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_AVAIL))
			VFSATTR_RETURN(fsap, f_bavail, nmp->nm_fsattr.nfsa_space_avail / bsize);
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_TOTAL) &&
		    NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SPACE_FREE))
			VFSATTR_RETURN(fsap, f_bused,
				(nmp->nm_fsattr.nfsa_space_total / bsize) -
				(nmp->nm_fsattr.nfsa_space_free / bsize));
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_FILES_TOTAL))
			VFSATTR_RETURN(fsap, f_files, nmp->nm_fsattr.nfsa_files_total);
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_FILES_FREE))
			VFSATTR_RETURN(fsap, f_ffree, nmp->nm_fsattr.nfsa_files_free);
		lck_mtx_unlock(&nmp->nm_lock);
	}

	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		u_int32_t caps, valid;
		nfsnode_t np;

		nfsm_assert(error, VFSTONFS(mp), ENXIO);
		if (error)
			return (error);
		np = nmp->nm_dnp;
		lck_mtx_lock(&nmp->nm_lock);

		/*
		 * The capabilities[] array defines what this volume supports.
		 *
		 * The valid[] array defines which bits this code understands
		 * the meaning of (whether the volume has that capability or not).
		 * Any zero bits here means "I don't know what you're asking about"
		 * and the caller cannot tell whether that capability is
		 * present or not.
		 */
		caps = valid = 0;
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SYMLINK_SUPPORT)) {
			valid |= VOL_CAP_FMT_SYMBOLICLINKS;
			if (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_SYMLINK)
				caps |= VOL_CAP_FMT_SYMBOLICLINKS;
		}
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_LINK_SUPPORT)) {
			valid |= VOL_CAP_FMT_HARDLINKS;
			if (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_LINK)
				caps |= VOL_CAP_FMT_HARDLINKS;
		}
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_CASE_INSENSITIVE)) {
			valid |= VOL_CAP_FMT_CASE_SENSITIVE;
			if (!(nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_CASE_INSENSITIVE))
				caps |= VOL_CAP_FMT_CASE_SENSITIVE;
		}
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_CASE_PRESERVING)) {
			valid |= VOL_CAP_FMT_CASE_PRESERVING;
			if (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_CASE_PRESERVING)
				caps |= VOL_CAP_FMT_CASE_PRESERVING;
		}
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXFILESIZE)) {
			/* Is server's max file size at least 2TB? */
			if (nmp->nm_fsattr.nfsa_maxfilesize >= 0x20000000000ULL)
				caps |= VOL_CAP_FMT_2TB_FILESIZE;
		} else if (nfsvers >= NFS_VER3) {
			/*
			 * NFSv3 and up supports 64 bits of file size.
			 * So, we'll just assume maxfilesize >= 2TB
			 */
			caps |= VOL_CAP_FMT_2TB_FILESIZE;
		}
		if (nfsvers >= NFS_VER4) {
			caps |= VOL_CAP_FMT_HIDDEN_FILES;
			valid |= VOL_CAP_FMT_HIDDEN_FILES;
			// VOL_CAP_FMT_OPENDENYMODES
		}
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] =
			// VOL_CAP_FMT_PERSISTENTOBJECTIDS |
			// VOL_CAP_FMT_SYMBOLICLINKS |
			// VOL_CAP_FMT_HARDLINKS |
			// VOL_CAP_FMT_JOURNAL |
			// VOL_CAP_FMT_JOURNAL_ACTIVE |
			// VOL_CAP_FMT_NO_ROOT_TIMES |
			// VOL_CAP_FMT_SPARSE_FILES |
			// VOL_CAP_FMT_ZERO_RUNS |
			// VOL_CAP_FMT_CASE_SENSITIVE |
			// VOL_CAP_FMT_CASE_PRESERVING |
			// VOL_CAP_FMT_FAST_STATFS |
			// VOL_CAP_FMT_2TB_FILESIZE |
			// VOL_CAP_FMT_OPENDENYMODES |
			// VOL_CAP_FMT_HIDDEN_FILES |
			caps;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_FORMAT] =
			VOL_CAP_FMT_PERSISTENTOBJECTIDS |
			// VOL_CAP_FMT_SYMBOLICLINKS |
			// VOL_CAP_FMT_HARDLINKS |
			// VOL_CAP_FMT_JOURNAL |
			// VOL_CAP_FMT_JOURNAL_ACTIVE |
			// VOL_CAP_FMT_NO_ROOT_TIMES |
			// VOL_CAP_FMT_SPARSE_FILES |
			// VOL_CAP_FMT_ZERO_RUNS |
			// VOL_CAP_FMT_CASE_SENSITIVE |
			// VOL_CAP_FMT_CASE_PRESERVING |
			VOL_CAP_FMT_FAST_STATFS |
			VOL_CAP_FMT_2TB_FILESIZE |
			// VOL_CAP_FMT_OPENDENYMODES |
			// VOL_CAP_FMT_HIDDEN_FILES |
			valid;

		/*
		 * We don't support most of the interfaces.
		 *
		 * We MAY support locking, but we don't have any easy way of probing.
		 * We can tell if there's no lockd running or if locks have been
		 * disabled for a mount, so we can definitely answer NO in that case.
		 * Any attempt to send a request to lockd to test for locking support
		 * may cause the lazily-launched locking daemons to be started
		 * unnecessarily.  So we avoid that.  However, we do record if we ever
		 * successfully perform a lock operation on a mount point, so if it
		 * looks like lock ops have worked, we do report that we support them.
		 */
		caps = valid = 0;
		if (nfsvers >= NFS_VER4) {
			caps = VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK;
			valid = VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK;
			// VOL_CAP_INT_EXTENDED_SECURITY
			// VOL_CAP_INT_NAMEDSTREAMS
			// VOL_CAP_INT_EXTENDED_ATTR
		} else if ((nmp->nm_flag & NFSMNT_NOLOCKS)) {
			/* locks disabled on this mount, so they definitely won't work */
			valid = VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK;
		} else if (nmp->nm_state & NFSSTA_LOCKSWORK) {
			caps = VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK;
			valid = VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK;
		}
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] =
			// VOL_CAP_INT_SEARCHFS |
			// VOL_CAP_INT_ATTRLIST |
			// VOL_CAP_INT_NFSEXPORT |
			// VOL_CAP_INT_READDIRATTR |
			// VOL_CAP_INT_EXCHANGEDATA |
			// VOL_CAP_INT_COPYFILE |
			// VOL_CAP_INT_ALLOCATE |
			// VOL_CAP_INT_VOL_RENAME |
			// VOL_CAP_INT_ADVLOCK |
			// VOL_CAP_INT_FLOCK |
			// VOL_CAP_INT_EXTENDED_SECURITY |
			// VOL_CAP_INT_USERACCESS |
			// VOL_CAP_INT_MANLOCK |
			// VOL_CAP_INT_NAMEDSTREAMS |
			// VOL_CAP_INT_EXTENDED_ATTR |
			caps;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_SEARCHFS |
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT |
			VOL_CAP_INT_READDIRATTR |
			VOL_CAP_INT_EXCHANGEDATA |
			VOL_CAP_INT_COPYFILE |
			VOL_CAP_INT_ALLOCATE |
			VOL_CAP_INT_VOL_RENAME |
			// VOL_CAP_INT_ADVLOCK |
			// VOL_CAP_INT_FLOCK |
			// VOL_CAP_INT_EXTENDED_SECURITY |
			// VOL_CAP_INT_USERACCESS |
			// VOL_CAP_INT_MANLOCK |
			// VOL_CAP_INT_NAMEDSTREAMS |
			// VOL_CAP_INT_EXTENDED_ATTR |
			valid;

		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED1] = 0;

		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2] = 0;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED2] = 0;

		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
		lck_mtx_unlock(&nmp->nm_lock);
	}

	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		fsap->f_attributes.validattr.commonattr = 0;
		fsap->f_attributes.validattr.volattr =
			ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
		fsap->f_attributes.validattr.dirattr = 0;
		fsap->f_attributes.validattr.fileattr = 0;
		fsap->f_attributes.validattr.forkattr = 0;

		fsap->f_attributes.nativeattr.commonattr = 0;
		fsap->f_attributes.nativeattr.volattr =
			ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
		fsap->f_attributes.nativeattr.dirattr = 0;
		fsap->f_attributes.nativeattr.fileattr = 0;
		fsap->f_attributes.nativeattr.forkattr = 0;

		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}

	return (error);
}

/*
 * nfs version 3 fsinfo rpc call
 */
static int
nfs3_fsinfo(struct nfsmount *nmp, nfsnode_t np, vfs_context_t ctx)
{
	int error = 0, lockerror, status, prefsize, maxsize, nmlocked = 0;
	u_int64_t xid;
	uint32_t val;
	struct nfsm_chain nmreq, nmrep;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	nfsm_chain_build_alloc_init(error, &nmreq, NFSX_FH(nmp->nm_vers));
	nfsm_chain_add_fh(error, &nmreq, nmp->nm_vers, np->n_fhp, np->n_fhsize);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC_FSINFO, ctx,
			&nmrep, &xid, &status);
	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsm_chain_postop_attr_update(error, &nmrep, np, &xid);
	if (!lockerror)
		nfs_unlock(np);
	if (!error)
		error = status;
	nfsmout_if(error);

	lck_mtx_lock(&nmp->nm_lock);
	nmlocked = 1;

	nfsm_chain_get_32(error, &nmrep, maxsize);
	nfsm_chain_get_32(error, &nmrep, prefsize);
	nfsmout_if(error);
	nmp->nm_fsattr.nfsa_maxread = maxsize;
	if (prefsize < nmp->nm_rsize)
		nmp->nm_rsize = (prefsize + NFS_FABLKSIZE - 1) &
			~(NFS_FABLKSIZE - 1);
	if (maxsize < nmp->nm_rsize) {
		nmp->nm_rsize = maxsize & ~(NFS_FABLKSIZE - 1);
		if (nmp->nm_rsize == 0)
			nmp->nm_rsize = maxsize;
	}
	nfsm_chain_adv(error, &nmrep, NFSX_UNSIGNED); // skip rtmult

	nfsm_chain_get_32(error, &nmrep, maxsize);
	nfsm_chain_get_32(error, &nmrep, prefsize);
	nfsmout_if(error);
	nmp->nm_fsattr.nfsa_maxwrite = maxsize;
	if (prefsize < nmp->nm_wsize)
		nmp->nm_wsize = (prefsize + NFS_FABLKSIZE - 1) &
			~(NFS_FABLKSIZE - 1);
	if (maxsize < nmp->nm_wsize) {
		nmp->nm_wsize = maxsize & ~(NFS_FABLKSIZE - 1);
		if (nmp->nm_wsize == 0)
			nmp->nm_wsize = maxsize;
	}
	nfsm_chain_adv(error, &nmrep, NFSX_UNSIGNED); // skip wtmult

	nfsm_chain_get_32(error, &nmrep, prefsize);
	nfsmout_if(error);
	if (prefsize < nmp->nm_readdirsize)
		nmp->nm_readdirsize = prefsize;
	if (maxsize < nmp->nm_readdirsize)
		nmp->nm_readdirsize = maxsize;

	nfsm_chain_get_64(error, &nmrep, maxsize);
	nmp->nm_fsattr.nfsa_maxfilesize = maxsize;

	nfsm_chain_adv(error, &nmrep, 2 * NFSX_UNSIGNED); // skip time_delta

	/* convert FS properties to our own flags */
	nfsm_chain_get_32(error, &nmrep, val);
	nfsmout_if(error);
	if (val & NFSV3FSINFO_LINK)
		nmp->nm_fsattr.nfsa_flags |= NFS_FSFLAG_LINK;
	if (val & NFSV3FSINFO_SYMLINK)
		nmp->nm_fsattr.nfsa_flags |= NFS_FSFLAG_SYMLINK;
	if (val & NFSV3FSINFO_HOMOGENEOUS)
		nmp->nm_fsattr.nfsa_flags |= NFS_FSFLAG_HOMOGENEOUS;
	if (val & NFSV3FSINFO_CANSETTIME)
		nmp->nm_fsattr.nfsa_flags |= NFS_FSFLAG_SET_TIME;
	nmp->nm_state |= NFSSTA_GOTFSINFO;
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXREAD);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXWRITE);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXFILESIZE);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_LINK_SUPPORT);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_SYMLINK_SUPPORT);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_HOMOGENEOUS);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_CANSETTIME);
nfsmout:
	if (nmlocked)
		lck_mtx_unlock(&nmp->nm_lock);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * Mount a remote root fs via. nfs. This depends on the info in the
 * nfs_diskless structure that has been filled in properly by some primary
 * bootstrap.
 * It goes something like this:
 * - do enough of "ifconfig" by calling ifioctl() so that the system
 *   can talk to the server
 * - If nfs_diskless.mygateway is filled in, use that address as
 *   a default gateway.
 * - hand craft the swap nfs vnode hanging off a fake mount point
 *	if swdevt[0].sw_dev == NODEV
 * - build the rootfs mount point and call mountnfs() to do the rest.
 */
int
nfs_mountroot(void)
{
	struct nfs_diskless nd;
	struct nfs_vattr nvattr;
	mount_t mp = NULL;
	vnode_t vp = NULL;
	vfs_context_t ctx;
	int error;
#if !defined(NO_MOUNT_PRIVATE)
	mount_t mppriv = NULL;
	vnode_t vppriv = NULL;
#endif /* NO_MOUNT_PRIVATE */
	int v3, sotype;

	/*
	 * Call nfs_boot_init() to fill in the nfs_diskless struct.
	 * Note: networking must already have been configured before
	 * we're called.
	 */
	bzero((caddr_t) &nd, sizeof(nd));
	error = nfs_boot_init(&nd);
	if (error) {
		panic("nfs_boot_init failed with %d\n", error);
	}

	/*
	 * Try NFSv3 first, then fallback to NFSv2.
	 * Likewise, try TCP first, then fall back to UDP.
	 */
	v3 = 1;
	sotype = SOCK_STREAM;

tryagain:
	error = nfs_boot_getfh(&nd, v3, sotype);
	if (error) {
		if (error == EHOSTDOWN || error == EHOSTUNREACH) {
			if (nd.nd_root.ndm_path)
				FREE_ZONE(nd.nd_root.ndm_path,
					  MAXPATHLEN, M_NAMEI);
			if (nd.nd_private.ndm_path)
				FREE_ZONE(nd.nd_private.ndm_path,
					  MAXPATHLEN, M_NAMEI);
			return (error);
		}
		if (v3) {
			if (sotype == SOCK_STREAM) {
				printf("nfs_boot_getfh(v3,TCP) failed with %d, trying UDP...\n", error);
				sotype = SOCK_DGRAM;
				goto tryagain;
			}
			printf("nfs_boot_getfh(v3,UDP) failed with %d, trying v2...\n", error);
			v3 = 0;
			sotype = SOCK_STREAM;
			goto tryagain;
		} else if (sotype == SOCK_STREAM) {
			printf("nfs_boot_getfh(v2,TCP) failed with %d, trying UDP...\n", error);
			sotype = SOCK_DGRAM;
			goto tryagain;
		}
		switch(error) {
		case EPROGUNAVAIL:
			panic("nfs_boot_getfh(v2,UDP) failed: NFS server mountd not responding - check server configuration: %s", PE_boot_args());
		case EACCES:
		case EPERM:
			panic("nfs_boot_getfh(v2,UDP) failed: NFS server refused mount - check server configuration: %s", PE_boot_args());
		default:
			panic("nfs_boot_getfh(v2,UDP) failed with %d: %s", error, PE_boot_args());
		}
	}

	ctx = vfs_context_kernel();

	/*
	 * Create the root mount point.
	 */
#if !defined(NO_MOUNT_PRIVATE)
	{
		//PWC hack until we have a real "mount" tool to remount root rw
		int rw_root=0;
		int flags = MNT_ROOTFS|MNT_RDONLY;
		PE_parse_boot_arg("-rwroot_hack", &rw_root);
		if(rw_root)
		{
			flags = MNT_ROOTFS;
			kprintf("-rwroot_hack in effect: mounting root fs read/write\n");
		}
				
	if ((error = nfs_mount_diskless(&nd.nd_root, "/", flags, &vp, &mp, ctx)))
#else
	if ((error = nfs_mount_diskless(&nd.nd_root, "/", MNT_ROOTFS, &vp, &mp, ctx)))
#endif /* NO_MOUNT_PRIVATE */
	{
		if (v3) {
			if (sotype == SOCK_STREAM) {
				printf("nfs_mount_diskless(v3,TCP) failed with %d, trying UDP...\n", error);
				sotype = SOCK_DGRAM;
				goto tryagain;
			}
			printf("nfs_mount_diskless(v3,UDP) failed with %d, trying v2...\n", error);
			v3 = 0;
			sotype = SOCK_STREAM;
			goto tryagain;
		} else if (sotype == SOCK_STREAM) {
			printf("nfs_mount_diskless(v2,TCP) failed with %d, trying UDP...\n", error);
			sotype = SOCK_DGRAM;
			goto tryagain;
		}
		panic("nfs_mount_diskless(v2,UDP) root failed with %d: %s\n", error, PE_boot_args());
	}
	}
	printf("root on %s\n", (char *)&nd.nd_root.ndm_host);

	vfs_unbusy(mp);
	mount_list_add(mp);
	rootvp = vp;
	
#if !defined(NO_MOUNT_PRIVATE)
	if (nd.nd_private.ndm_saddr.sin_addr.s_addr) {
	    error = nfs_mount_diskless_private(&nd.nd_private, "/private",
					       0, &vppriv, &mppriv, ctx);
	    if (error) {
		panic("nfs_mount_diskless private failed with %d\n", error);
	    }
	    printf("private on %s\n", (char *)&nd.nd_private.ndm_host);

	    vfs_unbusy(mppriv);
	    mount_list_add(mppriv);
	}

#endif /* NO_MOUNT_PRIVATE */

	if (nd.nd_root.ndm_path)
		FREE_ZONE(nd.nd_root.ndm_path, MAXPATHLEN, M_NAMEI);
	if (nd.nd_private.ndm_path)
		FREE_ZONE(nd.nd_private.ndm_path, MAXPATHLEN, M_NAMEI);

	/* Get root attributes (for the time). */
	error = nfs_getattr(VTONFS(vp), &nvattr, ctx, 0);
	if (error) panic("nfs_mountroot: getattr for root");
	return (0);
}

/*
 * Internal version of mount system call for diskless setup.
 */
static int
nfs_mount_diskless(
	struct nfs_dlmount *ndmntp,
	const char *mntname,
	int mntflag,
	vnode_t *vpp,
	mount_t *mpp,
	vfs_context_t ctx)
{
	struct user_nfs_args args;
	mount_t mp;
	mbuf_t m;
	int error;

	if ((error = vfs_rootmountalloc("nfs", ndmntp->ndm_host, &mp))) {
		printf("nfs_mount_diskless: NFS not configured");
		return (error);
	}

	mp->mnt_flag |= mntflag;
	if (!(mntflag & MNT_RDONLY))
		mp->mnt_flag &= ~MNT_RDONLY;

	/* Initialize mount args. */
	bzero((caddr_t) &args, sizeof(args));
	args.addr     = CAST_USER_ADDR_T(&ndmntp->ndm_saddr);
	args.addrlen  = ndmntp->ndm_saddr.sin_len;
	args.sotype   = ndmntp->ndm_sotype;
	args.fh       = CAST_USER_ADDR_T(&ndmntp->ndm_fh[0]);
	args.fhsize   = ndmntp->ndm_fhlen;
	args.hostname = CAST_USER_ADDR_T(ndmntp->ndm_host);
	args.flags    = NFSMNT_RESVPORT;
	if (ndmntp->ndm_nfsv3)
		args.flags |= NFSMNT_NFSV3;

	error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_SONAME, &m);
	if (error) {
		printf("nfs_mount_diskless: mbuf_get(soname) failed");
		return (error);
	}
	mbuf_setlen(m, ndmntp->ndm_saddr.sin_len);
	bcopy(&ndmntp->ndm_saddr, mbuf_data(m), ndmntp->ndm_saddr.sin_len);
	if ((error = mountnfs(&args, mp, m, ctx, vpp))) {
		printf("nfs_mountroot: mount %s failed: %d\n", mntname, error);
		// XXX vfs_rootmountfailed(mp);
		mount_list_lock();
		mp->mnt_vtable->vfc_refcount--;
		mount_list_unlock();
		vfs_unbusy(mp);
		mount_lock_destroy(mp);
#if CONFIG_MACF
		mac_mount_label_destroy(mp);
#endif
		FREE_ZONE(mp, sizeof(struct mount), M_MOUNT);
		return (error);
	}
	*mpp = mp;
	return (0);
}

#if !defined(NO_MOUNT_PRIVATE)
/*
 * Internal version of mount system call to mount "/private"
 * separately in diskless setup
 */
static int
nfs_mount_diskless_private(
	struct nfs_dlmount *ndmntp,
	const char *mntname,
	int mntflag,
	vnode_t *vpp,
	mount_t *mpp,
	vfs_context_t ctx)
{
	struct user_nfs_args args;
	mount_t mp;
	mbuf_t m;
	int error;
	proc_t procp;
	struct vfstable *vfsp;
	struct nameidata nd;
	vnode_t vp;

	procp = current_proc(); /* XXX */

	{
	/*
	 * mimic main()!. Temporarily set up rootvnode and other stuff so
	 * that namei works. Need to undo this because main() does it, too
	 */
		struct filedesc *fdp;	/* pointer to file descriptor state */
		fdp = procp->p_fd;
		mountlist.tqh_first->mnt_flag |= MNT_ROOTFS;

		/* Get the vnode for '/'. Set fdp->fd_cdir to reference it. */
		if (VFS_ROOT(mountlist.tqh_first, &rootvnode, NULL))
			panic("cannot find root vnode");
		error = vnode_ref(rootvnode);
		if (error) {
			printf("nfs_mountroot: vnode_ref() failed on root vnode!\n");
			goto out;
		}
		fdp->fd_cdir = rootvnode;
		fdp->fd_rdir = NULL;
	}

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE32,
	    CAST_USER_ADDR_T(mntname), ctx);
	if ((error = namei(&nd))) {
		printf("nfs_mountroot: private namei failed!\n");
		goto out;
	}
	{
		/* undo vnode_ref() in mimic main()! */
		vnode_rele(rootvnode);
	}
	nameidone(&nd);
	vp = nd.ni_vp;

	if ((error = VNOP_FSYNC(vp, MNT_WAIT, ctx)) ||
	    (error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0))) {
		vnode_put(vp);
		goto out;
	}
	if (vnode_vtype(vp) != VDIR) {
		vnode_put(vp);
		error = ENOTDIR;
		goto out;
	}
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strncmp(vfsp->vfc_name, "nfs", sizeof(vfsp->vfc_name)))
			break;
	if (vfsp == NULL) {
		printf("nfs_mountroot: private NFS not configured\n");
		vnode_put(vp);
		error = ENODEV;
		goto out;
	}
	if (vnode_mountedhere(vp) != NULL) {
		vnode_put(vp);
		error = EBUSY;
		goto out;
	}

	/*
	 * Allocate and initialize the filesystem.
	 */
	mp = _MALLOC_ZONE((u_long)sizeof(struct mount), M_MOUNT, M_WAITOK);
	if (!mp) {
		printf("nfs_mountroot: unable to allocate mount structure\n");
		vnode_put(vp);
		error = ENOMEM;
		goto out;
	}
	bzero((char *)mp, (u_long)sizeof(struct mount));

	/* Initialize the default IO constraints */
	mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
	mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;
	mp->mnt_ioflags = 0;
	mp->mnt_realrootvp = NULLVP;
	mp->mnt_authcache_ttl = CACHED_LOOKUP_RIGHT_TTL;

	mount_lock_init(mp);
	TAILQ_INIT(&mp->mnt_vnodelist);
	TAILQ_INIT(&mp->mnt_workerqueue);
	TAILQ_INIT(&mp->mnt_newvnodes);
	(void)vfs_busy(mp, LK_NOWAIT);
	TAILQ_INIT(&mp->mnt_vnodelist);
	mount_list_lock();
	vfsp->vfc_refcount++;
	mount_list_unlock();
	mp->mnt_vtable = vfsp;
	mp->mnt_op = vfsp->vfc_vfsops;
	// mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag = mntflag;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_vfsstat.f_fstypename, vfsp->vfc_name, MFSNAMELEN-1);
	vp->v_mountedhere = mp;
	mp->mnt_vnodecovered = vp;
	mp->mnt_vfsstat.f_owner = kauth_cred_getuid(kauth_cred_get());
	(void) copystr(mntname, mp->mnt_vfsstat.f_mntonname, MNAMELEN - 1, 0);
	(void) copystr(ndmntp->ndm_host, mp->mnt_vfsstat.f_mntfromname, MNAMELEN - 1, 0);
#if CONFIG_MACF
	mac_mount_label_init(mp);
	mac_mount_label_associate(ctx, mp);
#endif

	/* Initialize mount args. */
	bzero((caddr_t) &args, sizeof(args));
	args.addr     = CAST_USER_ADDR_T(&ndmntp->ndm_saddr);
	args.addrlen  = ndmntp->ndm_saddr.sin_len;
	args.sotype   = ndmntp->ndm_sotype;
	args.fh       = CAST_USER_ADDR_T(ndmntp->ndm_fh);
	args.fhsize   = ndmntp->ndm_fhlen;
	args.hostname = CAST_USER_ADDR_T(ndmntp->ndm_host);
	args.flags    = NFSMNT_RESVPORT;
	if (ndmntp->ndm_nfsv3)
		args.flags |= NFSMNT_NFSV3;

	error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_SONAME, &m);
	if (error) {
		printf("nfs_mount_diskless_private: mbuf_get(soname) failed");
		goto out;
	}
	mbuf_setlen(m, ndmntp->ndm_saddr.sin_len);
	bcopy(&ndmntp->ndm_saddr, mbuf_data(m), ndmntp->ndm_saddr.sin_len);
	if ((error = mountnfs(&args, mp, m, ctx, &vp))) {
		printf("nfs_mountroot: mount %s failed: %d\n", mntname, error);
		mount_list_lock();
		vfsp->vfc_refcount--;
		mount_list_unlock();
		vfs_unbusy(mp);
		mount_lock_destroy(mp);
#if CONFIG_MACF
		mac_mount_label_destroy(mp);
#endif
		FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		goto out;
	}

	*mpp = mp;
	*vpp = vp;
out:
	return (error);
}
#endif /* NO_MOUNT_PRIVATE */

/*
 * VFS Operations.
 *
 * mount system call
 */
static int
nfs_vfs_mount(mount_t mp, vnode_t vp, user_addr_t data, vfs_context_t ctx)
{
	int error, argsvers;
	struct user_nfs_args args;
	struct nfs_args tempargs;
	mbuf_t nam;
	size_t len;
	u_char nfh[NFSX_V3FHMAX];
	char *mntfrom;

	error = copyin(data, (caddr_t)&argsvers, sizeof (argsvers));
	if (error)
		return (error);

	switch (argsvers) {
	case 3:
		if (vfs_context_is64bit(ctx))
			error = copyin(data, (caddr_t)&args, sizeof (struct user_nfs_args3));
		else
			error = copyin(data, (caddr_t)&tempargs, sizeof (struct nfs_args3));
		break;
	case 4:
		if (vfs_context_is64bit(ctx))
			error = copyin(data, (caddr_t)&args, sizeof (struct user_nfs_args4));
		else
			error = copyin(data, (caddr_t)&tempargs, sizeof (struct nfs_args4));
		break;
	case 5:
		if (vfs_context_is64bit(ctx))
			error = copyin(data, (caddr_t)&args, sizeof (args));
		else
			error = copyin(data, (caddr_t)&tempargs, sizeof (tempargs));
		break;
	default:
		return (EPROGMISMATCH);
	}
	if (error)
		return (error);

	if (!vfs_context_is64bit(ctx)) {
		args.version = tempargs.version;
		args.addrlen = tempargs.addrlen;
		args.sotype = tempargs.sotype;
		args.proto = tempargs.proto;
		args.fhsize = tempargs.fhsize;
		args.flags = tempargs.flags;
		args.wsize = tempargs.wsize;
		args.rsize = tempargs.rsize;
		args.readdirsize = tempargs.readdirsize;
		args.timeo = tempargs.timeo;
		args.retrans = tempargs.retrans;
		args.maxgrouplist = tempargs.maxgrouplist;
		args.readahead = tempargs.readahead;
		args.leaseterm = tempargs.leaseterm;
		args.deadthresh = tempargs.deadthresh;
		args.addr = CAST_USER_ADDR_T(tempargs.addr);
		args.fh = CAST_USER_ADDR_T(tempargs.fh);
		args.hostname = CAST_USER_ADDR_T(tempargs.hostname);
		if (argsvers >= 4) {
			args.acregmin = tempargs.acregmin;
			args.acregmax = tempargs.acregmax;
			args.acdirmin = tempargs.acdirmin;
			args.acdirmax = tempargs.acdirmax;
		}
		if (argsvers >= 5)
			args.auth = tempargs.auth;
	}

	if (args.fhsize < 0 || args.fhsize > NFSX_V3FHMAX)
		return (EINVAL);
	if (args.fhsize > 0) {
		error = copyin(args.fh, (caddr_t)nfh, args.fhsize);
		if (error)
			return (error);
	}

	mntfrom = &vfs_statfs(mp)->f_mntfromname[0];
	error = copyinstr(args.hostname, mntfrom, MAXPATHLEN-1, &len);
	if (error)
		return (error);
	bzero(&mntfrom[len], MAXPATHLEN - len);

	/* sockargs() call must be after above copyin() calls */
	error = sockargs(&nam, args.addr, args.addrlen, MBUF_TYPE_SONAME);
	if (error)
		return (error);

	args.fh = CAST_USER_ADDR_T(&nfh[0]);
	error = mountnfs(&args, mp, nam, ctx, &vp);
	return (error);
}

/*
 * Common code for mount and mountroot
 */

static int
nfs3_mount(
	struct nfsmount *nmp,
	vfs_context_t ctx,
	struct user_nfs_args *argp,
	nfsnode_t *npp)
{
	int error = 0;
	struct nfs_vattr nvattr;
	u_int64_t xid;
	u_char *fhp;

	*npp = NULL;

	/*
	 * Get file attributes for the mountpoint.  These are needed
	 * in order to properly create the root vnode.
	 */
	// LP64todo - fix CAST_DOWN of argp->fh
	fhp = CAST_DOWN(u_char *, argp->fh);
	error = nfs3_getattr_rpc(NULL, nmp->nm_mountp, fhp, argp->fhsize,
			ctx, &nvattr, &xid);
	if (error)
		goto out;

	error = nfs_nget(nmp->nm_mountp, NULL, NULL, fhp, argp->fhsize,
			&nvattr, &xid, NG_MARKROOT, npp);
	if (*npp)
		nfs_unlock(*npp);
	if (error)
		goto out;

	/*
	 * Try to make sure we have all the general info from the server.
	 */
	if (nmp->nm_vers == NFS_VER2) {
		NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXNAME);
		nmp->nm_fsattr.nfsa_maxname = NFS_MAXNAMLEN;
	} else if (nmp->nm_vers == NFS_VER3) {
		/* get the NFSv3 FSINFO */
		error = nfs3_fsinfo(nmp, *npp, ctx);
		if (error)
			goto out;
		/* If the server indicates all pathconf info is */
		/* the same, grab a copy of that info now */
		if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_HOMOGENEOUS) &&
		    (nmp->nm_fsattr.nfsa_flags & NFS_FSFLAG_HOMOGENEOUS)) {
			struct nfs_fsattr nfsa;
			if (!nfs3_pathconf_rpc(*npp, &nfsa, ctx)) {
				/* cache a copy of the results */
				lck_mtx_lock(&nmp->nm_lock);
				nfs3_pathconf_cache(nmp, &nfsa);
				lck_mtx_unlock(&nmp->nm_lock);
			}
		}
	}
out:
	if (*npp && error) {
		vnode_put(NFSTOV(*npp));
		*npp = NULL;
	}
	return (error);
}

static int
nfs4_mount(
	struct nfsmount *nmp,
	vfs_context_t ctx,
	__unused struct user_nfs_args *argp,
	nfsnode_t *npp)
{
	struct nfsm_chain nmreq, nmrep;
	int error = 0, numops, status, interval;
	char *path = &vfs_statfs(nmp->nm_mountp)->f_mntfromname[0];
	char *name, *nextname;
	fhandle_t fh;
	struct nfs_vattr nvattr;
	u_int64_t xid;
	struct timeval now;

	*npp = NULL;
	fh.fh_len = 0;
	microtime(&now);
	nmp->nm_mounttime = ((uint64_t)now.tv_sec << 32) | now.tv_usec;

	/* look up path to get fh and attrs for mount point root */
	numops = 2; // PUTROOTFH + LOOKUP* + GETATTR
	while (*path && (*path != '/'))
		path++;
	name = path;
	while (*name) {
		while (*name && (*name == '/'))
			name++;
		if (!*name)
			break;
		nextname = name;
		while (*nextname && (*nextname != '/'))
			nextname++;
		numops++;
		name = nextname;
	}
	nfsm_chain_build_alloc_init(error, &nmreq, 25 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "mount", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTROOTFH);
	// (LOOKUP)*
	name = path;
	while (*name) {
		while (*name && (*name == '/'))
			name++;
		if (!*name)
			break;
		nextname = name;
		while (*nextname && (*nextname != '/'))
			nextname++;
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_LOOKUP);
		nfsm_chain_add_string(error, &nmreq, name, nextname - name);
		name = nextname;
	}
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	NFS4_DEFAULT_ATTRIBUTES(nmp->nm_fsattr.nfsa_supp_attr);
	NFS_BITMAP_SET(nmp->nm_fsattr.nfsa_supp_attr, NFS_FATTR_FILEHANDLE);
	nfsm_chain_add_bitmap(error, &nmreq, nmp->nm_fsattr.nfsa_supp_attr, NFS_ATTR_BITMAP_LEN);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(NULL, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTROOTFH);
	name = path;
	while (*name) {
		while (*name && (*name == '/'))
			name++;
		if (!*name)
			break;
		nextname = name;
		while (*nextname && (*nextname != '/'))
			nextname++;
		nfsm_chain_op_check(error, &nmrep, NFS_OP_LOOKUP);
		name = nextname;
	}
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsmout_if(error);
	NFS_CLEAR_ATTRIBUTES(nmp->nm_fsattr.nfsa_bitmap);
	NFS_CLEAR_ATTRIBUTES(&nvattr.nva_bitmap);
	error = nfs4_parsefattr(&nmrep, &nmp->nm_fsattr, &nvattr, &fh, NULL);
	if (!error && !NFS_BITMAP_ISSET(&nvattr.nva_bitmap, NFS_FATTR_FILEHANDLE)) {
		printf("nfs: mount didn't return filehandle?\n");
		error = EBADRPC;
	}
	nfsmout_if(error);

	error = nfs_nget(nmp->nm_mountp, NULL, NULL, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MARKROOT, npp);
	nfsmout_if(error);

	/* XXX local locking for now */
	vfs_setlocklocal(nmp->nm_mountp);

	/* adjust I/O sizes to server limits */
	if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXREAD)) {
		if (nmp->nm_fsattr.nfsa_maxread < (uint64_t)nmp->nm_rsize) {
			nmp->nm_rsize = nmp->nm_fsattr.nfsa_maxread & ~(NFS_FABLKSIZE - 1);
			if (nmp->nm_rsize == 0)
				nmp->nm_rsize = nmp->nm_fsattr.nfsa_maxread;
		}
	}
	if (NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_bitmap, NFS_FATTR_MAXWRITE)) {
		if (nmp->nm_fsattr.nfsa_maxwrite < (uint64_t)nmp->nm_wsize) {
			nmp->nm_wsize = nmp->nm_fsattr.nfsa_maxwrite & ~(NFS_FABLKSIZE - 1);
			if (nmp->nm_wsize == 0)
				nmp->nm_wsize = nmp->nm_fsattr.nfsa_maxwrite;
		}
	}

	/* set up lease renew timer */
	nmp->nm_renew_timer = thread_call_allocate(nfs4_renew_timer, nmp);
	interval = nmp->nm_fsattr.nfsa_lease / 2;
	if (interval < 1)
		interval = 1;
	nfs_interval_timer_start(nmp->nm_renew_timer, interval * 1000);

nfsmout:
	if (*npp)
		nfs_unlock(*npp);
	return (error);
}

static int
mountnfs(
	struct user_nfs_args *argp,
	mount_t mp,
	mbuf_t nam,
	vfs_context_t ctx,
	vnode_t *vpp)
{
	struct nfsmount *nmp;
	nfsnode_t np;
	int error, maxio, iosize;
	struct vfsstatfs *sbp;
	struct timespec ts = { 1, 0 };

	/*
	 * Silently clear NFSMNT_NOCONN if it's a TCP mount, it makes
	 * no sense in that context.
	 */
	if (argp->sotype == SOCK_STREAM)
		argp->flags &= ~NFSMNT_NOCONN;

	if (vfs_flags(mp) & MNT_UPDATE) {
		nmp = VFSTONFS(mp);
		/* update paths, file handles, etc, here	XXX */
		mbuf_freem(nam);
		return (0);
	} else {
		MALLOC_ZONE(nmp, struct nfsmount *,
				sizeof (struct nfsmount), M_NFSMNT, M_WAITOK);
		if (!nmp) {
			mbuf_freem(nam);
			return (ENOMEM);
		}
		bzero((caddr_t)nmp, sizeof (struct nfsmount));
		lck_mtx_init(&nmp->nm_lock, nfs_mount_grp, LCK_ATTR_NULL);
		TAILQ_INIT(&nmp->nm_resendq);
		TAILQ_INIT(&nmp->nm_iodq);
		TAILQ_INIT(&nmp->nm_gsscl);
		vfs_setfsprivate(mp, nmp);

		nfs_nhinit_finish();
	}
	lck_mtx_lock(&nmp->nm_lock);

	/* setup defaults */
	nmp->nm_vers = NFS_VER2;
	nmp->nm_timeo = NFS_TIMEO;
	nmp->nm_retry = NFS_RETRANS;
	if (argp->sotype == SOCK_DGRAM) {
		nmp->nm_wsize = NFS_DGRAM_WSIZE;
		nmp->nm_rsize = NFS_DGRAM_RSIZE;
	} else {
		nmp->nm_wsize = NFS_WSIZE;
		nmp->nm_rsize = NFS_RSIZE;
	}
	nmp->nm_readdirsize = NFS_READDIRSIZE;
	nmp->nm_numgrps = NFS_MAXGRPS;
	nmp->nm_readahead = NFS_DEFRAHEAD;
	nmp->nm_tprintf_delay = nfs_tprintf_delay;
	if (nmp->nm_tprintf_delay < 0)
		nmp->nm_tprintf_delay = 0;
	nmp->nm_tprintf_initial_delay = nfs_tprintf_initial_delay;
	if (nmp->nm_tprintf_initial_delay < 0)
		nmp->nm_tprintf_initial_delay = 0;
	nmp->nm_acregmin = NFS_MINATTRTIMO;
	nmp->nm_acregmax = NFS_MAXATTRTIMO;
	nmp->nm_acdirmin = NFS_MINDIRATTRTIMO;
	nmp->nm_acdirmax = NFS_MAXDIRATTRTIMO;
	nmp->nm_auth = RPCAUTH_SYS;

	vfs_getnewfsid(mp);
	nmp->nm_mountp = mp;
	vfs_setauthopaque(mp);
	nmp->nm_flag = argp->flags;
	nmp->nm_nam = nam;

	if (argp->flags & NFSMNT_NFSV4) {
		nmp->nm_vers = NFS_VER4;
		/* NFSv4 is only allowed over TCP. */
		if (argp->sotype != SOCK_STREAM) {
			error = EINVAL;
			goto bad;
		}
	} else if (argp->flags & NFSMNT_NFSV3)
		nmp->nm_vers = NFS_VER3;

	if (nmp->nm_vers == NFS_VER2)
		nmp->nm_flag &= ~NFSMNT_RDIRPLUS;

	if ((argp->flags & NFSMNT_TIMEO) && argp->timeo > 0) {
		nmp->nm_timeo = (argp->timeo * NFS_HZ + 5) / 10;
		if (nmp->nm_timeo < NFS_MINTIMEO)
			nmp->nm_timeo = NFS_MINTIMEO;
		else if (nmp->nm_timeo > NFS_MAXTIMEO)
			nmp->nm_timeo = NFS_MAXTIMEO;
	}

	if ((argp->flags & NFSMNT_RETRANS) && argp->retrans > 1) {
		nmp->nm_retry = argp->retrans;
		if (nmp->nm_retry > NFS_MAXREXMIT)
			nmp->nm_retry = NFS_MAXREXMIT;
	}

	if (nmp->nm_vers != NFS_VER2) {
		if (argp->sotype == SOCK_DGRAM)
			maxio = NFS_MAXDGRAMDATA;
		else
			maxio = NFS_MAXDATA;
	} else
		maxio = NFS_V2MAXDATA;

	if ((argp->flags & NFSMNT_WSIZE) && argp->wsize > 0) {
		nmp->nm_wsize = argp->wsize;
		/* Round down to multiple of blocksize */
		nmp->nm_wsize &= ~(NFS_FABLKSIZE - 1);
		if (nmp->nm_wsize <= 0)
			nmp->nm_wsize = NFS_FABLKSIZE;
	}
	if (nmp->nm_wsize > maxio)
		nmp->nm_wsize = maxio;
	if (nmp->nm_wsize > NFS_MAXBSIZE)
		nmp->nm_wsize = NFS_MAXBSIZE;

	if ((argp->flags & NFSMNT_RSIZE) && argp->rsize > 0) {
		nmp->nm_rsize = argp->rsize;
		/* Round down to multiple of blocksize */
		nmp->nm_rsize &= ~(NFS_FABLKSIZE - 1);
		if (nmp->nm_rsize <= 0)
			nmp->nm_rsize = NFS_FABLKSIZE;
	}
	if (nmp->nm_rsize > maxio)
		nmp->nm_rsize = maxio;
	if (nmp->nm_rsize > NFS_MAXBSIZE)
		nmp->nm_rsize = NFS_MAXBSIZE;

	if ((argp->flags & NFSMNT_READDIRSIZE) && argp->readdirsize > 0) {
		nmp->nm_readdirsize = argp->readdirsize;
	}
	if (nmp->nm_readdirsize > maxio)
		nmp->nm_readdirsize = maxio;
	if (nmp->nm_readdirsize > nmp->nm_rsize)
		nmp->nm_readdirsize = nmp->nm_rsize;

	if ((argp->flags & NFSMNT_MAXGRPS) && argp->maxgrouplist >= 0 &&
		argp->maxgrouplist <= NFS_MAXGRPS)
		nmp->nm_numgrps = argp->maxgrouplist;
	if ((argp->flags & NFSMNT_READAHEAD) && argp->readahead >= 0 &&
		argp->readahead <= NFS_MAXRAHEAD)
		nmp->nm_readahead = argp->readahead;
	if (argp->flags & NFSMNT_READAHEAD)
		nmp->nm_readahead = argp->readahead;
	if (nmp->nm_readahead < 0)
		nmp->nm_readahead = 0;
	else if (nmp->nm_readahead > NFS_MAXRAHEAD)
		nmp->nm_readahead = NFS_MAXRAHEAD;

	if (argp->version >= 4) {
		if ((argp->flags & NFSMNT_ACREGMIN) && argp->acregmin >= 0)
			nmp->nm_acregmin = argp->acregmin;
		if ((argp->flags & NFSMNT_ACREGMAX) && argp->acregmax >= 0)
			nmp->nm_acregmax = argp->acregmax;
		if ((argp->flags & NFSMNT_ACDIRMIN) && argp->acdirmin >= 0)
			nmp->nm_acdirmin = argp->acdirmin;
		if ((argp->flags & NFSMNT_ACDIRMAX) && argp->acdirmax >= 0)
			nmp->nm_acdirmax = argp->acdirmax;
		if (nmp->nm_acregmin > nmp->nm_acregmax)
			nmp->nm_acregmin = nmp->nm_acregmax;
		if (nmp->nm_acdirmin > nmp->nm_acdirmax)
			nmp->nm_acdirmin = nmp->nm_acdirmax;
	}
	if (argp->version >= 5) {
		if (argp->flags & NFSMNT_SECFLAVOR) {
			/*
			 * Check for valid security flavor
			 */
			switch (argp->auth) {
			case RPCAUTH_SYS:
			case RPCAUTH_KRB5:
			case RPCAUTH_KRB5I:
			case RPCAUTH_KRB5P:
				nmp->nm_auth = argp->auth;
				break;
			default:
				error = EINVAL;
				goto bad;
			}
		}
	}

	/* set up the version-specific function tables */
	if (nmp->nm_vers < NFS_VER4)
		nmp->nm_funcs = &nfs3_funcs;
	else
		nmp->nm_funcs = &nfs4_funcs;

	/* Set up the sockets and related info */
	nmp->nm_sotype = argp->sotype;
	nmp->nm_soproto = argp->proto;
	if (nmp->nm_sotype == SOCK_DGRAM)
		TAILQ_INIT(&nmp->nm_cwndq);

	lck_mtx_unlock(&nmp->nm_lock);

	/* make sure mbuf constants are set up */
	if (!nfs_mbuf_mhlen)
		nfs_mbuf_init();

	/* NFS does its own node locking */
	mp->mnt_vtable->vfc_threadsafe = TRUE;

	/* set up the socket */
	if ((error = nfs_connect(nmp)))
		goto bad;

	/*
	 * Get the root node/attributes from the NFS server and
	 * do any basic, version-specific setup.
	 */
	error = nmp->nm_funcs->nf_mount(nmp, ctx, argp, &np);
	if (error)
		goto bad;

	/*
	 * A reference count is needed on the node representing the
	 * remote root.  If this object is not persistent, then backward
	 * traversals of the mount point (i.e. "..") will not work if
	 * the node gets flushed out of the cache.
	 */
	nmp->nm_dnp = np;
	*vpp = NFSTOV(np);
	/* get usecount and drop iocount */
	error = vnode_ref(*vpp);
	vnode_put(*vpp);
	if (error)
		goto bad;

	/*
	 * Do statfs to ensure static info gets set to reasonable values.
	 */
	if ((error = nmp->nm_funcs->nf_update_statfs(nmp, ctx)))
		goto bad;
	sbp = vfs_statfs(mp);
	sbp->f_bsize = nmp->nm_fsattr.nfsa_bsize;
	sbp->f_blocks = nmp->nm_fsattr.nfsa_space_total / sbp->f_bsize;
	sbp->f_bfree = nmp->nm_fsattr.nfsa_space_free / sbp->f_bsize;
	sbp->f_bavail = nmp->nm_fsattr.nfsa_space_avail / sbp->f_bsize;
	sbp->f_bused = (nmp->nm_fsattr.nfsa_space_total / sbp->f_bsize) -
			(nmp->nm_fsattr.nfsa_space_free / sbp->f_bsize);
	sbp->f_files = nmp->nm_fsattr.nfsa_files_total;
	sbp->f_ffree = nmp->nm_fsattr.nfsa_files_free;
	sbp->f_iosize = nfs_iosize;

	/*
	 * Calculate the size used for I/O buffers.  Use the larger
	 * of the two sizes to minimise NFS requests but make sure
	 * that it is at least one VM page to avoid wasting buffer
	 * space and to allow easy mmapping of I/O buffers.
	 * The read/write RPC calls handle the splitting up of
	 * buffers into multiple requests if the buffer size is
	 * larger than the I/O size.
	 */
	iosize = max(nmp->nm_rsize, nmp->nm_wsize);
	if (iosize < PAGE_SIZE)
		iosize = PAGE_SIZE;
	nmp->nm_biosize = trunc_page_32(iosize);

	/*
	 * V3 mounts give us a (relatively) reliable remote access(2)
	 * call, so advertise the fact.
	 *
	 * XXX this may not be the best way to go, as the granularity
	 *     offered isn't a good match to our needs.
	 */
	if (nmp->nm_vers != NFS_VER2)
		vfs_setauthopaqueaccess(mp);

	if (nmp->nm_flag & NFSMNT_LOCALLOCKS)
		vfs_setlocklocal(nmp->nm_mountp);
	if (!(nmp->nm_flag & (NFSMNT_NOLOCKS|NFSMNT_LOCALLOCKS)))
		nfs_lockd_mount_change(1);

	lck_mtx_lock(&nmp->nm_lock);
	nmp->nm_state |= NFSSTA_MOUNTED;
	lck_mtx_unlock(&nmp->nm_lock);
	return (0);
bad:
	/* mark the socket for termination */
	lck_mtx_lock(&nmp->nm_lock);
	nmp->nm_sockflags |= NMSOCK_UNMOUNT;
	/* wait for any socket poking to complete */
	while (nmp->nm_sockflags & NMSOCK_POKE)
		msleep(&nmp->nm_sockflags, &nmp->nm_lock, PZERO-1, "nfswaitpoke", &ts);
	/* wait for the socket thread to terminate */
	while (nmp->nm_sockthd) {
		wakeup(&nmp->nm_sockthd);
		msleep(&nmp->nm_sockthd, &nmp->nm_lock, PZERO-1, "nfswaitsockthd", &ts);
	}
	/* tear down the socket */
	lck_mtx_unlock(&nmp->nm_lock);
	nfs_disconnect(nmp);
	if (nmp->nm_renew_timer) {
		thread_call_cancel(nmp->nm_renew_timer);
		thread_call_free(nmp->nm_renew_timer);
	}
	lck_mtx_destroy(&nmp->nm_lock, nfs_mount_grp);
	FREE_ZONE((caddr_t)nmp, sizeof (struct nfsmount), M_NFSMNT);
	mbuf_freem(nam);
	return (error);
}


/*
 * unmount system call
 */
static int
nfs_vfs_unmount(
	mount_t mp,
	int mntflags,
	__unused vfs_context_t ctx)
{
	struct nfsmount *nmp;
	vnode_t vp;
	int error, flags = 0, docallback;
	struct nfsreq *req, *treq;
	struct nfs_reqqhead iodq;
	struct timespec ts = { 1, 0 };

	nmp = VFSTONFS(mp);
	lck_mtx_lock(&nmp->nm_lock);
	/*
	 * During a force unmount we want to...
	 *   Mark that we are doing a force unmount.
	 *   Make the mountpoint soft.
	 */
	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		nmp->nm_state |= NFSSTA_FORCE;
		nmp->nm_flag |= NFSMNT_SOFT;
	}
	/*
	 * Goes something like this..
	 * - Call vflush() to clear out vnodes for this file system,
	 *   except for the swap files. Deal with them in 2nd pass.
	 * - Decrement reference on the vnode representing remote root.
	 * - Close the socket
	 * - Free up the data structures
	 */
	vp = NFSTOV(nmp->nm_dnp);
	lck_mtx_unlock(&nmp->nm_lock);
	
	/*
	 * vflush will check for busy vnodes on mountpoint.
	 * Will do the right thing for MNT_FORCE. That is, we should
	 * not get EBUSY back.
	 */
	error = vflush(mp, vp, SKIPSWAP | flags);
	if (mntflags & MNT_FORCE) {
		error = vflush(mp, NULLVP, flags); /* locks vp in the process */
	} else {
		if (vnode_isinuse(vp, 1))
			return (EBUSY);
		error = vflush(mp, vp, flags);
	}
	if (error)
		return (error);

	lck_mtx_lock(&nmp->nm_lock);
	nmp->nm_state &= ~NFSSTA_MOUNTED;
	lck_mtx_unlock(&nmp->nm_lock);

	/*
	 * Release the root vnode reference held by mountnfs()
	 */
	vnode_rele(vp);

	vflush(mp, NULLVP, FORCECLOSE);

	/*
	 * Destroy any RPCSEC_GSS contexts
	 */
	if (!TAILQ_EMPTY(&nmp->nm_gsscl))
		nfs_gss_clnt_ctx_unmount(nmp, mntflags);

	vfs_setfsprivate(mp, 0); /* don't want to end up using stale vp */

	/* mark the socket for termination */
	lck_mtx_lock(&nmp->nm_lock);
	nmp->nm_sockflags |= NMSOCK_UNMOUNT;

	/* wait for any socket poking to complete */
	while (nmp->nm_sockflags & NMSOCK_POKE)
		msleep(&nmp->nm_sockflags, &nmp->nm_lock, PZERO-1, "nfswaitpoke", &ts);

	/* wait for the socket thread to terminate */
	while (nmp->nm_sockthd) {
		wakeup(&nmp->nm_sockthd);
		msleep(&nmp->nm_sockthd, &nmp->nm_lock, PZERO-1, "nfswaitsockthd", &ts);
	}

	/* tear down the socket */
	lck_mtx_unlock(&nmp->nm_lock);
	nfs_disconnect(nmp);
	lck_mtx_lock(&nmp->nm_lock);

	/* cancel any renew timer */
	if (nmp->nm_renew_timer) {
		thread_call_cancel(nmp->nm_renew_timer);
		thread_call_free(nmp->nm_renew_timer);
	}

	mbuf_freem(nmp->nm_nam);
	lck_mtx_unlock(&nmp->nm_lock);

	if (!(nmp->nm_flag & (NFSMNT_NOLOCKS|NFSMNT_LOCALLOCKS)))
		nfs_lockd_mount_change(-1);

	/*
	 * Loop through outstanding request list and remove dangling
	 * references to defunct nfsmount struct
	 */
	TAILQ_INIT(&iodq);
	lck_mtx_lock(nfs_request_mutex);
	TAILQ_FOREACH(req, &nfs_reqq, r_chain) {
		if (req->r_nmp == nmp) {
			lck_mtx_lock(&req->r_mtx);
			req->r_nmp = NULL;
			lck_mtx_unlock(&req->r_mtx);
			if (req->r_callback.rcb_func) {
				/* async I/O RPC needs to be finished */
				lck_mtx_lock(nfsiod_mutex);
				if (req->r_achain.tqe_next == NFSREQNOLIST)
					TAILQ_INSERT_TAIL(&iodq, req, r_achain);
				lck_mtx_unlock(nfsiod_mutex);
			}
			lck_mtx_lock(&nmp->nm_lock);
			if (req->r_rchain.tqe_next != NFSREQNOLIST) {
				TAILQ_REMOVE(&nmp->nm_resendq, req, r_rchain);
				req->r_rchain.tqe_next = NFSREQNOLIST;
				req->r_flags &= ~R_RESENDQ;
			}
			lck_mtx_unlock(&nmp->nm_lock);
			wakeup(req);
		}
	}
	lck_mtx_unlock(nfs_request_mutex);

	/* finish any async I/O RPCs queued up */
	lck_mtx_lock(nfsiod_mutex);
	TAILQ_CONCAT(&iodq, &nmp->nm_iodq, r_achain);
	lck_mtx_unlock(nfsiod_mutex);
	TAILQ_FOREACH_SAFE(req, &iodq, r_achain, treq) {
		TAILQ_REMOVE(&iodq, req, r_achain);
		req->r_achain.tqe_next = NFSREQNOLIST;
		lck_mtx_lock(&req->r_mtx);
		req->r_error = ENXIO;
		docallback = !(req->r_flags & R_WAITSENT);
		lck_mtx_unlock(&req->r_mtx);
		if (docallback)
			req->r_callback.rcb_func(req);
	}

	lck_mtx_destroy(&nmp->nm_lock, nfs_mount_grp);
	FREE_ZONE((caddr_t)nmp, sizeof (struct nfsmount), M_NFSMNT);
	return (0);
}

/*
 * Return root of a filesystem
 */
static int
nfs_vfs_root(mount_t mp, vnode_t *vpp, __unused vfs_context_t ctx)
{
	vnode_t vp;
	struct nfsmount *nmp;
	int error;
	u_long vpid;

	nmp = VFSTONFS(mp);
	vp = NFSTOV(nmp->nm_dnp);
	vpid = vnode_vid(vp);
	while ((error = vnode_getwithvid(vp, vpid))) {
		/* vnode_get() may return ENOENT if the dir changes. */
		/* If that happens, just try it again, else return the error. */
		if ((error != ENOENT) || (vnode_vid(vp) == vpid))
			return (error);
		vpid = vnode_vid(vp);
	}
	*vpp = vp;
	return (0);
}

/*
 * Do operations associated with quotas
 */
#if !QUOTA
static int
nfs_vfs_quotactl(
	__unused mount_t mp,
	__unused int cmds,
	__unused uid_t uid,
	__unused caddr_t datap,
	__unused vfs_context_t context)
{
	return (ENOTSUP);
}
#else
static int
nfs_aux_request(
	struct nfsmount *nmp,
	thread_t thd,
	struct sockaddr_in *saddr,
	mbuf_t mreq,
	uint32_t xid,
	int timeo,
	struct nfsm_chain *nmrep)
{
	int error = 0, on = 1, try, sendat = 2;
	socket_t so = NULL;
	struct timeval tv = { 1, 0 };
	mbuf_t m, mrep = NULL;
	struct msghdr msg;
	uint32_t rxid, reply, reply_status, rejected_status;
	uint32_t verf_type, verf_len, accepted_status;
	size_t readlen;

	/* create socket and set options */
	if (((error = sock_socket(saddr->sin_family, SOCK_DGRAM, IPPROTO_UDP, NULL, NULL, &so))) ||
	    ((error = sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))) ||
	    ((error = sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))) ||
	    ((error = sock_setsockopt(so, SOL_SOCKET, SO_NOADDRERR, &on, sizeof(on)))))
		goto nfsmout;

	for (try=0; try < timeo; try++) {
		if ((error = nfs_sigintr(nmp, NULL, thd, 0)))
			break;
		if (!try || (try == sendat)) {
			/* send the request (resending periodically) */
			if ((error = mbuf_copym(mreq, 0, MBUF_COPYALL, MBUF_WAITOK, &m)))
				goto nfsmout;
			bzero(&msg, sizeof(msg));
			msg.msg_name = saddr;
			msg.msg_namelen = saddr->sin_len;
			if ((error = sock_sendmbuf(so, &msg, m, 0, NULL)))
				goto nfsmout;
			sendat *= 2;
			if (sendat > 30)
				sendat = 30;
		}
		/* wait for the response */
		readlen = 1<<18;
		bzero(&msg, sizeof(msg));
		error = sock_receivembuf(so, &msg, &mrep, 0, &readlen);
		if (error == EWOULDBLOCK)
			continue;
		nfsmout_if(error);
		/* parse the response */
		nfsm_chain_dissect_init(error, nmrep, mrep);
		nfsm_chain_get_32(error, nmrep, rxid);
		nfsm_chain_get_32(error, nmrep, reply);
		nfsmout_if(error);
		if ((rxid != xid) || (reply != RPC_REPLY))
			error = EBADRPC;
		nfsm_chain_get_32(error, nmrep, reply_status);
		nfsmout_if(error);
		if (reply_status == RPC_MSGDENIED) {
			nfsm_chain_get_32(error, nmrep, rejected_status);
			nfsmout_if(error);
			error = (rejected_status == RPC_MISMATCH) ? ENOTSUP : EACCES;
			goto nfsmout;
		}
		nfsm_chain_get_32(error, nmrep, verf_type); /* verifier flavor */
		nfsm_chain_get_32(error, nmrep, verf_len); /* verifier length */
		nfsmout_if(error);
		if (verf_len)
			nfsm_chain_adv(error, nmrep, nfsm_rndup(verf_len));
		nfsm_chain_get_32(error, nmrep, accepted_status);
		nfsm_assert(error, (accepted_status == RPC_SUCCESS), EIO);
		break;
	}
nfsmout:
	if (so) {
		sock_shutdown(so, SHUT_RDWR);
		sock_close(so);
	}
	mbuf_freem(mreq);
	return (error);
}

static int
nfs3_getquota(struct nfsmount *nmp, vfs_context_t ctx, u_long id, int type, struct dqblk *dqb)
{
	int error = 0, auth_len, slen, timeo;
	int rqvers = (type == GRPQUOTA) ? RPCRQUOTA_EXT_VER : RPCRQUOTA_VER;
	thread_t thd = vfs_context_thread(ctx);
	kauth_cred_t cred = vfs_context_ucred(ctx);
	char *path;
	uint64_t xid = 0;
	struct nfsm_chain nmreq, nmrep;
	mbuf_t mreq;
	uint32_t val = 0, bsize;
	struct sockaddr *nam = mbuf_data(nmp->nm_nam);
	struct sockaddr_in saddr;
	struct timeval now;

	bcopy(nam, &saddr, min(sizeof(saddr), nam->sa_len));
	auth_len = ((((cred->cr_ngroups - 1) > nmp->nm_numgrps) ?
			nmp->nm_numgrps : (cred->cr_ngroups - 1)) << 2) +
			5 * NFSX_UNSIGNED;
	timeo = (nmp->nm_flag & NFSMNT_SOFT) ? 10 : 60;
	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	/* check if we have a recently cached rquota port */
	if (nmp->nm_rqport) {
		microuptime(&now);
		if ((nmp->nm_rqportstamp + 60) >= (uint32_t)now.tv_sec)
			goto got_rqport;
	}

	/* send portmap request to get rquota port */
	saddr.sin_port = htons(PMAPPORT);
	nfsm_chain_build_alloc_init(error, &nmreq, 4*NFSX_UNSIGNED);
	nfsm_chain_add_32(error, &nmreq, RPCPROG_RQUOTA);
	nfsm_chain_add_32(error, &nmreq, rqvers);
	nfsm_chain_add_32(error, &nmreq, IPPROTO_UDP);
	nfsm_chain_add_32(error, &nmreq, 0);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfsm_rpchead2(SOCK_DGRAM, PMAPPROG, PMAPVERS, PMAPPROC_GETPORT,
			RPCAUTH_SYS, auth_len, cred, NULL, nmreq.nmc_mhead, &xid, &mreq);
	nfsmout_if(error);
	nmreq.nmc_mhead = NULL;
	error = nfs_aux_request(nmp, thd, &saddr, mreq, R_XID32(xid), timeo, &nmrep);
	nfsmout_if(error);

	/* grab rquota port from portmap response */
	nfsm_chain_get_32(error, &nmrep, val);
	nfsmout_if(error);
	nmp->nm_rqport = val;
	microuptime(&now);
	nmp->nm_rqportstamp = now.tv_sec;
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	xid = 0;

got_rqport:
	/* rquota request */
	saddr.sin_port = htons(nmp->nm_rqport);
	path = &vfs_statfs(nmp->nm_mountp)->f_mntfromname[0];
	while (*path && (*path != '/'))
		path++;
	slen = strlen(path);
	nfsm_chain_build_alloc_init(error, &nmreq, 3 * NFSX_UNSIGNED + nfsm_rndup(slen));
	nfsm_chain_add_string(error, &nmreq, path, slen);
	if (type == GRPQUOTA)
		nfsm_chain_add_32(error, &nmreq, type);
	nfsm_chain_add_32(error, &nmreq, id);
	nfsm_chain_build_done(error, &nmreq);
	nfsmout_if(error);
	error = nfsm_rpchead2(SOCK_DGRAM, RPCPROG_RQUOTA, rqvers, RPCRQUOTA_GET,
			RPCAUTH_SYS, auth_len, cred, NULL, nmreq.nmc_mhead, &xid, &mreq);
	nfsmout_if(error);
	nmreq.nmc_mhead = NULL;
	error = nfs_aux_request(nmp, thd, &saddr, mreq, R_XID32(xid), timeo, &nmrep);
	nfsmout_if(error);

	/* parse rquota response */
	nfsm_chain_get_32(error, &nmrep, val);
	if (!error && (val != RQUOTA_STAT_OK)) {
		if (val == RQUOTA_STAT_NOQUOTA)
			error = ENOENT;
		else if (val == RQUOTA_STAT_EPERM)
			error = EPERM;
		else
			error = EIO;
	}
	nfsm_chain_get_32(error, &nmrep, bsize);
	nfsm_chain_adv(error, &nmrep, NFSX_UNSIGNED);
	nfsm_chain_get_32(error, &nmrep, val);
	nfsmout_if(error);
	dqb->dqb_bhardlimit = (uint64_t)val * bsize;
	nfsm_chain_get_32(error, &nmrep, val);
	nfsmout_if(error);
	dqb->dqb_bsoftlimit = (uint64_t)val * bsize;
	nfsm_chain_get_32(error, &nmrep, val);
	nfsmout_if(error);
	dqb->dqb_curbytes = (uint64_t)val * bsize;
	nfsm_chain_get_32(error, &nmrep, dqb->dqb_ihardlimit);
	nfsm_chain_get_32(error, &nmrep, dqb->dqb_isoftlimit);
	nfsm_chain_get_32(error, &nmrep, dqb->dqb_curinodes);
	nfsm_chain_get_32(error, &nmrep, dqb->dqb_btime);
	nfsm_chain_get_32(error, &nmrep, dqb->dqb_itime);
	nfsmout_if(error);
	dqb->dqb_id = id;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

static int
nfs4_getquota(struct nfsmount *nmp, vfs_context_t ctx, u_long id, int type, struct dqblk *dqb)
{
	nfsnode_t np;
	int error = 0, status, nfsvers, numops;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN];
	thread_t thd = vfs_context_thread(ctx);
	kauth_cred_t cred = vfs_context_ucred(ctx);

	if (type != USRQUOTA)  /* NFSv4 only supports user quotas */
		return (ENOTSUP);

	/* first check that the server supports any of the quota attributes */
	if (!NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_supp_attr, NFS_FATTR_QUOTA_AVAIL_HARD) &&
	    !NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_supp_attr, NFS_FATTR_QUOTA_AVAIL_SOFT) &&
	    !NFS_BITMAP_ISSET(nmp->nm_fsattr.nfsa_supp_attr, NFS_FATTR_QUOTA_USED))
		return (ENOTSUP);

	/*
	 * The credential passed to the server needs to have
	 * an effective uid that matches the given uid.
	 */
	if (id != kauth_cred_getuid(cred)) {
		struct ucred temp_cred;
		bzero(&temp_cred, sizeof(temp_cred));
		temp_cred.cr_uid = id;
		temp_cred.cr_ngroups = cred->cr_ngroups;
		bcopy(cred->cr_groups, temp_cred.cr_groups, sizeof(temp_cred.cr_groups));
		cred = kauth_cred_create(&temp_cred);
		if (!IS_VALID_CRED(cred))
			return (ENOMEM);
	} else {
		kauth_cred_ref(cred);
	}

	nfsvers = nmp->nm_vers;
	np = nmp->nm_dnp;
	if ((error = vnode_get(NFSTOV(np)))) {
		kauth_cred_unref(&cred);
		return(error);
	}

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH + GETATTR
	numops = 2;
	nfsm_chain_build_alloc_init(error, &nmreq, 15 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "quota", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	NFS_CLEAR_ATTRIBUTES(bitmap);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_QUOTA_AVAIL_HARD);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_QUOTA_AVAIL_SOFT);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_QUOTA_USED);
	nfsm_chain_add_bitmap_masked(error, &nmreq, bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request2(np, NULL, &nmreq, NFSPROC4_COMPOUND, thd, cred, 0, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_assert(error, NFSTONMP(np), ENXIO);
	nfsmout_if(error);
	error = nfs4_parsefattr(&nmrep, NULL, NULL, NULL, dqb);
	nfsmout_if(error);
	nfsm_assert(error, NFSTONMP(np), ENXIO);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	vnode_put(NFSTOV(np));
	kauth_cred_unref(&cred);
	return (error);
}

static int
nfs_vfs_quotactl(mount_t mp, int cmds, uid_t uid, caddr_t datap, vfs_context_t ctx)
{
	struct nfsmount *nmp;
	int cmd, type, error, nfsvers;
	uid_t ruid = vfs_context_ucred(ctx)->cr_ruid;
	struct dqblk *dqb = (struct dqblk*)datap;

	if (!(nmp = VFSTONFS(mp)))
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if (uid == ~0U)
		uid = ruid;

	/* we can only support Q_GETQUOTA */
	cmd = cmds >> SUBCMDSHIFT;
	switch (cmd) {
	case Q_GETQUOTA:
		break;
	case Q_QUOTAON:
	case Q_QUOTAOFF:
	case Q_SETQUOTA:
	case Q_SETUSE:
	case Q_SYNC:
	case Q_QUOTASTAT:
		return (ENOTSUP);
	default:
		return (EINVAL);
	}

	type = cmds & SUBCMDMASK;
	if ((u_int)type >= MAXQUOTAS)
		return (EINVAL);
	if ((uid != ruid) && ((error = vfs_context_suser(ctx))))
		return (error);

	if (vfs_busy(mp, LK_NOWAIT))
		return (0);
	bzero(dqb, sizeof(*dqb));
	error = nmp->nm_funcs->nf_getquota(nmp, ctx, uid, type, dqb);
	vfs_unbusy(mp);
	return (error);
}
#endif

/*
 * Flush out the buffer cache
 */

struct nfs_sync_cargs {
	thread_t	thd;
	int		waitfor;
	int		error;
};

static int
nfs_sync_callout(vnode_t vp, void *arg)
{
	struct nfs_sync_cargs *cargs = (struct nfs_sync_cargs*)arg;
	int error;

	if (LIST_EMPTY(&VTONFS(vp)->n_dirtyblkhd))
		return (VNODE_RETURNED);
	if (VTONFS(vp)->n_wrbusy > 0)
		return (VNODE_RETURNED);
	if (VTONFS(vp)->n_bflag & (NBFLUSHINPROG|NBINVALINPROG))
		return (VNODE_RETURNED);

	error = nfs_flush(VTONFS(vp), cargs->waitfor, cargs->thd, 0);
	if (error)
		cargs->error = error;

	return (VNODE_RETURNED);
}

static int
nfs_vfs_sync(mount_t mp, int waitfor, vfs_context_t ctx)
{
	struct nfs_sync_cargs cargs;

	cargs.waitfor = waitfor;
	cargs.thd = vfs_context_thread(ctx);
	cargs.error = 0;

	vnode_iterate(mp, 0, nfs_sync_callout, &cargs);

	return (cargs.error);
}

/*
 * NFS flat namespace lookup.
 * Currently unsupported.
 */
/*ARGSUSED*/
static int
nfs_vfs_vget(
	__unused mount_t mp,
	__unused ino64_t ino,
	__unused vnode_t *vpp,
	__unused vfs_context_t ctx)
{

	return (ENOTSUP);
}

/*
 * At this point, this should never happen
 */
/*ARGSUSED*/
static int
nfs_vfs_fhtovp(
	__unused mount_t mp,
	__unused int fhlen,
	__unused unsigned char *fhp,
	__unused vnode_t *vpp,
	__unused vfs_context_t ctx)
{

	return (ENOTSUP);
}

/*
 * Vnode pointer to File handle, should never happen either
 */
/*ARGSUSED*/
static int
nfs_vfs_vptofh(
	__unused vnode_t vp,
	__unused int *fhlenp,
	__unused unsigned char *fhp,
	__unused vfs_context_t ctx)
{

	return (ENOTSUP);
}

/*
 * Vfs start routine, a no-op.
 */
/*ARGSUSED*/
static int
nfs_vfs_start(
	__unused mount_t mp,
	__unused int flags,
	__unused vfs_context_t ctx)
{

	return (0);
}

/*
 * Do that sysctl thang...
 */
static int
nfs_vfs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp,
           user_addr_t newp, size_t newlen, vfs_context_t ctx)
{
	int error = 0, val;
	struct sysctl_req *req = NULL;
	struct vfsidctl vc;
	struct user_vfsidctl user_vc;
	mount_t mp;
	struct nfsmount *nmp = NULL;
	struct vfsquery vq;
	boolean_t is_64_bit;
#if NFSSERVER
	struct nfs_exportfs *nxfs;
	struct nfs_export *nx;
	struct nfs_active_user_list *ulist;
	struct nfs_export_stat_desc stat_desc;
	struct nfs_export_stat_rec statrec;
	struct nfs_user_stat_node *unode, *unode_next;
	struct nfs_user_stat_desc ustat_desc;
	struct nfs_user_stat_user_rec ustat_rec;
	struct nfs_user_stat_path_rec upath_rec;
	uint bytes_avail, bytes_total, recs_copied;
	uint numExports, totlen, pos, numRecs, count;
#endif /* NFSSERVER */

	/*
	 * All names at this level are terminal.
	 */
	if (namelen > 1)
		return (ENOTDIR);	/* overloaded */

	is_64_bit = vfs_context_is64bit(ctx);

	/* common code for "new style" VFS_CTL sysctl, get the mount. */
	switch (name[0]) {
	case VFS_CTL_TIMEO:
	case VFS_CTL_QUERY:
	case VFS_CTL_NOLOCKS:
		req = CAST_DOWN(struct sysctl_req *, oldp);
		if (is_64_bit) {
			error = SYSCTL_IN(req, &user_vc, sizeof(user_vc));
			if (error)
				 return (error);
			mp = vfs_getvfs(&user_vc.vc_fsid);
		} else {
			error = SYSCTL_IN(req, &vc, sizeof(vc));
			if (error)
				return (error);
			mp = vfs_getvfs(&vc.vc_fsid);
		}
		if (mp == NULL)
			return (ENOENT);
		nmp = VFSTONFS(mp);
		if (nmp == NULL)
			return (ENOENT);
		bzero(&vq, sizeof(vq));
		req->newidx = 0;
		if (is_64_bit) {
			req->newptr = user_vc.vc_ptr;
			req->newlen = (size_t)user_vc.vc_len;
		} else {
			req->newptr = CAST_USER_ADDR_T(vc.vc_ptr);
			req->newlen = vc.vc_len;
		}
	}

	switch(name[0]) {
	case NFS_NFSSTATS:
		if (!oldp) {
			*oldlenp = sizeof nfsstats;
			return (0);
		}

		if (*oldlenp < sizeof nfsstats) {
			*oldlenp = sizeof nfsstats;
			return (ENOMEM);
		}

		error = copyout(&nfsstats, oldp, sizeof nfsstats);
		if (error)
			return (error);

		if (newp && newlen != sizeof nfsstats)
			return (EINVAL);

		if (newp)
			return copyin(newp, &nfsstats, sizeof nfsstats);
		return (0);
#if NFSSERVER
	case NFS_EXPORTSTATS:
		/* setup export stat descriptor */
		stat_desc.rec_vers = NFS_EXPORT_STAT_REC_VERSION;

		if (!nfsrv_is_initialized()) {
			stat_desc.rec_count = 0;
			if (oldp && (*oldlenp >= sizeof(struct nfs_export_stat_desc)))
				error = copyout(&stat_desc, oldp, sizeof(struct nfs_export_stat_desc));
			*oldlenp = sizeof(struct nfs_export_stat_desc);
			return (error);
		}

		/* Count the number of exported directories */
		lck_rw_lock_shared(&nfsrv_export_rwlock);
		numExports = 0;
		LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next)
			LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next)
					numExports += 1;

		/* update stat descriptor's export record count */
		stat_desc.rec_count = numExports;

		/* calculate total size of required buffer */
		totlen = sizeof(struct nfs_export_stat_desc) + (numExports * sizeof(struct nfs_export_stat_rec));

		/* Check caller's buffer */
		if (oldp == 0) {
			lck_rw_done(&nfsrv_export_rwlock);
			/* indicate required buffer len */
			*oldlenp = totlen;
			return (0);
		}

		/* We require the caller's buffer to be at least large enough to hold the descriptor */
		if (*oldlenp < sizeof(struct nfs_export_stat_desc)) {
			lck_rw_done(&nfsrv_export_rwlock);
			/* indicate required buffer len */
			*oldlenp = totlen;
			return (ENOMEM);
		}

		/* indicate required buffer len */
		*oldlenp = totlen;

		/* check if export table is empty */
		if (!numExports) {
			lck_rw_done(&nfsrv_export_rwlock);
			error = copyout(&stat_desc, oldp, sizeof(struct nfs_export_stat_desc));
			return (error);
		}

		/* calculate how many actual export stat records fit into caller's buffer */
		numRecs = (*oldlenp - sizeof(struct nfs_export_stat_desc)) / sizeof(struct nfs_export_stat_rec);

		if (!numRecs) {
			/* caller's buffer can only accomodate descriptor */
			lck_rw_done(&nfsrv_export_rwlock);
			stat_desc.rec_count = 0;
			error = copyout(&stat_desc, oldp, sizeof(struct nfs_export_stat_desc));
			return (error);
		}

		/* adjust to actual number of records to copyout to caller's buffer */
		if (numRecs > numExports)
			numRecs = numExports;

		/* set actual number of records we are returning */
		stat_desc.rec_count = numRecs;

		/* first copy out the stat descriptor */
		pos = 0;
		error = copyout(&stat_desc, oldp + pos, sizeof(struct nfs_export_stat_desc));
		if (error) {
			lck_rw_done(&nfsrv_export_rwlock);
			return (error);
		}
		pos += sizeof(struct nfs_export_stat_desc);

		/* Loop through exported directories */
		count = 0;
		LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next) {
			LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {

				if (count >= numRecs)
					break;

				/* build exported filesystem path */
				snprintf(statrec.path, sizeof(statrec.path), "%s%s%s",
					nxfs->nxfs_path, ((nxfs->nxfs_path[1] && nx->nx_path[0]) ? "/" : ""),
					nx->nx_path);

				/* build the 64-bit export stat counters */
				statrec.ops = ((uint64_t)nx->nx_stats.ops.hi << 32) |
						nx->nx_stats.ops.lo;
				statrec.bytes_read = ((uint64_t)nx->nx_stats.bytes_read.hi << 32) |
						nx->nx_stats.bytes_read.lo;
				statrec.bytes_written = ((uint64_t)nx->nx_stats.bytes_written.hi << 32) |
						nx->nx_stats.bytes_written.lo;
				error = copyout(&statrec, oldp + pos, sizeof(statrec));
				if (error) {
					lck_rw_done(&nfsrv_export_rwlock);
					return (error);
				}
				/* advance buffer position */
				pos += sizeof(statrec);
			}
		}
		lck_rw_done(&nfsrv_export_rwlock);
		break;
	case NFS_USERSTATS:
		/* init structures used for copying out of kernel */
		ustat_desc.rec_vers = NFS_USER_STAT_REC_VERSION;
		ustat_rec.rec_type = NFS_USER_STAT_USER_REC;
		upath_rec.rec_type = NFS_USER_STAT_PATH_REC;

		/* initialize counters */
		bytes_total = sizeof(struct nfs_user_stat_desc);
		bytes_avail  = *oldlenp;
		recs_copied = 0;

		if (!nfsrv_is_initialized()) /* NFS server not initialized, so no stats */
			goto ustat_skip;

		/* reclaim old expired user nodes */
		nfsrv_active_user_list_reclaim();

		/* reserve space for the buffer descriptor */
		if (bytes_avail >= sizeof(struct nfs_user_stat_desc))
			bytes_avail -= sizeof(struct nfs_user_stat_desc);
		else
			bytes_avail = 0;

		/* put buffer position past the buffer descriptor */
		pos = sizeof(struct nfs_user_stat_desc);

		/* Loop through exported directories */
		lck_rw_lock_shared(&nfsrv_export_rwlock);
		LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next) {
			LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
				/* copy out path */
				if (bytes_avail >= sizeof(struct nfs_user_stat_path_rec)) {
					snprintf(upath_rec.path, sizeof(upath_rec.path), "%s%s%s",
					    nxfs->nxfs_path, ((nxfs->nxfs_path[1] && nx->nx_path[0]) ? "/" : ""),
					    nx->nx_path);

					error = copyout(&upath_rec, oldp + pos, sizeof(struct nfs_user_stat_path_rec));
					if (error) {
						/* punt */
						goto ustat_done;
					}

					pos += sizeof(struct nfs_user_stat_path_rec);
					bytes_avail -= sizeof(struct nfs_user_stat_path_rec);
					recs_copied++;
				}
				else {
					/* Caller's buffer is exhausted */
					bytes_avail = 0;
				}

				bytes_total += sizeof(struct nfs_user_stat_path_rec);

				/* Scan through all user nodes of this export */
				ulist = &nx->nx_user_list;
				lck_mtx_lock(&ulist->user_mutex);
				for (unode = TAILQ_FIRST(&ulist->user_lru); unode; unode = unode_next) {
					unode_next = TAILQ_NEXT(unode, lru_link);

					/* copy out node if there is space */
					if (bytes_avail >= sizeof(struct nfs_user_stat_user_rec)) {
						/* prepare a user stat rec for copying out */
						ustat_rec.uid = unode->uid;
						bcopy(&unode->sock, &ustat_rec.sock, unode->sock.ss_len);
						ustat_rec.ops = unode->ops;
						ustat_rec.bytes_read = unode->bytes_read;
						ustat_rec.bytes_written = unode->bytes_written;
						ustat_rec.tm_start = unode->tm_start;
						ustat_rec.tm_last = unode->tm_last;

						error = copyout(&ustat_rec, oldp + pos, sizeof(struct nfs_user_stat_user_rec));

						if (error) {
							/* punt */
							lck_mtx_unlock(&ulist->user_mutex);
							goto ustat_done;
						}

						pos += sizeof(struct nfs_user_stat_user_rec);
						bytes_avail -= sizeof(struct nfs_user_stat_user_rec);
						recs_copied++;
					}
					else {
						/* Caller's buffer is exhausted */
						bytes_avail = 0;
					}
					bytes_total += sizeof(struct nfs_user_stat_user_rec);
				}
				/* can unlock this export's list now */
				lck_mtx_unlock(&ulist->user_mutex);
			}
		}

ustat_done:
		/* unlock the export table */
		lck_rw_done(&nfsrv_export_rwlock);

ustat_skip:
		/* indicate number of actual records copied */
		ustat_desc.rec_count = recs_copied;

		if (!error) {
			/* check if there was enough room for the buffer descriptor */
			if (*oldlenp >= sizeof(struct nfs_user_stat_desc))
				error = copyout(&ustat_desc, oldp, sizeof(struct nfs_user_stat_desc));
			else
				error = ENOMEM;

			/* always indicate required buffer size */
			*oldlenp = bytes_total;
		}
		break;
	case NFS_USERCOUNT:
		if (!oldp) {
			*oldlenp = sizeof(nfsrv_user_stat_node_count);
			return (0);
		}

		if (*oldlenp < sizeof(nfsrv_user_stat_node_count)) {
			*oldlenp = sizeof(nfsrv_user_stat_node_count);
			return (ENOMEM);
		}

		if (nfsrv_is_initialized()) {
			/* reclaim old expired user nodes */
			nfsrv_active_user_list_reclaim();
		}

		error = copyout(&nfsrv_user_stat_node_count, oldp, sizeof(nfsrv_user_stat_node_count));
		break;
#endif /* NFSSERVER */
	case VFS_CTL_NOLOCKS:
 		if (req->oldptr != USER_ADDR_NULL) {
			lck_mtx_lock(&nmp->nm_lock);
			val = (nmp->nm_flag & NFSMNT_NOLOCKS) ? 1 : 0;
			lck_mtx_unlock(&nmp->nm_lock);
 			error = SYSCTL_OUT(req, &val, sizeof(val));
 			if (error)
 				return (error);
 		}
 		if (req->newptr != USER_ADDR_NULL) {
 			error = SYSCTL_IN(req, &val, sizeof(val));
 			if (error)
 				return (error);
			lck_mtx_lock(&nmp->nm_lock);
			if (nmp->nm_flag & NFSMNT_LOCALLOCKS) {
				/* can't toggle locks when using local locks */
				error = EINVAL;
			} else if (val) {
				if (!(nmp->nm_flag & NFSMNT_NOLOCKS))
					nfs_lockd_mount_change(-1);
				nmp->nm_flag |= NFSMNT_NOLOCKS;
				nmp->nm_state &= ~NFSSTA_LOCKTIMEO;
			} else {
				if (nmp->nm_flag & NFSMNT_NOLOCKS)
					nfs_lockd_mount_change(1);
				nmp->nm_flag &= ~NFSMNT_NOLOCKS;
			}
			lck_mtx_unlock(&nmp->nm_lock);
 		}
		break;
	case VFS_CTL_QUERY:
		lck_mtx_lock(&nmp->nm_lock);
		if (nmp->nm_state & (NFSSTA_TIMEO|NFSSTA_JUKEBOXTIMEO))
			vq.vq_flags |= VQ_NOTRESP;
		if (!(nmp->nm_flag & (NFSMNT_NOLOCKS|NFSMNT_LOCALLOCKS)) &&
		    (nmp->nm_state & NFSSTA_LOCKTIMEO))
			vq.vq_flags |= VQ_NOTRESP;
		lck_mtx_unlock(&nmp->nm_lock);
		error = SYSCTL_OUT(req, &vq, sizeof(vq));
		break;
 	case VFS_CTL_TIMEO:
 		if (req->oldptr != USER_ADDR_NULL) {
			lck_mtx_lock(&nmp->nm_lock);
			val = nmp->nm_tprintf_initial_delay;
			lck_mtx_unlock(&nmp->nm_lock);
 			error = SYSCTL_OUT(req, &val, sizeof(val));
 			if (error)
 				return (error);
 		}
 		if (req->newptr != USER_ADDR_NULL) {
 			error = SYSCTL_IN(req, &val, sizeof(val));
 			if (error)
 				return (error);
			lck_mtx_lock(&nmp->nm_lock);
 			if (val < 0)
 				nmp->nm_tprintf_initial_delay = 0;
			else
				nmp->nm_tprintf_initial_delay = val;
			lck_mtx_unlock(&nmp->nm_lock);
 		}
		break;
	default:
		return (ENOTSUP);
	}
	return (error);
}
