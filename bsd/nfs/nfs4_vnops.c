/*
 * Copyright (c) 2006-2007 Apple Inc. All rights reserved.
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

/*
 * vnode op calls for NFS version 4
 */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/resourcevar.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/conf.h>
#include <sys/vnode_internal.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/ubc_internal.h>
#include <sys/attr.h>
#include <sys/signalvar.h>
#include <sys/uio_internal.h>

#include <vfs/vfs_support.h>

#include <sys/vm.h>

#include <sys/time.h>
#include <kern/clock.h>
#include <libkern/OSAtomic.h>

#include <miscfs/fifofs/fifo.h>
#include <miscfs/specfs/specdev.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfs_lock.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <vm/vm_kern.h>

#include <kern/task.h>
#include <kern/sched_prim.h>


int
nfs4_access_rpc(nfsnode_t np, u_long *mode, vfs_context_t ctx)
{
	int error = 0, status, numops, slot;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	struct timeval now;
	uint32_t access, supported = 0, missing;
	struct nfsmount *nmp = NFSTONMP(np);
	int nfsvers = nmp->nm_vers;
	uid_t uid;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	numops = 3; // PUTFH + ACCESS + GETATTR
	nfsm_chain_build_alloc_init(error, &nmreq, 17 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "access", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_ACCESS);
	nfsm_chain_add_32(error, &nmreq, *mode);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_ACCESS);
	nfsm_chain_get_32(error, &nmrep, supported);
	nfsm_chain_get_32(error, &nmrep, access);
	nfsmout_if(error);
	if ((missing = (*mode & ~supported))) {
		/* missing support for something(s) we wanted */
		if (missing & NFS_ACCESS_DELETE) {
			/*
			 * If the server doesn't report DELETE (possible
			 * on UNIX systems), we'll assume that it is OK
			 * and just let any subsequent delete action fail
			 * if it really isn't deletable.
			 */
			access |= NFS_ACCESS_DELETE;
		}
	}
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	nfsmout_if(error);

	uid = kauth_cred_getuid(vfs_context_ucred(ctx));
	slot = nfs_node_mode_slot(np, uid, 1);
	np->n_modeuid[slot] = uid;
	microuptime(&now);
	np->n_modestamp[slot] = now.tv_sec;
	np->n_mode[slot] = access;

	/* pass back the mode returned with this request */
	*mode = np->n_mode[slot];
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_getattr_rpc(
	nfsnode_t np,
	mount_t mp,
	u_char *fhp,
	size_t fhsize,
	vfs_context_t ctx,
	struct nfs_vattr *nvap,
	u_int64_t *xidp)
{
	struct nfsmount *nmp = mp ? VFSTONFS(mp) : NFSTONMP(np);
	int error = 0, status, nfsvers, numops;
	struct nfsm_chain nmreq, nmrep;

	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	numops = 2; // PUTFH + GETATTR
	nfsm_chain_build_alloc_init(error, &nmreq, 15 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "getattr", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, fhp, fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(np, mp, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, xidp, &status);

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsmout_if(error);
	NFS_CLEAR_ATTRIBUTES(nvap->nva_bitmap);
	error = nfs4_parsefattr(&nmrep, NULL, nvap, NULL, NULL);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_readlink_rpc(nfsnode_t np, char *buf, uint32_t *buflenp, vfs_context_t ctx)
{
	struct nfsmount *nmp;
	int error = 0, lockerror = ENOENT, status, numops;
	uint32_t len = 0;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	numops = 3; // PUTFH + GETATTR + READLINK
	nfsm_chain_build_alloc_init(error, &nmreq, 16 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "readlink", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, NFS_VER4, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_READLINK);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, NFS_VER4, NULL, &xid);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_READLINK);
	nfsm_chain_get_32(error, &nmrep, len);
	nfsmout_if(error);
	if (len >= *buflenp) {
		if (np->n_size && (np->n_size < *buflenp))
			len = np->n_size;
		else
			len = *buflenp - 1;
	}
	nfsm_chain_get_opaque(error, &nmrep, len, buf);
	if (!error)
		*buflenp = len;
nfsmout:
	if (!lockerror)
		nfs_unlock(np);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_read_rpc_async(
	nfsnode_t np,
	off_t offset,
	size_t len,
	thread_t thd,
	kauth_cred_t cred,
	struct nfsreq_cbinfo *cb,
	struct nfsreq **reqp)
{
	struct nfsmount *nmp;
	int error = 0, nfsvers, numops;
	struct nfsm_chain nmreq;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);

	// PUTFH + READ + GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 22 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "read", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_READ);

	/* XXX use special stateid for now */
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);

	nfsm_chain_add_64(error, &nmreq, offset);
	nfsm_chain_add_32(error, &nmreq, len);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request_async(np, NULL, &nmreq, NFSPROC4_COMPOUND, thd, cred, cb, reqp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	return (error);
}

int
nfs4_read_rpc_async_finish(
	nfsnode_t np,
	struct nfsreq *req,
	struct uio *uiop,
	size_t *lenp,
	int *eofp)
{
	struct nfsmount *nmp;
	int error = 0, lockerror, nfsvers, numops, status, eof = 0;
	size_t retlen = 0;
	u_int64_t xid;
	struct nfsm_chain nmrep;

	nmp = NFSTONMP(np);
	if (!nmp) {
		nfs_request_async_cancel(req);
		return (ENXIO);
	}
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmrep);

	error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	if (error == EINPROGRESS) /* async request restarted */
		return (error);

	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_READ);
	nfsm_chain_get_32(error, &nmrep, eof);
	nfsm_chain_get_32(error, &nmrep, retlen);
	if (!error) {
		*lenp = MIN(retlen, *lenp);
		error = nfsm_chain_get_uio(&nmrep, *lenp, uiop);
	}
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	if (!lockerror)
		nfs_unlock(np);
	if (eofp) {
		if (!eof && !retlen)
			eof = 1;
		*eofp = eof;
	}
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_write_rpc_async(
	nfsnode_t np,
	struct uio *uiop,
	size_t len,
	thread_t thd,
	kauth_cred_t cred,
	int iomode,
	struct nfsreq_cbinfo *cb,
	struct nfsreq **reqp)
{
	struct nfsmount *nmp;
	int error = 0, nfsvers, numops;
	off_t offset;
	struct nfsm_chain nmreq;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	offset = uiop->uio_offset;

	nfsm_chain_null(&nmreq);

	// PUTFH + WRITE + GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 25 * NFSX_UNSIGNED + len);
	nfsm_chain_add_compound_header(error, &nmreq, "write", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_WRITE);

	/* XXX use special stateid for now */
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);
	nfsm_chain_add_32(error, &nmreq, 0xffffffff);

	nfsm_chain_add_64(error, &nmreq, uiop->uio_offset);
	nfsm_chain_add_32(error, &nmreq, iomode);
	nfsm_chain_add_32(error, &nmreq, len);
	if (!error)
		error = nfsm_chain_add_uio(&nmreq, uiop, len);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);

	error = nfs_request_async(np, NULL, &nmreq, NFSPROC4_COMPOUND, thd, cred, cb, reqp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	return (error);
}

int
nfs4_write_rpc_async_finish(
	nfsnode_t np,
	struct nfsreq *req,
	int *iomodep,
	size_t *rlenp,
	uint64_t *wverfp)
{
	struct nfsmount *nmp;
	int error = 0, lockerror = ENOENT, nfsvers, numops, status;
	int committed = NFS_WRITE_FILESYNC;
	size_t rlen = 0;
	u_int64_t xid, wverf;
	mount_t mp;
	struct nfsm_chain nmrep;

	nmp = NFSTONMP(np);
	if (!nmp) {
		nfs_request_async_cancel(req);
		return (ENXIO);
	}
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmrep);

	error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	if (error == EINPROGRESS) /* async request restarted */
		return (error);
	nmp = NFSTONMP(np);
	if (!nmp)
		error = ENXIO;
	if (!error && (lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_WRITE);
	nfsm_chain_get_32(error, &nmrep, rlen);
	nfsmout_if(error);
	*rlenp = rlen;
	if (rlen <= 0)
		error = NFSERR_IO;
	nfsm_chain_get_32(error, &nmrep, committed);
	nfsm_chain_get_64(error, &nmrep, wverf);
	nfsmout_if(error);
	if (wverfp)
		*wverfp = wverf;
	lck_mtx_lock(&nmp->nm_lock);
	if (!(nmp->nm_state & NFSSTA_HASWRITEVERF)) {
		nmp->nm_verf = wverf;
		nmp->nm_state |= NFSSTA_HASWRITEVERF;
	} else if (nmp->nm_verf != wverf) {
		nmp->nm_verf = wverf;
	}
	lck_mtx_unlock(&nmp->nm_lock);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
nfsmout:
	if (!lockerror)
		nfs_unlock(np);
	nfsm_chain_cleanup(&nmrep);
	if ((committed != NFS_WRITE_FILESYNC) && nfs_allow_async &&
	    ((mp = NFSTOMP(np))) && (vfs_flags(mp) & MNT_ASYNC))
		committed = NFS_WRITE_FILESYNC;
	*iomodep = committed;
	return (error);
}

int
nfs4_remove_rpc(
	nfsnode_t dnp,
	char *name,
	int namelen,
	thread_t thd,
	kauth_cred_t cred)
{
	int error = 0, remove_error = 0, status;
	struct nfsmount *nmp;
	int nfsvers, numops;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, REMOVE, GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 17 * NFSX_UNSIGNED + namelen);
	nfsm_chain_add_compound_header(error, &nmreq, "remove", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_REMOVE);
	nfsm_chain_add_string(error, &nmreq, name, namelen);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);

	error = nfs_request2(dnp, NULL, &nmreq, NFSPROC4_COMPOUND, thd, cred, 0, &nmrep, &xid, &status);

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_REMOVE);
	remove_error = error;
	nfsm_chain_check_change_info(error, &nmrep, dnp);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(dnp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	dnp->n_flag |= NMODIFIED;

	return (remove_error);
}

int
nfs4_rename_rpc(
	nfsnode_t fdnp,
	char *fnameptr,
	int fnamelen,
	nfsnode_t tdnp,
	char *tnameptr,
	int tnamelen,
	vfs_context_t ctx)
{
	int error = 0, status, nfsvers, numops;
	struct nfsmount *nmp;
	u_int64_t xid, savedxid;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(fdnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH(FROM), SAVEFH, PUTFH(TO), RENAME, GETATTR(TO), RESTOREFH, GETATTR(FROM)
	numops = 7;
	nfsm_chain_build_alloc_init(error, &nmreq, 30 * NFSX_UNSIGNED + fnamelen + tnamelen);
	nfsm_chain_add_compound_header(error, &nmreq, "rename", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, fdnp->n_fhp, fdnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SAVEFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, tdnp->n_fhp, tdnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_RENAME);
	nfsm_chain_add_string(error, &nmreq, fnameptr, fnamelen);
	nfsm_chain_add_string(error, &nmreq, tnameptr, tnamelen);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_RESTOREFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);

	error = nfs_request(fdnp, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SAVEFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RENAME);
	nfsm_chain_check_change_info(error, &nmrep, fdnp);
	nfsm_chain_check_change_info(error, &nmrep, tdnp);
	/* directory attributes: if we don't get them, make sure to invalidate */
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	savedxid = xid;
	nfsm_chain_loadattr(error, &nmrep, tdnp, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(tdnp);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RESTOREFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	xid = savedxid;
	nfsm_chain_loadattr(error, &nmrep, fdnp, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(fdnp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	fdnp->n_flag |= NMODIFIED;
	tdnp->n_flag |= NMODIFIED;
	/* Kludge: Map EEXIST => 0 assuming that it is a reply to a retry. */
	if (error == EEXIST)
		error = 0;
	return (error);
}

/*
 * NFS V4 readdir RPC.
 */
#define	DIRHDSIZ	((int)(sizeof(struct dirent) - (MAXNAMLEN + 1)))
int
nfs4_readdir_rpc(nfsnode_t dnp, struct uio *uiop, vfs_context_t ctx)
{
	size_t len, tlen, skiplen, left;
	struct dirent *dp = NULL;
	vnode_t newvp;
	nfsuint64 *cookiep;
	struct componentname cn, *cnp = &cn;
	nfsuint64 cookie;
	struct nfsmount *nmp;
	nfsnode_t np;
	int error = 0, lockerror, status, more_entries = 1, blksiz = 0, bigenough = 1;
	int nfsvers, rdirplus, nmreaddirsize, nmrsize, eof, i, numops;
	u_int64_t xid, savexid;
	struct nfs_vattr nvattr;
	struct nfsm_chain nmreq, nmrep;
	char *cp;
	const char *tag;
	uint32_t entry_attrs[NFS_ATTR_BITMAP_LEN];
	fhandle_t fh;

#if DIAGNOSTIC
	/* XXX limitation based on need to adjust uio */
	if (uiop->uio_iovcnt != 1 || (uiop->uio_offset & (DIRBLKSIZ - 1)) ||
		(uio_uio_resid(uiop) & (DIRBLKSIZ - 1)))
		panic("nfs4_readdir_rpc: bad uio");
#endif
	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	nmreaddirsize = nmp->nm_readdirsize;
	nmrsize = nmp->nm_rsize;
	rdirplus = (nmp->nm_flag & NFSMNT_RDIRPLUS) ? 1 : 0;

	bzero(cnp, sizeof(*cnp));
	newvp = NULLVP;

	/*
	 * Set up attribute request for entries.
	 * For READDIRPLUS functionality, get everything.
	 * Otherwise, just get what we need for struct dirent.
	 */
	if (rdirplus) {
		tag = "READDIRPLUS";
		for (i=0; i < NFS_ATTR_BITMAP_LEN; i++)
			entry_attrs[i] =
				nfs_getattr_bitmap[i] &
				nmp->nm_fsattr.nfsa_supp_attr[i];
		NFS_BITMAP_SET(entry_attrs, NFS_FATTR_FILEHANDLE);
	} else {
		tag = "READDIR";
		NFS_CLEAR_ATTRIBUTES(entry_attrs);
		NFS_BITMAP_SET(entry_attrs, NFS_FATTR_TYPE);
		NFS_BITMAP_SET(entry_attrs, NFS_FATTR_FILEID);
	}
	/* XXX NFS_BITMAP_SET(entry_attrs, NFS_FATTR_MOUNTED_ON_FILEID); */
	NFS_BITMAP_SET(entry_attrs, NFS_FATTR_RDATTR_ERROR);

	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_SHARED)))
		return (lockerror);

	/*
	 * If there is no cookie, assume directory was stale.
	 */
	cookiep = nfs_getcookie(dnp, uiop->uio_offset, 0);
	if (cookiep)
		cookie = *cookiep;
	else {
		nfs_unlock(dnp);
		return (NFSERR_BAD_COOKIE);
	}

	/*
	 * The NFS client is responsible for the "." and ".."
	 * entries in the directory.  So, we put them at the top.
	 */
	if ((uiop->uio_offset == 0) &&
	    ((2*(4 + DIRHDSIZ)) <= uio_uio_resid(uiop))) {
		/* add "." entry */
		len = 2;
		tlen = nfsm_rndup(len);
		// LP64todo - fix this!
		dp = (struct dirent *) CAST_DOWN(caddr_t, uio_iov_base(uiop));
		dp->d_fileno = dnp->n_vattr.nva_fileid;
		dp->d_namlen = len;
		dp->d_reclen = tlen + DIRHDSIZ;
		dp->d_type = DT_DIR;
		strlcpy(dp->d_name, ".", len);
		blksiz += dp->d_reclen;
		if (blksiz == DIRBLKSIZ)
			blksiz = 0;
		uiop->uio_offset += DIRHDSIZ + tlen;
		uio_iov_base_add(uiop, DIRHDSIZ + tlen);
		uio_uio_resid_add(uiop, -(DIRHDSIZ + tlen));
		uio_iov_len_add(uiop, -(DIRHDSIZ + tlen));
		/* add ".." entry */
		len = 3;
		tlen = nfsm_rndup(len);
		// LP64todo - fix this!
		dp = (struct dirent *) CAST_DOWN(caddr_t, uio_iov_base(uiop));
		if (dnp->n_parent)
			dp->d_fileno = VTONFS(dnp->n_parent)->n_vattr.nva_fileid;
		else
			dp->d_fileno = dnp->n_vattr.nva_fileid;
		dp->d_namlen = len;
		dp->d_reclen = tlen + DIRHDSIZ;
		dp->d_type = DT_DIR;
		strlcpy(dp->d_name, "..", len);
		blksiz += dp->d_reclen;
		if (blksiz == DIRBLKSIZ)
			blksiz = 0;
		uiop->uio_offset += DIRHDSIZ + tlen;
		uio_iov_base_add(uiop, DIRHDSIZ + tlen);
		uio_uio_resid_add(uiop, -(DIRHDSIZ + tlen));
		uio_iov_len_add(uiop, -(DIRHDSIZ + tlen));
		cookie.nfsuquad[0] = 0;
		cookie.nfsuquad[1] = 2;
	}

	/*
	 * Loop around doing readdir rpc's of size nm_readdirsize
	 * truncated to a multiple of DIRBLKSIZ.
	 * The stopping criteria is EOF or buffer full.
	 */
	while (more_entries && bigenough) {
		nfsm_chain_null(&nmreq);
		nfsm_chain_null(&nmrep);
		nfsm_assert(error, NFSTONMP(dnp), ENXIO);

		numops = 3; // PUTFH + GETATTR + READDIR
		nfsm_chain_build_alloc_init(error, &nmreq, 26 * NFSX_UNSIGNED);
		nfsm_chain_add_compound_header(error, &nmreq, tag, numops);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
		nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
		nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
			NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_READDIR);
		/* opaque values don't need swapping, but as long */
		/* as we are consistent about it, it should be ok */
		nfsm_chain_add_32(error, &nmreq, cookie.nfsuquad[0]);
		if ((cookie.nfsuquad[0] == 0) && (cookie.nfsuquad[1] <= 2))
			nfsm_chain_add_32(error, &nmreq, 0);
		else
			nfsm_chain_add_32(error, &nmreq, cookie.nfsuquad[1]);
		nfsm_chain_add_32(error, &nmreq, dnp->n_cookieverf.nfsuquad[0]);
		nfsm_chain_add_32(error, &nmreq, dnp->n_cookieverf.nfsuquad[1]);
		nfsm_chain_add_32(error, &nmreq, nmreaddirsize);
		nfsm_chain_add_32(error, &nmreq, nmrsize);
		nfsm_chain_add_bitmap(error, &nmreq, entry_attrs, NFS_ATTR_BITMAP_LEN);
		nfsm_chain_build_done(error, &nmreq);
		nfsm_assert(error, (numops == 0), EPROTO);
		nfs_unlock(dnp);
		nfsmout_if(error);
		error = nfs_request(dnp, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

		if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
			error = lockerror;
		savexid = xid;
		nfsm_chain_skip_tag(error, &nmrep);
		nfsm_chain_get_32(error, &nmrep, numops);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
		nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_READDIR);
		nfsm_chain_get_32(error, &nmrep, dnp->n_cookieverf.nfsuquad[0]);
		nfsm_chain_get_32(error, &nmrep, dnp->n_cookieverf.nfsuquad[1]);
		nfsm_chain_get_32(error, &nmrep, more_entries);
		nfs_unlock(dnp);
		nfsmout_if(error);

		/* Loop through the entries, massaging them into "dirent" form. */
		/* If READDIRPLUS, also create the vnodes. */
		while (more_entries && bigenough) {
			/* Entry: COOKIE, NAME, FATTR */
			nfsm_chain_get_32(error, &nmrep, cookie.nfsuquad[0]);
			nfsm_chain_get_32(error, &nmrep, cookie.nfsuquad[1]);
			nfsm_chain_get_32(error, &nmrep, len);
			nfsmout_if(error);
			/* Note: NFS supports longer names, but struct dirent doesn't */
			/* so we just truncate the names to fit */
			if (len <= 0) {
				error = EBADRPC;
				goto nfsmout;
			}
			if (len > MAXNAMLEN) {
				skiplen = len - MAXNAMLEN;
				len = MAXNAMLEN;
			} else {
				skiplen = 0;
			}
			tlen = nfsm_rndup(len);
			if (tlen == len)
				tlen += 4;	/* To ensure null termination */
			left = DIRBLKSIZ - blksiz;
			if ((tlen + DIRHDSIZ) > left) {
				dp->d_reclen += left;
				uio_iov_base_add(uiop, left);
				uio_iov_len_add(uiop, -left);
				uiop->uio_offset += left;
				uio_uio_resid_add(uiop, -left);
				blksiz = 0;
			}
			if ((tlen + DIRHDSIZ) > uio_uio_resid(uiop)) {
				bigenough = 0;
				break;
			}
			// LP64todo - fix this!
			dp = (struct dirent *) CAST_DOWN(caddr_t, uio_iov_base(uiop));
			dp->d_fileno = 0;
			dp->d_namlen = len;
			dp->d_reclen = tlen + DIRHDSIZ;
			dp->d_type = DT_UNKNOWN;
			blksiz += dp->d_reclen;
			if (blksiz == DIRBLKSIZ)
				blksiz = 0;
			uiop->uio_offset += DIRHDSIZ;
#if LP64KERN
			uio_uio_resid_add(uiop, -((int64_t)DIRHDSIZ));
			uio_iov_len_add(uiop, -((int64_t)DIRHDSIZ));
#else
			uio_uio_resid_add(uiop, -((int)DIRHDSIZ));
			uio_iov_len_add(uiop, -((int)DIRHDSIZ));
#endif
			uio_iov_base_add(uiop, DIRHDSIZ);
			// LP64todo - fix this!
			cnp->cn_nameptr = CAST_DOWN(caddr_t, uio_iov_base(uiop));
			cnp->cn_namelen = len;
			error = nfsm_chain_get_uio(&nmrep, len, uiop);
			if (skiplen)
				nfsm_chain_adv(error, &nmrep,
					nfsm_rndup(len + skiplen) - nfsm_rndup(len));
			nfsmout_if(error);
			NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
			error = nfs4_parsefattr(&nmrep, NULL, &nvattr, &fh, NULL);
			if (error && NFS_BITMAP_ISSET(nvattr.nva_bitmap, NFS_FATTR_RDATTR_ERROR)) {
				/* OK, we didn't get attributes, whatever... */
				NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
				error = 0;
			}
			nfsm_chain_get_32(error, &nmrep, more_entries);
			nfsmout_if(error);

			cp = CAST_DOWN(caddr_t, uio_iov_base(uiop));
			tlen -= len;
			*cp = '\0';
			uio_iov_base_add(uiop, tlen);
			uio_iov_len_add(uiop, -tlen);
			uiop->uio_offset += tlen;
			uio_uio_resid_add(uiop, -tlen);

			/*
			 * Skip any "." and ".." entries returned from server.
			 * (Actually, just leave it in place with d_fileno == 0.)
			 */
			if ((cnp->cn_nameptr[0] == '.') &&
			    ((len == 1) || ((len == 2) && (cnp->cn_nameptr[1] == '.')))) {
				/* clear the name too */
				dp->d_namlen = 0;
				dp->d_name[0] = '\0';
				continue;
			}

			if (NFS_BITMAP_ISSET(nvattr.nva_bitmap, NFS_FATTR_TYPE))
				dp->d_type = IFTODT(VTTOIF(nvattr.nva_type));
			if (NFS_BITMAP_ISSET(nvattr.nva_bitmap, NFS_FATTR_FILEID))
				dp->d_fileno = (int)nvattr.nva_fileid;
			if (rdirplus && NFS_BITMAP_ISSET(nvattr.nva_bitmap, NFS_FATTR_FILEHANDLE) &&
			    !NFS_CMPFH(dnp, fh.fh_data, fh.fh_len)) {
				cnp->cn_hash = 0;
				error = nfs_nget(NFSTOMP(dnp), dnp, cnp,
						fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &np);
				if (!error) {
					nfs_unlock(np);
					vnode_put(NFSTOV(np));
				}
			}
			nfsmout_if(error);
		}
		/* If at end of rpc data, get the eof boolean */
		if (!more_entries) {
			nfsm_chain_get_32(error, &nmrep, eof);
			if (!error)
				more_entries = (eof == 0);
		}
		if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_SHARED)))
			error = lockerror;
		nfsmout_if(error);
		nfsm_chain_cleanup(&nmrep);
	}
	nfs_unlock(dnp);
	/*
	 * Fill last record, iff any, out to a multiple of DIRBLKSIZ
	 * by increasing d_reclen for the last record.
	 */
	if (blksiz > 0) {
		left = DIRBLKSIZ - blksiz;
		dp->d_reclen += left;
		uio_iov_base_add(uiop, left);
		uio_iov_len_add(uiop, -left);
		uiop->uio_offset += left;
		uio_uio_resid_add(uiop, -left);
	}

	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	/*
	 * We are now either at the end of the directory or have filled the
	 * block.
	 */
	if (bigenough)
		dnp->n_direofoffset = uiop->uio_offset;
	else {
		if (uio_uio_resid(uiop) > 0)
			printf("EEK! nfs4_readdir_rpc resid > 0\n");
		cookiep = nfs_getcookie(dnp, uiop->uio_offset, 1);
		if (cookiep)
			*cookiep = cookie;
	}

	nfs_unlock(dnp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_lookup_rpc_async(
	nfsnode_t dnp,
	char *name,
	int namelen,
	vfs_context_t ctx,
	struct nfsreq **reqp)
{
	int error = 0, isdotdot = 0, getattrs = 1, nfsvers, numops;
	struct nfsm_chain nmreq;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN];
	struct nfsmount *nmp;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if ((name[0] == '.') && (name[1] == '.') && (namelen == 2))
		isdotdot = 1;

	nfsm_chain_null(&nmreq);

	// PUTFH, GETATTR, LOOKUP(P), GETATTR (FH)
	numops = getattrs ? 4 : 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 20 * NFSX_UNSIGNED + namelen);
	nfsm_chain_add_compound_header(error, &nmreq, "lookup", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	if (isdotdot) {
		nfsm_chain_add_32(error, &nmreq, NFS_OP_LOOKUPP);
	} else {
		nfsm_chain_add_32(error, &nmreq, NFS_OP_LOOKUP);
		nfsm_chain_add_string(error, &nmreq, name, namelen);
	}
	if (getattrs) {
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
		NFS_COPY_ATTRIBUTES(nfs_getattr_bitmap, bitmap);
		NFS_BITMAP_SET(bitmap, NFS_FATTR_FILEHANDLE);
		nfsm_chain_add_bitmap_masked(error, &nmreq, bitmap,
			NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	}
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC4_COMPOUND,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, reqp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	return (error);
}

int
nfs4_lookup_rpc_async_finish(
	nfsnode_t dnp,
	__unused vfs_context_t ctx,
	struct nfsreq *req,
	u_int64_t *xidp,
	fhandle_t *fhp,
	struct nfs_vattr *nvap)
{
	int error = 0, status, nfsvers, numops;
	uint32_t val = 0;
	u_int64_t xid;
	struct nfsmount *nmp;
	struct nfsm_chain nmrep;

	nmp = NFSTONMP(dnp);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmrep);

	error = nfs_request_async_finish(req, &nmrep, &xid, &status);

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	if (xidp)
		*xidp = xid;
	nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);

	// nfsm_chain_op_check(error, &nmrep, (isdotdot ? NFS_OP_LOOKUPP : NFS_OP_LOOKUP));
	nfsm_chain_get_32(error, &nmrep, val);
	nfsm_assert(error, (val == NFS_OP_LOOKUPP) || (val == NFS_OP_LOOKUP), EBADRPC);
	nfsm_chain_get_32(error, &nmrep, val);
	nfsm_assert(error, (val == NFS_OK), val);

	nfsmout_if(error || !fhp || !nvap);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsmout_if(error);
	NFS_CLEAR_ATTRIBUTES(nvap->nva_bitmap);
	error = nfs4_parsefattr(&nmrep, NULL, nvap, fhp, NULL);
	if (!NFS_BITMAP_ISSET(nvap->nva_bitmap, NFS_FATTR_FILEHANDLE)) {
		error = EBADRPC;
		goto nfsmout;
	}
nfsmout:
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_commit_rpc(
	nfsnode_t np,
	u_int64_t offset,
	u_int64_t count,
	kauth_cred_t cred)
{
	struct nfsmount *nmp;
	int error = 0, lockerror, status, nfsvers, numops;
	u_int64_t xid, wverf;
	uint32_t count32;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(np);
	FSDBG(521, np, offset, count, nmp ? nmp->nm_state : 0);
	if (!nmp)
		return (ENXIO);
	if (!(nmp->nm_state & NFSSTA_HASWRITEVERF))
		return (0);
	nfsvers = nmp->nm_vers;

	if (count > UINT32_MAX)
		count32 = 0;
	else
		count32 = count;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, COMMIT, GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 19 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "commit", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_COMMIT);
	nfsm_chain_add_64(error, &nmreq, offset);
	nfsm_chain_add_32(error, &nmreq, count32);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request2(np, NULL, &nmreq, NFSPROC4_COMPOUND,
			current_thread(), cred, 0, &nmrep, &xid, &status);

	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_COMMIT);
	nfsm_chain_get_64(error, &nmrep, wverf);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	if (!lockerror)
		nfs_unlock(np);
	nfsmout_if(error);
	lck_mtx_lock(&nmp->nm_lock);
	if (nmp->nm_verf != wverf) {
		nmp->nm_verf = wverf;
		error = NFSERR_STALEWRITEVERF;
	}
	lck_mtx_unlock(&nmp->nm_lock);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_pathconf_rpc(
	nfsnode_t np,
	struct nfs_fsattr *nfsap,
	vfs_context_t ctx)
{
	u_int64_t xid;
	int error = 0, lockerror, status, nfsvers, numops;
	struct nfsm_chain nmreq, nmrep;
	struct nfsmount *nmp = NFSTONMP(np);
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN];
	struct nfs_vattr nvattr;

	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	/* NFSv4: fetch "pathconf" info for this node */
	numops = 2; // PUTFH + GETATTR
	nfsm_chain_build_alloc_init(error, &nmreq, 16 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "pathconf", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	NFS_COPY_ATTRIBUTES(nfs_getattr_bitmap, bitmap);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_MAXLINK);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_MAXNAME);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_NO_TRUNC);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_CHOWN_RESTRICTED);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_CASE_INSENSITIVE);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_CASE_PRESERVING);
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
	nfsmout_if(error);
	NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
	error = nfs4_parsefattr(&nmrep, nfsap, &nvattr, NULL, NULL);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfs_loadattrcache(np, &nvattr, &xid, 0);
	if (!lockerror)
		nfs_unlock(np);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_vnop_getattr(
	struct vnop_getattr_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	struct vnode_attr *vap = ap->a_vap;
	struct nfs_vattr nva;
	int error;

	error = nfs_getattr(VTONFS(ap->a_vp), &nva, ap->a_context, 0);
	if (error)
		return (error);

	/* copy what we have in nva to *a_vap */
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_RAWDEV)) {
		dev_t rdev = makedev(nva.nva_rawdev.specdata1, nva.nva_rawdev.specdata2);
		VATTR_RETURN(vap, va_rdev, rdev);
	}
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_NUMLINKS))
		VATTR_RETURN(vap, va_nlink, nva.nva_nlink);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_SIZE))
		VATTR_RETURN(vap, va_data_size, nva.nva_size);
	// VATTR_RETURN(vap, va_data_alloc, ???);
	// VATTR_RETURN(vap, va_total_size, ???);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_SPACE_USED))
		VATTR_RETURN(vap, va_total_alloc, nva.nva_bytes);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_OWNER))
		VATTR_RETURN(vap, va_uid, nva.nva_uid);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_OWNER_GROUP))
		VATTR_RETURN(vap, va_gid, nva.nva_gid);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_MODE))
		VATTR_RETURN(vap, va_mode, nva.nva_mode);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_ARCHIVE) ||
	    NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_HIDDEN)) {
		uint32_t flags = 0;
		if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_ARCHIVE))
			flags |= SF_ARCHIVED;
		if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_HIDDEN))
			flags |= UF_HIDDEN;
		VATTR_RETURN(vap, va_flags, flags);
	}
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_TIME_CREATE)) {
		vap->va_create_time.tv_sec = nva.nva_timesec[NFSTIME_CREATE];
		vap->va_create_time.tv_nsec = nva.nva_timensec[NFSTIME_CREATE];
		VATTR_SET_SUPPORTED(vap, va_create_time);
	}
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_TIME_ACCESS)) {
		vap->va_access_time.tv_sec = nva.nva_timesec[NFSTIME_ACCESS];
		vap->va_access_time.tv_nsec = nva.nva_timensec[NFSTIME_ACCESS];
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_TIME_MODIFY)) {
		vap->va_modify_time.tv_sec = nva.nva_timesec[NFSTIME_MODIFY];
		vap->va_modify_time.tv_nsec = nva.nva_timensec[NFSTIME_MODIFY];
		VATTR_SET_SUPPORTED(vap, va_modify_time);
	}
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_TIME_METADATA)) {
		vap->va_change_time.tv_sec = nva.nva_timesec[NFSTIME_CHANGE];
		vap->va_change_time.tv_nsec = nva.nva_timensec[NFSTIME_CHANGE];
		VATTR_SET_SUPPORTED(vap, va_change_time);
	}
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_TIME_BACKUP)) {
		vap->va_backup_time.tv_sec = nva.nva_timesec[NFSTIME_BACKUP];
		vap->va_backup_time.tv_nsec = nva.nva_timensec[NFSTIME_BACKUP];
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_FILEID))
		VATTR_RETURN(vap, va_fileid, nva.nva_fileid);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_TYPE))
		VATTR_RETURN(vap, va_type, nva.nva_type);
	if (NFS_BITMAP_ISSET(nva.nva_bitmap, NFS_FATTR_CHANGE))
		VATTR_RETURN(vap, va_filerev, nva.nva_change);

	// other attrs we might support someday:
	// VATTR_RETURN(vap, va_encoding, ??? /* potentially unnormalized UTF-8? */);
	// struct kauth_acl *va_acl;	/* access control list */
	// guid_t	va_uuuid;	/* file owner UUID */
	// guid_t	va_guuid;	/* file group UUID */

	return (error);
}

int
nfs4_setattr_rpc(
	nfsnode_t np,
	struct vnode_attr *vap,
	vfs_context_t ctx,
	int alreadylocked)
{
	struct nfsmount *nmp = NFSTONMP(np);
	int error = 0, lockerror = ENOENT, status, nfsvers, numops;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN], bmlen, stateid;

	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if (VATTR_IS_ACTIVE(vap, va_flags) && (vap->va_flags & ~(SF_ARCHIVED|UF_HIDDEN))) {
		/* we don't support setting unsupported flags (duh!) */
		if (vap->va_active & ~VNODE_ATTR_va_flags)
			return (EINVAL);	/* return EINVAL if other attributes also set */
		else
			return (ENOTSUP);	/* return ENOTSUP for chflags(2) */
	}

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, SETATTR, GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 40 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "setattr", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SETATTR);
	if (VATTR_IS_ACTIVE(vap, va_data_size))
		stateid = 0xffffffff; /* XXX use the special stateid for now */
	else
		stateid = 0;
	nfsm_chain_add_32(error, &nmreq, stateid);
	nfsm_chain_add_32(error, &nmreq, stateid);
	nfsm_chain_add_32(error, &nmreq, stateid);
	nfsm_chain_add_32(error, &nmreq, stateid);
	nfsm_chain_add_fattr4(error, &nmreq, vap, nmp);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	if (!alreadylocked && ((lockerror = nfs_lock(np, NFS_NODE_LOCK_EXCLUSIVE))))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SETATTR);
	bmlen = NFS_ATTR_BITMAP_LEN;
	nfsm_chain_get_bitmap(error, &nmrep, bitmap, bmlen);
	nfsmout_if(error);
	nfs_vattr_set_supported(bitmap, vap);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(np);
nfsmout:
	if (!alreadylocked && !lockerror)
		nfs_unlock(np);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_vnop_open(struct vnop_open_args *ap)
{
	return nfs3_vnop_open(ap);
}

int
nfs4_vnop_close(struct vnop_close_args *ap)
{
	return nfs3_vnop_close(ap);
}

int
nfs4_vnop_advlock(__unused struct vnop_advlock_args *ap)
{
	return (ENOSYS);
}

/*
 * Note: the NFSv4 CREATE RPC is for everything EXCEPT regular files.
 * Files are created using the NFSv4 OPEN RPC.  So we must open the
 * file to create it and then close it immediately.
 */
int
nfs4_vnop_create(
	struct vnop_create_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	struct componentname *cnp = ap->a_cnp;
	struct vnode_attr *vap = ap->a_vap;
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	struct nfsmount *nmp;
	struct nfs_vattr nvattr, dnvattr;
	int error = 0, create_error = EIO, lockerror = ENOENT, status;
	int nfsvers, numops;
	u_int64_t xid, savedxid = 0;
	nfsnode_t dnp = VTONFS(dvp);
	nfsnode_t np = NULL;
	vnode_t newvp = NULL;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN], bmlen;
	uint32_t seqid, stateid[4], rflags, delegation, val;
	fhandle_t fh;
	struct nfsreq *req = NULL;
	struct nfs_dulookup dul;

	static uint32_t nfs4_open_owner_hack = 0;

	nmp = VTONMP(dvp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	seqid = stateid[0] = stateid[1] = stateid[2] = stateid[3] = 0;
	rflags = 0;

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, SAVEFH, OPEN(CREATE), GETATTR(FH), RESTOREFH, GETATTR
	numops = 6;
	nfsm_chain_build_alloc_init(error, &nmreq, 53 * NFSX_UNSIGNED + cnp->cn_namelen);
	nfsm_chain_add_compound_header(error, &nmreq, "create", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SAVEFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_OPEN);
	nfsm_chain_add_32(error, &nmreq, seqid);
	seqid++;
	nfsm_chain_add_32(error, &nmreq, NFS_OPEN_SHARE_ACCESS_BOTH);
	nfsm_chain_add_32(error, &nmreq, NFS_OPEN_SHARE_DENY_NONE);
	nfsm_chain_add_64(error, &nmreq, nmp->nm_clientid); // open_owner4.clientid
	OSAddAtomic(1, (SInt32*)&nfs4_open_owner_hack);
	nfsm_chain_add_32(error, &nmreq, sizeof(nfs4_open_owner_hack));
	nfsm_chain_add_opaque(error, &nmreq, &nfs4_open_owner_hack, sizeof(nfs4_open_owner_hack)); // open_owner4.owner
	// openflag4
	nfsm_chain_add_32(error, &nmreq, NFS_OPEN_CREATE);
	nfsm_chain_add_32(error, &nmreq, NFS_CREATE_UNCHECKED); // XXX exclusive/guarded
	nfsm_chain_add_fattr4(error, &nmreq, vap, nmp);
	// open_claim4
	nfsm_chain_add_32(error, &nmreq, NFS_CLAIM_NULL);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	NFS_COPY_ATTRIBUTES(nfs_getattr_bitmap, bitmap);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_FILEHANDLE);
	nfsm_chain_add_bitmap_masked(error, &nmreq, bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_RESTOREFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC4_COMPOUND,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
	if (!error) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	}
	savedxid = xid;

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SAVEFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_OPEN);
	nfsm_chain_get_32(error, &nmrep, stateid[0]);
	nfsm_chain_get_32(error, &nmrep, stateid[1]);
	nfsm_chain_get_32(error, &nmrep, stateid[2]);
	nfsm_chain_get_32(error, &nmrep, stateid[3]);
	nfsm_chain_check_change_info(error, &nmrep, dnp);
	nfsm_chain_get_32(error, &nmrep, rflags);
	bmlen = NFS_ATTR_BITMAP_LEN;
	nfsm_chain_get_bitmap(error, &nmrep, bitmap, bmlen);
	nfsm_chain_get_32(error, &nmrep, delegation);
	if (!error)
		switch (delegation) {
		case NFS_OPEN_DELEGATE_NONE:
			break;
		case NFS_OPEN_DELEGATE_READ:
			printf("nfs4_vnop_create: read delegation?\n");
			nfsm_chain_adv(error, &nmrep, 5*NFSX_UNSIGNED);
			// ACE:
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			nfsm_chain_get_32(error, &nmrep, val); /* string length */
			nfsm_chain_adv(error, &nmrep, nfsm_rndup(val));
			break;
		case NFS_OPEN_DELEGATE_WRITE:
			printf("nfs4_vnop_create: write delegation?\n");
			nfsm_chain_adv(error, &nmrep, 5*NFSX_UNSIGNED);
			nfsm_chain_adv(error, &nmrep, 3*NFSX_UNSIGNED);
			// ACE:
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			nfsm_chain_get_32(error, &nmrep, val); /* string length */
			nfsm_chain_adv(error, &nmrep, nfsm_rndup(val));
			break;
		default:
			error = EBADRPC;
			break;
		}
	/* At this point if we have no error, the object was created. */
	/* if we don't get attributes, then we should lookitup. */
	create_error = error;
	nfsmout_if(error);
	nfs_vattr_set_supported(bitmap, vap);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsmout_if(error);
	NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
	error = nfs4_parsefattr(&nmrep, NULL, &nvattr, &fh, NULL);
	nfsmout_if(error);
	if (!NFS_BITMAP_ISSET(nvattr.nva_bitmap, NFS_FATTR_FILEHANDLE)) {
		printf("nfs: open/create didn't return filehandle?\n");
		error = EBADRPC;
		goto nfsmout;
	}
	/* directory attributes: if we don't get them, make sure to invalidate */
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RESTOREFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(dnp);

	if (rflags & NFS_OPEN_RESULT_CONFIRM) {
		nfsm_chain_cleanup(&nmreq);
		nfsm_chain_cleanup(&nmrep);
		// PUTFH, OPEN_CONFIRM, GETATTR
		numops = 3;
		nfsm_chain_build_alloc_init(error, &nmreq, 23 * NFSX_UNSIGNED);
		nfsm_chain_add_compound_header(error, &nmreq, "create_confirm", numops);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
		nfsm_chain_add_fh(error, &nmreq, nfsvers, fh.fh_data, fh.fh_len);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_OPEN_CONFIRM);
		nfsm_chain_add_32(error, &nmreq, stateid[0]);
		nfsm_chain_add_32(error, &nmreq, stateid[1]);
		nfsm_chain_add_32(error, &nmreq, stateid[2]);
		nfsm_chain_add_32(error, &nmreq, stateid[3]);
		nfsm_chain_add_32(error, &nmreq, seqid);
		seqid++;
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
		nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
			NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
		nfsm_chain_build_done(error, &nmreq);
		nfsm_assert(error, (numops == 0), EPROTO);
		nfsmout_if(error);
		error = nfs_request(dnp, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

		nfsm_chain_skip_tag(error, &nmrep);
		nfsm_chain_get_32(error, &nmrep, numops);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_OPEN_CONFIRM);
		nfsm_chain_get_32(error, &nmrep, stateid[0]);
		nfsm_chain_get_32(error, &nmrep, stateid[1]);
		nfsm_chain_get_32(error, &nmrep, stateid[2]);
		nfsm_chain_get_32(error, &nmrep, stateid[3]);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
		nfsmout_if(error);
		NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
		error = nfs4_parsefattr(&nmrep, NULL, &nvattr, NULL, NULL);
		nfsmout_if(error);
		savedxid = xid;
	}
	nfsmout_if(error);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	// PUTFH, CLOSE
	numops = 2;
	nfsm_chain_build_alloc_init(error, &nmreq, 19 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "create_close", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, fh.fh_data, fh.fh_len);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_CLOSE);
	nfsm_chain_add_32(error, &nmreq, seqid);
	seqid++;
	nfsm_chain_add_32(error, &nmreq, stateid[0]);
	nfsm_chain_add_32(error, &nmreq, stateid[1]);
	nfsm_chain_add_32(error, &nmreq, stateid[2]);
	nfsm_chain_add_32(error, &nmreq, stateid[3]);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(dnp, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_CLOSE);
	nfsm_chain_get_32(error, &nmrep, stateid[0]);
	nfsm_chain_get_32(error, &nmrep, stateid[1]);
	nfsm_chain_get_32(error, &nmrep, stateid[2]);
	nfsm_chain_get_32(error, &nmrep, stateid[3]);
	if (error)
		printf("nfs4_vnop_create: close error %d\n", error);

nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror) {
		if (!create_error && (dnp->n_flag & NNEGNCENTRIES)) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(dvp);
		}
		dnp->n_flag |= NMODIFIED;
		if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
			if (NFS_CHANGED_NC(nfsvers, dnp, &dnvattr)) {
				dnp->n_flag &= ~NNEGNCENTRIES;
				cache_purge(dvp);
				NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnvattr);
			}
		}
	}

	if (!error && fh.fh_len) {
		/* create the vnode with the filehandle and attributes */
		xid = savedxid;
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &np);
		if (!error)
			newvp = NFSTOV(np);
	}

	nfs_dulookup_finish(&dul, dnp, ctx);

	/*
	 * Kludge: Map EEXIST => 0 assuming that you have a reply to a retry
	 * if we can succeed in looking up the object.
	 */
	if ((create_error == EEXIST) || (!create_error && !newvp)) {
		error = nfs_lookitup(dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx, &np);
		if (!error) {
			newvp = NFSTOV(np);
			if (vnode_vtype(newvp) != VLNK)
				error = EEXIST;
		}
	}
	if (!lockerror)
		nfs_unlock(dnp);
	if (error) {
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
		}
	} else {
		nfs_unlock(np);
		*vpp = newvp;
	}
	return (error);
}

/*
 * Note: the NFSv4 CREATE RPC is for everything EXCEPT regular files.
 */
static int
nfs4_create_rpc(
	vfs_context_t ctx,
	nfsnode_t dnp,
	struct componentname *cnp,
	struct vnode_attr *vap,
	int type,
	char *link,
	nfsnode_t *npp)
{
	struct nfsmount *nmp;
	struct nfs_vattr nvattr, dnvattr;
	int error = 0, create_error = EIO, lockerror = ENOENT, status;
	int nfsvers, numops;
	u_int64_t xid, savedxid = 0;
	nfsnode_t np = NULL;
	vnode_t newvp = NULL;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN], bmlen;
	const char *tag;
	nfs_specdata sd;
	fhandle_t fh;
	struct nfsreq *req = NULL;
	struct nfs_dulookup dul;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	sd.specdata1 = sd.specdata2 = 0;

	switch (type) {
	case NFLNK:
		tag = "symlink";
		break;
	case NFBLK:
	case NFCHR:
		tag = "mknod";
		if (!VATTR_IS_ACTIVE(vap, va_rdev))
			return (EINVAL);
		sd.specdata1 = major(vap->va_rdev);
		sd.specdata2 = minor(vap->va_rdev);
		break;
	case NFSOCK:
	case NFFIFO:
		tag = "mknod";
		break;
	case NFDIR:
		tag = "mkdir";
		break;
	default:
		return (EINVAL);
	}

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, SAVEFH, CREATE, GETATTR(FH), RESTOREFH, GETATTR
	numops = 6;
	nfsm_chain_build_alloc_init(error, &nmreq, 66 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, tag, numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SAVEFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_CREATE);
	nfsm_chain_add_32(error, &nmreq, type);
	if (type == NFLNK) {
		nfsm_chain_add_string(error, &nmreq, link, strlen(link));
	} else if ((type == NFBLK) || (type == NFCHR)) {
		nfsm_chain_add_32(error, &nmreq, sd.specdata1);
		nfsm_chain_add_32(error, &nmreq, sd.specdata2);
	}
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	nfsm_chain_add_fattr4(error, &nmreq, vap, nmp);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	NFS_COPY_ATTRIBUTES(nfs_getattr_bitmap, bitmap);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_FILEHANDLE);
	nfsm_chain_add_bitmap_masked(error, &nmreq, bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_RESTOREFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	if ((lockerror = nfs_lock(dnp, NFS_NODE_LOCK_EXCLUSIVE)))
		error = lockerror;
	nfsmout_if(error);

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC4_COMPOUND,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
	if (!error) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	}

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SAVEFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_CREATE);
	nfsm_chain_check_change_info(error, &nmrep, dnp);
	bmlen = NFS_ATTR_BITMAP_LEN;
	nfsm_chain_get_bitmap(error, &nmrep, bitmap, bmlen);
	/* At this point if we have no error, the object was created. */
	/* if we don't get attributes, then we should lookitup. */
	create_error = error;
	nfsmout_if(error);
	nfs_vattr_set_supported(bitmap, vap);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsmout_if(error);
	NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
	error = nfs4_parsefattr(&nmrep, NULL, &nvattr, &fh, NULL);
	nfsmout_if(error);
	if (!NFS_BITMAP_ISSET(nvattr.nva_bitmap, NFS_FATTR_FILEHANDLE)) {
		printf("nfs: create/%s didn't return filehandle?\n", tag);
		error = EBADRPC;
		goto nfsmout;
	}
	/* directory attributes: if we don't get them, make sure to invalidate */
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RESTOREFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	savedxid = xid;
	nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(dnp);

nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror) {
		if (!create_error && (dnp->n_flag & NNEGNCENTRIES)) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(NFSTOV(dnp));
		}
		dnp->n_flag |= NMODIFIED;
		if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
			if (NFS_CHANGED_NC(nfsvers, dnp, &dnvattr)) {
				dnp->n_flag &= ~NNEGNCENTRIES;
				cache_purge(NFSTOV(dnp));
				NFS_CHANGED_UPDATE_NC(nfsvers, dnp, &dnvattr);
			}
		}
	}

	if (!error && fh.fh_len) {
		/* create the vnode with the filehandle and attributes */
		xid = savedxid;
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &np);
		if (!error)
			newvp = NFSTOV(np);
	}

	nfs_dulookup_finish(&dul, dnp, ctx);

	/*
	 * Kludge: Map EEXIST => 0 assuming that you have a reply to a retry
	 * if we can succeed in looking up the object.
	 */
	if ((create_error == EEXIST) || (!create_error && !newvp)) {
		error = nfs_lookitup(dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx, &np);
		if (!error) {
			newvp = NFSTOV(np);
			if (vnode_vtype(newvp) != VLNK)
				error = EEXIST;
		}
	}
	if (!lockerror)
		nfs_unlock(dnp);
	if (error) {
		if (newvp) {
			nfs_unlock(np);
			vnode_put(newvp);
		}
	} else {
		nfs_unlock(np);
		*npp = np;
	}
	return (error);
}

int
nfs4_vnop_mknod(
	struct vnop_mknod_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	nfsnode_t np = NULL;
	struct nfsmount *nmp;
	int error;

	nmp = VTONMP(ap->a_dvp);
	if (!nmp)
		return (ENXIO);

	if (!VATTR_IS_ACTIVE(ap->a_vap, va_type))
		return (EINVAL);
	switch (ap->a_vap->va_type) {
	case VBLK:
	case VCHR:
	case VFIFO:
	case VSOCK:
		break;
	default:
		return (ENOTSUP);
	}

	error = nfs4_create_rpc(ap->a_context, VTONFS(ap->a_dvp), ap->a_cnp, ap->a_vap,
			vtonfs_type(ap->a_vap->va_type, nmp->nm_vers), NULL, &np);
	if (!error)
		*ap->a_vpp = NFSTOV(np);
	return (error);
}

int
nfs4_vnop_mkdir(
	struct vnop_mkdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap)
{
	nfsnode_t np = NULL;
	int error;

	error = nfs4_create_rpc(ap->a_context, VTONFS(ap->a_dvp), ap->a_cnp, ap->a_vap,
			NFDIR, NULL, &np);
	if (!error)
		*ap->a_vpp = NFSTOV(np);
	return (error);
}

int
nfs4_vnop_symlink(
	struct vnop_symlink_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t *a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		char *a_target;
		vfs_context_t a_context;
	} */ *ap)
{
	nfsnode_t np = NULL;
	int error;

	error = nfs4_create_rpc(ap->a_context, VTONFS(ap->a_dvp), ap->a_cnp, ap->a_vap,
			NFLNK, ap->a_target, &np);
	if (!error)
		*ap->a_vpp = NFSTOV(np);
	return (error);
}

int
nfs4_vnop_link(
	struct vnop_link_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vnode_t a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	vnode_t tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	int error = 0, status;
	struct nfsmount *nmp;
	nfsnode_t np = VTONFS(vp);
	nfsnode_t tdnp = VTONFS(tdvp);
	int nfsvers, numops;
	u_int64_t xid, savedxid;
	struct nfsm_chain nmreq, nmrep;

	if (vnode_mount(vp) != vnode_mount(tdvp))
		return (EXDEV);

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	/*
	 * Push all writes to the server, so that the attribute cache
	 * doesn't get "out of sync" with the server.
	 * XXX There should be a better way!
	 */
	nfs_flush(np, MNT_WAIT, vfs_context_thread(ctx), V_IGNORE_WRITEERR);

	error = nfs_lock2(tdnp, np, NFS_NODE_LOCK_EXCLUSIVE);
	if (error)
		return (error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH(SOURCE), SAVEFH, PUTFH(DIR), LINK, GETATTR(DIR), RESTOREFH, GETATTR
	numops = 7;
	nfsm_chain_build_alloc_init(error, &nmreq, 29 * NFSX_UNSIGNED + cnp->cn_namelen);
	nfsm_chain_add_compound_header(error, &nmreq, "link", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SAVEFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, tdnp->n_fhp, tdnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_LINK);
	nfsm_chain_add_string(error, &nmreq, cnp->cn_nameptr, cnp->cn_namelen);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_RESTOREFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(tdnp, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SAVEFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_LINK);
	nfsm_chain_check_change_info(error, &nmrep, tdnp);
	/* directory attributes: if we don't get them, make sure to invalidate */
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	savedxid = xid;
	nfsm_chain_loadattr(error, &nmrep, tdnp, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(tdnp);
	/* link attributes: if we don't get them, make sure to invalidate */
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RESTOREFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	xid = savedxid;
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(np);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	tdnp->n_flag |= NMODIFIED;
	/* Kludge: Map EEXIST => 0 assuming that it is a reply to a retry. */
	if (error == EEXIST)
		error = 0;
	if (!error && (tdnp->n_flag & NNEGNCENTRIES)) {
		tdnp->n_flag &= ~NNEGNCENTRIES;
		cache_purge_negatives(tdvp);
	}
	nfs_unlock2(tdnp, np);
	return (error);
}

int
nfs4_vnop_rmdir(
	struct vnop_rmdir_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_dvp;
		vnode_t a_vp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	vnode_t dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	int error = 0;
	nfsnode_t np = VTONFS(vp);
	nfsnode_t dnp = VTONFS(dvp);
	struct nfs_vattr dnvattr;
	struct nfs_dulookup dul;

	if (vnode_vtype(vp) != VDIR)
		return (EINVAL);

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen);

	if ((error = nfs_lock2(dnp, np, NFS_NODE_LOCK_EXCLUSIVE)))
		return (error);

	nfs_dulookup_start(&dul, dnp, ctx);

	error = nfs4_remove_rpc(dnp, cnp->cn_nameptr, cnp->cn_namelen,
			vfs_context_thread(ctx), vfs_context_ucred(ctx));

	cache_purge(vp);
	if (!nfs_getattr(dnp, &dnvattr, ctx, 1)) {
		if (NFS_CHANGED_NC(NFS_VER4, dnp, &dnvattr)) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge(dvp);
			NFS_CHANGED_UPDATE_NC(NFS_VER4, dnp, &dnvattr);
		}
	}

	nfs_dulookup_finish(&dul, dnp, ctx);
	nfs_unlock2(dnp, np);

	/*
	 * Kludge: Map ENOENT => 0 assuming that you have a reply to a retry.
	 */
	if (error == ENOENT)
		error = 0;
	if (!error) {
		/*
		 * remove nfsnode from hash now so we can't accidentally find it
		 * again if another object gets created with the same filehandle
		 * before this vnode gets reclaimed
		 */
		lck_mtx_lock(nfs_node_hash_mutex);
		if (np->n_hflag & NHHASHED) {
			LIST_REMOVE(np, n_hash);
			np->n_hflag &= ~NHHASHED;
			FSDBG(266, 0, np, np->n_flag, 0xb1eb1e);
		}
		lck_mtx_unlock(nfs_node_hash_mutex);
	}
	return (error);
}

