/*
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
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
#include <sys/uio.h>

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
nfs4_access_rpc(nfsnode_t np, u_int32_t *mode, vfs_context_t ctx)
{
	int error = 0, lockerror = ENOENT, status, numops, slot;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;
	struct timeval now;
	uint32_t access = 0, supported = 0, missing;
	struct nfsmount *nmp = NFSTONMP(np);
	int nfsvers = nmp->nm_vers;
	uid_t uid;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, ACCESS, GETATTR
	numops = 3;
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

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
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
	/* Some servers report DELETE support but erroneously give a denied answer. */
	if ((*mode & NFS_ACCESS_DELETE) && nfs_access_delete && !(access & NFS_ACCESS_DELETE))
		access |= NFS_ACCESS_DELETE;
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
	if (!lockerror)
		nfs_node_unlock(np);
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

	// PUTFH, GETATTR
	numops = 2;
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

	// PUTFH, GETATTR, READLINK
	numops = 3;
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

	if ((lockerror = nfs_node_lock(np)))
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
		nfs_node_unlock(np);
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
	nfs_stateid stateid;
	struct nfsm_chain nmreq;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);

	// PUTFH, READ, GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 22 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "read", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_READ);
	nfs_get_stateid(np, thd, cred, &stateid);
	nfsm_chain_add_stateid(error, &nmreq, &stateid);
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
	uio_t uio,
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

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_READ);
	nfsm_chain_get_32(error, &nmrep, eof);
	nfsm_chain_get_32(error, &nmrep, retlen);
	if (!error) {
		*lenp = MIN(retlen, *lenp);
		error = nfsm_chain_get_uio(&nmrep, *lenp, uio);
	}
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	if (!lockerror)
		nfs_node_unlock(np);
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
	uio_t uio,
	size_t len,
	thread_t thd,
	kauth_cred_t cred,
	int iomode,
	struct nfsreq_cbinfo *cb,
	struct nfsreq **reqp)
{
	struct nfsmount *nmp;
	int error = 0, nfsvers, numops;
	nfs_stateid stateid;
	struct nfsm_chain nmreq;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmreq);

	// PUTFH, WRITE, GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 25 * NFSX_UNSIGNED + len);
	nfsm_chain_add_compound_header(error, &nmreq, "write", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_WRITE);
	nfs_get_stateid(np, thd, cred, &stateid);
	nfsm_chain_add_stateid(error, &nmreq, &stateid);
	nfsm_chain_add_64(error, &nmreq, uio_offset(uio));
	nfsm_chain_add_32(error, &nmreq, iomode);
	nfsm_chain_add_32(error, &nmreq, len);
	if (!error)
		error = nfsm_chain_add_uio(&nmreq, uio, len);
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
	if (!error && (lockerror = nfs_node_lock(np)))
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
		nfs_node_unlock(np);
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
	int error = 0, lockerror = ENOENT, remove_error = 0, status;
	struct nfsmount *nmp;
	int nfsvers, numops;
	u_int64_t xid;
	struct nfsm_chain nmreq, nmrep;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
restart:
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

	if ((lockerror = nfs_node_lock(dnp)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_REMOVE);
	remove_error = error;
	nfsm_chain_check_change_info(error, &nmrep, dnp);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);
	if (error && !lockerror)
		NATTRINVALIDATE(dnp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror) {
		dnp->n_flag |= NMODIFIED;
		nfs_node_unlock(dnp);
	}
	if (error == NFSERR_GRACE) {
		tsleep(&nmp->nm_state, (PZERO-1), "nfsgrace", 2*hz);
		goto restart;
	}

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
	int error = 0, lockerror = ENOENT, status, nfsvers, numops;
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

	if ((lockerror = nfs_node_lock2(fdnp, tdnp)))
		error = lockerror;
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
	if (error && !lockerror)
		NATTRINVALIDATE(tdnp);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RESTOREFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	xid = savedxid;
	nfsm_chain_loadattr(error, &nmrep, fdnp, nfsvers, NULL, &xid);
	if (error && !lockerror)
		NATTRINVALIDATE(fdnp);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	if (!lockerror) {
		fdnp->n_flag |= NMODIFIED;
		tdnp->n_flag |= NMODIFIED;
		nfs_node_unlock2(fdnp, tdnp);
	}
	/* Kludge: Map EEXIST => 0 assuming that it is a reply to a retry. */
	if (error == EEXIST)
		error = 0;
	return (error);
}

/*
 * NFS V4 readdir RPC.
 */
int
nfs4_readdir_rpc(nfsnode_t dnp, struct nfsbuf *bp, vfs_context_t ctx)
{
	struct nfsmount *nmp;
	int error = 0, lockerror, nfsvers, rdirplus, bigcookies, numops;
	int i, status, more_entries = 1, eof, bp_dropped = 0;
	uint32_t nmreaddirsize, nmrsize;
	uint32_t namlen, skiplen, fhlen, xlen, attrlen, reclen, space_free, space_needed;
	uint64_t cookie, lastcookie, xid, savedxid;
	struct nfsm_chain nmreq, nmrep, nmrepsave;
	fhandle_t fh;
	struct nfs_vattr nvattr, *nvattrp;
	struct nfs_dir_buf_header *ndbhp;
	struct direntry *dp;
	char *padstart, padlen;
	const char *tag;
	uint32_t entry_attrs[NFS_ATTR_BITMAP_LEN];
	struct timeval now;

	nmp = NFSTONMP(dnp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;
	nmreaddirsize = nmp->nm_readdirsize;
	nmrsize = nmp->nm_rsize;
	bigcookies = nmp->nm_state & NFSSTA_BIGCOOKIES;
	rdirplus = ((nfsvers > NFS_VER2) && (nmp->nm_flag & NFSMNT_RDIRPLUS)) ? 1 : 0;

	/*
	 * Set up attribute request for entries.
	 * For READDIRPLUS functionality, get everything.
	 * Otherwise, just get what we need for struct direntry.
	 */
	if (rdirplus) {
		tag = "readdirplus";
		for (i=0; i < NFS_ATTR_BITMAP_LEN; i++)
			entry_attrs[i] =
				nfs_getattr_bitmap[i] &
				nmp->nm_fsattr.nfsa_supp_attr[i];
		NFS_BITMAP_SET(entry_attrs, NFS_FATTR_FILEHANDLE);
	} else {
		tag = "readdir";
		NFS_CLEAR_ATTRIBUTES(entry_attrs);
		NFS_BITMAP_SET(entry_attrs, NFS_FATTR_TYPE);
		NFS_BITMAP_SET(entry_attrs, NFS_FATTR_FILEID);
	}
	/* XXX NFS_BITMAP_SET(entry_attrs, NFS_FATTR_MOUNTED_ON_FILEID); */
	NFS_BITMAP_SET(entry_attrs, NFS_FATTR_RDATTR_ERROR);

	/* lock to protect access to cookie verifier */
	if ((lockerror = nfs_node_lock(dnp)))
		return (lockerror);

	/* determine cookie to use, and move dp to the right offset */
	ndbhp = (struct nfs_dir_buf_header*)bp->nb_data;
	dp = NFS_DIR_BUF_FIRST_DIRENTRY(bp);
	if (ndbhp->ndbh_count) {
		for (i=0; i < ndbhp->ndbh_count-1; i++)
			dp = NFS_DIRENTRY_NEXT(dp);
		cookie = dp->d_seekoff;
		dp = NFS_DIRENTRY_NEXT(dp);
	} else {
		cookie = bp->nb_lblkno;
		/* increment with every buffer read */
		OSAddAtomic(1, &nfsstats.readdir_bios);
	}
	lastcookie = cookie;

	/*
	 * The NFS client is responsible for the "." and ".." entries in the
	 * directory.  So, we put them at the start of the first buffer.
	 */
	if ((bp->nb_lblkno == 0) && (ndbhp->ndbh_count == 0)) {
		fh.fh_len = 0;
		fhlen = rdirplus ? fh.fh_len + 1 : 0;
		xlen = rdirplus ? (fhlen + sizeof(time_t)) : 0;
		/* "." */
		namlen = 1;
		reclen = NFS_DIRENTRY_LEN(namlen + xlen);
		if (xlen)
			bzero(&dp->d_name[namlen+1], xlen);
		dp->d_namlen = namlen;
		strlcpy(dp->d_name, ".", namlen+1);
		dp->d_fileno = dnp->n_vattr.nva_fileid;
		dp->d_type = DT_DIR;
		dp->d_reclen = reclen;
		dp->d_seekoff = 1;
		padstart = dp->d_name + dp->d_namlen + 1 + xlen;
		dp = NFS_DIRENTRY_NEXT(dp);
		padlen = (char*)dp - padstart;
		if (padlen > 0)
			bzero(padstart, padlen);
		if (rdirplus) /* zero out attributes */
			bzero(NFS_DIR_BUF_NVATTR(bp, 0), sizeof(struct nfs_vattr));

		/* ".." */
		namlen = 2;
		reclen = NFS_DIRENTRY_LEN(namlen + xlen);
		if (xlen)
			bzero(&dp->d_name[namlen+1], xlen);
		dp->d_namlen = namlen;
		strlcpy(dp->d_name, "..", namlen+1);
		if (dnp->n_parent)
			dp->d_fileno = VTONFS(dnp->n_parent)->n_vattr.nva_fileid;
		else
			dp->d_fileno = dnp->n_vattr.nva_fileid;
		dp->d_type = DT_DIR;
		dp->d_reclen = reclen;
		dp->d_seekoff = 2;
		padstart = dp->d_name + dp->d_namlen + 1 + xlen;
		dp = NFS_DIRENTRY_NEXT(dp);
		padlen = (char*)dp - padstart;
		if (padlen > 0)
			bzero(padstart, padlen);
		if (rdirplus) /* zero out attributes */
			bzero(NFS_DIR_BUF_NVATTR(bp, 1), sizeof(struct nfs_vattr));

		ndbhp->ndbh_entry_end = (char*)dp - bp->nb_data;
		ndbhp->ndbh_count = 2;
	}

	/*
	 * Loop around doing readdir(plus) RPCs of size nm_readdirsize until
	 * the buffer is full (or we hit EOF).  Then put the remainder of the
	 * results in the next buffer(s).
	 */
	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);
	while (nfs_dir_buf_freespace(bp, rdirplus) && !(ndbhp->ndbh_flags & NDB_FULL)) {

		// PUTFH, GETATTR, READDIR
		numops = 3;
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
		nfsm_chain_add_64(error, &nmreq, (cookie <= 2) ? 0 : cookie);
		nfsm_chain_add_64(error, &nmreq, dnp->n_cookieverf);
		nfsm_chain_add_32(error, &nmreq, nmreaddirsize);
		nfsm_chain_add_32(error, &nmreq, nmrsize);
		nfsm_chain_add_bitmap(error, &nmreq, entry_attrs, NFS_ATTR_BITMAP_LEN);
		nfsm_chain_build_done(error, &nmreq);
		nfsm_assert(error, (numops == 0), EPROTO);
		nfs_node_unlock(dnp);
		nfsmout_if(error);
		error = nfs_request(dnp, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

		if ((lockerror = nfs_node_lock(dnp)))
			error = lockerror;

		savedxid = xid;
		nfsm_chain_skip_tag(error, &nmrep);
		nfsm_chain_get_32(error, &nmrep, numops);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
		nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_READDIR);
		nfsm_chain_get_64(error, &nmrep, dnp->n_cookieverf);
		nfsm_chain_get_32(error, &nmrep, more_entries);

		if (!lockerror) {
			nfs_node_unlock(dnp);
			lockerror = ENOENT;
		}
		nfsmout_if(error);

		if (rdirplus)
			microuptime(&now);

		/* loop through the entries packing them into the buffer */
		while (more_entries) {
			/* Entry: COOKIE, NAME, FATTR */
			nfsm_chain_get_64(error, &nmrep, cookie);
			nfsm_chain_get_32(error, &nmrep, namlen);
			nfsmout_if(error);
			if (!bigcookies && (cookie >> 32) && (nmp == NFSTONMP(dnp))) {
				/* we've got a big cookie, make sure flag is set */
				lck_mtx_lock(&nmp->nm_lock);
				nmp->nm_state |= NFSSTA_BIGCOOKIES;
				lck_mtx_unlock(&nmp->nm_lock);
				bigcookies = 1;
			}
			/* just truncate names that don't fit in direntry.d_name */
			if (namlen <= 0) {
				error = EBADRPC;
				goto nfsmout;
			}
			if (namlen > (sizeof(dp->d_name)-1)) {
				skiplen = namlen - sizeof(dp->d_name) + 1;
				namlen = sizeof(dp->d_name) - 1;
			} else {
				skiplen = 0;
			}
			/* guess that fh size will be same as parent */
			fhlen = rdirplus ? (1 + dnp->n_fhsize) : 0;
			xlen = rdirplus ? (fhlen + sizeof(time_t)) : 0;
			attrlen = rdirplus ? sizeof(struct nfs_vattr) : 0;
			reclen = NFS_DIRENTRY_LEN(namlen + xlen);
			space_needed = reclen + attrlen;
			space_free = nfs_dir_buf_freespace(bp, rdirplus);
			if (space_needed > space_free) {
				/*
				 * We still have entries to pack, but we've
				 * run out of room in the current buffer.
				 * So we need to move to the next buffer.
				 * The block# for the next buffer is the
				 * last cookie in the current buffer.
				 */
nextbuffer:
				ndbhp->ndbh_flags |= NDB_FULL;
				nfs_buf_release(bp, 0);
				bp_dropped = 1;
				bp = NULL;
				error = nfs_buf_get(dnp, lastcookie, NFS_DIRBLKSIZ, vfs_context_thread(ctx), NBLK_READ, &bp);
				nfsmout_if(error);
				/* initialize buffer */
				ndbhp = (struct nfs_dir_buf_header*)bp->nb_data;
				ndbhp->ndbh_flags = 0;
				ndbhp->ndbh_count = 0;
				ndbhp->ndbh_entry_end = sizeof(*ndbhp);
				ndbhp->ndbh_ncgen = dnp->n_ncgen;
				space_free = nfs_dir_buf_freespace(bp, rdirplus);
				dp = NFS_DIR_BUF_FIRST_DIRENTRY(bp);
				/* increment with every buffer read */
				OSAddAtomic(1, &nfsstats.readdir_bios);
			}
			nmrepsave = nmrep;
			dp->d_fileno = cookie; /* placeholder */
			dp->d_seekoff = cookie;
			dp->d_namlen = namlen;
			dp->d_reclen = reclen;
			dp->d_type = DT_UNKNOWN;
			nfsm_chain_get_opaque(error, &nmrep, namlen, dp->d_name);
			nfsmout_if(error);
			dp->d_name[namlen] = '\0';
			if (skiplen)
				nfsm_chain_adv(error, &nmrep,
					nfsm_rndup(namlen + skiplen) - nfsm_rndup(namlen));
			nfsmout_if(error);
			nvattrp = rdirplus ? NFS_DIR_BUF_NVATTR(bp, ndbhp->ndbh_count) : &nvattr;
			NFS_CLEAR_ATTRIBUTES(nvattrp->nva_bitmap);
			error = nfs4_parsefattr(&nmrep, NULL, nvattrp, &fh, NULL);
			if (error && NFS_BITMAP_ISSET(nvattrp->nva_bitmap, NFS_FATTR_RDATTR_ERROR)) {
				/* OK, we didn't get attributes, whatever... */
				if (rdirplus) /* mark the attributes invalid */
					bzero(nvattrp, sizeof(struct nfs_vattr));
				else
					NFS_CLEAR_ATTRIBUTES(nvattrp->nva_bitmap);
				error = 0;
			}
			/* check for more entries after this one */
			nfsm_chain_get_32(error, &nmrep, more_entries);
			nfsmout_if(error);

			/* Skip any "." and ".." entries returned from server. */
			if ((dp->d_name[0] == '.') && ((namlen == 1) || ((namlen == 2) && (dp->d_name[1] == '.')))) {
				lastcookie = cookie;
				continue;
			}

			if (NFS_BITMAP_ISSET(nvattrp->nva_bitmap, NFS_FATTR_TYPE))
				dp->d_type = IFTODT(VTTOIF(nvattrp->nva_type));
			if (NFS_BITMAP_ISSET(nvattrp->nva_bitmap, NFS_FATTR_FILEID))
				dp->d_fileno = nvattrp->nva_fileid;
			if (rdirplus) {
				/* fileid is already in d_fileno, so stash xid in attrs */
				nvattrp->nva_fileid = savedxid;
				if (NFS_BITMAP_ISSET(nvattrp->nva_bitmap, NFS_FATTR_FILEHANDLE)) {
					fhlen = fh.fh_len + 1;
					xlen = fhlen + sizeof(time_t);
					reclen = NFS_DIRENTRY_LEN(namlen + xlen);
					space_needed = reclen + attrlen;
					if (space_needed > space_free) {
						/* didn't actually have the room... move on to next buffer */
						nmrep = nmrepsave;
						goto nextbuffer;
					}
					/* pack the file handle into the record */
					dp->d_name[dp->d_namlen+1] = fh.fh_len;
					bcopy(fh.fh_data, &dp->d_name[dp->d_namlen+2], fh.fh_len);
				} else {
					/* mark the file handle invalid */
					fh.fh_len = 0;
					fhlen = fh.fh_len + 1;
					xlen = fhlen + sizeof(time_t);
					reclen = NFS_DIRENTRY_LEN(namlen + xlen);
					bzero(&dp->d_name[dp->d_namlen+1], fhlen);
				}
				*(time_t*)(&dp->d_name[dp->d_namlen+1+fhlen]) = now.tv_sec;
				dp->d_reclen = reclen;
			}
			padstart = dp->d_name + dp->d_namlen + 1 + xlen;
			ndbhp->ndbh_count++;
			lastcookie = cookie;

			/* advance to next direntry in buffer */
			dp = NFS_DIRENTRY_NEXT(dp);
			ndbhp->ndbh_entry_end = (char*)dp - bp->nb_data;
			/* zero out the pad bytes */
			padlen = (char*)dp - padstart;
			if (padlen > 0)
				bzero(padstart, padlen);
		}
		/* Finally, get the eof boolean */
		nfsm_chain_get_32(error, &nmrep, eof);
		nfsmout_if(error);
		if (eof) {
			ndbhp->ndbh_flags |= (NDB_FULL|NDB_EOF);
			nfs_node_lock_force(dnp);
			dnp->n_eofcookie = lastcookie;
			nfs_node_unlock(dnp);
		} else {
			more_entries = 1;
		}
		if (bp_dropped) {
			nfs_buf_release(bp, 0);
			bp = NULL;
			break;
		}
		if ((lockerror = nfs_node_lock(dnp)))
			error = lockerror;
		nfsmout_if(error);
		nfsm_chain_cleanup(&nmrep);
		nfsm_chain_null(&nmreq);
	}
nfsmout:
	if (bp_dropped && bp)
		nfs_buf_release(bp, 0);
	if (!lockerror)
		nfs_node_unlock(dnp);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (bp_dropped ? NFSERR_DIRBUFDROPPED : error);
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
	int error = 0, lockerror = ENOENT, status, nfsvers, numops;
	uint32_t val = 0;
	u_int64_t xid;
	struct nfsmount *nmp;
	struct nfsm_chain nmrep;

	nmp = NFSTONMP(dnp);
	nfsvers = nmp->nm_vers;

	nfsm_chain_null(&nmrep);

	error = nfs_request_async_finish(req, &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(dnp)))
		error = lockerror;
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
	if (!lockerror)
		nfs_node_unlock(dnp);
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

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_COMMIT);
	nfsm_chain_get_64(error, &nmrep, wverf);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
	if (!lockerror)
		nfs_node_unlock(np);
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
	// PUTFH, GETATTR
	numops = 2;
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
	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	if (!error)
		nfs_loadattrcache(np, &nvattr, &xid, 0);
	if (!lockerror)
		nfs_node_unlock(np);
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

	error = nfs_getattr(VTONFS(ap->a_vp), &nva, ap->a_context, NGA_CACHED);
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
	vfs_context_t ctx)
{
	struct nfsmount *nmp = NFSTONMP(np);
	int error = 0, lockerror = ENOENT, status, nfsvers, numops;
	u_int64_t xid, nextxid;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN], bmlen;
	nfs_stateid stateid;

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
		nfs_get_stateid(np, vfs_context_thread(ctx), vfs_context_ucred(ctx), &stateid);
	else
		stateid.seqid = stateid.other[0] = stateid.other[1] = stateid.other[2] = 0;
	nfsm_chain_add_stateid(error, &nmreq, &stateid);
	nfsm_chain_add_fattr4(error, &nmreq, vap, nmp);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(np)))
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
	/*
	 * We just changed the attributes and we want to make sure that we
	 * see the latest attributes.  Get the next XID.  If it's not the
	 * next XID after the SETATTR XID, then it's possible that another
	 * RPC was in flight at the same time and it might put stale attributes
	 * in the cache.  In that case, we invalidate the attributes and set
	 * the attribute cache XID to guarantee that newer attributes will
	 * get loaded next.
	 */
	nextxid = 0;
	nfs_get_xid(&nextxid);
	if (nextxid != (xid + 1)) {
		np->n_xid = nextxid;
		NATTRINVALIDATE(np);
	}
nfsmout:
	if (!lockerror)
		nfs_node_unlock(np);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * Wait for any pending recovery to complete.
 */
int
nfs_mount_state_wait_for_recovery(struct nfsmount *nmp)
{
	struct timespec ts = { 1, 0 };
	int error = 0, slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

	lck_mtx_lock(&nmp->nm_lock);
	while (nmp->nm_state & NFSSTA_RECOVER) {
		if ((error = nfs_sigintr(nmp, NULL, current_thread(), 1)))
			break;
		nfs_mount_sock_thread_wake(nmp);
		msleep(&nmp->nm_state, &nmp->nm_lock, slpflag|(PZERO-1), "nfsrecoverwait", &ts);
	}
	lck_mtx_unlock(&nmp->nm_lock);

	return (error);
}

/*
 * We're about to use/manipulate NFS mount's open/lock state.
 * Wait for any pending state recovery to complete, then
 * mark the state as being in use (which will hold off
 * the recovery thread until we're done).
 */
int
nfs_mount_state_in_use_start(struct nfsmount *nmp)
{
	struct timespec ts = { 1, 0 };
	int error = 0, slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

	if (!nmp)
		return (ENXIO);
	lck_mtx_lock(&nmp->nm_lock);
	while (nmp->nm_state & NFSSTA_RECOVER) {
		if ((error = nfs_sigintr(nmp, NULL, current_thread(), 1)))
			break;
		nfs_mount_sock_thread_wake(nmp);
		msleep(&nmp->nm_state, &nmp->nm_lock, slpflag|(PZERO-1), "nfsrecoverwait", &ts);
	}
	if (!error)
		nmp->nm_stateinuse++;
	lck_mtx_unlock(&nmp->nm_lock);

	return (error);
}

/*
 * We're done using/manipulating the NFS mount's open/lock
 * state.  If the given error indicates that recovery should
 * be performed, we'll initiate recovery.
 */
int
nfs_mount_state_in_use_end(struct nfsmount *nmp, int error)
{
	int restart = nfs_mount_state_error_should_restart(error);

	if (!nmp)
		return (restart);
	lck_mtx_lock(&nmp->nm_lock);
	if (restart && (error != NFSERR_OLD_STATEID) && (error != NFSERR_GRACE)) {
		if (!(nmp->nm_state & NFSSTA_RECOVER)) {
			printf("nfs_mount_state_in_use_end: error %d, initiating recovery\n", error);
			nmp->nm_state |= NFSSTA_RECOVER;
			nfs_mount_sock_thread_wake(nmp);
		}
	}
	if (nmp->nm_stateinuse > 0)
		nmp->nm_stateinuse--;
	else
		panic("NFS mount state in use count underrun");
	if (!nmp->nm_stateinuse && (nmp->nm_state & NFSSTA_RECOVER))
		wakeup(&nmp->nm_stateinuse);
	lck_mtx_unlock(&nmp->nm_lock);
	if (error == NFSERR_GRACE)
		tsleep(&nmp->nm_state, (PZERO-1), "nfsgrace", 2*hz);

	return (restart);
}

/*
 * Does the error mean we should restart/redo a state-related operation?
 */
int
nfs_mount_state_error_should_restart(int error)
{
	switch (error) {
	case NFSERR_STALE_STATEID:
	case NFSERR_STALE_CLIENTID:
	case NFSERR_ADMIN_REVOKED:
	case NFSERR_EXPIRED:
	case NFSERR_OLD_STATEID:
	case NFSERR_BAD_STATEID:
	case NFSERR_GRACE:
		return (1);
	}
	return (0);
}

/*
 * In some cases we may want to limit how many times we restart a
 * state-related operation - e.g. we're repeatedly getting NFSERR_GRACE.
 * Base the limit on the lease (as long as it's not too short).
 */
uint
nfs_mount_state_max_restarts(struct nfsmount *nmp)
{
	return (MAX(nmp->nm_fsattr.nfsa_lease, 60));
}


/*
 * Mark an NFS node's open state as busy.
 */
int
nfs_open_state_set_busy(nfsnode_t np, vfs_context_t ctx)
{
	struct nfsmount *nmp;
	thread_t thd = vfs_context_thread(ctx);
	struct timespec ts = {2, 0};
	int error = 0, slpflag;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

	lck_mtx_lock(&np->n_openlock);
	while (np->n_openflags & N_OPENBUSY) {
		if ((error = nfs_sigintr(nmp, NULL, thd, 0)))
			break;
		np->n_openflags |= N_OPENWANT;
		msleep(&np->n_openflags, &np->n_openlock, slpflag, "nfs_open_state_set_busy", &ts);
	}
	if (!error)
		np->n_openflags |= N_OPENBUSY;
	lck_mtx_unlock(&np->n_openlock);

	return (error);
}

/*
 * Clear an NFS node's open state busy flag and wake up
 * anyone wanting it.
 */
void
nfs_open_state_clear_busy(nfsnode_t np)
{
	int wanted;

	lck_mtx_lock(&np->n_openlock);
	if (!(np->n_openflags & N_OPENBUSY))
		panic("nfs_open_state_clear_busy");
	wanted = (np->n_openflags & N_OPENWANT);
	np->n_openflags &= ~(N_OPENBUSY|N_OPENWANT);
	lck_mtx_unlock(&np->n_openlock);
	if (wanted)
		wakeup(&np->n_openflags);
}

/*
 * Search a mount's open owner list for the owner for this credential.
 * If not found and "alloc" is set, then allocate a new one.
 */
struct nfs_open_owner *
nfs_open_owner_find(struct nfsmount *nmp, kauth_cred_t cred, int alloc)
{
	uid_t uid = kauth_cred_getuid(cred);
	struct nfs_open_owner *noop, *newnoop = NULL;

tryagain:
	lck_mtx_lock(&nmp->nm_lock);
	TAILQ_FOREACH(noop, &nmp->nm_open_owners, noo_link) {
		if (kauth_cred_getuid(noop->noo_cred) == uid)
			break;
	}

	if (!noop && !newnoop && alloc) {
		lck_mtx_unlock(&nmp->nm_lock);
		MALLOC(newnoop, struct nfs_open_owner *, sizeof(struct nfs_open_owner), M_TEMP, M_WAITOK);
		if (!newnoop)
			return (NULL);
		bzero(newnoop, sizeof(*newnoop));
		lck_mtx_init(&newnoop->noo_lock, nfs_open_grp, LCK_ATTR_NULL);
		newnoop->noo_mount = nmp;
		kauth_cred_ref(cred);
		newnoop->noo_cred = cred;
		newnoop->noo_name = OSAddAtomic(1, &nfs_open_owner_seqnum);
		TAILQ_INIT(&newnoop->noo_opens);
		goto tryagain;
	}
	if (!noop && newnoop) {
		newnoop->noo_flags |= NFS_OPEN_OWNER_LINK;
		TAILQ_INSERT_HEAD(&nmp->nm_open_owners, newnoop, noo_link);
		noop = newnoop;
	}
	lck_mtx_unlock(&nmp->nm_lock);

	if (newnoop && (noop != newnoop))
		nfs_open_owner_destroy(newnoop);

	if (noop)
		nfs_open_owner_ref(noop);

	return (noop);
}

/*
 * destroy an open owner that's no longer needed
 */
void
nfs_open_owner_destroy(struct nfs_open_owner *noop)
{
	if (noop->noo_cred)
		kauth_cred_unref(&noop->noo_cred);
	lck_mtx_destroy(&noop->noo_lock, nfs_open_grp);
	FREE(noop, M_TEMP);
}

/*
 * acquire a reference count on an open owner
 */
void
nfs_open_owner_ref(struct nfs_open_owner *noop)
{
	lck_mtx_lock(&noop->noo_lock);
	noop->noo_refcnt++;
	lck_mtx_unlock(&noop->noo_lock);
}

/*
 * drop a reference count on an open owner and destroy it if
 * it is no longer referenced and no longer on the mount's list.
 */
void
nfs_open_owner_rele(struct nfs_open_owner *noop)
{
	lck_mtx_lock(&noop->noo_lock);
	if (noop->noo_refcnt < 1)
		panic("nfs_open_owner_rele: no refcnt");
	noop->noo_refcnt--;
	if (!noop->noo_refcnt && (noop->noo_flags & NFS_OPEN_OWNER_BUSY))
		panic("nfs_open_owner_rele: busy");
	/* XXX we may potentially want to clean up idle/unused open owner structures */
	if (noop->noo_refcnt || (noop->noo_flags & NFS_OPEN_OWNER_LINK)) {
		lck_mtx_unlock(&noop->noo_lock);
		return;
	}
	/* owner is no longer referenced or linked to mount, so destroy it */
	lck_mtx_unlock(&noop->noo_lock);
	nfs_open_owner_destroy(noop);
}

/*
 * Mark an open owner as busy because we are about to
 * start an operation that uses and updates open owner state.
 */
int
nfs_open_owner_set_busy(struct nfs_open_owner *noop, thread_t thd)
{
	struct nfsmount *nmp;
	struct timespec ts = {2, 0};
	int error = 0, slpflag;

	nmp = noop->noo_mount;
	if (!nmp)
		return (ENXIO);
	slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

	lck_mtx_lock(&noop->noo_lock);
	while (noop->noo_flags & NFS_OPEN_OWNER_BUSY) {
		if ((error = nfs_sigintr(nmp, NULL, thd, 0)))
			break;
		noop->noo_flags |= NFS_OPEN_OWNER_WANT;
		msleep(noop, &noop->noo_lock, slpflag, "nfs_open_owner_set_busy", &ts);
	}
	if (!error)
		noop->noo_flags |= NFS_OPEN_OWNER_BUSY;
	lck_mtx_unlock(&noop->noo_lock);

	return (error);
}

/*
 * Clear the busy flag on an open owner and wake up anyone waiting
 * to mark it busy.
 */
void
nfs_open_owner_clear_busy(struct nfs_open_owner *noop)
{
	int wanted;

	lck_mtx_lock(&noop->noo_lock);
	if (!(noop->noo_flags & NFS_OPEN_OWNER_BUSY))
		panic("nfs_open_owner_clear_busy");
	wanted = (noop->noo_flags & NFS_OPEN_OWNER_WANT);
	noop->noo_flags &= ~(NFS_OPEN_OWNER_BUSY|NFS_OPEN_OWNER_WANT);
	lck_mtx_unlock(&noop->noo_lock);
	if (wanted)
		wakeup(noop);
}

/*
 * Given an open/lock owner and an error code, increment the
 * sequence ID if appropriate.
 */
void
nfs_owner_seqid_increment(struct nfs_open_owner *noop, struct nfs_lock_owner *nlop, int error)
{
	switch (error) {
	case NFSERR_STALE_CLIENTID:
	case NFSERR_STALE_STATEID:
	case NFSERR_OLD_STATEID:
	case NFSERR_BAD_STATEID:
	case NFSERR_BAD_SEQID:
	case NFSERR_BADXDR:
	case NFSERR_RESOURCE:
	case NFSERR_NOFILEHANDLE:
		/* do not increment the open seqid on these errors */
		return;
	}
	if (noop)
		noop->noo_seqid++;
	if (nlop)
		nlop->nlo_seqid++;
}

/*
 * Search a node's open file list for any conflicts with this request.
 * Also find this open owner's open file structure.
 * If not found and "alloc" is set, then allocate one.
 */
int
nfs_open_file_find(
	nfsnode_t np,
	struct nfs_open_owner *noop,
	struct nfs_open_file **nofpp,
	uint32_t accessMode,
	uint32_t denyMode,
	int alloc)
{
	struct nfs_open_file *nofp = NULL, *nofp2, *newnofp = NULL;

	if (!np)
		goto alloc;
tryagain:
	lck_mtx_lock(&np->n_openlock);
	TAILQ_FOREACH(nofp2, &np->n_opens, nof_link) {
		if (nofp2->nof_owner == noop) {
			nofp = nofp2;
			if (!accessMode)
				break;
		}
		if ((accessMode & nofp2->nof_deny) || (denyMode & nofp2->nof_access)) {
			/* This request conflicts with an existing open on this client. */
			lck_mtx_unlock(&np->n_openlock);
			*nofpp = NULL;
			return (EACCES);
		}
	}

	/*
	 * If this open owner doesn't have an open
	 * file structure yet, we create one for it.
	 */
	if (!nofp && !newnofp && alloc) {
		lck_mtx_unlock(&np->n_openlock);
alloc:
		MALLOC(newnofp, struct nfs_open_file *, sizeof(struct nfs_open_file), M_TEMP, M_WAITOK);
		if (!newnofp) {
			*nofpp = NULL;
			return (ENOMEM);
		}
		bzero(newnofp, sizeof(*newnofp));
		lck_mtx_init(&newnofp->nof_lock, nfs_open_grp, LCK_ATTR_NULL);
		newnofp->nof_owner = noop;
		nfs_open_owner_ref(noop);
		newnofp->nof_np = np;
		lck_mtx_lock(&noop->noo_lock);
		TAILQ_INSERT_HEAD(&noop->noo_opens, newnofp, nof_oolink);
		lck_mtx_unlock(&noop->noo_lock);
		if (np)
			goto tryagain;
	}
	if (!nofp && newnofp) {
		if (np)
			TAILQ_INSERT_HEAD(&np->n_opens, newnofp, nof_link);
		nofp = newnofp;
	}
	if (np)
		lck_mtx_unlock(&np->n_openlock);

	if (newnofp && (nofp != newnofp))
		nfs_open_file_destroy(newnofp);

	*nofpp = nofp;
	return (nofp ? 0 : ESRCH);
}

/*
 * Destroy an open file structure.
 */
void
nfs_open_file_destroy(struct nfs_open_file *nofp)
{
	lck_mtx_lock(&nofp->nof_owner->noo_lock);
	TAILQ_REMOVE(&nofp->nof_owner->noo_opens, nofp, nof_oolink);
	lck_mtx_unlock(&nofp->nof_owner->noo_lock);
	nfs_open_owner_rele(nofp->nof_owner);
	lck_mtx_destroy(&nofp->nof_lock, nfs_open_grp);
	FREE(nofp, M_TEMP);
}

/*
 * Mark an open file as busy because we are about to
 * start an operation that uses and updates open file state.
 */
int
nfs_open_file_set_busy(struct nfs_open_file *nofp, thread_t thd)
{
	struct nfsmount *nmp;
	struct timespec ts = {2, 0};
	int error = 0, slpflag;

	nmp = nofp->nof_owner->noo_mount;
	if (!nmp)
		return (ENXIO);
	slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

	lck_mtx_lock(&nofp->nof_lock);
	while (nofp->nof_flags & NFS_OPEN_FILE_BUSY) {
		if ((error = nfs_sigintr(nmp, NULL, thd, 0)))
			break;
		nofp->nof_flags |= NFS_OPEN_FILE_WANT;
		msleep(nofp, &nofp->nof_lock, slpflag, "nfs_open_file_set_busy", &ts);
	}
	if (!error)
		nofp->nof_flags |= NFS_OPEN_FILE_BUSY;
	lck_mtx_unlock(&nofp->nof_lock);

	return (error);
}

/*
 * Clear the busy flag on an open file and wake up anyone waiting
 * to mark it busy.
 */
void
nfs_open_file_clear_busy(struct nfs_open_file *nofp)
{
	int wanted;

	lck_mtx_lock(&nofp->nof_lock);
	if (!(nofp->nof_flags & NFS_OPEN_FILE_BUSY))
		panic("nfs_open_file_clear_busy");
	wanted = (nofp->nof_flags & NFS_OPEN_FILE_WANT);
	nofp->nof_flags &= ~(NFS_OPEN_FILE_BUSY|NFS_OPEN_FILE_WANT);
	lck_mtx_unlock(&nofp->nof_lock);
	if (wanted)
		wakeup(nofp);
}

/*
 * Get the current (delegation, lock, open, default) stateid for this node.
 * If node has a delegation, use that stateid.
 * If pid has a lock, use the lockowner's stateid.
 * Or use the open file's stateid.
 * If no open file, use a default stateid of all ones.
 */
void
nfs_get_stateid(nfsnode_t np, thread_t thd, kauth_cred_t cred, nfs_stateid *sid)
{
	struct nfsmount *nmp = NFSTONMP(np);
	proc_t p = thd ? get_bsdthreadtask_info(thd) : current_thread();  // XXX async I/O requests don't have a thread
	struct nfs_open_owner *noop = NULL;
	struct nfs_open_file *nofp = NULL;
	struct nfs_lock_owner *nlop = NULL;
	nfs_stateid *s = NULL;

	if (np->n_openflags & N_DELEG_MASK)
		s = &np->n_dstateid;
	else if (p)
		nlop = nfs_lock_owner_find(np, p, 0);
	if (nlop && !TAILQ_EMPTY(&nlop->nlo_locks)) {
		/* we hold locks, use lock stateid */
		s = &nlop->nlo_stateid;
	} else if (((noop = nfs_open_owner_find(nmp, cred, 0))) &&
		 (nfs_open_file_find(np, noop, &nofp, 0, 0, 0) == 0) &&
		 !(nofp->nof_flags & NFS_OPEN_FILE_LOST) &&
		 nofp->nof_access) {
		/* we (should) have the file open, use open stateid */
		if (nofp->nof_flags & NFS_OPEN_FILE_REOPEN)
			nfs4_reopen(nofp, thd);
		if (!(nofp->nof_flags & NFS_OPEN_FILE_LOST))
			s = &nofp->nof_stateid;
	}

	if (s) {
		sid->seqid = s->seqid;
		sid->other[0] = s->other[0];
		sid->other[1] = s->other[1];
		sid->other[2] = s->other[2];
	} else {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs_get_stateid: no stateid for %s\n", vname ? vname : "???");
		vnode_putname(vname);
		sid->seqid = sid->other[0] = sid->other[1] = sid->other[2] = 0xffffffff;
	}
	if (nlop)
		nfs_lock_owner_rele(nlop);
	if (noop)
		nfs_open_owner_rele(noop);
}

/*
 * We always send the open RPC even if this open's mode is a subset of all
 * the existing opens.  This makes sure that we will always be able to do a
 * downgrade to any of the open modes.
 *
 * Note: local conflicts should have already been checked. (nfs_open_file_find)
 */
int
nfs4_open(
	nfsnode_t np,
	struct nfs_open_file *nofp,
	uint32_t accessMode,
	uint32_t denyMode,
	vfs_context_t ctx)
{
	vnode_t vp = NFSTOV(np);
	vnode_t dvp = NULL;
	struct componentname cn;
	const char *vname = NULL;
	size_t namelen;
	char smallname[128];
	char *filename = NULL;
	int error = 0, readtoo = 0;

	dvp = vnode_getparent(vp);
	vname = vnode_getname(vp);
	if (!dvp || !vname) {
		error = EIO;
		goto out;
	}
	filename = &smallname[0];
	namelen = snprintf(filename, sizeof(smallname), "%s", vname);
	if (namelen >= sizeof(smallname)) {
		namelen++;  /* snprintf result doesn't include '\0' */
		MALLOC(filename, char *, namelen, M_TEMP, M_WAITOK);
		if (!filename) {
			error = ENOMEM;
			goto out;
		}
		snprintf(filename, namelen, "%s", vname);
	}
	bzero(&cn, sizeof(cn));
	cn.cn_nameptr = filename;
	cn.cn_namelen = namelen;

	if (!(accessMode & NFS_OPEN_SHARE_ACCESS_READ)) {
		/*
		 * Try to open it for read access too,
		 * so the buffer cache can read data.
		 */
		readtoo = 1;
		accessMode |= NFS_OPEN_SHARE_ACCESS_READ;
	}
tryagain:
	error = nfs4_open_rpc(nofp, ctx, &cn, NULL, dvp, &vp, NFS_OPEN_NOCREATE, accessMode, denyMode);
	if (error) {
		if (!nfs_mount_state_error_should_restart(error) && readtoo) {
			/* try again without the extra read access */
			accessMode &= ~NFS_OPEN_SHARE_ACCESS_READ;
			readtoo = 0;
			goto tryagain;
		}
		goto out;
	}
	nofp->nof_access |= accessMode;
	nofp->nof_deny |= denyMode;

	if (denyMode == NFS_OPEN_SHARE_DENY_NONE) {
		if (accessMode == NFS_OPEN_SHARE_ACCESS_READ)
			nofp->nof_r++;
		else if (accessMode == NFS_OPEN_SHARE_ACCESS_WRITE)
			nofp->nof_w++;
		else if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH)
			nofp->nof_rw++;
	} else if (denyMode == NFS_OPEN_SHARE_DENY_WRITE) {
		if (accessMode == NFS_OPEN_SHARE_ACCESS_READ)
			nofp->nof_r_dw++;
		else if (accessMode == NFS_OPEN_SHARE_ACCESS_WRITE)
			nofp->nof_w_dw++;
		else if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH)
			nofp->nof_rw_dw++;
	} else { /* NFS_OPEN_SHARE_DENY_BOTH */
		if (accessMode == NFS_OPEN_SHARE_ACCESS_READ)
			nofp->nof_r_drw++;
		else if (accessMode == NFS_OPEN_SHARE_ACCESS_WRITE)
			nofp->nof_w_drw++;
		else if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH)
			nofp->nof_rw_drw++;
	}
	nofp->nof_opencnt++;
out:
	if (filename && (filename != &smallname[0]))
		FREE(filename, M_TEMP);
	if (vname)
		vnode_putname(vname);
	if (dvp != NULLVP)
		vnode_put(dvp);
	return (error);
}


int
nfs4_vnop_open(
	struct vnop_open_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_mode;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	int error, accessMode, denyMode, opened = 0;
	struct nfs_open_owner *noop = NULL;
	struct nfs_open_file *nofp = NULL;

	if (!(ap->a_mode & (FREAD|FWRITE)))
		return (EINVAL);

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);

	/* First, call the common code */
	if ((error = nfs3_vnop_open(ap)))
		return (error);

	if (!vnode_isreg(vp)) {
		/* Just mark that it was opened */
		lck_mtx_lock(&np->n_openlock);
		np->n_openrefcnt++;
		lck_mtx_unlock(&np->n_openlock);
		return (0);
	}

	/* mode contains some combination of: FREAD, FWRITE, O_SHLOCK, O_EXLOCK */
	accessMode = 0;
	if (ap->a_mode & FREAD)
		accessMode |= NFS_OPEN_SHARE_ACCESS_READ;
	if (ap->a_mode & FWRITE)
		accessMode |= NFS_OPEN_SHARE_ACCESS_WRITE;
	if (ap->a_mode & O_EXLOCK)
		denyMode = NFS_OPEN_SHARE_DENY_BOTH;
	else if (ap->a_mode & O_SHLOCK)
		denyMode = NFS_OPEN_SHARE_DENY_WRITE;
	else
		denyMode = NFS_OPEN_SHARE_DENY_NONE;

	noop = nfs_open_owner_find(nmp, vfs_context_ucred(ctx), 1);
	if (!noop)
		return (ENOMEM);

restart:
	error = nfs_mount_state_in_use_start(nmp);
	if (error) {
		nfs_open_owner_rele(noop);
		return (error);
	}

	error = nfs_open_file_find(np, noop, &nofp, accessMode, denyMode, 1);
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_LOST)) {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs_vnop_open: LOST %s\n", vname);
		vnode_putname(vname);
		error = EIO;
	}
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_REOPEN)) {
		nfs_mount_state_in_use_end(nmp, 0);
		nfs4_reopen(nofp, vfs_context_thread(ctx));
		nofp = NULL;
		goto restart;
	}
	if (!error)
		error = nfs_open_file_set_busy(nofp, vfs_context_thread(ctx));
	if (error) {
		nofp = NULL;
		goto out;
	}

	/*
	 * If we just created the file and the modes match, then we simply use
	 * the open performed in the create.  Otherwise, send the request.
	 */
	if ((nofp->nof_flags & NFS_OPEN_FILE_CREATE) &&
	    (nofp->nof_creator == current_thread()) &&
	    (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH) &&
	    (denyMode == NFS_OPEN_SHARE_DENY_NONE)) {
		nofp->nof_flags &= ~NFS_OPEN_FILE_CREATE;
		nofp->nof_creator = NULL;
	} else {
		if (!opened)
			error = nfs4_open(np, nofp, accessMode, denyMode, ctx);
		if ((error == EACCES) && (nofp->nof_flags & NFS_OPEN_FILE_CREATE) &&
		    (nofp->nof_creator == current_thread())) {
			/*
			 * Ugh.  This can happen if we just created the file with read-only
			 * perms and we're trying to open it for real with different modes
			 * (e.g. write-only or with a deny mode) and the server decides to
			 * not allow the second open because of the read-only perms.
			 * The best we can do is to just use the create's open.
			 * We may have access we don't need or we may not have a requested
			 * deny mode.  We may log complaints later, but we'll try to avoid it.
			 */
			if (denyMode != NFS_OPEN_SHARE_DENY_NONE) {
				const char *vname = vnode_getname(NFSTOV(np));
				printf("nfs4_vnop_open: deny mode foregone on create, %s\n", vname);
				vnode_putname(vname);
			}
			nofp->nof_creator = NULL;
			error = 0;
		}
		if (error)
			goto out;
		opened = 1;
		/*
		 * If we had just created the file, we already had it open.
		 * If the actual open mode is less than what we grabbed at
		 * create time, then we'll downgrade the open here.
		 */
		if ((nofp->nof_flags & NFS_OPEN_FILE_CREATE) &&
		    (nofp->nof_creator == current_thread())) {
			error = nfs4_close(np, nofp, NFS_OPEN_SHARE_ACCESS_BOTH, NFS_OPEN_SHARE_DENY_NONE, ctx);
			if (error) {
				const char *vname = vnode_getname(NFSTOV(np));
				printf("nfs_vnop_open: create close error %d, %s\n", error, vname);
				vnode_putname(vname);
			}
			if (!nfs_mount_state_error_should_restart(error)) {
				error = 0;
				nofp->nof_flags &= ~NFS_OPEN_FILE_CREATE;
			}
		}
	}

out:
	if (nofp)
		nfs_open_file_clear_busy(nofp);
	if (nfs_mount_state_in_use_end(nmp, error)) {
		nofp = NULL;
		goto restart;
	}
	if (noop)
		nfs_open_owner_rele(noop);
	if (error) {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs_vnop_open: error %d, %s\n", error, vname);
		vnode_putname(vname);
	}
	return (error);
}

int
nfs4_close(
	nfsnode_t np,
	struct nfs_open_file *nofp,
	uint32_t accessMode,
	uint32_t denyMode,
	vfs_context_t ctx)
{
	struct nfs_lock_owner *nlop;
	int error = 0, changed = 0, closed = 0;
	uint32_t newAccessMode, newDenyMode;

	/* warn if modes don't match current state */
	if (((accessMode & nofp->nof_access) != accessMode) || ((denyMode & nofp->nof_deny) != denyMode)) {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs4_close: mode mismatch %d %d, current %d %d, %s\n",
			accessMode, denyMode, nofp->nof_access, nofp->nof_deny, vname);
		vnode_putname(vname);
	}

	/*
	 * If we're closing a write-only open, we may not have a write-only count
	 * if we also grabbed read access.  So, check the read-write count.
	 */
	if (denyMode == NFS_OPEN_SHARE_DENY_NONE) {
		if ((accessMode == NFS_OPEN_SHARE_ACCESS_WRITE) &&
		    (nofp->nof_w == 0) && nofp->nof_rw)
			accessMode = NFS_OPEN_SHARE_ACCESS_BOTH;
	} else if (denyMode == NFS_OPEN_SHARE_DENY_WRITE) {
		if ((accessMode == NFS_OPEN_SHARE_ACCESS_WRITE) &&
		    (nofp->nof_w_dw == 0) && nofp->nof_rw_dw)
			accessMode = NFS_OPEN_SHARE_ACCESS_BOTH;
	} else { /* NFS_OPEN_SHARE_DENY_BOTH */
		if ((accessMode == NFS_OPEN_SHARE_ACCESS_WRITE) &&
		    (nofp->nof_w_drw == 0) && nofp->nof_rw_drw)
			accessMode = NFS_OPEN_SHARE_ACCESS_BOTH;
	}

	/*
	 * Calculate new modes: a mode bit gets removed when there's only
	 * one count in all the corresponding counts
	 */
	newAccessMode = nofp->nof_access;
	newDenyMode = nofp->nof_deny;
	if ((accessMode & NFS_OPEN_SHARE_ACCESS_READ) &&
	    (newAccessMode & NFS_OPEN_SHARE_ACCESS_READ) &&
	    ((nofp->nof_r + nofp->nof_rw + nofp->nof_r_dw +
	      nofp->nof_rw_dw + nofp->nof_r_drw + nofp->nof_rw_dw) == 1)) {
		newAccessMode &= ~NFS_OPEN_SHARE_ACCESS_READ;
		changed = 1;
	}
	if ((accessMode & NFS_OPEN_SHARE_ACCESS_WRITE) &&
	    (newAccessMode & NFS_OPEN_SHARE_ACCESS_WRITE) &&
	    ((nofp->nof_w + nofp->nof_rw + nofp->nof_w_dw +
	      nofp->nof_rw_dw + nofp->nof_w_drw + nofp->nof_rw_dw) == 1)) {
		newAccessMode &= ~NFS_OPEN_SHARE_ACCESS_WRITE;
		changed = 1;
	}
	if ((denyMode & NFS_OPEN_SHARE_DENY_READ) &&
	    (newDenyMode & NFS_OPEN_SHARE_DENY_READ) &&
	    ((nofp->nof_r_drw + nofp->nof_w_drw + nofp->nof_rw_drw) == 1)) {
		newDenyMode &= ~NFS_OPEN_SHARE_DENY_READ;
		changed = 1;
	}
	if ((denyMode & NFS_OPEN_SHARE_DENY_WRITE) &&
	    (newDenyMode & NFS_OPEN_SHARE_DENY_WRITE) &&
	    ((nofp->nof_r_drw + nofp->nof_w_drw + nofp->nof_rw_drw +
	      nofp->nof_r_dw + nofp->nof_w_dw + nofp->nof_rw_dw) == 1)) {
		newDenyMode &= ~NFS_OPEN_SHARE_DENY_WRITE;
		changed = 1;
	}


	if ((newAccessMode == 0) || (nofp->nof_opencnt == 1)) {
		/*
		 * No more access after this close, so clean up and close it.
		 */
		closed = 1;
		if (!(nofp->nof_flags & NFS_OPEN_FILE_LOST))
			error = nfs4_close_rpc(np, nofp, vfs_context_thread(ctx), vfs_context_ucred(ctx), 0);
		if (error == NFSERR_LOCKS_HELD) {
			/*
			 * Hmm... the server says we have locks we need to release first
			 * Find the lock owner and try to unlock everything.
			 */
			nlop = nfs_lock_owner_find(np, vfs_context_proc(ctx), 0);
			if (nlop) {
				nfs4_unlock_rpc(np, nlop, F_WRLCK, 0, UINT64_MAX, ctx);
				nfs_lock_owner_rele(nlop);
			}
			error = nfs4_close_rpc(np, nofp, vfs_context_thread(ctx), vfs_context_ucred(ctx), 0);
		}
	} else if (changed) {
		/*
		 * File is still open but with less access, so downgrade the open.
		 */
		if (!(nofp->nof_flags & NFS_OPEN_FILE_LOST))
			error = nfs4_open_downgrade_rpc(np, nofp, ctx);
	}

	if (error) {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs4_close: error %d, %s\n", error, vname);
		vnode_putname(vname);
		return (error);
	}

	/* Decrement the corresponding open access/deny mode counter. */
	if (denyMode == NFS_OPEN_SHARE_DENY_NONE) {
		if (accessMode == NFS_OPEN_SHARE_ACCESS_READ) {
			if (nofp->nof_r == 0)
				printf("nfs4_close: open(R) count underrun\n");
			else
				nofp->nof_r--;
		} else if (accessMode == NFS_OPEN_SHARE_ACCESS_WRITE) {
			if (nofp->nof_w == 0)
				printf("nfs4_close: open(W) count underrun\n");
			else
				nofp->nof_w--;
		} else if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH) {
			if (nofp->nof_rw == 0)
				printf("nfs4_close: open(RW) count underrun\n");
			else
				nofp->nof_rw--;
		}
	} else if (denyMode == NFS_OPEN_SHARE_DENY_WRITE) {
		if (accessMode == NFS_OPEN_SHARE_ACCESS_READ) {
			if (nofp->nof_r_dw == 0)
				printf("nfs4_close: open(R,DW) count underrun\n");
			else
				nofp->nof_r_dw--;
		} else if (accessMode == NFS_OPEN_SHARE_ACCESS_WRITE) {
			if (nofp->nof_w_dw == 0)
				printf("nfs4_close: open(W,DW) count underrun\n");
			else
				nofp->nof_w_dw--;
		} else if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH) {
			if (nofp->nof_rw_dw == 0)
				printf("nfs4_close: open(RW,DW) count underrun\n");
			else
				nofp->nof_rw_dw--;
		}
	} else { /* NFS_OPEN_SHARE_DENY_BOTH */
		if (accessMode == NFS_OPEN_SHARE_ACCESS_READ) {
			if (nofp->nof_r_drw == 0)
				printf("nfs4_close: open(R,DRW) count underrun\n");
			else
				nofp->nof_r_drw--;
		} else if (accessMode == NFS_OPEN_SHARE_ACCESS_WRITE) {
			if (nofp->nof_w_drw == 0)
				printf("nfs4_close: open(W,DRW) count underrun\n");
			else
				nofp->nof_w_drw--;
		} else if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH) {
			if (nofp->nof_rw_drw == 0)
				printf("nfs4_close: open(RW,DRW) count underrun\n");
			else
				nofp->nof_rw_drw--;
		}
	}
	/* update the modes */
	nofp->nof_access = newAccessMode;
	nofp->nof_deny = newDenyMode;
	if (closed) {
		if (nofp->nof_r || nofp->nof_w ||
		    (nofp->nof_rw && !((nofp->nof_flags & NFS_OPEN_FILE_CREATE) && !nofp->nof_creator && (nofp->nof_rw == 1))) ||
		    nofp->nof_r_dw || nofp->nof_w_dw || nofp->nof_rw_dw ||
		    nofp->nof_r_drw || nofp->nof_w_drw || nofp->nof_rw_drw)
			printf("nfs4_close: unexpected count: %u %u %u dw %u %u %u drw %u %u %u flags 0x%x\n",
				nofp->nof_r, nofp->nof_w, nofp->nof_rw,
				nofp->nof_r_dw, nofp->nof_w_dw, nofp->nof_rw_dw,
				nofp->nof_r_drw, nofp->nof_w_drw, nofp->nof_rw_drw,
				nofp->nof_flags);
		/* clear out all open info, just to be safe */
		nofp->nof_access = nofp->nof_deny = 0;
		nofp->nof_mmap_access = nofp->nof_mmap_deny = 0;
		nofp->nof_r = nofp->nof_w = nofp->nof_rw = 0;
		nofp->nof_r_dw = nofp->nof_w_dw = nofp->nof_rw_dw = 0;
		nofp->nof_r_drw = nofp->nof_w_drw = nofp->nof_rw_drw = 0;
		nofp->nof_flags &= ~NFS_OPEN_FILE_CREATE;
		/* XXX we may potentially want to clean up idle/unused open file structures */
	}
	nofp->nof_opencnt--;
	if (nofp->nof_flags & NFS_OPEN_FILE_LOST) {
		error = EIO;
		if (!nofp->nof_opencnt)
			nofp->nof_flags &= ~NFS_OPEN_FILE_LOST;
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs_close: LOST%s, %s\n", !(nofp->nof_flags & NFS_OPEN_FILE_LOST) ? " (last)" : "", vname);
		vnode_putname(vname);
	}
	return (error);
}

int
nfs4_vnop_close(
	struct vnop_close_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflag;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	int fflag = ap->a_fflag;
	int error, common_error, accessMode, denyMode;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	struct nfs_open_owner *noop = NULL;
	struct nfs_open_file *nofp = NULL;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);

	/* First, call the common code */
	common_error = nfs3_vnop_close(ap);

	if (!vnode_isreg(vp)) {
		/* Just mark that it was closed */
		lck_mtx_lock(&np->n_openlock);
		np->n_openrefcnt--;
		lck_mtx_unlock(&np->n_openlock);
		return (common_error);
	}

	noop = nfs_open_owner_find(nmp, vfs_context_ucred(ctx), 0);
	if (!noop) {
		printf("nfs4_vnop_close: can't get open owner!\n");
		return (EIO);
	}

restart:
	error = nfs_mount_state_in_use_start(nmp);
	if (error) {
		nfs_open_owner_rele(noop);
		return (error);
	}

	error = nfs_open_file_find(np, noop, &nofp, 0, 0, 0);
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_REOPEN)) {
		nfs_mount_state_in_use_end(nmp, 0);
		nfs4_reopen(nofp, vfs_context_thread(ctx));
		nofp = NULL;
		goto restart;
	}
	if (error) {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs4_vnop_close: no open file for owner %d, %s\n", error, vname);
		vnode_putname(vname);
		error = EBADF;
		goto out;
	}
	error = nfs_open_file_set_busy(nofp, vfs_context_thread(ctx));
	if (error) {
		nofp = NULL;
		goto out;
	}

	/* fflag contains some combination of: FREAD, FWRITE, FHASLOCK */
	accessMode = 0;
	if (fflag & FREAD)
		accessMode |= NFS_OPEN_SHARE_ACCESS_READ;
	if (fflag & FWRITE)
		accessMode |= NFS_OPEN_SHARE_ACCESS_WRITE;
// XXX It would be nice if we still had the O_EXLOCK/O_SHLOCK flags that were on the open
//	if (fflag & O_EXLOCK)
//		denyMode = NFS_OPEN_SHARE_DENY_BOTH;
//	else if (fflag & O_SHLOCK)
//		denyMode = NFS_OPEN_SHARE_DENY_WRITE;
//	else
//		denyMode = NFS_OPEN_SHARE_DENY_NONE;
	if (fflag & FHASLOCK) {
		/* XXX assume FHASLOCK is for the deny mode and not flock */
		/* FHASLOCK flock will be unlocked in the close path, but the flag is not cleared. */
		if (nofp->nof_deny & NFS_OPEN_SHARE_DENY_READ)
			denyMode = NFS_OPEN_SHARE_DENY_BOTH;
		else if (nofp->nof_deny & NFS_OPEN_SHARE_DENY_WRITE)
			denyMode = NFS_OPEN_SHARE_DENY_WRITE;
		else
			denyMode = NFS_OPEN_SHARE_DENY_NONE;
	} else {
			denyMode = NFS_OPEN_SHARE_DENY_NONE;
	}

	if (!accessMode) {
		error = EINVAL;
		goto out;
	}

	error = nfs4_close(np, nofp, accessMode, denyMode, ctx);
	if (error) {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs_vnop_close: close error %d, %s\n", error, vname);
		vnode_putname(vname);
	}

out:
	if (nofp)
		nfs_open_file_clear_busy(nofp);
	if (nfs_mount_state_in_use_end(nmp, error)) {
		nofp = NULL;
		goto restart;
	}
	if (noop)
		nfs_open_owner_rele(noop);
	if (error) {
		const char *vname = vnode_getname(NFSTOV(np));
		printf("nfs_vnop_close: error %d, %s\n", error, vname);
		vnode_putname(vname);
	}
	if (!error)
		error = common_error;
	return (error);
}

int
nfs4_vnop_mmap(
	struct vnop_mmap_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		int a_fflags;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	int error = 0, accessMode, denyMode;
	struct nfsmount *nmp;
	struct nfs_open_owner *noop = NULL;
	struct nfs_open_file *nofp = NULL;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);

	if (!vnode_isreg(vp) || !(ap->a_fflags & (PROT_READ|PROT_WRITE)))
		return (EINVAL);

	/*
	 * fflags contains some combination of: PROT_READ, PROT_WRITE
	 * Since it's not possible to mmap() without having the file open for reading,
	 * read access is always there (regardless if PROT_READ is not set).
	 */
	accessMode = NFS_OPEN_SHARE_ACCESS_READ;
	if (ap->a_fflags & PROT_WRITE)
		accessMode |= NFS_OPEN_SHARE_ACCESS_WRITE;
	denyMode = NFS_OPEN_SHARE_DENY_NONE;

	noop = nfs_open_owner_find(nmp, vfs_context_ucred(ctx), 0);
	if (!noop) {
		printf("nfs4_vnop_mmap: no open owner\n");
		return (EPERM);
	}

restart:
	error = nfs_mount_state_in_use_start(nmp);
	if (error) {
		nfs_open_owner_rele(noop);
		return (error);
	}

	error = nfs_open_file_find(np, noop, &nofp, 0, 0, 1);
	if (error || (!error && (nofp->nof_flags & NFS_OPEN_FILE_LOST))) {
		printf("nfs4_vnop_mmap: no open file for owner %d\n", error);
		error = EPERM;
	}
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_REOPEN)) {
		nfs_mount_state_in_use_end(nmp, 0);
		nfs4_reopen(nofp, vfs_context_thread(ctx));
		nofp = NULL;
		goto restart;
	}
	if (!error)
		error = nfs_open_file_set_busy(nofp, vfs_context_thread(ctx));
	if (error) {
		nofp = NULL;
		goto out;
	}

	/*
	 * The open reference for mmap must mirror an existing open because
	 * we may need to reclaim it after the file is closed.
	 * So grab another open count matching the accessMode passed in.
	 * If we already had an mmap open, prefer read/write without deny mode.
	 * This means we may have to drop the current mmap open first.
	 */

	/* determine deny mode for open */
	if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH) {
		if (nofp->nof_rw)
			denyMode = NFS_OPEN_SHARE_DENY_NONE;
		else if (nofp->nof_rw_dw)
			denyMode = NFS_OPEN_SHARE_DENY_WRITE;
		else if (nofp->nof_rw_drw)
			denyMode = NFS_OPEN_SHARE_DENY_BOTH;
		else
			error = EPERM;
	} else { /* NFS_OPEN_SHARE_ACCESS_READ */
		if (nofp->nof_r)
			denyMode = NFS_OPEN_SHARE_DENY_NONE;
		else if (nofp->nof_r_dw)
			denyMode = NFS_OPEN_SHARE_DENY_WRITE;
		else if (nofp->nof_r_drw)
			denyMode = NFS_OPEN_SHARE_DENY_BOTH;
		else
			error = EPERM;
	}
	if (error) /* mmap mode without proper open mode */
		goto out;

	/*
	 * If the existing mmap access is more than the new access OR the
	 * existing access is the same and the existing deny mode is less,
	 * then we'll stick with the existing mmap open mode.
	 */
	if ((nofp->nof_mmap_access > accessMode) ||
	    ((nofp->nof_mmap_access == accessMode) && (nofp->nof_mmap_deny <= denyMode)))
		goto out;

	/* update mmap open mode */
	if (nofp->nof_mmap_access) {
		error = nfs4_close(np, nofp, nofp->nof_mmap_access, nofp->nof_mmap_deny, ctx);
		if (error) {
			if (!nfs_mount_state_error_should_restart(error))
				printf("nfs_vnop_mmap: close of previous mmap mode failed: %d\n", error);
			const char *vname = vnode_getname(NFSTOV(np));
			printf("nfs_vnop_mmap: update, close error %d, %s\n", error, vname);
			vnode_putname(vname);
			goto out;
		}
		nofp->nof_mmap_access = nofp->nof_mmap_deny = 0;
	}

	if (accessMode == NFS_OPEN_SHARE_ACCESS_BOTH) {
		if (denyMode == NFS_OPEN_SHARE_DENY_NONE)
			nofp->nof_rw++;
		else if (denyMode == NFS_OPEN_SHARE_DENY_WRITE)
			nofp->nof_rw_dw++;
		else /* NFS_OPEN_SHARE_DENY_BOTH */
			nofp->nof_rw_drw++;
	} else if (accessMode == NFS_OPEN_SHARE_ACCESS_READ) {
		if (denyMode == NFS_OPEN_SHARE_DENY_NONE)
			nofp->nof_r++;
		else if (denyMode == NFS_OPEN_SHARE_DENY_WRITE)
			nofp->nof_r_dw++;
		else /* NFS_OPEN_SHARE_DENY_BOTH */
			nofp->nof_r_drw++;
	}
	nofp->nof_mmap_access = accessMode;
	nofp->nof_mmap_deny = denyMode;
	nofp->nof_opencnt++;

out:
	if (nofp)
		nfs_open_file_clear_busy(nofp);
	if (nfs_mount_state_in_use_end(nmp, error)) {
		nofp = NULL;
		goto restart;
	}
	if (noop)
		nfs_open_owner_rele(noop);
	return (error);
}


int
nfs4_vnop_mnomap(
	struct vnop_mnomap_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		vfs_context_t a_context;
	} */ *ap)
{
	vfs_context_t ctx = ap->a_context;
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(vp);
	struct nfsmount *nmp;
	struct nfs_open_file *nofp = NULL;
	int error;

	nmp = VTONMP(vp);
	if (!nmp)
		return (ENXIO);

	/* walk all open files and close all mmap opens */
loop:
	error = nfs_mount_state_in_use_start(nmp);
	if (error)
		return (error);
	lck_mtx_lock(&np->n_openlock);
	TAILQ_FOREACH(nofp, &np->n_opens, nof_link) {
		if (!nofp->nof_mmap_access)
			continue;
		lck_mtx_unlock(&np->n_openlock);
		if (nofp->nof_flags & NFS_OPEN_FILE_REOPEN) {
			nfs_mount_state_in_use_end(nmp, 0);
			nfs4_reopen(nofp, vfs_context_thread(ctx));
			goto loop;
		}
		error = nfs_open_file_set_busy(nofp, vfs_context_thread(ctx));
		if (error) {
			lck_mtx_lock(&np->n_openlock);
			break;
		}
		if (nofp->nof_mmap_access) {
			error = nfs4_close(np, nofp, nofp->nof_mmap_access, nofp->nof_mmap_deny, ctx);
			if (!nfs_mount_state_error_should_restart(error)) {
				if (error) /* not a state-operation-restarting error, so just clear the access */
					printf("nfs_vnop_mnomap: close of mmap mode failed: %d\n", error);
				nofp->nof_mmap_access = nofp->nof_mmap_deny = 0;
			}
			if (error) {
				const char *vname = vnode_getname(NFSTOV(np));
				printf("nfs_vnop_mnomap: error %d, %s\n", error, vname);
				vnode_putname(vname);
			}
		}
		nfs_open_file_clear_busy(nofp);
		nfs_mount_state_in_use_end(nmp, error);
		goto loop;
	}
	lck_mtx_unlock(&np->n_openlock);
	nfs_mount_state_in_use_end(nmp, error);
	return (error);
}

/*
 * Search a node's lock owner list for the owner for this process.
 * If not found and "alloc" is set, then allocate a new one.
 */
struct nfs_lock_owner *
nfs_lock_owner_find(nfsnode_t np, proc_t p, int alloc)
{
	pid_t pid = proc_pid(p);
	struct nfs_lock_owner *nlop, *newnlop = NULL;

tryagain:
	lck_mtx_lock(&np->n_openlock);
	TAILQ_FOREACH(nlop, &np->n_lock_owners, nlo_link) {
		if (nlop->nlo_pid != pid)
			continue;
		if (timevalcmp(&nlop->nlo_pid_start, &p->p_start, ==))
			break;
		/* stale lock owner... reuse it if we can */
		if (nlop->nlo_refcnt) {
			TAILQ_REMOVE(&np->n_lock_owners, nlop, nlo_link);
			nlop->nlo_flags &= ~NFS_LOCK_OWNER_LINK;
			lck_mtx_unlock(&np->n_openlock);
			goto tryagain;
		}
		nlop->nlo_pid_start = p->p_start;
		nlop->nlo_seqid = 0;
		nlop->nlo_stategenid = 0;
		break;
	}

	if (!nlop && !newnlop && alloc) {
		lck_mtx_unlock(&np->n_openlock);
		MALLOC(newnlop, struct nfs_lock_owner *, sizeof(struct nfs_lock_owner), M_TEMP, M_WAITOK);
		if (!newnlop)
			return (NULL);
		bzero(newnlop, sizeof(*newnlop));
		lck_mtx_init(&newnlop->nlo_lock, nfs_open_grp, LCK_ATTR_NULL);
		newnlop->nlo_pid = pid;
		newnlop->nlo_pid_start = p->p_start;
		newnlop->nlo_name = OSAddAtomic(1, &nfs_lock_owner_seqnum);
		TAILQ_INIT(&newnlop->nlo_locks);
		goto tryagain;
	}
	if (!nlop && newnlop) {
		newnlop->nlo_flags |= NFS_LOCK_OWNER_LINK;
		TAILQ_INSERT_HEAD(&np->n_lock_owners, newnlop, nlo_link);
		nlop = newnlop;
	}
	lck_mtx_unlock(&np->n_openlock);

	if (newnlop && (nlop != newnlop))
		nfs_lock_owner_destroy(newnlop);

	if (nlop)
		nfs_lock_owner_ref(nlop);

	return (nlop);
}

/*
 * destroy a lock owner that's no longer needed
 */
void
nfs_lock_owner_destroy(struct nfs_lock_owner *nlop)
{
	if (nlop->nlo_open_owner) {
		nfs_open_owner_rele(nlop->nlo_open_owner);
		nlop->nlo_open_owner = NULL;
	}
	lck_mtx_destroy(&nlop->nlo_lock, nfs_open_grp);
	FREE(nlop, M_TEMP);
}

/*
 * acquire a reference count on a lock owner
 */
void
nfs_lock_owner_ref(struct nfs_lock_owner *nlop)
{
	lck_mtx_lock(&nlop->nlo_lock);
	nlop->nlo_refcnt++;
	lck_mtx_unlock(&nlop->nlo_lock);
}

/*
 * drop a reference count on a lock owner and destroy it if
 * it is no longer referenced and no longer on the mount's list.
 */
void
nfs_lock_owner_rele(struct nfs_lock_owner *nlop)
{
	lck_mtx_lock(&nlop->nlo_lock);
	if (nlop->nlo_refcnt < 1)
		panic("nfs_lock_owner_rele: no refcnt");
	nlop->nlo_refcnt--;
	if (!nlop->nlo_refcnt && (nlop->nlo_flags & NFS_LOCK_OWNER_BUSY))
		panic("nfs_lock_owner_rele: busy");
	/* XXX we may potentially want to clean up idle/unused lock owner structures */
	if (nlop->nlo_refcnt || (nlop->nlo_flags & NFS_LOCK_OWNER_LINK)) {
		lck_mtx_unlock(&nlop->nlo_lock);
		return;
	}
	/* owner is no longer referenced or linked to mount, so destroy it */
	lck_mtx_unlock(&nlop->nlo_lock);
	nfs_lock_owner_destroy(nlop);
}

/*
 * Mark a lock owner as busy because we are about to
 * start an operation that uses and updates lock owner state.
 */
int
nfs_lock_owner_set_busy(struct nfs_lock_owner *nlop, thread_t thd)
{
	struct nfsmount *nmp;
	struct timespec ts = {2, 0};
	int error = 0, slpflag;

	nmp = nlop->nlo_open_owner->noo_mount;
	if (!nmp)
		return (ENXIO);
	slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

	lck_mtx_lock(&nlop->nlo_lock);
	while (nlop->nlo_flags & NFS_LOCK_OWNER_BUSY) {
		if ((error = nfs_sigintr(nmp, NULL, thd, 0)))
			break;
		nlop->nlo_flags |= NFS_LOCK_OWNER_WANT;
		msleep(nlop, &nlop->nlo_lock, slpflag, "nfs_lock_owner_set_busy", &ts);
	}
	if (!error)
		nlop->nlo_flags |= NFS_LOCK_OWNER_BUSY;
	lck_mtx_unlock(&nlop->nlo_lock);

	return (error);
}

/*
 * Clear the busy flag on a lock owner and wake up anyone waiting
 * to mark it busy.
 */
void
nfs_lock_owner_clear_busy(struct nfs_lock_owner *nlop)
{
	int wanted;

	lck_mtx_lock(&nlop->nlo_lock);
	if (!(nlop->nlo_flags & NFS_LOCK_OWNER_BUSY))
		panic("nfs_lock_owner_clear_busy");
	wanted = (nlop->nlo_flags & NFS_LOCK_OWNER_WANT);
	nlop->nlo_flags &= ~(NFS_LOCK_OWNER_BUSY|NFS_LOCK_OWNER_WANT);
	lck_mtx_unlock(&nlop->nlo_lock);
	if (wanted)
		wakeup(nlop);
}

/*
 * Insert a held lock into a lock owner's sorted list.
 * (flock locks are always inserted at the head the list)
 */
void
nfs_lock_owner_insert_held_lock(struct nfs_lock_owner *nlop, struct nfs_file_lock *newnflp)
{
	struct nfs_file_lock *nflp;

	/* insert new lock in lock owner's held lock list */
	lck_mtx_lock(&nlop->nlo_lock);
	if ((newnflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == NFS_FILE_LOCK_STYLE_FLOCK) {
		TAILQ_INSERT_HEAD(&nlop->nlo_locks, newnflp, nfl_lolink);
	} else {
		TAILQ_FOREACH(nflp, &nlop->nlo_locks, nfl_lolink) {
			if (newnflp->nfl_start < nflp->nfl_start)
				break;
		}
		if (nflp)
			TAILQ_INSERT_BEFORE(nflp, newnflp, nfl_lolink);
		else
			TAILQ_INSERT_TAIL(&nlop->nlo_locks, newnflp, nfl_lolink);
	}
	lck_mtx_unlock(&nlop->nlo_lock);
}

/*
 * Get a file lock structure for this lock owner.
 */
struct nfs_file_lock *
nfs_file_lock_alloc(struct nfs_lock_owner *nlop)
{
	struct nfs_file_lock *nflp = NULL;

	lck_mtx_lock(&nlop->nlo_lock);
	if (!nlop->nlo_alock.nfl_owner) {
		nflp = &nlop->nlo_alock;
		nflp->nfl_owner = nlop;
	}
	lck_mtx_unlock(&nlop->nlo_lock);
	if (!nflp) {
		MALLOC(nflp, struct nfs_file_lock *, sizeof(struct nfs_file_lock), M_TEMP, M_WAITOK);
		if (!nflp)
			return (NULL);
		bzero(nflp, sizeof(*nflp));
		nflp->nfl_flags |= NFS_FILE_LOCK_ALLOC;
		nflp->nfl_owner = nlop;
	}
	nfs_lock_owner_ref(nlop);
	return (nflp);
}

/*
 * destroy the given NFS file lock structure
 */
void
nfs_file_lock_destroy(struct nfs_file_lock *nflp)
{
	struct nfs_lock_owner *nlop = nflp->nfl_owner;

	if (nflp->nfl_flags & NFS_FILE_LOCK_ALLOC) {
		nflp->nfl_owner = NULL;
		FREE(nflp, M_TEMP);
	} else {
		lck_mtx_lock(&nlop->nlo_lock);
		bzero(nflp, sizeof(nflp));
		lck_mtx_unlock(&nlop->nlo_lock);
	}
	nfs_lock_owner_rele(nlop);
}

/*
 * Check if one file lock conflicts with another.
 * (nflp1 is the new lock.  nflp2 is the existing lock.)
 */
int
nfs_file_lock_conflict(struct nfs_file_lock *nflp1, struct nfs_file_lock *nflp2, int *willsplit)
{
	/* no conflict if lock is dead */
	if ((nflp1->nfl_flags & NFS_FILE_LOCK_DEAD) || (nflp2->nfl_flags & NFS_FILE_LOCK_DEAD))
		return (0);
	/* no conflict if it's ours - unless the lock style doesn't match */
	if ((nflp1->nfl_owner == nflp2->nfl_owner) &&
	    ((nflp1->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == (nflp2->nfl_flags & NFS_FILE_LOCK_STYLE_MASK))) {
		if (willsplit && (nflp1->nfl_type != nflp2->nfl_type) &&
		    (nflp1->nfl_start > nflp2->nfl_start) &&
		    (nflp1->nfl_end < nflp2->nfl_end))
			*willsplit = 1;
		return (0);
	}
	/* no conflict if ranges don't overlap */
	if ((nflp1->nfl_start > nflp2->nfl_end) || (nflp1->nfl_end < nflp2->nfl_start))
		return (0);
	/* no conflict if neither lock is exclusive */
	if ((nflp1->nfl_type != F_WRLCK) && (nflp2->nfl_type != F_WRLCK))
		return (0);
	/* conflict */
	return (1);
}

/*
 * Send an NFSv4 LOCK RPC to the server.
 */
int
nfs4_lock_rpc(
	nfsnode_t np,
	struct nfs_open_file *nofp,
	struct nfs_file_lock *nflp,
	int reclaim,
	thread_t thd,
	kauth_cred_t cred)
{
	struct nfs_lock_owner *nlop = nflp->nfl_owner;
	struct nfsmount *nmp;
	struct nfsm_chain nmreq, nmrep;
	uint64_t xid;
	uint32_t locktype;
	int error = 0, lockerror = ENOENT, newlocker, numops, status;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);

	newlocker = (nlop->nlo_stategenid != nmp->nm_stategenid);
	locktype = (nflp->nfl_flags & NFS_FILE_LOCK_WAIT) ?
			((nflp->nfl_type == F_WRLCK) ?
				NFS_LOCK_TYPE_WRITEW :
				NFS_LOCK_TYPE_READW) :
			((nflp->nfl_type == F_WRLCK) ?
				NFS_LOCK_TYPE_WRITE :
				NFS_LOCK_TYPE_READ);
	if (newlocker) {
		error = nfs_open_file_set_busy(nofp, thd);
		if (error)
			return (error);
		error = nfs_open_owner_set_busy(nofp->nof_owner, thd);
		if (error) {
			nfs_open_file_clear_busy(nofp);
			return (error);
		}
		if (!nlop->nlo_open_owner) {
			nfs_open_owner_ref(nofp->nof_owner);
			nlop->nlo_open_owner = nofp->nof_owner;
		}
	}
	error = nfs_lock_owner_set_busy(nlop, thd);
	if (error) {
		if (newlocker) {
			nfs_open_owner_clear_busy(nofp->nof_owner);
			nfs_open_file_clear_busy(nofp);
		}
		return (error);
	}

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, GETATTR, LOCK
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 33 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "lock", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, NFS_VER4, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_LOCK);
	nfsm_chain_add_32(error, &nmreq, locktype);
	nfsm_chain_add_32(error, &nmreq, reclaim);
	nfsm_chain_add_64(error, &nmreq, nflp->nfl_start);
	nfsm_chain_add_64(error, &nmreq, NFS_LOCK_LENGTH(nflp->nfl_start, nflp->nfl_end));
	nfsm_chain_add_32(error, &nmreq, newlocker);
	if (newlocker) {
		nfsm_chain_add_32(error, &nmreq, nofp->nof_owner->noo_seqid);
		nfsm_chain_add_stateid(error, &nmreq, &nofp->nof_stateid);
		nfsm_chain_add_32(error, &nmreq, nlop->nlo_seqid);
		nfsm_chain_add_lock_owner4(error, &nmreq, nmp, nlop);
	} else {
		nfsm_chain_add_stateid(error, &nmreq, &nlop->nlo_stateid);
		nfsm_chain_add_32(error, &nmreq, nlop->nlo_seqid);
	}
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);

	error = nfs_request2(np, NULL, &nmreq, NFSPROC4_COMPOUND, thd, cred, (reclaim ? R_RECOVER : 0), &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, NFS_VER4, NULL, &xid);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_LOCK);
	nfs_owner_seqid_increment(newlocker ? nofp->nof_owner : NULL, nlop, error);
	nfsm_chain_get_stateid(error, &nmrep, &nlop->nlo_stateid);

	/* Update the lock owner's stategenid once it appears the server has state for it. */
	/* We determine this by noting the request was successful (we got a stateid). */
	if (newlocker && !error)
		nlop->nlo_stategenid = nmp->nm_stategenid;
nfsmout:
	if (!lockerror)
		nfs_node_unlock(np);
	nfs_lock_owner_clear_busy(nlop);
	if (newlocker) {
		nfs_open_owner_clear_busy(nofp->nof_owner);
		nfs_open_file_clear_busy(nofp);
	}
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * Send an NFSv4 LOCKU RPC to the server.
 */
int
nfs4_unlock_rpc(
	nfsnode_t np,
	struct nfs_lock_owner *nlop,
	int type,
	uint64_t start,
	uint64_t end,
	vfs_context_t ctx)
{
	struct nfsmount *nmp;
	struct nfsm_chain nmreq, nmrep;
	uint64_t xid;
	int error = 0, lockerror = ENOENT, numops, status;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);

	error = nfs_lock_owner_set_busy(nlop, vfs_context_thread(ctx));
	if (error)
		return (error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, GETATTR, LOCKU
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 26 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "unlock", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, NFS_VER4, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_LOCKU);
	nfsm_chain_add_32(error, &nmreq, (type == F_WRLCK) ? NFS_LOCK_TYPE_WRITE : NFS_LOCK_TYPE_READ);
	nfsm_chain_add_32(error, &nmreq, nlop->nlo_seqid);
	nfsm_chain_add_stateid(error, &nmreq, &nlop->nlo_stateid);
	nfsm_chain_add_64(error, &nmreq, start);
	nfsm_chain_add_64(error, &nmreq, NFS_LOCK_LENGTH(start, end));
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);

	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, NFS_VER4, NULL, &xid);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_LOCKU);
	nfs_owner_seqid_increment(NULL, nlop, error);
	nfsm_chain_get_stateid(error, &nmrep, &nlop->nlo_stateid);
nfsmout:
	if (!lockerror)
		nfs_node_unlock(np);
	nfs_lock_owner_clear_busy(nlop);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * Check for any conflicts with the given lock.
 *
 * Checking for a lock doesn't require the file to be opened.
 * So we skip all the open owner, open file, lock owner work
 * and just check for a conflicting lock.
 */
int
nfs4_getlock(
	nfsnode_t np,
	struct nfs_lock_owner *nlop,
	struct flock *fl,
	uint64_t start,
	uint64_t end,
	vfs_context_t ctx)
{
	struct nfsmount *nmp;
	struct nfs_file_lock *nflp;
	struct nfsm_chain nmreq, nmrep;
	uint64_t xid, val64 = 0;
	uint32_t val = 0;
	int error = 0, lockerror = ENOENT, numops, status;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);

	lck_mtx_lock(&np->n_openlock);
	/* scan currently held locks for conflict */
	TAILQ_FOREACH(nflp, &np->n_locks, nfl_link) {
		if (nflp->nfl_flags & NFS_FILE_LOCK_BLOCKED)
			continue;
		if ((start <= nflp->nfl_end) && (end >= nflp->nfl_start) &&
		    ((fl->l_type == F_WRLCK) || (nflp->nfl_type == F_WRLCK)))
			break;
	}
	if (nflp) {
		/* found a conflicting lock */
		fl->l_type = nflp->nfl_type;
		fl->l_pid = (nflp->nfl_flags & NFS_FILE_LOCK_STYLE_FLOCK) ? -1 : nflp->nfl_owner->nlo_pid;
		fl->l_start = nflp->nfl_start;
		fl->l_len = NFS_FLOCK_LENGTH(nflp->nfl_start, nflp->nfl_end);
		fl->l_whence = SEEK_SET;
	}
	lck_mtx_unlock(&np->n_openlock);
	if (nflp)
		return (0);

	/* no conflict found locally, so ask the server */

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, GETATTR, LOCKT
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 26 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "locktest", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, NFS_VER4, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_LOCKT);
	nfsm_chain_add_32(error, &nmreq, (fl->l_type == F_WRLCK) ? NFS_LOCK_TYPE_WRITE : NFS_LOCK_TYPE_READ);
	nfsm_chain_add_64(error, &nmreq, start);
	nfsm_chain_add_64(error, &nmreq, NFS_LOCK_LENGTH(start, end));
	nfsm_chain_add_lock_owner4(error, &nmreq, nmp, nlop);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);

	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, NFS_VER4, NULL, &xid);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_LOCKT);
	if (error == NFSERR_DENIED) {
		error = 0;
		nfsm_chain_get_64(error, &nmrep, fl->l_start);
		nfsm_chain_get_64(error, &nmrep, val64);
		fl->l_len = (val64 == UINT64_MAX) ? 0 : val64;
		nfsm_chain_get_32(error, &nmrep, val);
		fl->l_type = (val == NFS_LOCK_TYPE_WRITE) ? F_WRLCK : F_RDLCK;
		fl->l_pid = 0;
		fl->l_whence = SEEK_SET;
	} else if (!error) {
		fl->l_type = F_UNLCK;
	}
nfsmout:
	if (!lockerror)
		nfs_node_unlock(np);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

/*
 * Acquire a file lock for the given range.
 *
 * Add the lock (request) to the lock queue.
 * Scan the lock queue for any conflicting locks.
 * If a conflict is found, block or return an error.
 * Once end of queue is reached, send request to the server.
 * If the server grants the lock, scan the lock queue and
 * update any existing locks.  Then (optionally) scan the
 * queue again to coalesce any locks adjacent to the new one.
 */
int
nfs4_setlock(
	nfsnode_t np,
	struct nfs_open_file *nofp,
	struct nfs_lock_owner *nlop,
	int op,
	uint64_t start,
	uint64_t end,
	int style,
	short type,
	vfs_context_t ctx)
{
	struct nfsmount *nmp;
	struct nfs_file_lock *newnflp, *nflp, *nflp2 = NULL, *nextnflp, *flocknflp = NULL;
	struct nfs_file_lock *coalnflp;
	int error = 0, error2, willsplit = 0, delay, slpflag, busy = 0, inuse = 0, restart, inqueue = 0;
	struct timespec ts = {1, 0};

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;

	/* allocate a new lock */
	newnflp = nfs_file_lock_alloc(nlop);
	if (!newnflp)
		return (ENOLCK);
	newnflp->nfl_start = start;
	newnflp->nfl_end = end;
	newnflp->nfl_type = type;
	if (op == F_SETLKW)
		newnflp->nfl_flags |= NFS_FILE_LOCK_WAIT;
	newnflp->nfl_flags |= style;
	newnflp->nfl_flags |= NFS_FILE_LOCK_BLOCKED;

	if ((style == NFS_FILE_LOCK_STYLE_FLOCK) && (type == F_WRLCK)) {
		/*
		 * For exclusive flock-style locks, if we block waiting for the
		 * lock, we need to first release any currently held shared
		 * flock-style lock.  So, the first thing we do is check if we
		 * have a shared flock-style lock.
		 */
		nflp = TAILQ_FIRST(&nlop->nlo_locks);
		if (nflp && ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) != NFS_FILE_LOCK_STYLE_FLOCK))
			nflp = NULL;
		if (nflp && (nflp->nfl_type != F_RDLCK))
			nflp = NULL;
		flocknflp = nflp;
	}

restart:
	restart = 0;
	error = nfs_mount_state_in_use_start(nmp);
	if (error)
		goto error_out;
	inuse = 1;
	if (nofp->nof_flags & NFS_OPEN_FILE_REOPEN) {
		nfs_mount_state_in_use_end(nmp, 0);
		inuse = 0;
		nfs4_reopen(nofp, vfs_context_thread(ctx));
		goto restart;
	}

	lck_mtx_lock(&np->n_openlock);
	if (!inqueue) {
		/* insert new lock at beginning of list */
		TAILQ_INSERT_HEAD(&np->n_locks, newnflp, nfl_link);
		inqueue = 1;
	}

	/* scan current list of locks (held and pending) for conflicts */
	for (nflp = TAILQ_NEXT(newnflp, nfl_link); nflp; nflp = TAILQ_NEXT(nflp, nfl_link)) {
		if (!nfs_file_lock_conflict(newnflp, nflp, &willsplit))
			continue;
		/* Conflict */
		if (!(newnflp->nfl_flags & NFS_FILE_LOCK_WAIT)) {
			error = EAGAIN;
			break;
		}
		/* Block until this lock is no longer held. */
		if (nflp->nfl_blockcnt == UINT_MAX) {
			error = ENOLCK;
			break;
		}
		nflp->nfl_blockcnt++;
		do {
			if (flocknflp) {
				/* release any currently held shared lock before sleeping */
				lck_mtx_unlock(&np->n_openlock);
				nfs_mount_state_in_use_end(nmp, 0);
				inuse = 0;
				error = nfs4_unlock(np, nofp, nlop, 0, UINT64_MAX, NFS_FILE_LOCK_STYLE_FLOCK, ctx);
				flocknflp = NULL;
				if (!error)
					error = nfs_mount_state_in_use_start(nmp);
				if (error) {
					lck_mtx_lock(&np->n_openlock);
					break;
				}
				inuse = 1;
				lck_mtx_lock(&np->n_openlock);
				/* no need to block/sleep if the conflict is gone */
				if (!nfs_file_lock_conflict(newnflp, nflp, NULL))
					break;
			}
			msleep(nflp, &np->n_openlock, slpflag, "nfs4_setlock_blocked", &ts);
			error = nfs_sigintr(NFSTONMP(np), NULL, vfs_context_thread(ctx), 0);
			if (!error && (nmp->nm_state & NFSSTA_RECOVER)) {
				/* looks like we have a recover pending... restart */
				restart = 1;
				lck_mtx_unlock(&np->n_openlock);
				nfs_mount_state_in_use_end(nmp, 0);
				inuse = 0;
				lck_mtx_lock(&np->n_openlock);
				break;
			}
		} while (!error && nfs_file_lock_conflict(newnflp, nflp, NULL));
		nflp->nfl_blockcnt--;
		if ((nflp->nfl_flags & NFS_FILE_LOCK_DEAD) && !nflp->nfl_blockcnt) {
			TAILQ_REMOVE(&np->n_locks, nflp, nfl_link);
			nfs_file_lock_destroy(nflp);
		}
		if (error || restart)
			break;
	}
	lck_mtx_unlock(&np->n_openlock);
	if (restart)
		goto restart;
	if (error)
		goto error_out;

	if (willsplit) {
		/*
		 * It looks like this operation is splitting a lock.
		 * We allocate a new lock now so we don't have to worry
		 * about the allocation failing after we've updated some state.
		 */
		nflp2 = nfs_file_lock_alloc(nlop);
		if (!nflp2) {
			error = ENOLCK;
			goto error_out;
		}
	}

	/* once scan for local conflicts is clear, send request to server */
	if ((error = nfs_open_state_set_busy(np, ctx)))
		goto error_out;
	busy = 1;
	delay = 0;
	do {
		error = nfs4_lock_rpc(np, nofp, newnflp, 0, vfs_context_thread(ctx), vfs_context_ucred(ctx));
		if (!error || ((error != NFSERR_DENIED) && (error != NFSERR_GRACE)))
			break;
		/* request was denied due to either conflict or grace period */
		if ((error != NFSERR_GRACE) && !(newnflp->nfl_flags & NFS_FILE_LOCK_WAIT)) {
			error = EAGAIN;
			break;
		}
		if (flocknflp) {
			/* release any currently held shared lock before sleeping */
			nfs_open_state_clear_busy(np);
			busy = 0;
			nfs_mount_state_in_use_end(nmp, 0);
			inuse = 0;
			error2 = nfs4_unlock(np, nofp, nlop, 0, UINT64_MAX, NFS_FILE_LOCK_STYLE_FLOCK, ctx);
			flocknflp = NULL;
			if (!error2)
				error2 = nfs_mount_state_in_use_start(nmp);
			if (!error2) {
				inuse = 1;
				error2 = nfs_open_state_set_busy(np, ctx);
			}
			if (error2) {
				error = error2;
				break;
			}
			busy = 1;
		}
		/* wait a little bit and send the request again */
		if (error == NFSERR_GRACE)
			delay = 4;
		if (delay < 4)
			delay++;
		tsleep(newnflp, slpflag, "nfs4_setlock_delay", delay * (hz/2));
		error = nfs_sigintr(NFSTONMP(np), NULL, vfs_context_thread(ctx), 0);
		if (!error && (nmp->nm_state & NFSSTA_RECOVER)) {
			/* looks like we have a recover pending... restart */
			nfs_open_state_clear_busy(np);
			busy = 0;
			nfs_mount_state_in_use_end(nmp, 0);
			inuse = 0;
			goto restart;
		}
	} while (!error);

error_out:
	if (nfs_mount_state_error_should_restart(error)) {
		/* looks like we need to restart this operation */
		if (busy) {
			nfs_open_state_clear_busy(np);
			busy = 0;
		}
		if (inuse) {
			nfs_mount_state_in_use_end(nmp, error);
			inuse = 0;
		}
		goto restart;
	}
	lck_mtx_lock(&np->n_openlock);
	newnflp->nfl_flags &= ~NFS_FILE_LOCK_BLOCKED;
	if (error) {
		newnflp->nfl_flags |= NFS_FILE_LOCK_DEAD;
		if (newnflp->nfl_blockcnt) {
			/* wake up anyone blocked on this lock */
			wakeup(newnflp);
		} else {
			/* remove newnflp from lock list and destroy */
			TAILQ_REMOVE(&np->n_locks, newnflp, nfl_link);
			nfs_file_lock_destroy(newnflp);
		}
		lck_mtx_unlock(&np->n_openlock);
		if (busy)
			nfs_open_state_clear_busy(np);
		if (inuse)
			nfs_mount_state_in_use_end(nmp, error);
		if (nflp2)
			nfs_file_lock_destroy(nflp2);
		return (error);
	}

	/* server granted the lock */

	/*
	 * Scan for locks to update.
	 *
	 * Locks completely covered are killed.
	 * At most two locks may need to be clipped.
	 * It's possible that a single lock may need to be split.
	 */
	TAILQ_FOREACH_SAFE(nflp, &np->n_locks, nfl_link, nextnflp) {
		if (nflp == newnflp)
			continue;
		if (nflp->nfl_flags & (NFS_FILE_LOCK_BLOCKED|NFS_FILE_LOCK_DEAD))
			continue;
		if (nflp->nfl_owner != nlop)
			continue;
		if ((newnflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) != (nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK))
			continue;
		if ((newnflp->nfl_start > nflp->nfl_end) || (newnflp->nfl_end < nflp->nfl_start))
			continue;
		/* here's one to update */
		if ((newnflp->nfl_start <= nflp->nfl_start) && (newnflp->nfl_end >= nflp->nfl_end)) {
			/* The entire lock is being replaced. */
			nflp->nfl_flags |= NFS_FILE_LOCK_DEAD;
			lck_mtx_lock(&nlop->nlo_lock);
			TAILQ_REMOVE(&nlop->nlo_locks, nflp, nfl_lolink);
			lck_mtx_unlock(&nlop->nlo_lock);
			/* lock will be destroyed below, if no waiters */
		} else if ((newnflp->nfl_start > nflp->nfl_start) && (newnflp->nfl_end < nflp->nfl_end)) {
			/* We're replacing a range in the middle of a lock. */
			/* The current lock will be split into two locks. */
			/* Update locks and insert new lock after current lock. */
			nflp2->nfl_flags |= (nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK);
			nflp2->nfl_type = nflp->nfl_type;
			nflp2->nfl_start = newnflp->nfl_end + 1;
			nflp2->nfl_end = nflp->nfl_end;
			nflp->nfl_end = newnflp->nfl_start - 1;
			TAILQ_INSERT_AFTER(&np->n_locks, nflp, nflp2, nfl_link);
			nfs_lock_owner_insert_held_lock(nlop, nflp2);
			nextnflp = nflp2;
			nflp2 = NULL;
		} else if (newnflp->nfl_start > nflp->nfl_start) {
			/* We're replacing the end of a lock. */
			nflp->nfl_end = newnflp->nfl_start - 1;
		} else if (newnflp->nfl_end < nflp->nfl_end) {
			/* We're replacing the start of a lock. */
			nflp->nfl_start = newnflp->nfl_end + 1;
		}
		if (nflp->nfl_blockcnt) {
			/* wake up anyone blocked on this lock */
			wakeup(nflp);
		} else if (nflp->nfl_flags & NFS_FILE_LOCK_DEAD) {
			/* remove nflp from lock list and destroy */
			TAILQ_REMOVE(&np->n_locks, nflp, nfl_link);
			nfs_file_lock_destroy(nflp);
		}
	}

	nfs_lock_owner_insert_held_lock(nlop, newnflp);

	/*
	 * POSIX locks should be coalesced when possible.
	 */
	if ((style == NFS_FILE_LOCK_STYLE_POSIX) && (nofp->nof_flags & NFS_OPEN_FILE_POSIXLOCK)) {
		/*
		 * Walk through the lock queue and check each of our held locks with
		 * the previous and next locks in the lock owner's "held lock list".
		 * If the two locks can be coalesced, we merge the current lock into
		 * the other (previous or next) lock.  Merging this way makes sure that
		 * lock ranges are always merged forward in the lock queue.  This is
		 * important because anyone blocked on the lock being "merged away"
		 * will still need to block on that range and it will simply continue
		 * checking locks that are further down the list.
		 */
		TAILQ_FOREACH_SAFE(nflp, &np->n_locks, nfl_link, nextnflp) {
			if (nflp->nfl_flags & (NFS_FILE_LOCK_BLOCKED|NFS_FILE_LOCK_DEAD))
				continue;
			if (nflp->nfl_owner != nlop)
				continue;
			if ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) != NFS_FILE_LOCK_STYLE_POSIX)
				continue;
			if (((coalnflp = TAILQ_PREV(nflp, nfs_file_lock_queue, nfl_lolink))) &&
			    ((coalnflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == NFS_FILE_LOCK_STYLE_POSIX) &&
			    (coalnflp->nfl_type == nflp->nfl_type) &&
			    (coalnflp->nfl_end == (nflp->nfl_start - 1))) {
				coalnflp->nfl_end = nflp->nfl_end;
				nflp->nfl_flags |= NFS_FILE_LOCK_DEAD;
				lck_mtx_lock(&nlop->nlo_lock);
				TAILQ_REMOVE(&nlop->nlo_locks, nflp, nfl_lolink);
				lck_mtx_unlock(&nlop->nlo_lock);
			} else if (((coalnflp = TAILQ_NEXT(nflp, nfl_lolink))) &&
			    ((coalnflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == NFS_FILE_LOCK_STYLE_POSIX) &&
			    (coalnflp->nfl_type == nflp->nfl_type) &&
			    (coalnflp->nfl_start == (nflp->nfl_end + 1))) {
				coalnflp->nfl_start = nflp->nfl_start;
				nflp->nfl_flags |= NFS_FILE_LOCK_DEAD;
				lck_mtx_lock(&nlop->nlo_lock);
				TAILQ_REMOVE(&nlop->nlo_locks, nflp, nfl_lolink);
				lck_mtx_unlock(&nlop->nlo_lock);
			}
			if (!(nflp->nfl_flags & NFS_FILE_LOCK_DEAD))
				continue;
			if (nflp->nfl_blockcnt) {
				/* wake up anyone blocked on this lock */
				wakeup(nflp);
			} else {
				/* remove nflp from lock list and destroy */
				TAILQ_REMOVE(&np->n_locks, nflp, nfl_link);
				nfs_file_lock_destroy(nflp);
			}
		}
	}

	lck_mtx_unlock(&np->n_openlock);
	nfs_open_state_clear_busy(np);
	nfs_mount_state_in_use_end(nmp, error);

	if (nflp2)
		nfs_file_lock_destroy(nflp2);
	return (error);
}

int
nfs4_unlock(
	nfsnode_t np,
	struct nfs_open_file *nofp,
	struct nfs_lock_owner *nlop,
	uint64_t start,
	uint64_t end,
	int style,
	vfs_context_t ctx)
{
	struct nfsmount *nmp;
	struct nfs_file_lock *nflp, *nextnflp, *newnflp = NULL;
	int error = 0, willsplit = 0, send_unlock_rpcs = 1;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);

restart:
	if ((error = nfs_mount_state_in_use_start(nmp)))
		return (error);
	if (nofp->nof_flags & NFS_OPEN_FILE_REOPEN) {
		nfs_mount_state_in_use_end(nmp, 0);
		nfs4_reopen(nofp, vfs_context_thread(ctx));
		goto restart;
	}
	if ((error = nfs_open_state_set_busy(np, ctx))) {
		nfs_mount_state_in_use_end(nmp, error);
		return (error);
	}

	lck_mtx_lock(&np->n_openlock);
	if ((start > 0) && (end < UINT64_MAX) && !willsplit) {
		/*
		 * We may need to allocate a new lock if an existing lock gets split.
		 * So, we first scan the list to check for a split, and if there's
		 * going to be one, we'll allocate one now.
		 */
		TAILQ_FOREACH_SAFE(nflp, &np->n_locks, nfl_link, nextnflp) {
			if (nflp->nfl_flags & (NFS_FILE_LOCK_BLOCKED|NFS_FILE_LOCK_DEAD))
				continue;
			if (nflp->nfl_owner != nlop)
				continue;
			if ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) != style)
				continue;
			if ((start > nflp->nfl_end) || (end < nflp->nfl_start))
				continue;
			if ((start > nflp->nfl_start) && (end < nflp->nfl_end)) {
				willsplit = 1;
				break;
			}
		}
		if (willsplit) {
			lck_mtx_unlock(&np->n_openlock);
			nfs_open_state_clear_busy(np);
			nfs_mount_state_in_use_end(nmp, 0);
			newnflp = nfs_file_lock_alloc(nlop);
			if (!newnflp)
				return (ENOMEM);
			goto restart;
		}
	}

	/*
	 * Free all of our locks in the given range.
	 *
	 * Note that this process requires sending requests to the server.
	 * Because of this, we will release the n_openlock while performing 
	 * the unlock RPCs.  The N_OPENBUSY state keeps the state of *held*
	 * locks from changing underneath us.  However, other entries in the
	 * list may be removed.  So we need to be careful walking the list.
	 */

	/*
	 * Don't unlock ranges that are held by other-style locks.
	 * If style is posix, don't send any unlock rpcs if flock is held.
	 * If we unlock an flock, don't send unlock rpcs for any posix-style
	 * ranges held - instead send unlocks for the ranges not held.
	 */
	if ((style == NFS_FILE_LOCK_STYLE_POSIX) &&
	    ((nflp = TAILQ_FIRST(&nlop->nlo_locks))) &&
	    ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == NFS_FILE_LOCK_STYLE_FLOCK))
		send_unlock_rpcs = 0;
	if ((style == NFS_FILE_LOCK_STYLE_FLOCK) &&
	    ((nflp = TAILQ_FIRST(&nlop->nlo_locks))) &&
	    ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == NFS_FILE_LOCK_STYLE_FLOCK) &&
	    ((nflp = TAILQ_NEXT(nflp, nfl_lolink))) &&
	    ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == NFS_FILE_LOCK_STYLE_POSIX)) {
		uint64_t s = 0;
		int type = TAILQ_FIRST(&nlop->nlo_locks)->nfl_type;
		while (nflp) {
			if ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) == NFS_FILE_LOCK_STYLE_POSIX) {
				/* unlock the range preceding this lock */
				lck_mtx_unlock(&np->n_openlock);
				error = nfs4_unlock_rpc(np, nlop, type, s, nflp->nfl_start-1, ctx);
				if (nfs_mount_state_error_should_restart(error)) {
					nfs_open_state_clear_busy(np);
					nfs_mount_state_in_use_end(nmp, error);
					goto restart;
				}
				lck_mtx_lock(&np->n_openlock);
				if (error)
					goto out;
				s = nflp->nfl_end+1;
			}
			nflp = TAILQ_NEXT(nflp, nfl_lolink);
		}
		lck_mtx_unlock(&np->n_openlock);
		error = nfs4_unlock_rpc(np, nlop, type, s, end, ctx);
		if (nfs_mount_state_error_should_restart(error)) {
			nfs_open_state_clear_busy(np);
			nfs_mount_state_in_use_end(nmp, error);
			goto restart;
		}
		lck_mtx_lock(&np->n_openlock);
		if (error)
			goto out;
		send_unlock_rpcs = 0;
	}

	TAILQ_FOREACH_SAFE(nflp, &np->n_locks, nfl_link, nextnflp) {
		if (nflp->nfl_flags & (NFS_FILE_LOCK_BLOCKED|NFS_FILE_LOCK_DEAD))
			continue;
		if (nflp->nfl_owner != nlop)
			continue;
		if ((nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK) != style)
			continue;
		if ((start > nflp->nfl_end) || (end < nflp->nfl_start))
			continue;
		/* here's one to unlock */
		if ((start <= nflp->nfl_start) && (end >= nflp->nfl_end)) {
			/* The entire lock is being unlocked. */
			if (send_unlock_rpcs) {
				lck_mtx_unlock(&np->n_openlock);
				error = nfs4_unlock_rpc(np, nlop, nflp->nfl_type, nflp->nfl_start, nflp->nfl_end, ctx);
				if (nfs_mount_state_error_should_restart(error)) {
					nfs_open_state_clear_busy(np);
					nfs_mount_state_in_use_end(nmp, error);
					goto restart;
				}
				lck_mtx_lock(&np->n_openlock);
			}
			nextnflp = TAILQ_NEXT(nflp, nfl_link);
			if (error)
				break;
			nflp->nfl_flags |= NFS_FILE_LOCK_DEAD;
			lck_mtx_lock(&nlop->nlo_lock);
			TAILQ_REMOVE(&nlop->nlo_locks, nflp, nfl_lolink);
			lck_mtx_unlock(&nlop->nlo_lock);
			/* lock will be destroyed below, if no waiters */
		} else if ((start > nflp->nfl_start) && (end < nflp->nfl_end)) {
			/* We're unlocking a range in the middle of a lock. */
			/* The current lock will be split into two locks. */
			if (send_unlock_rpcs) {
				lck_mtx_unlock(&np->n_openlock);
				error = nfs4_unlock_rpc(np, nlop, nflp->nfl_type, start, end, ctx);
				if (nfs_mount_state_error_should_restart(error)) {
					nfs_open_state_clear_busy(np);
					nfs_mount_state_in_use_end(nmp, error);
					goto restart;
				}
				lck_mtx_lock(&np->n_openlock);
			}
			if (error)
				break;
			/* update locks and insert new lock after current lock */
			newnflp->nfl_flags |= (nflp->nfl_flags & NFS_FILE_LOCK_STYLE_MASK);
			newnflp->nfl_type = nflp->nfl_type;
			newnflp->nfl_start = end + 1;
			newnflp->nfl_end = nflp->nfl_end;
			nflp->nfl_end = start - 1;
			TAILQ_INSERT_AFTER(&np->n_locks, nflp, newnflp, nfl_link);
			nfs_lock_owner_insert_held_lock(nlop, newnflp);
			nextnflp = newnflp;
			newnflp = NULL;
		} else if (start > nflp->nfl_start) {
			/* We're unlocking the end of a lock. */
			if (send_unlock_rpcs) {
				lck_mtx_unlock(&np->n_openlock);
				error = nfs4_unlock_rpc(np, nlop, nflp->nfl_type, start, nflp->nfl_end, ctx);
				if (nfs_mount_state_error_should_restart(error)) {
					nfs_open_state_clear_busy(np);
					nfs_mount_state_in_use_end(nmp, error);
					goto restart;
				}
				lck_mtx_lock(&np->n_openlock);
			}
			nextnflp = TAILQ_NEXT(nflp, nfl_link);
			if (error)
				break;
			nflp->nfl_end = start - 1;
		} else if (end < nflp->nfl_end) {
			/* We're unlocking the start of a lock. */
			if (send_unlock_rpcs) {
				lck_mtx_unlock(&np->n_openlock);
				error = nfs4_unlock_rpc(np, nlop, nflp->nfl_type, nflp->nfl_start, end, ctx);
				if (nfs_mount_state_error_should_restart(error)) {
					nfs_open_state_clear_busy(np);
					nfs_mount_state_in_use_end(nmp, error);
					goto restart;
				}
				lck_mtx_lock(&np->n_openlock);
			}
			nextnflp = TAILQ_NEXT(nflp, nfl_link);
			if (error)
				break;
			nflp->nfl_start = end + 1;
		}
		if (nflp->nfl_blockcnt) {
			/* wake up anyone blocked on this lock */
			wakeup(nflp);
		} else if (nflp->nfl_flags & NFS_FILE_LOCK_DEAD) {
			/* remove nflp from lock list and destroy */
			TAILQ_REMOVE(&np->n_locks, nflp, nfl_link);
			nfs_file_lock_destroy(nflp);
		}
	}
out:
	lck_mtx_unlock(&np->n_openlock);
	nfs_open_state_clear_busy(np);
	nfs_mount_state_in_use_end(nmp, 0);

	if (newnflp)
		nfs_file_lock_destroy(newnflp);
	return (error);
}

/*
 * NFSv4 advisory file locking
 */
int
nfs4_vnop_advlock(
	struct vnop_advlock_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		caddr_t a_id;
		int a_op;
		struct flock *a_fl;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t vp = ap->a_vp;
	nfsnode_t np = VTONFS(ap->a_vp);
	struct flock *fl = ap->a_fl;
	int op = ap->a_op;
	int flags = ap->a_flags;
	vfs_context_t ctx = ap->a_context;
	struct nfsmount *nmp;
	struct nfs_vattr nvattr;
	struct nfs_open_owner *noop = NULL;
	struct nfs_open_file *nofp = NULL;
	struct nfs_lock_owner *nlop = NULL;
	off_t lstart;
	uint64_t start, end;
	int error = 0, modified, style;
#define OFF_MAX QUAD_MAX

	nmp = VTONMP(ap->a_vp);
	if (!nmp)
		return (ENXIO);

	switch (fl->l_whence) {
	case SEEK_SET:
	case SEEK_CUR:
		/*
		 * Caller is responsible for adding any necessary offset
		 * to fl->l_start when SEEK_CUR is used.
		 */
		lstart = fl->l_start;
		break;
	case SEEK_END:
		/* need to flush, and refetch attributes to make */
		/* sure we have the correct end of file offset   */
		if ((error = nfs_node_lock(np)))
			return (error);
		modified = (np->n_flag & NMODIFIED);
		nfs_node_unlock(np);
		if (modified && ((error = nfs_vinvalbuf(vp, V_SAVE, ctx, 1))))
			return (error);
		if ((error = nfs_getattr(np, &nvattr, ctx, NGA_UNCACHED)))
			return (error);
		nfs_data_lock(np, NFS_DATA_LOCK_SHARED);
		if ((np->n_size > OFF_MAX) ||
		    ((fl->l_start > 0) && (np->n_size > (u_quad_t)(OFF_MAX - fl->l_start))))
			error = EOVERFLOW;
		lstart = np->n_size + fl->l_start;
		nfs_data_unlock(np);
		if (error)
			return (error);
		break;
	default:
		return (EINVAL);
	}
	if (lstart < 0)
		return (EINVAL);
	start = lstart;
	if (fl->l_len == 0) {
		end = UINT64_MAX;
	} else if (fl->l_len > 0) {
		if ((fl->l_len - 1) > (OFF_MAX - lstart))
			return (EOVERFLOW);
		end = start - 1 + fl->l_len;
	} else { /* l_len is negative */
		if ((lstart + fl->l_len) < 0)
			return (EINVAL);
		end = start - 1;
		start += fl->l_len;
	}
	if (error)
		return (error);

	style = (flags & F_FLOCK) ? NFS_FILE_LOCK_STYLE_FLOCK : NFS_FILE_LOCK_STYLE_POSIX;
	if ((style == NFS_FILE_LOCK_STYLE_FLOCK) && ((start != 0) || (end != UINT64_MAX)))
		return (EINVAL);

	/* find the lock owner, alloc if not unlock */
	nlop = nfs_lock_owner_find(np, vfs_context_proc(ctx), (op != F_UNLCK));
	if (!nlop) {
		error = (op == F_UNLCK) ? 0 : ENOMEM;
		if (error)
			printf("nfs4_vnop_advlock: no lock owner %d\n", error);
		goto out;
	}

	if (op == F_GETLK) {
		error = nfs4_getlock(np, nlop, fl, start, end, ctx);
	} else {
		/* find the open owner */
		noop = nfs_open_owner_find(nmp, vfs_context_ucred(ctx), 0);
		if (!noop) {
			printf("nfs4_vnop_advlock: no open owner\n");
			error = EPERM;
			goto out;
		}
		/* find the open file */
restart:
		error = nfs_open_file_find(np, noop, &nofp, 0, 0, 0);
		if (error)
			error = EBADF;
		if (!error && (nofp->nof_flags & NFS_OPEN_FILE_LOST)) {
			printf("nfs_vnop_advlock: LOST\n");
			error = EIO;
		}
		if (!error && (nofp->nof_flags & NFS_OPEN_FILE_REOPEN)) {
			nfs4_reopen(nofp, vfs_context_thread(ctx));
			nofp = NULL;
			goto restart;
		}
		if (error) {
			printf("nfs4_vnop_advlock: no open file %d\n", error);
			goto out;
		}
		if (op == F_UNLCK) {
			error = nfs4_unlock(np, nofp, nlop, start, end, style, ctx);
		} else if ((op == F_SETLK) || (op == F_SETLKW)) {
			if ((op == F_SETLK) && (flags & F_WAIT))
				op = F_SETLKW;
			error = nfs4_setlock(np, nofp, nlop, op, start, end, style, fl->l_type, ctx);
		} else {
			/* not getlk, unlock or lock? */
			error = EINVAL;
		}
	}

out:
	if (nlop)
		nfs_lock_owner_rele(nlop);
	if (noop)
		nfs_open_owner_rele(noop);
	return (error);
}

/*
 * Check if an open owner holds any locks on a file.
 */
int
nfs4_check_for_locks(struct nfs_open_owner *noop, struct nfs_open_file *nofp)
{
	struct nfs_lock_owner *nlop;

	TAILQ_FOREACH(nlop, &nofp->nof_np->n_lock_owners, nlo_link) {
		if (nlop->nlo_open_owner != noop)
			continue;
		if (!TAILQ_EMPTY(&nlop->nlo_locks))
			break;
	}
	return (nlop ? 1 : 0);
}

/*
 * Reopen simple (no deny, no locks) open state that was lost.
 */
void
nfs4_reopen(struct nfs_open_file *nofp, thread_t thd)
{
	struct nfs_open_owner *noop = nofp->nof_owner;
	struct nfsmount *nmp = NFSTONMP(nofp->nof_np);
	vnode_t vp = NFSTOV(nofp->nof_np);
	vnode_t dvp = NULL;
	struct componentname cn;
	const char *vname = NULL;
	size_t namelen;
	char smallname[128];
	char *filename = NULL;
	int error = 0, done = 0, slpflag = (nmp->nm_flag & NFSMNT_INT) ? PCATCH : 0;
	struct timespec ts = { 1, 0 };

	lck_mtx_lock(&nofp->nof_lock);
	while (nofp->nof_flags & NFS_OPEN_FILE_REOPENING) {
		if ((error = nfs_sigintr(nmp, NULL, thd, 0)))
			break;
		msleep(&nofp->nof_flags, &nofp->nof_lock, slpflag|(PZERO-1), "nfsreopenwait", &ts);
	}
	if (!(nofp->nof_flags & NFS_OPEN_FILE_REOPEN)) {
		lck_mtx_unlock(&nofp->nof_lock);
		return;
	}
	nofp->nof_flags |= NFS_OPEN_FILE_REOPENING;
	lck_mtx_unlock(&nofp->nof_lock);

	dvp = vnode_getparent(vp);
	vname = vnode_getname(vp);
	if (!dvp || !vname) {
		error = EIO;
		goto out;
	}
	filename = &smallname[0];
	namelen = snprintf(filename, sizeof(smallname), "%s", vname);
	if (namelen >= sizeof(smallname)) {
		namelen++;  /* snprintf result doesn't include '\0' */
		MALLOC(filename, char *, namelen, M_TEMP, M_WAITOK);
		if (!filename) {
			error = ENOMEM;
			goto out;
		}
		snprintf(filename, namelen, "%s", vname);
	}
	bzero(&cn, sizeof(cn));
	cn.cn_nameptr = filename;
	cn.cn_namelen = namelen;

restart:
	done = 0;
	if ((error = nfs_mount_state_in_use_start(nmp)))
		goto out;

	if (nofp->nof_rw)
		error = nfs4_open_reopen_rpc(nofp, thd, noop->noo_cred, &cn, dvp, &vp, NFS_OPEN_SHARE_ACCESS_BOTH, NFS_OPEN_SHARE_DENY_NONE);
	if (!error && nofp->nof_w)
		error = nfs4_open_reopen_rpc(nofp, thd, noop->noo_cred, &cn, dvp, &vp, NFS_OPEN_SHARE_ACCESS_WRITE, NFS_OPEN_SHARE_DENY_NONE);
	if (!error && nofp->nof_r)
		error = nfs4_open_reopen_rpc(nofp, thd, noop->noo_cred, &cn, dvp, &vp, NFS_OPEN_SHARE_ACCESS_READ, NFS_OPEN_SHARE_DENY_NONE);

	if (nfs_mount_state_in_use_end(nmp, error)) {
		if (error == NFSERR_GRACE)
			goto restart;
		error = 0;
		goto out;
	}
	done = 1;
out:
	lck_mtx_lock(&nofp->nof_lock);
	nofp->nof_flags &= ~NFS_OPEN_FILE_REOPENING;
	if (error)
		nofp->nof_flags |= NFS_OPEN_FILE_LOST;
	if (done)
		nofp->nof_flags &= ~NFS_OPEN_FILE_REOPEN;
	else
		printf("nfs4_reopen: failed, error %d, lost %d\n", error, (nofp->nof_flags & NFS_OPEN_FILE_LOST) ? 1 : 0);
	lck_mtx_unlock(&nofp->nof_lock);
	if (filename && (filename != &smallname[0]))
		FREE(filename, M_TEMP);
	if (vname)
		vnode_putname(vname);
	if (dvp != NULLVP)
		vnode_put(dvp);
}

/*
 * Send a normal OPEN RPC to open/create a file.
 */
int
nfs4_open_rpc(
	struct nfs_open_file *nofp,
	vfs_context_t ctx,
	struct componentname *cnp,
	struct vnode_attr *vap,
	vnode_t dvp,
	vnode_t *vpp,
	int create,
	int share_access,
	int share_deny)
{
	return (nfs4_open_rpc_internal(nofp, ctx, vfs_context_thread(ctx), vfs_context_ucred(ctx),
					cnp, vap, dvp, vpp, create, share_access, share_deny));
}

/*
 * Send an OPEN RPC to reopen a file.
 */
int
nfs4_open_reopen_rpc(
	struct nfs_open_file *nofp,
	thread_t thd,
	kauth_cred_t cred,
	struct componentname *cnp,
	vnode_t dvp,
	vnode_t *vpp,
	int share_access,
	int share_deny)
{
	return (nfs4_open_rpc_internal(nofp, NULL, thd, cred, cnp, NULL, dvp, vpp, 0, share_access, share_deny));
}

/*
 * common OPEN RPC code
 *
 * If create is set, ctx must be passed in.
 */
int
nfs4_open_rpc_internal(
	struct nfs_open_file *nofp,
	vfs_context_t ctx,
	thread_t thd,
	kauth_cred_t cred,
	struct componentname *cnp,
	struct vnode_attr *vap,
	vnode_t dvp,
	vnode_t *vpp,
	int create,
	int share_access,
	int share_deny)
{
	struct nfsmount *nmp;
	struct nfs_open_owner *noop = nofp->nof_owner;
	struct nfs_vattr nvattr, dnvattr;
	int error = 0, open_error = EIO, lockerror = ENOENT, busyerror = ENOENT, status;
	int nfsvers, numops, exclusive = 0, gotuid, gotgid;
	u_int64_t xid, savedxid = 0;
	nfsnode_t dnp = VTONFS(dvp);
	nfsnode_t np, newnp = NULL;
	vnode_t newvp = NULL;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN], bmlen;
	uint32_t rflags, delegation = 0, recall = 0, val;
	struct nfs_stateid stateid, dstateid, *sid;
	fhandle_t fh;
	struct nfsreq *req = NULL;
	struct nfs_dulookup dul;

	if (create && !ctx)
		return (EINVAL);

	nmp = VTONMP(dvp);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	np = *vpp ? VTONFS(*vpp) : NULL;
	if (create && vap) {
		exclusive = (vap->va_vaflags & VA_EXCLUSIVE);
		nfs_avoid_needless_id_setting_on_create(dnp, vap, ctx);
		gotuid = VATTR_IS_ACTIVE(vap, va_uid);
		gotgid = VATTR_IS_ACTIVE(vap, va_gid);
	} else {
		exclusive = gotuid = gotgid = 0;
	}
	if (nofp) {
		sid = &nofp->nof_stateid;
	} else {
		stateid.seqid = stateid.other[0] = stateid.other[1] = stateid.other[2] = 0;
		sid = &stateid;
	}

	if ((error = nfs_open_owner_set_busy(noop, thd)))
		return (error);
again:
	rflags = 0;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, SAVEFH, OPEN(CREATE?), GETATTR(FH), RESTOREFH, GETATTR
	numops = 6;
	nfsm_chain_build_alloc_init(error, &nmreq, 53 * NFSX_UNSIGNED + cnp->cn_namelen);
	nfsm_chain_add_compound_header(error, &nmreq, create ? "create" : "open", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, dnp->n_fhp, dnp->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_SAVEFH);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_OPEN);
	nfsm_chain_add_32(error, &nmreq, noop->noo_seqid);
	nfsm_chain_add_32(error, &nmreq, share_access);
	nfsm_chain_add_32(error, &nmreq, share_deny);

	// open owner: clientid + uid
	nfsm_chain_add_64(error, &nmreq, nmp->nm_clientid); // open_owner4.clientid
	nfsm_chain_add_32(error, &nmreq, NFSX_UNSIGNED);
	nfsm_chain_add_32(error, &nmreq, kauth_cred_getuid(noop->noo_cred)); // open_owner4.owner

	// openflag4
	nfsm_chain_add_32(error, &nmreq, create);
	if (create) {
		if (exclusive) {
			static uint32_t create_verf; // XXX need a better verifier
			create_verf++;
			nfsm_chain_add_32(error, &nmreq, NFS_CREATE_EXCLUSIVE);
			/* insert 64 bit verifier */
			nfsm_chain_add_32(error, &nmreq, create_verf);
			nfsm_chain_add_32(error, &nmreq, create_verf);
		} else {
			nfsm_chain_add_32(error, &nmreq, NFS_CREATE_UNCHECKED);
			nfsm_chain_add_fattr4(error, &nmreq, vap, nmp);
		}
	}

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
	if (!error)
		error = busyerror = nfs_node_set_busy(dnp, thd);
	nfsmout_if(error);

	if (create)
		nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx);

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC4_COMPOUND, thd, cred, NULL, &req);
	if (!error) {
		if (create)
			nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
		savedxid = xid;
	}

	if (create)
		nfs_dulookup_finish(&dul, dnp, ctx);

	if ((lockerror = nfs_node_lock(dnp)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_SAVEFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_OPEN);
	nfs_owner_seqid_increment(noop, NULL, error);
	nfsm_chain_get_stateid(error, &nmrep, sid);
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
			nfsm_chain_get_stateid(error, &nmrep, &dstateid);
			nfsm_chain_get_32(error, &nmrep, recall);
			// ACE: (skip) XXX
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			nfsm_chain_get_32(error, &nmrep, val); /* string length */
			nfsm_chain_adv(error, &nmrep, nfsm_rndup(val));
			break;
		case NFS_OPEN_DELEGATE_WRITE:
			nfsm_chain_get_stateid(error, &nmrep, &dstateid);
			nfsm_chain_get_32(error, &nmrep, recall);
			// space (skip) XXX
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			// ACE: (skip) XXX
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			nfsm_chain_get_32(error, &nmrep, val); /* string length */
			nfsm_chain_adv(error, &nmrep, nfsm_rndup(val));
			break;
		default:
			error = EBADRPC;
			break;
		}
	/* At this point if we have no error, the object was created/opened. */
	/* if we don't get attributes, then we should lookitup. */
	open_error = error;
	nfsmout_if(error);
	if (create && !exclusive)
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
	if (!create && np && !NFS_CMPFH(np, fh.fh_data, fh.fh_len)) {
		// XXX for the open case, what if fh doesn't match the vnode we think we're opening?
		printf("nfs4_open_rpc: warning: file handle mismatch\n");
	}
	/* directory attributes: if we don't get them, make sure to invalidate */
	nfsm_chain_op_check(error, &nmrep, NFS_OP_RESTOREFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, dnp, nfsvers, NULL, &xid);
	if (error)
		NATTRINVALIDATE(dnp);
	nfsmout_if(error);

	if (rflags & NFS_OPEN_RESULT_LOCKTYPE_POSIX)
		nofp->nof_flags |= NFS_OPEN_FILE_POSIXLOCK;

	if (rflags & NFS_OPEN_RESULT_CONFIRM) {
		nfs_node_unlock(dnp);
		lockerror = ENOENT;
		nfsm_chain_cleanup(&nmreq);
		nfsm_chain_cleanup(&nmrep);
		// PUTFH, OPEN_CONFIRM, GETATTR
		numops = 3;
		nfsm_chain_build_alloc_init(error, &nmreq, 23 * NFSX_UNSIGNED);
		nfsm_chain_add_compound_header(error, &nmreq, "open_confirm", numops);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
		nfsm_chain_add_fh(error, &nmreq, nfsvers, fh.fh_data, fh.fh_len);
		numops--;
		nfsm_chain_add_32(error, &nmreq, NFS_OP_OPEN_CONFIRM);
		nfsm_chain_add_stateid(error, &nmreq, sid);
		nfsm_chain_add_32(error, &nmreq, noop->noo_seqid);
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
		nfsmout_if(error);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_OPEN_CONFIRM);
		nfs_owner_seqid_increment(noop, NULL, error);
		nfsm_chain_get_stateid(error, &nmrep, sid);
		nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
		nfsmout_if(error);
		NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
		error = nfs4_parsefattr(&nmrep, NULL, &nvattr, NULL, NULL);
		nfsmout_if(error);
		savedxid = xid;
		if ((lockerror = nfs_node_lock(dnp)))
			error = lockerror;
	}

nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);

	if (!lockerror && create) {
		if (!open_error && (dnp->n_flag & NNEGNCENTRIES)) {
			dnp->n_flag &= ~NNEGNCENTRIES;
			cache_purge_negatives(dvp);
		}
		dnp->n_flag |= NMODIFIED;
		nfs_node_unlock(dnp);
		lockerror = ENOENT;
		nfs_getattr(dnp, &dnvattr, ctx, NGA_CACHED);
	}
	if (!lockerror)
		nfs_node_unlock(dnp);
	if (!error && create && fh.fh_len) {
		/* create the vnode with the filehandle and attributes */
		xid = savedxid;
		error = nfs_nget(NFSTOMP(dnp), dnp, cnp, fh.fh_data, fh.fh_len, &nvattr, &xid, NG_MAKEENTRY, &newnp);
		if (!error)
			newvp = NFSTOV(newnp);
	}
	if (!busyerror)
		nfs_node_clear_busy(dnp);
	if ((delegation == NFS_OPEN_DELEGATE_READ) || (delegation == NFS_OPEN_DELEGATE_WRITE)) {
		if (!np)
			np = newnp;
		if (!error && np && !recall) {
			/* stuff the delegation state in the node */
			lck_mtx_lock(&np->n_openlock);
			np->n_openflags &= ~N_DELEG_MASK;
			np->n_openflags |= ((delegation == NFS_OPEN_DELEGATE_READ) ? N_DELEG_READ : N_DELEG_WRITE);
			np->n_dstateid = dstateid;
			lck_mtx_unlock(&np->n_openlock);
		}
		if (recall) {
			nfs4_delegreturn_rpc(nmp, fh.fh_data, fh.fh_len, &dstateid, thd, cred);
			if (np) {
				lck_mtx_lock(&np->n_openlock);
				np->n_openflags &= ~N_DELEG_MASK;
				lck_mtx_unlock(&np->n_openlock);
			}
		}
	}
	if (error) {
		if (exclusive && (error == NFSERR_NOTSUPP)) {
			exclusive = 0;
			goto again;
		}
		if (newvp) {
			nfs_node_unlock(newnp);
			vnode_put(newvp);
		}
	} else if (create) {
		nfs_node_unlock(newnp);
		if (exclusive) {
			error = nfs4_setattr_rpc(newnp, vap, ctx);
			if (error && (gotuid || gotgid)) {
				/* it's possible the server didn't like our attempt to set IDs. */
				/* so, let's try it again without those */
				VATTR_CLEAR_ACTIVE(vap, va_uid);
				VATTR_CLEAR_ACTIVE(vap, va_gid);
				error = nfs4_setattr_rpc(newnp, vap, ctx);
			}
		}
		if (error)
			vnode_put(newvp);
		else
			*vpp = newvp;
	}
	nfs_open_owner_clear_busy(noop);
	return (error);
}

/*
 * Send an OPEN RPC to reclaim an open file.
 */
int
nfs4_open_reclaim_rpc(
	struct nfs_open_file *nofp,
	int share_access,
	int share_deny)
{
	struct nfsmount *nmp;
	struct nfs_open_owner *noop = nofp->nof_owner;
	struct nfs_vattr nvattr;
	int error = 0, lockerror = ENOENT, status;
	int nfsvers, numops;
	u_int64_t xid;
	nfsnode_t np = nofp->nof_np;
	struct nfsm_chain nmreq, nmrep;
	uint32_t bitmap[NFS_ATTR_BITMAP_LEN], bmlen;
	uint32_t rflags = 0, delegation, recall = 0, val;
	fhandle_t fh;
	struct nfs_stateid dstateid;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if ((error = nfs_open_owner_set_busy(noop, current_thread())))
		return (error);

	delegation = NFS_OPEN_DELEGATE_NONE;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, OPEN, GETATTR(FH)
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 48 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "open_reclaim", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_OPEN);
	nfsm_chain_add_32(error, &nmreq, noop->noo_seqid);
	nfsm_chain_add_32(error, &nmreq, share_access);
	nfsm_chain_add_32(error, &nmreq, share_deny);
	// open owner: clientid + uid
	nfsm_chain_add_64(error, &nmreq, nmp->nm_clientid); // open_owner4.clientid
	nfsm_chain_add_32(error, &nmreq, NFSX_UNSIGNED);
	nfsm_chain_add_32(error, &nmreq, kauth_cred_getuid(noop->noo_cred)); // open_owner4.owner
	// openflag4
	nfsm_chain_add_32(error, &nmreq, NFS_OPEN_NOCREATE);
	// open_claim4
	nfsm_chain_add_32(error, &nmreq, NFS_CLAIM_PREVIOUS);
	delegation = (np->n_openflags & N_DELEG_READ) ? NFS_OPEN_DELEGATE_READ :
			(np->n_openflags & N_DELEG_WRITE) ? NFS_OPEN_DELEGATE_WRITE :
			NFS_OPEN_DELEGATE_NONE;
	nfsm_chain_add_32(error, &nmreq, delegation);
	delegation = NFS_OPEN_DELEGATE_NONE;
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	NFS_COPY_ATTRIBUTES(nfs_getattr_bitmap, bitmap);
	NFS_BITMAP_SET(bitmap, NFS_FATTR_FILEHANDLE);
	nfsm_chain_add_bitmap_masked(error, &nmreq, bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);

	error = nfs_request2(np, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND, current_thread(), noop->noo_cred, R_RECOVER, &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_OPEN);
	nfs_owner_seqid_increment(noop, NULL, error);
	nfsm_chain_get_stateid(error, &nmrep, &nofp->nof_stateid);
	nfsm_chain_check_change_info(error, &nmrep, np);
	nfsm_chain_get_32(error, &nmrep, rflags);
	bmlen = NFS_ATTR_BITMAP_LEN;
	nfsm_chain_get_bitmap(error, &nmrep, bitmap, bmlen);
	nfsm_chain_get_32(error, &nmrep, delegation);
	if (!error)
		switch (delegation) {
		case NFS_OPEN_DELEGATE_NONE:
			break;
		case NFS_OPEN_DELEGATE_READ:
			nfsm_chain_get_stateid(error, &nmrep, &dstateid);
			nfsm_chain_get_32(error, &nmrep, recall);
			// ACE: (skip) XXX
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			nfsm_chain_get_32(error, &nmrep, val); /* string length */
			nfsm_chain_adv(error, &nmrep, nfsm_rndup(val));
			if (!error) {
				/* stuff the delegation state in the node */
				lck_mtx_lock(&np->n_openlock);
				np->n_openflags &= ~N_DELEG_MASK;
				np->n_openflags |= N_DELEG_READ;
				np->n_dstateid = dstateid;
				lck_mtx_unlock(&np->n_openlock);
			}
			break;
		case NFS_OPEN_DELEGATE_WRITE:
			nfsm_chain_get_stateid(error, &nmrep, &dstateid);
			nfsm_chain_get_32(error, &nmrep, recall);
			// space (skip) XXX
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			// ACE: (skip) XXX
			nfsm_chain_adv(error, &nmrep, 3 * NFSX_UNSIGNED);
			nfsm_chain_get_32(error, &nmrep, val); /* string length */
			nfsm_chain_adv(error, &nmrep, nfsm_rndup(val));
			if (!error) {
				/* stuff the delegation state in the node */
				lck_mtx_lock(&np->n_openlock);
				np->n_openflags &= ~N_DELEG_MASK;
				np->n_openflags |= N_DELEG_WRITE;
				np->n_dstateid = dstateid;
				lck_mtx_unlock(&np->n_openlock);
			}
			break;
		default:
			error = EBADRPC;
			break;
		}
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	NFS_CLEAR_ATTRIBUTES(nvattr.nva_bitmap);
	error = nfs4_parsefattr(&nmrep, NULL, &nvattr, &fh, NULL);
	nfsmout_if(error);
	if (!NFS_BITMAP_ISSET(nvattr.nva_bitmap, NFS_FATTR_FILEHANDLE)) {
		printf("nfs: open reclaim didn't return filehandle?\n");
		error = EBADRPC;
		goto nfsmout;
	}
	if (!NFS_CMPFH(np, fh.fh_data, fh.fh_len)) {
		// XXX what if fh doesn't match the vnode we think we're re-opening?
		printf("nfs4_open_reclaim_rpc: warning: file handle mismatch\n");
	}
	error = nfs_loadattrcache(np, &nvattr, &xid, 1);
	nfsmout_if(error);
	if (rflags & NFS_OPEN_RESULT_LOCKTYPE_POSIX)
		nofp->nof_flags |= NFS_OPEN_FILE_POSIXLOCK;
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	if (!lockerror)
		nfs_node_unlock(np);
	nfs_open_owner_clear_busy(noop);
	if ((delegation == NFS_OPEN_DELEGATE_READ) || (delegation == NFS_OPEN_DELEGATE_WRITE)) {
		if (recall) {
			nfs4_delegreturn_rpc(nmp, fh.fh_data, fh.fh_len, &dstateid, current_thread(), noop->noo_cred);
			lck_mtx_lock(&np->n_openlock);
			np->n_openflags &= ~N_DELEG_MASK;
			lck_mtx_unlock(&np->n_openlock);
		}
	}
	return (error);
}

int
nfs4_open_downgrade_rpc(
	nfsnode_t np,
	struct nfs_open_file *nofp,
	vfs_context_t ctx)
{
	struct nfs_open_owner *noop = nofp->nof_owner;
	struct nfsmount *nmp;
	int error, lockerror = ENOENT, status, nfsvers, numops;
	struct nfsm_chain nmreq, nmrep;
	u_int64_t xid;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if ((error = nfs_open_owner_set_busy(noop, vfs_context_thread(ctx))))
		return (error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, OPEN_DOWNGRADE, GETATTR
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 23 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "open_downgrd", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_OPEN_DOWNGRADE);
	nfsm_chain_add_stateid(error, &nmreq, &nofp->nof_stateid);
	nfsm_chain_add_32(error, &nmreq, noop->noo_seqid);
	nfsm_chain_add_32(error, &nmreq, nofp->nof_access);
	nfsm_chain_add_32(error, &nmreq, nofp->nof_deny);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request(np, NULL, &nmreq, NFSPROC4_COMPOUND, ctx, &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_OPEN_DOWNGRADE);
	nfs_owner_seqid_increment(noop, NULL, error);
	nfsm_chain_get_stateid(error, &nmrep, &nofp->nof_stateid);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
nfsmout:
	if (!lockerror)
		nfs_node_unlock(np);
	nfs_open_owner_clear_busy(noop);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}

int
nfs4_close_rpc(
	nfsnode_t np,
	struct nfs_open_file *nofp,
	thread_t thd,
	kauth_cred_t cred,
	int flag)
{
	struct nfs_open_owner *noop = nofp->nof_owner;
	struct nfsmount *nmp;
	int error, lockerror = ENOENT, status, nfsvers, numops;
	struct nfsm_chain nmreq, nmrep;
	u_int64_t xid;

	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);
	nfsvers = nmp->nm_vers;

	if ((error = nfs_open_owner_set_busy(noop, thd)))
		return (error);

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, CLOSE, GETFH
	numops = 3;
	nfsm_chain_build_alloc_init(error, &nmreq, 23 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "close", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nfsvers, np->n_fhp, np->n_fhsize);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_CLOSE);
	nfsm_chain_add_32(error, &nmreq, noop->noo_seqid);
	nfsm_chain_add_stateid(error, &nmreq, &nofp->nof_stateid);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_GETATTR);
	nfsm_chain_add_bitmap_masked(error, &nmreq, nfs_getattr_bitmap,
		NFS_ATTR_BITMAP_LEN, nmp->nm_fsattr.nfsa_supp_attr);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request2(np, NULL, &nmreq, NFSPROC4_COMPOUND, thd, cred, flag, &nmrep, &xid, &status);

	if ((lockerror = nfs_node_lock(np)))
		error = lockerror;
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsmout_if(error);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_CLOSE);
	nfs_owner_seqid_increment(noop, NULL, error);
	nfsm_chain_get_stateid(error, &nmrep, &nofp->nof_stateid);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_GETATTR);
	nfsm_chain_loadattr(error, &nmrep, np, nfsvers, NULL, &xid);
nfsmout:
	if (!lockerror)
		nfs_node_unlock(np);
	nfs_open_owner_clear_busy(noop);
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}


int
nfs4_delegreturn_rpc(struct nfsmount *nmp, u_char *fhp, int fhlen, struct nfs_stateid *sid, thread_t thd, kauth_cred_t cred)
{
	int error = 0, status, numops;
	uint64_t xid;
	struct nfsm_chain nmreq, nmrep;

	nfsm_chain_null(&nmreq);
	nfsm_chain_null(&nmrep);

	// PUTFH, DELEGRETURN
	numops = 2;
	nfsm_chain_build_alloc_init(error, &nmreq, 16 * NFSX_UNSIGNED);
	nfsm_chain_add_compound_header(error, &nmreq, "delegreturn", numops);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_PUTFH);
	nfsm_chain_add_fh(error, &nmreq, nmp->nm_vers, fhp, fhlen);
	numops--;
	nfsm_chain_add_32(error, &nmreq, NFS_OP_DELEGRETURN);
	nfsm_chain_add_stateid(error, &nmreq, sid);
	nfsm_chain_build_done(error, &nmreq);
	nfsm_assert(error, (numops == 0), EPROTO);
	nfsmout_if(error);
	error = nfs_request2(NULL, nmp->nm_mountp, &nmreq, NFSPROC4_COMPOUND, thd, cred, R_RECOVER, &nmrep, &xid, &status);
	nfsm_chain_skip_tag(error, &nmrep);
	nfsm_chain_get_32(error, &nmrep, numops);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_PUTFH);
	nfsm_chain_op_check(error, &nmrep, NFS_OP_DELEGRETURN);
nfsmout:
	nfsm_chain_cleanup(&nmreq);
	nfsm_chain_cleanup(&nmrep);
	return (error);
}


/*
 * NFSv4 read call.
 * Just call nfs_bioread() to do the work.
 *
 * Note: the exec code paths have a tendency to call VNOP_READ (and VNOP_MMAP)
 * without first calling VNOP_OPEN, so we make sure the file is open here.
 */
int
nfs4_vnop_read(
	struct vnop_read_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap)
{
	vnode_t vp = ap->a_vp;
	vfs_context_t ctx = ap->a_context;
	nfsnode_t np;
	struct nfsmount *nmp;
	struct nfs_open_owner *noop;
	struct nfs_open_file *nofp;
	int error;

	if (vnode_vtype(ap->a_vp) != VREG)
		return (EPERM);

	np = VTONFS(vp);
	nmp = NFSTONMP(np);
	if (!nmp)
		return (ENXIO);

	noop = nfs_open_owner_find(nmp, vfs_context_ucred(ctx), 1);
	if (!noop)
		return (ENOMEM);
restart:
	error = nfs_open_file_find(np, noop, &nofp, 0, 0, 1);
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_LOST)) {
		printf("nfs_vnop_read: LOST\n");
		error = EIO;
	}
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_REOPEN)) {
		nfs4_reopen(nofp, vfs_context_thread(ctx));
		nofp = NULL;
		goto restart;
	}
	if (error) {
		nfs_open_owner_rele(noop);
		return (error);
	}
	if (!nofp->nof_access) {
		/* we don't have the file open, so open it for read access */
		error = nfs_mount_state_in_use_start(nmp);
		if (error) {
			nfs_open_owner_rele(noop);
			return (error);
		}
		error = nfs_open_file_set_busy(nofp, vfs_context_thread(ctx));
		if (error)
			nofp = NULL;
		if (!error)
			error = nfs4_open(np, nofp, NFS_OPEN_SHARE_ACCESS_READ, NFS_OPEN_SHARE_DENY_NONE, ctx);
		if (!error)
			nofp->nof_flags |= NFS_OPEN_FILE_NEEDCLOSE;
		if (nofp)
			nfs_open_file_clear_busy(nofp);
		if (nfs_mount_state_in_use_end(nmp, error)) {
			nofp = NULL;
			goto restart;
		}
	}
	nfs_open_owner_rele(noop);
	if (error)
		return (error);
	return (nfs_bioread(VTONFS(ap->a_vp), ap->a_uio, ap->a_ioflag, ap->a_context));
}

/*
 * Note: the NFSv4 CREATE RPC is for everything EXCEPT regular files.
 * Files are created using the NFSv4 OPEN RPC.  So we must open the
 * file to create it and then close it.
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
	nfsnode_t np;
	int error = 0;
	struct nfs_open_owner *noop = NULL;
	struct nfs_open_file *nofp = NULL;

	nmp = VTONMP(dvp);
	if (!nmp)
		return (ENXIO);

	nfs_avoid_needless_id_setting_on_create(VTONFS(dvp), vap, ctx);

	noop = nfs_open_owner_find(nmp, vfs_context_ucred(ctx), 1);
	if (!noop)
		return (ENOMEM);

restart:
	error = nfs_mount_state_in_use_start(nmp);
	if (error) {
		nfs_open_owner_rele(noop);
		return (error);
	}

	error = nfs_open_file_find(NULL, noop, &nofp, 0, 0, 1);
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_LOST)) {
		printf("nfs_vnop_create: LOST\n");
		error = EIO;
	}
	if (!error && (nofp->nof_flags & NFS_OPEN_FILE_REOPEN)) {
		nfs_mount_state_in_use_end(nmp, 0);
		nfs4_reopen(nofp, vfs_context_thread(ctx));
		nofp = NULL;
		goto restart;
	}
	if (!error)
		error = nfs_open_file_set_busy(nofp, vfs_context_thread(ctx));
	if (error) {
		nofp = NULL;
		goto out;
	}

	nofp->nof_opencnt++;
	nofp->nof_access = NFS_OPEN_SHARE_ACCESS_BOTH;
	nofp->nof_deny = NFS_OPEN_SHARE_DENY_NONE;
	nofp->nof_rw++;

	error = nfs4_open_rpc(nofp, ctx, cnp, vap, dvp, vpp, NFS_OPEN_CREATE,
			NFS_OPEN_SHARE_ACCESS_BOTH, NFS_OPEN_SHARE_DENY_NONE);
	if (!error && !*vpp) {
		printf("nfs4_open_rpc returned without a node?\n");
		/* Hmmm... with no node, we have no filehandle and can't close it */
		error = EIO;
	}
	if (error) {
		nofp->nof_rw--;
		nofp->nof_access = 0;
		nofp->nof_deny = 0;
		nofp->nof_opencnt--;
	}
	if (*vpp) {
		nofp->nof_np = np = VTONFS(*vpp);
		/* insert nofp onto np's open list */
		TAILQ_INSERT_HEAD(&np->n_opens, nofp, nof_link);
		if (!error) {
			nofp->nof_flags |= NFS_OPEN_FILE_CREATE;
			nofp->nof_creator = current_thread();
		}
	}
out:
	if (nofp)
		nfs_open_file_clear_busy(nofp);
	if (nfs_mount_state_in_use_end(nmp, error)) {
		nofp = NULL;
		goto restart;
	}
	if (noop)
		nfs_open_owner_rele(noop);
	return (error);
}

void
nfs_avoid_needless_id_setting_on_create(nfsnode_t dnp, struct vnode_attr *vap, vfs_context_t ctx)
{
	/*
	 * Don't bother setting UID if it's the same as the credential performing the create.
	 * Don't bother setting GID if it's the same as the directory or credential.
	 */
	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		if (kauth_cred_getuid(vfs_context_ucred(ctx)) == vap->va_uid)
			VATTR_CLEAR_ACTIVE(vap, va_uid);
	}
	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		if ((vap->va_gid == dnp->n_vattr.nva_gid) ||
		    (kauth_cred_getgid(vfs_context_ucred(ctx)) == vap->va_gid))
			VATTR_CLEAR_ACTIVE(vap, va_gid);
	}
}

/*
 * Note: the NFSv4 CREATE RPC is for everything EXCEPT regular files.
 */
int
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
	int error = 0, create_error = EIO, lockerror = ENOENT, busyerror = ENOENT, status;
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

	nfs_avoid_needless_id_setting_on_create(dnp, vap, ctx);

	error = busyerror = nfs_node_set_busy(dnp, vfs_context_thread(ctx));
	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx);

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

	error = nfs_request_async(dnp, NULL, &nmreq, NFSPROC4_COMPOUND,
			vfs_context_thread(ctx), vfs_context_ucred(ctx), NULL, &req);
	if (!error) {
		nfs_dulookup_start(&dul, dnp, ctx);
		error = nfs_request_async_finish(req, &nmrep, &xid, &status);
	}

	if ((lockerror = nfs_node_lock(dnp)))
		error = lockerror;
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
		nfs_node_unlock(dnp);
		/* nfs_getattr() will check changed and purge caches */
		nfs_getattr(dnp, &dnvattr, ctx, NGA_CACHED);
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
	if (!busyerror)
		nfs_node_clear_busy(dnp);
	if (error) {
		if (newvp) {
			nfs_node_unlock(np);
			vnode_put(newvp);
		}
	} else {
		nfs_node_unlock(np);
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
	int error = 0, lockerror = ENOENT, status;
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

	if ((error = nfs_node_set_busy2(tdnp, np, vfs_context_thread(ctx))))
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

	if ((lockerror = nfs_node_lock2(tdnp, np))) {
		error = lockerror;
		goto nfsmout;
	}
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
	if (!lockerror)
		tdnp->n_flag |= NMODIFIED;
	/* Kludge: Map EEXIST => 0 assuming that it is a reply to a retry. */
	if (error == EEXIST)
		error = 0;
	if (!error && (tdnp->n_flag & NNEGNCENTRIES)) {
		tdnp->n_flag &= ~NNEGNCENTRIES;
		cache_purge_negatives(tdvp);
	}
	if (!lockerror)
		nfs_node_unlock2(tdnp, np);
	nfs_node_clear_busy2(tdnp, np);
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

	if ((error = nfs_node_set_busy2(dnp, np, vfs_context_thread(ctx))))
		return (error);

	nfs_dulookup_init(&dul, dnp, cnp->cn_nameptr, cnp->cn_namelen, ctx);
	nfs_dulookup_start(&dul, dnp, ctx);

	error = nfs4_remove_rpc(dnp, cnp->cn_nameptr, cnp->cn_namelen,
			vfs_context_thread(ctx), vfs_context_ucred(ctx));

	nfs_name_cache_purge(dnp, np, cnp, ctx);
	/* nfs_getattr() will check changed and purge caches */
	nfs_getattr(dnp, &dnvattr, ctx, NGA_CACHED);
	nfs_dulookup_finish(&dul, dnp, ctx);
	nfs_node_clear_busy2(dnp, np);

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

