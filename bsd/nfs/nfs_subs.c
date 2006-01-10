/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 *	@(#)nfs_subs.c	8.8 (Berkeley) 5/22/95
 * FreeBSD-Id: nfs_subs.c,v 1.47 1997/11/07 08:53:24 phk Exp $
 */

/*
 * These functions support the macros and help fiddle mbuf chains for
 * the nfs op functions. They do things like create the rpc header and
 * copy data between mbuf chains and uio lists.
 */
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/ubc_internal.h>
#include <sys/fcntl.h>
#include <sys/uio_internal.h>
#include <sys/domain.h>
#include <libkern/OSAtomic.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#include <sys/time.h>
#include <kern/clock.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsrtt.h>
#include <nfs/nfs_lock.h>

#include <miscfs/specfs/specdev.h>

#include <netinet/in.h>
#if ISO
#include <netiso/iso.h>
#endif

#include <sys/kdebug.h>

SYSCTL_DECL(_vfs_generic);
SYSCTL_NODE(_vfs_generic, OID_AUTO, nfs, CTLFLAG_RW, 0, "nfs hinge");

#define FSDBG(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_NONE, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_TOP(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_START, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_BOT(A, B, C, D, E) \
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_END, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
/*
 * Data items converted to xdr at startup, since they are constant
 * This is kinda hokey, but may save a little time doing byte swaps
 */
u_long nfs_xdrneg1;
u_long rpc_call, rpc_vers, rpc_reply, rpc_msgdenied, rpc_autherr,
	rpc_mismatch, rpc_auth_unix, rpc_msgaccepted,
	rpc_auth_kerb;
u_long nfs_prog, nfs_true, nfs_false;
__private_extern__ int nfs_mbuf_mlen = 0, nfs_mbuf_mhlen = 0,
	nfs_mbuf_minclsize = 0, nfs_mbuf_mclbytes = 0;

/* And other global data */
static u_long nfs_xid = 0;
u_long nfs_xidwrap = 0;		/* to build a (non-wwrapping) 64 bit xid */
static enum vtype nv2tov_type[8]= {
	VNON, VREG, VDIR, VBLK, VCHR, VLNK, VNON,  VNON 
};
enum vtype nv3tov_type[8]= {
	VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO
};

int nfs_mount_type;
int nfs_ticks;

lck_grp_t *nfsd_lck_grp;
lck_grp_attr_t *nfsd_lck_grp_attr;
lck_attr_t *nfsd_lck_attr;
lck_mtx_t *nfsd_mutex;

lck_grp_attr_t *nfs_slp_group_attr;
lck_attr_t *nfs_slp_lock_attr;
lck_grp_t *nfs_slp_rwlock_group;
lck_grp_t *nfs_slp_mutex_group;

struct nfs_reqq nfs_reqq;
struct nfssvc_sockhead nfssvc_sockhead;
struct nfsd_head nfsd_head;
int nfsd_head_flag;

struct nfsexpfslist nfs_exports;
struct nfsexphashhead *nfsexphashtbl;
u_long nfsexphash;
lck_grp_attr_t *nfs_export_group_attr;
lck_attr_t *nfs_export_lock_attr;
lck_grp_t *nfs_export_rwlock_group;
lck_rw_t nfs_export_rwlock;

#ifndef NFS_NOSERVER
/*
 * Mapping of old NFS Version 2 RPC numbers to generic numbers.
 */
int nfsv3_procid[NFS_NPROCS] = {
	NFSPROC_NULL,
	NFSPROC_GETATTR,
	NFSPROC_SETATTR,
	NFSPROC_NOOP,
	NFSPROC_LOOKUP,
	NFSPROC_READLINK,
	NFSPROC_READ,
	NFSPROC_NOOP,
	NFSPROC_WRITE,
	NFSPROC_CREATE,
	NFSPROC_REMOVE,
	NFSPROC_RENAME,
	NFSPROC_LINK,
	NFSPROC_SYMLINK,
	NFSPROC_MKDIR,
	NFSPROC_RMDIR,
	NFSPROC_READDIR,
	NFSPROC_FSSTAT,
	NFSPROC_NOOP,
	NFSPROC_NOOP,
	NFSPROC_NOOP,
	NFSPROC_NOOP,
	NFSPROC_NOOP
};

#endif /* NFS_NOSERVER */
/*
 * and the reverse mapping from generic to Version 2 procedure numbers
 */
int nfsv2_procid[NFS_NPROCS] = {
	NFSV2PROC_NULL,
	NFSV2PROC_GETATTR,
	NFSV2PROC_SETATTR,
	NFSV2PROC_LOOKUP,
	NFSV2PROC_NOOP,
	NFSV2PROC_READLINK,
	NFSV2PROC_READ,
	NFSV2PROC_WRITE,
	NFSV2PROC_CREATE,
	NFSV2PROC_MKDIR,
	NFSV2PROC_SYMLINK,
	NFSV2PROC_CREATE,
	NFSV2PROC_REMOVE,
	NFSV2PROC_RMDIR,
	NFSV2PROC_RENAME,
	NFSV2PROC_LINK,
	NFSV2PROC_READDIR,
	NFSV2PROC_NOOP,
	NFSV2PROC_STATFS,
	NFSV2PROC_NOOP,
	NFSV2PROC_NOOP,
	NFSV2PROC_NOOP,
	NFSV2PROC_NOOP
};

#ifndef NFS_NOSERVER
/*
 * Maps errno values to nfs error numbers.
 * Use NFSERR_IO as the catch all for ones not specifically defined in
 * RFC 1094.
 */
static u_char nfsrv_v2errmap[ELAST] = {
  NFSERR_PERM,	NFSERR_NOENT,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_NXIO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_ACCES,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_EXIST,	NFSERR_IO,	NFSERR_NODEV,	NFSERR_NOTDIR,
  NFSERR_ISDIR,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_FBIG,	NFSERR_NOSPC,	NFSERR_IO,	NFSERR_ROFS,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_NAMETOL,	NFSERR_IO,	NFSERR_IO,
  NFSERR_NOTEMPTY, NFSERR_IO,	NFSERR_IO,	NFSERR_DQUOT,	NFSERR_STALE,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
};

/*
 * Maps errno values to nfs error numbers.
 * Although it is not obvious whether or not NFS clients really care if
 * a returned error value is in the specified list for the procedure, the
 * safest thing to do is filter them appropriately. For Version 2, the
 * X/Open XNFS document is the only specification that defines error values
 * for each RPC (The RFC simply lists all possible error values for all RPCs),
 * so I have decided to not do this for Version 2.
 * The first entry is the default error return and the rest are the valid
 * errors for that RPC in increasing numeric order.
 */
static short nfsv3err_null[] = {
	0,
	0,
};

static short nfsv3err_getattr[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_setattr[] = {
	NFSERR_IO,
	NFSERR_PERM,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOT_SYNC,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_lookup[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_NAMETOL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_access[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_readlink[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_read[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_NXIO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_write[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_FBIG,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_create[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_mkdir[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_symlink[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_mknod[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_BADTYPE,
	0,
};

static short nfsv3err_remove[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_rmdir[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_INVAL,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_NOTEMPTY,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_rename[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_XDEV,
	NFSERR_NOTDIR,
	NFSERR_ISDIR,
	NFSERR_INVAL,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_MLINK,
	NFSERR_NAMETOL,
	NFSERR_NOTEMPTY,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_link[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_XDEV,
	NFSERR_NOTDIR,
	NFSERR_INVAL,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_MLINK,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_readdir[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_BAD_COOKIE,
	NFSERR_TOOSMALL,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_readdirplus[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_BAD_COOKIE,
	NFSERR_NOTSUPP,
	NFSERR_TOOSMALL,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_fsstat[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_fsinfo[] = {
	NFSERR_STALE,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_pathconf[] = {
	NFSERR_STALE,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short nfsv3err_commit[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	0,
};

static short *nfsrv_v3errmap[] = {
	nfsv3err_null,
	nfsv3err_getattr,
	nfsv3err_setattr,
	nfsv3err_lookup,
	nfsv3err_access,
	nfsv3err_readlink,
	nfsv3err_read,
	nfsv3err_write,
	nfsv3err_create,
	nfsv3err_mkdir,
	nfsv3err_symlink,
	nfsv3err_mknod,
	nfsv3err_remove,
	nfsv3err_rmdir,
	nfsv3err_rename,
	nfsv3err_link,
	nfsv3err_readdir,
	nfsv3err_readdirplus,
	nfsv3err_fsstat,
	nfsv3err_fsinfo,
	nfsv3err_pathconf,
	nfsv3err_commit,
};

#endif /* NFS_NOSERVER */

extern struct nfsrtt nfsrtt;
extern struct nfsstats nfsstats;
extern nfstype nfsv2_type[9];
extern nfstype nfsv3_type[9];
extern struct nfsnodehashhead *nfsnodehashtbl;
extern u_long nfsnodehash;


LIST_HEAD(nfsnodehashhead, nfsnode);

/*
 * Create the header for an rpc request packet
 * The hsiz is the size of the rest of the nfs request header.
 * (just used to decide if a cluster is a good idea)
 */
int
nfsm_reqh(int hsiz, caddr_t *bposp, mbuf_t *mbp)
{
	int error;

	*mbp = NULL;
	if (hsiz >= nfs_mbuf_minclsize)
		error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, mbp);
	else
		error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, mbp);
	if (error)
		return (error);
	*bposp = mbuf_data(*mbp);
	return (0);
}

/*
 * Build the RPC header and fill in the authorization info.
 * The authorization string argument is only used when the credentials
 * come from outside of the kernel.
 * Returns the head of the mbuf list.
 */
int
nfsm_rpchead(cr, nmflag, procid, auth_type, auth_len, auth_str, verf_len,
	verf_str, mrest, mrest_len, mbp, xidp, mreqp)
	kauth_cred_t cr;
	int nmflag;
	int procid;
	int auth_type;
	int auth_len;
	char *auth_str;
	int verf_len;
	char *verf_str;
	mbuf_t mrest;
	int mrest_len;
	mbuf_t *mbp;
	u_long *xidp;
	mbuf_t *mreqp;
{
	mbuf_t mb;
	u_long *tl;
	caddr_t bpos;
	int i, error, len;
	mbuf_t mreq, mb2;
	int siz, grpsiz, authsiz, mlen;
	struct timeval tv;

	authsiz = nfsm_rndup(auth_len);
	len = authsiz + 10 * NFSX_UNSIGNED;
	if (len >= nfs_mbuf_minclsize) {
		error = mbuf_getpacket(MBUF_WAITOK, &mb);
	} else {
		error = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &mb);
		if (!error) {
			if (len < nfs_mbuf_mhlen)
				mbuf_align_32(mb, len);
			else
				mbuf_align_32(mb, 8 * NFSX_UNSIGNED);
		}
	}
	if (error) {
		/* unable to allocate packet */
		/* XXX nfsstat? */
		return (error);
	}
	mreq = mb;
	bpos = mbuf_data(mb);

	/*
	 * First the RPC header.
	 */
	nfsm_build(tl, u_long *, 8 * NFSX_UNSIGNED);

	/*
	 * derive initial xid from system time
	 */
	if (!nfs_xid) {
		/*
		 * Note: it's OK if this code inits nfs_xid to 0 (for example,
		 * due to a broken clock) because we immediately increment it
		 * and we guarantee to never use xid 0.  So, nfs_xid should only
		 * ever be 0 the first time this function is called.
		 */
		microtime(&tv);
		nfs_xid = tv.tv_sec << 12;
	}
	/*
	 * Skip zero xid if it should ever happen.
	 */
	if (++nfs_xid == 0) {
		nfs_xidwrap++;
		nfs_xid++;
	}

	*tl++ = *xidp = txdr_unsigned(nfs_xid);
	*tl++ = rpc_call;
	*tl++ = rpc_vers;
	*tl++ = txdr_unsigned(NFS_PROG);
	if (nmflag & NFSMNT_NFSV3)
		*tl++ = txdr_unsigned(NFS_VER3);
	else
		*tl++ = txdr_unsigned(NFS_VER2);
	if (nmflag & NFSMNT_NFSV3)
		*tl++ = txdr_unsigned(procid);
	else
		*tl++ = txdr_unsigned(nfsv2_procid[procid]);

	/*
	 * And then the authorization cred.
	 */
	*tl++ = txdr_unsigned(auth_type);
	*tl = txdr_unsigned(authsiz);
	switch (auth_type) {
	case RPCAUTH_UNIX:
		nfsm_build(tl, u_long *, auth_len);
		*tl++ = 0;		/* stamp ?? */
		*tl++ = 0;		/* NULL hostname */
		*tl++ = txdr_unsigned(kauth_cred_getuid(cr));
		*tl++ = txdr_unsigned(cr->cr_groups[0]);
		grpsiz = (auth_len >> 2) - 5;
		*tl++ = txdr_unsigned(grpsiz);
		for (i = 1; i <= grpsiz; i++)
			*tl++ = txdr_unsigned(cr->cr_groups[i]);
		break;
	case RPCAUTH_KERB4:
		siz = auth_len;
		mlen = mbuf_len(mb);
		while (siz > 0) {
			if (mbuf_trailingspace(mb) == 0) {
				mb2 = NULL;
				if (siz >= nfs_mbuf_minclsize)
					error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &mb2);
				else
					error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mb2);
				if (!error)
					error = mbuf_setnext(mb, mb2);
				if (error) {
					mbuf_freem(mreq);
					return (error);
				}
				mb = mb2;
				mlen = 0;
				bpos = mbuf_data(mb);
			}
			i = min(siz, mbuf_trailingspace(mb));
			bcopy(auth_str, bpos, i);
			mlen += i;
			mbuf_setlen(mb, mlen);
			auth_str += i;
			bpos += i;
			siz -= i;
		}
		if ((siz = (nfsm_rndup(auth_len) - auth_len)) > 0) {
			for (i = 0; i < siz; i++)
				*bpos++ = '\0';
			mlen += siz;
			mbuf_setlen(mb, mlen);
		}
		break;
	};

	/*
	 * And the verifier...
	 */
	nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
	if (verf_str) {
		mlen = mbuf_len(mb);
		*tl++ = txdr_unsigned(RPCAUTH_KERB4);
		*tl = txdr_unsigned(verf_len);
		siz = verf_len;
		while (siz > 0) {
			if (mbuf_trailingspace(mb) == 0) {
				mb2 = NULL;
				if (siz >= nfs_mbuf_minclsize)
					error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &mb2);
				else
					error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mb2);
				if (!error)
					error = mbuf_setnext(mb, mb2);
				if (error) {
					mbuf_freem(mreq);
					return (error);
				}
				mb = mb2;
				mlen = 0;
				bpos = mbuf_data(mb);
			}
			i = min(siz, mbuf_trailingspace(mb));
			bcopy(verf_str, bpos, i);
			mlen += i;
			mbuf_setlen(mb, mlen);
			verf_str += i;
			bpos += i;
			siz -= i;
		}
		if ((siz = (nfsm_rndup(verf_len) - verf_len)) > 0) {
			for (i = 0; i < siz; i++)
				*bpos++ = '\0';
			mlen += siz;
			mbuf_setlen(mb, mlen);
		}
	} else {
		*tl++ = txdr_unsigned(RPCAUTH_NULL);
		*tl = 0;
	}
	error = mbuf_pkthdr_setrcvif(mreq, 0);
	if (!error)
		error = mbuf_setnext(mb, mrest);
	if (error) {
		mbuf_freem(mreq);
		return (error);
	}
	mbuf_pkthdr_setlen(mreq, authsiz + 10 * NFSX_UNSIGNED + mrest_len);
	*mbp = mb;
	*mreqp = mreq;
	return (0);
}

/*
 * copies mbuf chain to the uio scatter/gather list
 */
int
nfsm_mbuftouio(mrep, uiop, siz, dpos)
	mbuf_t *mrep;
	struct uio *uiop;
	int siz;
	caddr_t *dpos;
{
	char *mbufcp, *uiocp;
	int xfer, left, len;
	mbuf_t mp;
	long uiosiz, rem;
	int error = 0;

	mp = *mrep;
	mbufcp = *dpos;
	len = (caddr_t)mbuf_data(mp) + mbuf_len(mp) - mbufcp;
	rem = nfsm_rndup(siz)-siz;
	while (siz > 0) {
		if (uiop->uio_iovcnt <= 0 || uiop->uio_iovs.iov32p == NULL)
			return (EFBIG);
		// LP64todo - fix this!
		left = uio_iov_len(uiop);
		uiocp = CAST_DOWN(caddr_t, uio_iov_base(uiop));
		if (left > siz)
			left = siz;
		uiosiz = left;
		while (left > 0) {
			while (len == 0) {
				mp = mbuf_next(mp);
				if (mp == NULL)
					return (EBADRPC);
				mbufcp = mbuf_data(mp);
				len = mbuf_len(mp);
			}
			xfer = (left > len) ? len : left;
			if (UIO_SEG_IS_USER_SPACE(uiop->uio_segflg))
				copyout(mbufcp, CAST_USER_ADDR_T(uiocp), xfer);
			else
				bcopy(mbufcp, uiocp, xfer);
			left -= xfer;
			len -= xfer;
			mbufcp += xfer;
			uiocp += xfer;
			uiop->uio_offset += xfer;
			uio_uio_resid_add(uiop, -xfer);
		}
		if (uio_iov_len(uiop) <= (size_t)siz) {
			uiop->uio_iovcnt--;
			uio_next_iov(uiop);
		} else {
			uio_iov_base_add(uiop, uiosiz);
			uio_iov_len_add(uiop, -uiosiz);
		}
		siz -= uiosiz;
	}
	*dpos = mbufcp;
	*mrep = mp;
	if (rem > 0) {
		if (len < rem)
			error = nfs_adv(mrep, dpos, rem, len);
		else
			*dpos += rem;
	}
	return (error);
}

/*
 * copies a uio scatter/gather list to an mbuf chain.
 * NOTE: can ony handle iovcnt == 1
 */
int
nfsm_uiotombuf(uiop, mq, siz, bpos)
	struct uio *uiop;
	mbuf_t *mq;
	int siz;
	caddr_t *bpos;
{
	char *uiocp;
	mbuf_t mp, mp2;
	int xfer, left, mlen, mplen;
	int uiosiz, clflg, rem, error;
	char *cp;

	if (uiop->uio_iovcnt != 1)
		panic("nfsm_uiotombuf: iovcnt != 1");

	if (siz > nfs_mbuf_mlen)		/* or should it >= MCLBYTES ?? */
		clflg = 1;
	else
		clflg = 0;
	rem = nfsm_rndup(siz)-siz;
	mp = mp2 = *mq;
	mplen = mbuf_len(mp);
	while (siz > 0) {
		// LP64todo - fix this!
		left = uio_iov_len(uiop);
		uiocp = CAST_DOWN(caddr_t, uio_iov_base(uiop));
		if (left > siz)
			left = siz;
		uiosiz = left;
		while (left > 0) {
			mlen = mbuf_trailingspace(mp);
			if (mlen == 0) {
				mp = NULL;
				if (clflg)
					error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &mp);
				else
					error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mp);
				if (!error)
					error = mbuf_setnext(mp2, mp);
				if (error)
					return (error);
				mplen = 0;
				mp2 = mp;
				mlen = mbuf_trailingspace(mp);
			}
			xfer = (left > mlen) ? mlen : left;
			if (UIO_SEG_IS_USER_SPACE(uiop->uio_segflg))
				copyin(CAST_USER_ADDR_T(uiocp), (caddr_t)mbuf_data(mp) + mplen, xfer);
			else
				bcopy(uiocp, (caddr_t)mbuf_data(mp) + mplen, xfer);
			mplen += xfer;
			mbuf_setlen(mp, mplen);
			left -= xfer;
			uiocp += xfer;
			uiop->uio_offset += xfer;
			uio_uio_resid_add(uiop, -xfer);
		}
		uio_iov_base_add(uiop, uiosiz);
		uio_iov_len_add(uiop, -uiosiz);
		siz -= uiosiz;
	}
	if (rem > 0) {
		if (rem > mbuf_trailingspace(mp)) {
			error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mp);
			if (!error)
				error = mbuf_setnext(mp2, mp);
			if (error)
				return (error);
			mplen = 0;
		}
		cp = (caddr_t)mbuf_data(mp) + mplen;
		for (left = 0; left < rem; left++)
			*cp++ = '\0';
		mplen += rem;
		mbuf_setlen(mp, mplen);
		*bpos = cp;
	} else {
		*bpos = (caddr_t)mbuf_data(mp) + mplen;
	}
	*mq = mp;
	return (0);
}

/*
 * Help break down an mbuf chain by setting the first siz bytes contiguous
 * pointed to by returned val.
 * This is used by the macros nfsm_dissect and nfsm_dissecton for tough
 * cases. (The macros use the vars. dpos and dpos2)
 */
int
nfsm_disct(mdp, dposp, siz, left, cp2)
	mbuf_t *mdp;
	caddr_t *dposp;
	int siz;
	int left;
	caddr_t *cp2;
{
	mbuf_t mp, mp2;
	int siz2, xfer, error, mp2len;
	caddr_t p, mp2data;

	mp = *mdp;
	while (left == 0) {
		*mdp = mp = mbuf_next(mp);
		if (mp == NULL)
			return (EBADRPC);
		left = mbuf_len(mp);
		*dposp = mbuf_data(mp);
	}
	if (left >= siz) {
		*cp2 = *dposp;
		*dposp += siz;
	} else if (mbuf_next(mp) == NULL) {
		return (EBADRPC);
	} else if (siz > nfs_mbuf_mhlen) {
		panic("nfs S too big");
	} else {
		error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mp2);
		if (error)
			return (error);
		error = mbuf_setnext(mp2, mbuf_next(mp));
		if (!error)
			error = mbuf_setnext(mp, mp2);
		if (error) {
			mbuf_free(mp2);
			return (error);
		}
		mbuf_setlen(mp, mbuf_len(mp) - left);
		mp = mp2;
		*cp2 = p = mbuf_data(mp);
		bcopy(*dposp, p, left);		/* Copy what was left */
		siz2 = siz-left;
		p += left;
		mp2 = mbuf_next(mp);
		mp2data = mbuf_data(mp2);
		mp2len = mbuf_len(mp2);
		/* Loop around copying up the siz2 bytes */
		while (siz2 > 0) {
			if (mp2 == NULL)
				return (EBADRPC);
			xfer = (siz2 > mp2len) ? mp2len : siz2;
			if (xfer > 0) {
				bcopy(mp2data, p, xfer);
				mp2data += xfer;
				mp2len -= xfer;
				mbuf_setdata(mp2, mp2data, mp2len);
				p += xfer;
				siz2 -= xfer;
			}
			if (siz2 > 0) {
				mp2 = mbuf_next(mp2);
				mp2data = mbuf_data(mp2);
				mp2len = mbuf_len(mp2);
			}
		}
		mbuf_setlen(mp, siz);
		*mdp = mp2;
		*dposp = mp2data;
	}
	return (0);
}

/*
 * Advance the position in the mbuf chain.
 */
int
nfs_adv(mdp, dposp, offs, left)
	mbuf_t *mdp;
	caddr_t *dposp;
	int offs;
	int left;
{
	mbuf_t m;
	int s;

	m = *mdp;
	s = left;
	while (s < offs) {
		offs -= s;
		m = mbuf_next(m);
		if (m == NULL)
			return (EBADRPC);
		s = mbuf_len(m);
	}
	*mdp = m;
	*dposp = (caddr_t)mbuf_data(m) + offs;
	return (0);
}

/*
 * Copy a string into mbufs for the hard cases...
 */
int
nfsm_strtmbuf(mb, bpos, cp, siz)
	mbuf_t *mb;
	char **bpos;
	char *cp;
	long siz;
{
	mbuf_t m1 = NULL, m2;
	long left, xfer, len, tlen, mlen;
	u_long *tl;
	int putsize, error;

	putsize = 1;
	m2 = *mb;
	left = mbuf_trailingspace(m2);
	if (left >= NFSX_UNSIGNED) {
		tl = ((u_long *)(*bpos));
		*tl++ = txdr_unsigned(siz);
		putsize = 0;
		left -= NFSX_UNSIGNED;
		len = mbuf_len(m2);
		len += NFSX_UNSIGNED;
		mbuf_setlen(m2, len);
		if (left > 0) {
			bcopy(cp, (caddr_t) tl, left);
			siz -= left;
			cp += left;
			len += left;
			mbuf_setlen(m2, len);
			left = 0;
		}
	}
	/* Loop around adding mbufs */
	while (siz > 0) {
		m1 = NULL;
		if (siz > nfs_mbuf_mlen)
			error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &m1);
		else
			error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &m1);
		if (!error)
			error = mbuf_setnext(m2, m1);
		if (error)
			return (error);
		mlen = mbuf_maxlen(m1);
		mbuf_setlen(m1, mlen);
		m2 = m1;
		tl = mbuf_data(m1);
		tlen = 0;
		if (putsize) {
			*tl++ = txdr_unsigned(siz);
			mlen -= NFSX_UNSIGNED;
			mbuf_setlen(m1, mlen);
			tlen = NFSX_UNSIGNED;
			putsize = 0;
		}
		if (siz < mlen) {
			len = nfsm_rndup(siz);
			xfer = siz;
			if (xfer < len)
				*(tl+(xfer>>2)) = 0;
		} else {
			xfer = len = mlen;
		}
		bcopy(cp, (caddr_t) tl, xfer);
		mbuf_setlen(m1, len + tlen);
		siz -= xfer;
		cp += xfer;
	}
	*mb = m1;
	*bpos = (caddr_t)mbuf_data(m1) + mbuf_len(m1);
	return (0);
}

/*
 * Called once to initialize data structures...
 */
int
nfs_init(struct vfsconf *vfsp)
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
	if (sizeof (struct nfssvc_sock) > NFS_SVCALLOC) {
		printf("struct nfssvc_sock bloated (> %dbytes)\n",NFS_SVCALLOC);
		printf("Try reducing NFS_UIDHASHSIZ\n");
	}
	if (sizeof (struct nfsuid) > NFS_UIDALLOC) {
		printf("struct nfsuid bloated (> %dbytes)\n",NFS_UIDALLOC);
		printf("Try unionizing the nu_nickname and nu_flag fields\n");
	}

	nfs_mount_type = vfsp->vfc_typenum;
	nfsrtt.pos = 0;
	rpc_vers = txdr_unsigned(RPC_VER2);
	rpc_call = txdr_unsigned(RPC_CALL);
	rpc_reply = txdr_unsigned(RPC_REPLY);
	rpc_msgdenied = txdr_unsigned(RPC_MSGDENIED);
	rpc_msgaccepted = txdr_unsigned(RPC_MSGACCEPTED);
	rpc_mismatch = txdr_unsigned(RPC_MISMATCH);
	rpc_autherr = txdr_unsigned(RPC_AUTHERR);
	rpc_auth_unix = txdr_unsigned(RPCAUTH_UNIX);
	rpc_auth_kerb = txdr_unsigned(RPCAUTH_KERB4);
	nfs_prog = txdr_unsigned(NFS_PROG);
	nfs_true = txdr_unsigned(TRUE);
	nfs_false = txdr_unsigned(FALSE);
	nfs_xdrneg1 = txdr_unsigned(-1);

	nfs_ticks = (hz * NFS_TICKINTVL + 500) / 1000;
	if (nfs_ticks < 1)
		nfs_ticks = 1;
	/* Ensure async daemons disabled */
	for (i = 0; i < NFS_MAXASYNCDAEMON; i++) {
		nfs_iodwant[i] = NULL;
		nfs_iodmount[i] = (struct nfsmount *)0;
	}
	/* init nfsiod mutex */
	nfs_iod_lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(nfs_iod_lck_grp_attr);
	nfs_iod_lck_grp = lck_grp_alloc_init("nfs_iod", nfs_iod_lck_grp_attr);
	nfs_iod_lck_attr = lck_attr_alloc_init();
	nfs_iod_mutex = lck_mtx_alloc_init(nfs_iod_lck_grp, nfs_iod_lck_attr);

	nfs_nbinit();			/* Init the nfsbuf table */
	nfs_nhinit();			/* Init the nfsnode table */
	nfs_lockinit();			/* Init the nfs lock state */

#ifndef NFS_NOSERVER
	/* init nfsd mutex */
	nfsd_lck_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setstat(nfsd_lck_grp_attr);
	nfsd_lck_grp = lck_grp_alloc_init("nfsd", nfsd_lck_grp_attr);
	nfsd_lck_attr = lck_attr_alloc_init();
	nfsd_mutex = lck_mtx_alloc_init(nfsd_lck_grp, nfsd_lck_attr);

	/* init slp rwlock */
	nfs_slp_lock_attr    = lck_attr_alloc_init();
	nfs_slp_group_attr   = lck_grp_attr_alloc_init();
	nfs_slp_rwlock_group = lck_grp_alloc_init("nfs-slp-rwlock", nfs_slp_group_attr);
	nfs_slp_mutex_group  = lck_grp_alloc_init("nfs-slp-mutex", nfs_slp_group_attr);

	/* init export data structures */
	nfsexphashtbl = hashinit(8, M_TEMP, &nfsexphash);
	LIST_INIT(&nfs_exports);
	nfs_export_lock_attr    = lck_attr_alloc_init();
	nfs_export_group_attr   = lck_grp_attr_alloc_init();
	nfs_export_rwlock_group = lck_grp_alloc_init("nfs-export-rwlock", nfs_export_group_attr);
	lck_rw_init(&nfs_export_rwlock, nfs_export_rwlock_group, nfs_export_lock_attr);

	lck_mtx_lock(nfsd_mutex);
	nfsrv_init(0);			/* Init server data structures */
	nfsrv_initcache();		/* Init the server request cache */
	lck_mtx_unlock(nfsd_mutex);
#endif

	/*
	 * Initialize reply list and start timer
	 */
	TAILQ_INIT(&nfs_reqq);

	nfs_timer(0);

	vfsp->vfc_refcount++; /* make us non-unloadable */
	return (0);
}

/*
 * initialize NFS's cache of mbuf constants
 */
void
nfs_mbuf_init(void)
{
	struct mbuf_stat ms;

	mbuf_stats(&ms);
	nfs_mbuf_mlen = ms.mlen;
	nfs_mbuf_mhlen = ms.mhlen;
	nfs_mbuf_minclsize = ms.minclsize;
	nfs_mbuf_mclbytes = ms.mclbytes;
}

/*
 * Parse the attributes that are in the mbuf list and store them in *nvap.
 */
int
nfs_parsefattr(mbuf_t *mdp, caddr_t *dposp, int v3, struct nfs_vattr *nvap)
{
	struct nfs_fattr *fp;
	long t1;
	caddr_t cp2;
	int error = 0, rdev;
	mbuf_t md;
	enum vtype vtype;
	u_short vmode;

	md = *mdp;
	t1 = ((caddr_t)mbuf_data(md) + mbuf_len(md)) - *dposp;
	if ((error = nfsm_disct(mdp, dposp, NFSX_FATTR(v3), t1, &cp2))) {
		return (error);
	}
	fp = (struct nfs_fattr *)cp2;
	if (v3) {
		vtype = nfsv3tov_type(fp->fa_type);
		vmode = fxdr_unsigned(u_short, fp->fa_mode);
		rdev = makedev(fxdr_unsigned(int, fp->fa3_rdev.specdata1),
			fxdr_unsigned(int, fp->fa3_rdev.specdata2));
	} else {
		vtype = nfsv2tov_type(fp->fa_type);
		vmode = fxdr_unsigned(u_short, fp->fa_mode);
		/*
		 * XXX
		 *
		 * The duplicate information returned in fa_type and fa_mode
		 * is an ambiguity in the NFS version 2 protocol.
		 *
		 * VREG should be taken literally as a regular file.  If a
		 * server intents to return some type information differently
		 * in the upper bits of the mode field (e.g. for sockets, or
		 * FIFOs), NFSv2 mandates fa_type to be VNON.  Anyway, we
		 * leave the examination of the mode bits even in the VREG
		 * case to avoid breakage for bogus servers, but we make sure
		 * that there are actually type bits set in the upper part of
		 * fa_mode (and failing that, trust the va_type field).
		 *
		 * NFSv3 cleared the issue, and requires fa_mode to not
		 * contain any type information (while also introduing sockets
		 * and FIFOs for fa_type).
		 */
		if (vtype == VNON || (vtype == VREG && (vmode & S_IFMT) != 0))
			vtype = IFTOVT(vmode);
		rdev = fxdr_unsigned(long, fp->fa2_rdev);
		/*
		 * Really ugly NFSv2 kludge.
		 */
		if (vtype == VCHR && rdev == (int)0xffffffff)
			vtype = VFIFO;
	}

	nvap->nva_type = vtype;
	nvap->nva_mode = (vmode & 07777);
	nvap->nva_rdev = (dev_t)rdev;
	nvap->nva_nlink = (uint64_t)fxdr_unsigned(u_long, fp->fa_nlink);
	nvap->nva_uid = fxdr_unsigned(uid_t, fp->fa_uid);
	nvap->nva_gid = fxdr_unsigned(gid_t, fp->fa_gid);
	if (v3) {
		fxdr_hyper(&fp->fa3_size, &nvap->nva_size);
		nvap->nva_blocksize = 16*1024;
		fxdr_hyper(&fp->fa3_used, &nvap->nva_bytes);
		fxdr_hyper(&fp->fa3_fileid, &nvap->nva_fileid);
		fxdr_nfsv3time(&fp->fa3_atime, &nvap->nva_atime);
		fxdr_nfsv3time(&fp->fa3_mtime, &nvap->nva_mtime);
		fxdr_nfsv3time(&fp->fa3_ctime, &nvap->nva_ctime);
	} else {
		nvap->nva_size = fxdr_unsigned(u_long, fp->fa2_size);
		nvap->nva_blocksize = fxdr_unsigned(long, fp->fa2_blocksize);
		nvap->nva_bytes = fxdr_unsigned(long, fp->fa2_blocks) * NFS_FABLKSIZE;
		nvap->nva_fileid = (uint64_t)fxdr_unsigned(u_long, fp->fa2_fileid);
		fxdr_nfsv2time(&fp->fa2_atime, &nvap->nva_atime);
		fxdr_nfsv2time(&fp->fa2_mtime, &nvap->nva_mtime);
		fxdr_nfsv2time(&fp->fa2_ctime, &nvap->nva_ctime);
	}

	return (0);
}

/*
 * Load the attribute cache (that lives in the nfsnode entry) with
 * the value pointed to by nvap, unless the file type in the attribute
 * cache doesn't match the file type in the nvap, in which case log a
 * warning and return ESTALE.
 *
 * If the dontshrink flag is set, then it's not safe to call ubc_setsize()
 * to shrink the size of the file.
 */
int
nfs_loadattrcache(
	struct nfsnode *np,
	struct nfs_vattr *nvap,
	u_int64_t *xidp,
	int dontshrink)
{
	mount_t mp;
	vnode_t vp;
	struct timeval now;
	struct nfs_vattr *npnvap;

	if (np->n_flag & NINIT) {
		vp = NULL;
		mp = np->n_mount;
	} else {
		vp = NFSTOV(np);
		mp = vnode_mount(vp);
	}

	FSDBG_TOP(527, vp, np, *xidp >> 32, *xidp);

	if (!VFSTONFS(mp)) {
		FSDBG_BOT(527, ENXIO, 1, 0, *xidp);
		return (ENXIO); 
	}

	if (*xidp < np->n_xid) {
		/*
		 * We have already updated attributes with a response from
		 * a later request.  The attributes we have here are probably
		 * stale so we drop them (just return).  However, our 
		 * out-of-order receipt could be correct - if the requests were
		 * processed out of order at the server.  Given the uncertainty
		 * we invalidate our cached attributes.  *xidp is zeroed here
		 * to indicate the attributes were dropped - only getattr
		 * cares - it needs to retry the rpc.
		 */
		NATTRINVALIDATE(np);
		FSDBG_BOT(527, 0, np, np->n_xid, *xidp);
		*xidp = 0;
		return (0);
	}

	if (vp && (nvap->nva_type != vnode_vtype(vp))) {
		/*
		 * The filehandle has changed type on us.  This can be
		 * caused by either the server not having unique filehandles
		 * or because another client has removed the previous
		 * filehandle and a new object (of a different type)
		 * has been created with the same filehandle.
		 *
		 * We can't simply switch the type on the vnode because
		 * there may be type-specific fields that need to be
		 * cleaned up or set up.
		 *
		 * So, what should we do with this vnode?
		 *
		 * About the best we can do is log a warning and return
		 * an error.  ESTALE is about the closest error, but it
		 * is a little strange that we come up with this error
		 * internally instead of simply passing it through from
		 * the server.  Hopefully, the vnode will be reclaimed
		 * soon so the filehandle can be reincarnated as the new
		 * object type.
		 */
		printf("nfs loadattrcache vnode changed type, was %d now %d\n",
			vnode_vtype(vp), nvap->nva_type);
		FSDBG_BOT(527, ESTALE, 3, 0, *xidp);
		return (ESTALE);
	}

	microuptime(&now);
	np->n_attrstamp = now.tv_sec;
	np->n_xid = *xidp;

	npnvap = &np->n_vattr;
	nvap->nva_fsid = vfs_statfs(mp)->f_fsid.val[0];
	bcopy((caddr_t)nvap, (caddr_t)npnvap, sizeof(*nvap));

	if (vp) {
		if (nvap->nva_size != np->n_size) {
			FSDBG(527, vp, nvap->nva_size, np->n_size,
			      (nvap->nva_type == VREG) |
			      (np->n_flag & NMODIFIED ? 6 : 4));
			if (nvap->nva_type == VREG) {
				int orig_size = np->n_size;
				if (np->n_flag & NMODIFIED) {
					if (nvap->nva_size < np->n_size)
						nvap->nva_size = np->n_size;
					else
						np->n_size = nvap->nva_size;
				} else
					np->n_size = nvap->nva_size;
				if (!UBCINFOEXISTS(vp) ||
				    (dontshrink && np->n_size < (u_quad_t)ubc_getsize(vp))) {
					nvap->nva_size = np->n_size = orig_size;
					NATTRINVALIDATE(np);
				} else {
					ubc_setsize(vp, (off_t)np->n_size); /* XXX */
				}
			} else
				np->n_size = nvap->nva_size;
		}
	} else {
		np->n_size = nvap->nva_size;
	}

	if (np->n_flag & NCHG) {
		if (np->n_flag & NACC)
			nvap->nva_atime = np->n_atim;
		if (np->n_flag & NUPD)
			nvap->nva_mtime = np->n_mtim;
	}

	FSDBG_BOT(527, 0, np, 0, *xidp);
	return (0);
}

/*
 * Calculate the attribute timeout based on
 * how recently the file has been modified.
 */
int
nfs_attrcachetimeout(vnode_t vp)
{
	struct nfsnode *np = VTONFS(vp);
	struct nfsmount *nmp;
	struct timeval now;
	int isdir, timeo;

	if (!(nmp = VFSTONFS(vnode_mount(vp))))
		return (0);

	isdir = vnode_isdir(vp);

	if ((np)->n_flag & NMODIFIED)
		timeo = isdir ? nmp->nm_acdirmin : nmp->nm_acregmin;
	else {
		/* Note that if the client and server clocks are way out of sync, */
		/* timeout will probably get clamped to a min or max value */
		microtime(&now);
		timeo = (now.tv_sec - (np)->n_mtime.tv_sec) / 10;
		if (isdir) {
			if (timeo < nmp->nm_acdirmin)
				timeo = nmp->nm_acdirmin;
			else if (timeo > nmp->nm_acdirmax)
				timeo = nmp->nm_acdirmax;
		} else {
			if (timeo < nmp->nm_acregmin)
				timeo = nmp->nm_acregmin;
			else if (timeo > nmp->nm_acregmax)
				timeo = nmp->nm_acregmax;
		}
	}

	return (timeo);
}

/*
 * Check the time stamp
 * If the cache is valid, copy contents to *nvaper and return 0
 * otherwise return an error
 */
int
nfs_getattrcache(vp, nvaper)
	vnode_t vp;
	struct nfs_vattr *nvaper;
{
	struct nfsnode *np = VTONFS(vp);
	struct nfs_vattr *nvap;
	struct timeval nowup;
	int32_t timeo;

	if (!NATTRVALID(np)) {
		FSDBG(528, vp, 0, 0, 0);
		OSAddAtomic(1, (SInt32*)&nfsstats.attrcache_misses);
		return (ENOENT);
	}

	timeo = nfs_attrcachetimeout(vp);

	microuptime(&nowup);
	if ((nowup.tv_sec - np->n_attrstamp) >= timeo) {
		FSDBG(528, vp, 0, 0, 1);
		OSAddAtomic(1, (SInt32*)&nfsstats.attrcache_misses);
		return (ENOENT);
	}
	FSDBG(528, vp, 0, 0, 2);
	OSAddAtomic(1, (SInt32*)&nfsstats.attrcache_hits);
	nvap = &np->n_vattr;

	if (nvap->nva_size != np->n_size) {
		FSDBG(528, vp, nvap->nva_size, np->n_size,
		      (nvap->nva_type == VREG) |
		      (np->n_flag & NMODIFIED ? 6 : 4));
		if (nvap->nva_type == VREG) {
			if (np->n_flag & NMODIFIED) {
				if (nvap->nva_size < np->n_size)
					nvap->nva_size = np->n_size;
				else
					np->n_size = nvap->nva_size;
			} else
				np->n_size = nvap->nva_size;
			ubc_setsize(vp, (off_t)np->n_size); /* XXX */
		} else
			np->n_size = nvap->nva_size;
	}

	bcopy((caddr_t)nvap, (caddr_t)nvaper, sizeof(struct nfs_vattr));
	if (np->n_flag & NCHG) {
		if (np->n_flag & NACC)
			nvaper->nva_atime = np->n_atim;
		if (np->n_flag & NUPD)
			nvaper->nva_mtime = np->n_mtim;
	}
	return (0);
}

#ifndef NFS_NOSERVER
/*
 * Extract a lookup path from the given mbufs and store it in
 * a newly allocated buffer saved in the given nameidata structure.
 * exptected string length given as *lenp and final string length
 * (after any WebNFS processing) is returned in *lenp.
 */
int
nfsm_path_mbuftond(
	mbuf_t *mdp,
	caddr_t *dposp,
	__unused int v3,
	__unused int pubflag,
	int* lenp,
	struct nameidata *ndp)
{
	int i, len, len2, rem, error = 0;
	mbuf_t md;
	char *fromcp, *tocp;
	struct componentname *cnp = &ndp->ni_cnd;
/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	int webcnt = 0, digitcnt = 0;
	char hexdigits[2];
#endif

	len = *lenp;
	if (len > (MAXPATHLEN - 1))
		return (ENAMETOOLONG);

	/*
	 * Get a buffer for the name to be translated, and copy the
	 * name into the buffer.
	 */
	MALLOC_ZONE(cnp->cn_pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (!cnp->cn_pnbuf)
		return (ENOMEM);
	cnp->cn_pnlen = MAXPATHLEN;
	cnp->cn_flags |= HASBUF;

	/*
	 * Copy the name from the mbuf list to the string
	 *
	 * Along the way, take note of any WebNFS characters
	 * and convert any % escapes.
	 */
	fromcp = *dposp;
	tocp = cnp->cn_pnbuf;
	md = *mdp;
	rem = (caddr_t)mbuf_data(md) + mbuf_len(md) - fromcp;
	for (i = 1; i <= len; i++) {
		while (rem == 0) {
			md = mbuf_next(md);
			if (md == NULL) {
				error = EBADRPC;
				goto out;
			}
			fromcp = mbuf_data(md);
			rem = mbuf_len(md);
		}
/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
		if (pubflag) {
			if ((i == 1) && ((unsigned char)*fromcp >= WEBNFS_SPECCHAR_START)) {
				switch ((unsigned char)*fromcp) {
				case WEBNFS_NATIVE_CHAR:
					/*
					 * 'Native' path for us is the same
					 * as a path according to the NFS spec,
					 * just skip the escape char.
					 */
					webcnt++;
					fromcp++;
					rem--;
					/* next iteration of for loop */
					continue;
				/*
				 * More may be added in the future, range 0x80-0xff.
				 * Don't currently support security query lookup (0x81).
				 */
				default:
					error = EIO;
					goto out;
				}
			}
			if (digitcnt) {
				/* We're expecting hex digits */
				if (!ISHEX(*fromcp)) {
					error = ENOENT;
					goto out;
				}
				digitcnt--;
				hexdigits[digitcnt ? 0 : 1] = *fromcp++;
				if (!digitcnt)
					*tocp++ = HEXSTRTOI(hexdigits);
				rem--;
				/* next iteration of for loop */
				continue;
			} else if (*fromcp == WEBNFS_ESC_CHAR) {
				/*
				 * We can't really look at the next couple
				 * bytes here safely/easily, so we note that
				 * the next two characters should be hex
				 * digits and later save them in hexdigits[].
				 * When we've got both, we'll convert it.
				 */
				digitcnt = 2;
				webcnt += 2;
				fromcp++;
				rem--;
				/* next iteration of for loop */
				continue;
			}
		}
		if (*fromcp == '\0' || (!pubflag && *fromcp == '/'))
#else
		if (*fromcp == '\0' || *fromcp == '/')
#endif
		{
			error = EACCES;
			goto out;
		}
		*tocp++ = *fromcp++;
		rem--;
	}
	*tocp = '\0';
	*mdp = md;
	*dposp = fromcp;
	len2 = nfsm_rndup(len)-len;
	if (len2 > 0) {
		if (rem >= len2)
			*dposp += len2;
		else if ((error = nfs_adv(mdp, dposp, len2, rem)) != 0)
			goto out;
	}

/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	if (pubflag) {
		if (digitcnt) {
			/* The string ended in the middle of an escape! */
			error = ENOENT;
			goto out;
		}
		len -= webcnt;
	}
#endif

out:
	if (error) {
		if (cnp->cn_pnbuf)
			FREE_ZONE(cnp->cn_pnbuf, MAXPATHLEN, M_NAMEI);
		cnp->cn_flags &= ~HASBUF;
	} else {
		ndp->ni_pathlen = len;
		*lenp = len;
	}
	return (error);
}

/*
 * Set up nameidata for a lookup() call and do it.
 *
 * If pubflag is set, this call is done for a lookup operation on the
 * public filehandle. In that case we allow crossing mountpoints and
 * absolute pathnames. However, the caller is expected to check that
 * the lookup result is within the public fs, and deny access if
 * it is not.
 */
int
nfs_namei(
	struct nfsrv_descript *nfsd,
	struct vfs_context *ctx,
	struct nameidata *ndp,
	struct nfs_filehandle *nfhp,
	mbuf_t nam,
	int pubflag,
	vnode_t *retdirp,
	struct nfs_export **nxp,
	struct nfs_export_options **nxop)
{
/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	char *cp;
	uio_t auio;
	char uio_buf[ UIO_SIZEOF(1) ];
	int linklen, olen = ndp->ni_pathlen;
#endif
	vnode_t dp;
	int error;
	struct componentname *cnp = &ndp->ni_cnd;
	char *tmppn;

	*retdirp = NULL;

	/*
	 * Extract and set starting directory.
	 */
	error = nfsrv_fhtovp(nfhp, nam, pubflag, &dp, nxp, nxop);
	if (error)
		goto out;
	error = nfsrv_credcheck(nfsd, *nxp, *nxop);
	if (error || (vnode_vtype(dp) != VDIR)) {
		vnode_put(dp);
		error = ENOTDIR;
		goto out;
	}

	ctx->vc_ucred = nfsd->nd_cr;
	ndp->ni_cnd.cn_context = ctx;

	if (*nxop && ((*nxop)->nxo_flags & NX_READONLY))
		cnp->cn_flags |= RDONLY;

	*retdirp = dp;

/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	if (pubflag) {
		ndp->ni_rootdir = rootvnode;
		ndp->ni_loopcnt = 0;
		if (cnp->cn_pnbuf[0] == '/') {
			vnode_put(dp);
			dp = rootvnode;
			error = vnode_get(dp);
			if (error) {
				*retdirp = NULL;
				goto out;
			}
		}
	} else {
		cnp->cn_flags |= NOCROSSMOUNT;
	}
#else
	cnp->cn_flags |= NOCROSSMOUNT;
#endif

	ndp->ni_usedvp = dp;

    for (;;) {
	cnp->cn_nameptr = cnp->cn_pnbuf;
	ndp->ni_startdir = dp;
	/*
	 * And call lookup() to do the real work
	 */
	error = lookup(ndp);
	if (error)
		break;
	/*
	 * Check for encountering a symbolic link
	 */
	if ((cnp->cn_flags & ISSYMLINK) == 0) {
		return (0);
	} else {
	        if ((cnp->cn_flags & FSNODELOCKHELD)) {
		        cnp->cn_flags &= ~FSNODELOCKHELD;
			unlock_fsnode(ndp->ni_dvp, NULL);
		}
/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
		if (!pubflag) {
#endif
		        if (cnp->cn_flags & (LOCKPARENT | WANTPARENT))
			        vnode_put(ndp->ni_dvp);
			if (ndp->ni_vp) {
			        vnode_put(ndp->ni_vp);
				ndp->ni_vp = NULL;
			}
			error = EINVAL;
			break;
/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
		}

		if (ndp->ni_loopcnt++ >= MAXSYMLINKS) {
			vnode_put(ndp->ni_vp);
			ndp->ni_vp = NULL;
			error = ELOOP;
			break;
		}
		/* XXX assert(olen <= MAXPATHLEN - 1); */
		if (ndp->ni_pathlen > 1) {
			MALLOC_ZONE(cp, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
			if (!cp) {
				vnode_put(ndp->ni_vp);
				ndp->ni_vp = NULL;
				error = ENOMEM;
				break;
			}
		} else {
			cp = cnp->cn_pnbuf;
		}
		auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
					&uio_buf[0], sizeof(uio_buf));
		if (!auio) {
			vnode_put(ndp->ni_vp);
			ndp->ni_vp = NULL;
			if (ndp->ni_pathlen > 1)
				FREE_ZONE(cp, MAXPATHLEN, M_NAMEI);
			error = ENOMEM;
			break;
		}
		uio_addiov(auio, CAST_USER_ADDR_T(cp), MAXPATHLEN);
		error = VNOP_READLINK(ndp->ni_vp, auio, cnp->cn_context);
		if (error) {
badlink:
			vnode_put(ndp->ni_vp);
			ndp->ni_vp = NULL;
			if (ndp->ni_pathlen > 1)
				FREE_ZONE(cp, MAXPATHLEN, M_NAMEI);
			break;
		}
		linklen = MAXPATHLEN - uio_resid(auio);
		if (linklen == 0) {
			error = ENOENT;
			goto badlink;
		}
		if (linklen + ndp->ni_pathlen >= MAXPATHLEN) {
			error = ENAMETOOLONG;
			goto badlink;
		}
		if (ndp->ni_pathlen > 1) {
			long len = cnp->cn_pnlen;
			tmppn = cnp->cn_pnbuf;
			cnp->cn_pnbuf = cp;
			cnp->cn_pnlen = olen + 1;
			bcopy(ndp->ni_next, cp + linklen, ndp->ni_pathlen);
			FREE_ZONE(tmppn, len, M_NAMEI);
		} else
			cnp->cn_pnbuf[linklen] = '\0';
		ndp->ni_pathlen += linklen;

		vnode_put(ndp->ni_vp);
		dp = ndp->ni_dvp;
		ndp->ni_dvp = NULL;

		/*
		 * Check if root directory should replace current directory.
		 */
		if (cnp->cn_pnbuf[0] == '/') {
			vnode_put(dp);
			dp = ndp->ni_rootdir;
			error = vnode_get(dp);
			if (error)
				break;
		}
#endif
	}
   }
out:
	tmppn = cnp->cn_pnbuf;
	cnp->cn_pnbuf = NULL;
	cnp->cn_flags &= ~HASBUF;
	FREE_ZONE(tmppn, cnp->cn_pnlen, M_NAMEI);

	return (error);
}

/*
 * A fiddled version of m_adj() that ensures null fill to a long
 * boundary and only trims off the back end
 */
void
nfsm_adj(mp, len, nul)
	mbuf_t mp;
	int len;
	int nul;
{
	mbuf_t m, mnext;
	int count, i, mlen;
	char *cp;

	/*
	 * Trim from tail.  Scan the mbuf chain,
	 * calculating its length and finding the last mbuf.
	 * If the adjustment only affects this mbuf, then just
	 * adjust and return.  Otherwise, rescan and truncate
	 * after the remaining size.
	 */
	count = 0;
	m = mp;
	for (;;) {
		mlen = mbuf_len(m);
		count += mlen;
		mnext = mbuf_next(m);
		if (mnext == NULL)
			break;
		m = mnext;
	}
	if (mlen > len) {
		mlen -= len;
		mbuf_setlen(m, mlen);
		if (nul > 0) {
			cp = (caddr_t)mbuf_data(m) + mlen - nul;
			for (i = 0; i < nul; i++)
				*cp++ = '\0';
		}
		return;
	}
	count -= len;
	if (count < 0)
		count = 0;
	/*
	 * Correct length for chain is "count".
	 * Find the mbuf with last data, adjust its length,
	 * and toss data from remaining mbufs on chain.
	 */
	for (m = mp; m; m = mbuf_next(m)) {
		mlen = mbuf_len(m);
		if (mlen >= count) {
			mlen = count;
			mbuf_setlen(m, count);
			if (nul > 0) {
				cp = (caddr_t)mbuf_data(m) + mlen - nul;
				for (i = 0; i < nul; i++)
					*cp++ = '\0';
			}
			break;
		}
		count -= mlen;
	}
	for (m = mbuf_next(m); m; m = mbuf_next(m))
		mbuf_setlen(m, 0);
}

/*
 * Make these functions instead of macros, so that the kernel text size
 * doesn't get too big...
 */
void
nfsm_srvwcc(nfsd, before_ret, before_vap, after_ret, after_vap, mbp, bposp)
	struct nfsrv_descript *nfsd;
	int before_ret;
	struct vnode_attr *before_vap;
	int after_ret;
	struct vnode_attr *after_vap;
	mbuf_t *mbp;
	char **bposp;
{
	mbuf_t mb = *mbp, mb2;
	char *bpos = *bposp;
	u_long *tl;

	if (before_ret) {
		nfsm_build(tl, u_long *, NFSX_UNSIGNED);
		*tl = nfs_false;
	} else {
		nfsm_build(tl, u_long *, 7 * NFSX_UNSIGNED);
		*tl++ = nfs_true;
		txdr_hyper(&(before_vap->va_data_size), tl);
		tl += 2;
		txdr_nfsv3time(&(before_vap->va_modify_time), tl);
		tl += 2;
		txdr_nfsv3time(&(before_vap->va_change_time), tl);
	}
	*bposp = bpos;
	*mbp = mb;
	nfsm_srvpostopattr(nfsd, after_ret, after_vap, mbp, bposp);
}

void
nfsm_srvpostopattr(nfsd, after_ret, after_vap, mbp, bposp)
	struct nfsrv_descript *nfsd;
	int after_ret;
	struct vnode_attr *after_vap;
	mbuf_t *mbp;
	char **bposp;
{
	mbuf_t mb = *mbp, mb2;
	char *bpos = *bposp;
	u_long *tl;
	struct nfs_fattr *fp;

	if (after_ret) {
		nfsm_build(tl, u_long *, NFSX_UNSIGNED);
		*tl = nfs_false;
	} else {
		nfsm_build(tl, u_long *, NFSX_UNSIGNED + NFSX_V3FATTR);
		*tl++ = nfs_true;
		fp = (struct nfs_fattr *)tl;
		nfsm_srvfattr(nfsd, after_vap, fp);
	}
	*mbp = mb;
	*bposp = bpos;
}

void
nfsm_srvfattr(nfsd, vap, fp)
	struct nfsrv_descript *nfsd;
	struct vnode_attr *vap;
	struct nfs_fattr *fp;
{

	// XXX Should we assert here that all fields are supported?

	fp->fa_nlink = txdr_unsigned(vap->va_nlink);
	fp->fa_uid = txdr_unsigned(vap->va_uid);
	fp->fa_gid = txdr_unsigned(vap->va_gid);
	if (nfsd->nd_flag & ND_NFSV3) {
		fp->fa_type = vtonfsv3_type(vap->va_type);
		fp->fa_mode = vtonfsv3_mode(vap->va_mode);
		txdr_hyper(&vap->va_data_size, &fp->fa3_size);
		txdr_hyper(&vap->va_data_alloc, &fp->fa3_used);
		fp->fa3_rdev.specdata1 = txdr_unsigned(major(vap->va_rdev));
		fp->fa3_rdev.specdata2 = txdr_unsigned(minor(vap->va_rdev));
		fp->fa3_fsid.nfsuquad[0] = 0;
		fp->fa3_fsid.nfsuquad[1] = txdr_unsigned(vap->va_fsid);
		txdr_hyper(&vap->va_fileid, &fp->fa3_fileid);
		txdr_nfsv3time(&vap->va_access_time, &fp->fa3_atime);
		txdr_nfsv3time(&vap->va_modify_time, &fp->fa3_mtime);
		txdr_nfsv3time(&vap->va_change_time, &fp->fa3_ctime);
	} else {
		fp->fa_type = vtonfsv2_type(vap->va_type);
		fp->fa_mode = vtonfsv2_mode(vap->va_type, vap->va_mode);
		fp->fa2_size = txdr_unsigned(vap->va_data_size);
		fp->fa2_blocksize = txdr_unsigned(vap->va_iosize);
		if (vap->va_type == VFIFO)
			fp->fa2_rdev = 0xffffffff;
		else
			fp->fa2_rdev = txdr_unsigned(vap->va_rdev);
		fp->fa2_blocks = txdr_unsigned(vap->va_data_alloc / NFS_FABLKSIZE);
		fp->fa2_fsid = txdr_unsigned(vap->va_fsid);
		fp->fa2_fileid = txdr_unsigned(vap->va_fileid);
		txdr_nfsv2time(&vap->va_access_time, &fp->fa2_atime);
		txdr_nfsv2time(&vap->va_modify_time, &fp->fa2_mtime);
		txdr_nfsv2time(&vap->va_change_time, &fp->fa2_ctime);
	}
}

/*
 * Build hash lists of net addresses and hang them off the NFS export.
 * Called by nfsrv_export() to set up the lists of export addresses.
 */
static int
nfsrv_hang_addrlist(struct nfs_export *nx, struct user_nfs_export_args *unxa)
{
	struct nfs_export_net_args nxna;
	struct nfs_netopt *no;
	struct radix_node_head *rnh;
	struct radix_node *rn;
	struct sockaddr *saddr, *smask;
	struct domain *dom;
	int i, error;
	unsigned int net;
	user_addr_t uaddr;
	kauth_cred_t cred;
	struct ucred temp_cred;

	uaddr = unxa->nxa_nets;
	for (net = 0; net < unxa->nxa_netcount; net++, uaddr += sizeof(nxna)) {
		error = copyin(uaddr, &nxna, sizeof(nxna));
		if (error)
			return (error);

		if (nxna.nxna_flags & (NX_MAPROOT|NX_MAPALL)) {
		        bzero(&temp_cred, sizeof(temp_cred));
			temp_cred.cr_uid = nxna.nxna_cred.cr_uid;
			temp_cred.cr_ngroups = nxna.nxna_cred.cr_ngroups;
			for (i=0; i < nxna.nxna_cred.cr_ngroups && i < NGROUPS; i++)
				temp_cred.cr_groups[i] = nxna.nxna_cred.cr_groups[i];

			cred = kauth_cred_create(&temp_cred);
			if (!cred)
				return (ENOMEM);
		} else {
			cred = NULL;
		}

		if (nxna.nxna_addr.ss_len == 0) {
			/* No address means this is a default/world export */
			if (nx->nx_flags & NX_DEFAULTEXPORT)
				return (EEXIST);
			nx->nx_flags |= NX_DEFAULTEXPORT;
			nx->nx_defopt.nxo_flags = nxna.nxna_flags;
			nx->nx_defopt.nxo_cred = cred;
			nx->nx_expcnt++;
			continue;
		}

		i = sizeof(struct nfs_netopt);
		i += nxna.nxna_addr.ss_len + nxna.nxna_mask.ss_len;
		MALLOC(no, struct nfs_netopt *, i, M_NETADDR, M_WAITOK);
		if (!no)
			return (ENOMEM);
		bzero(no, sizeof(struct nfs_netopt));
		no->no_opt.nxo_flags = nxna.nxna_flags;
		no->no_opt.nxo_cred = cred;

		saddr = (struct sockaddr *)(no + 1);
		bcopy(&nxna.nxna_addr, saddr, nxna.nxna_addr.ss_len);
		if (nxna.nxna_mask.ss_len) {
			smask = (struct sockaddr *)((caddr_t)saddr + nxna.nxna_addr.ss_len);
			bcopy(&nxna.nxna_mask, smask, nxna.nxna_mask.ss_len);
		} else {
			smask = NULL;
		}
		i = saddr->sa_family;
		if ((rnh = nx->nx_rtable[i]) == 0) {
			/*
			 * Seems silly to initialize every AF when most are not
			 * used, do so on demand here
			 */
			for (dom = domains; dom; dom = dom->dom_next)
				if (dom->dom_family == i && dom->dom_rtattach) {
					dom->dom_rtattach((void **)&nx->nx_rtable[i],
						dom->dom_rtoffset);
					break;
				}
			if ((rnh = nx->nx_rtable[i]) == 0) {
				kauth_cred_rele(cred);
				_FREE(no, M_NETADDR);
				return (ENOBUFS);
			}
		}
		rn = (*rnh->rnh_addaddr)((caddr_t)saddr, (caddr_t)smask, rnh, no->no_rnodes);
		if (rn == 0) {
			/*
			 * One of the reasons that rnh_addaddr may fail is that
			 * the entry already exists. To check for this case, we
			 * look up the entry to see if it is there. If so, we
			 * do not need to make a new entry but do continue.
			 */
			int matched = 0;
			rn = (*rnh->rnh_matchaddr)((caddr_t)saddr, rnh);
			if (rn != 0 && (rn->rn_flags & RNF_ROOT) == 0 &&
			    (((struct nfs_netopt *)rn)->no_opt.nxo_flags == nxna.nxna_flags)) {
				kauth_cred_t cred2 = ((struct nfs_netopt *)rn)->no_opt.nxo_cred;
				if (cred && cred2 && (cred->cr_uid == cred2->cr_uid) &&
				    (cred->cr_ngroups == cred2->cr_ngroups)) {
					for (i=0; i < cred2->cr_ngroups && i < NGROUPS; i++)
						if (cred->cr_groups[i] != cred2->cr_groups[i])
							break;
					if (i >= cred2->cr_ngroups || i >= NGROUPS)
						matched = 1;
				}
			}
			kauth_cred_rele(cred);
			_FREE(no, M_NETADDR);
			if (matched)
				continue;
			return (EPERM);
		}
		nx->nx_expcnt++;
	}

	return (0);
}

/*
 * In order to properly track an export's netopt count, we need to pass 
 * an additional argument to nfsrv_free_netopt() so that it can decrement
 * the export's netopt count.
 */
struct nfsrv_free_netopt_arg {
	uint32_t *cnt;
	struct radix_node_head *rnh;
};

static int
nfsrv_free_netopt(struct radix_node *rn, void *w)
{
	struct nfsrv_free_netopt_arg *fna = (struct nfsrv_free_netopt_arg *)w;
	struct radix_node_head *rnh = fna->rnh;
	uint32_t *cnt = fna->cnt;
	struct nfs_netopt *nno = (struct nfs_netopt *)rn;

	(*rnh->rnh_deladdr)(rn->rn_key, rn->rn_mask, rnh);
	if (nno->no_opt.nxo_cred)
		kauth_cred_rele(nno->no_opt.nxo_cred);
	_FREE((caddr_t)rn, M_NETADDR);
	*cnt -= 1;
	return (0);
}

/*
 * Free the net address hash lists that are hanging off the mount points.
 */
static void
nfsrv_free_addrlist(struct nfs_export *nx)
{
	int i;
	struct radix_node_head *rnh;
	struct nfsrv_free_netopt_arg fna;

	for (i = 0; i <= AF_MAX; i++)
		if ( (rnh = nx->nx_rtable[i]) ) {
			fna.rnh = rnh;
			fna.cnt = &nx->nx_expcnt;
			(*rnh->rnh_walktree)(rnh, nfsrv_free_netopt, (caddr_t)&fna);
			_FREE((caddr_t)rnh, M_RTABLE);
			nx->nx_rtable[i] = 0;
		}
}

void enablequotas(struct mount *mp, vfs_context_t ctx); // XXX

int
nfsrv_export(struct user_nfs_export_args *unxa, struct vfs_context *ctx)
{
	int error = 0, pathlen;
	struct nfs_exportfs *nxfs, *nxfs2, *nxfs3;
	struct nfs_export *nx, *nx2, *nx3;
	struct nfs_filehandle nfh;
	struct nameidata mnd, xnd;
	vnode_t mvp = NULL, xvp = NULL;
	mount_t mp;
	char path[MAXPATHLEN];
	int expisroot;

	if (unxa->nxa_flags & NXA_DELETE_ALL) {
		/* delete all exports on all file systems */
		lck_rw_lock_exclusive(&nfs_export_rwlock);
		while ((nxfs = LIST_FIRST(&nfs_exports))) {
			mp = vfs_getvfs_by_mntonname(nxfs->nxfs_path);
			if (mp)
				mp->mnt_flag &= ~MNT_EXPORTED;
			/* delete all exports on this file system */
			while ((nx = LIST_FIRST(&nxfs->nxfs_exports))) {
				LIST_REMOVE(nx, nx_next);
				LIST_REMOVE(nx, nx_hash);
				/* delete all netopts for this export */
				nfsrv_free_addrlist(nx);
				nx->nx_flags &= ~NX_DEFAULTEXPORT;
				if (nx->nx_defopt.nxo_cred) {
					kauth_cred_rele(nx->nx_defopt.nxo_cred);
					nx->nx_defopt.nxo_cred = NULL;
				}
				FREE(nx->nx_path, M_TEMP);
				FREE(nx, M_TEMP);
			}
			LIST_REMOVE(nxfs, nxfs_next);
			FREE(nxfs->nxfs_path, M_TEMP);
			FREE(nxfs, M_TEMP);
		}
		lck_rw_done(&nfs_export_rwlock);
		return (0);
	}

	error = copyinstr(unxa->nxa_fspath, path, MAXPATHLEN, (size_t *)&pathlen);
	if (error)
		return (error);

	lck_rw_lock_exclusive(&nfs_export_rwlock);

	// first check if we've already got an exportfs with the given ID
	LIST_FOREACH(nxfs, &nfs_exports, nxfs_next) {
		if (nxfs->nxfs_id == unxa->nxa_fsid)
			break;
	}
	if (nxfs) {
		/* verify exported FS path matches given path */
		if (strcmp(path, nxfs->nxfs_path)) {
			error = EEXIST;
			goto unlock_out;
		}
		mp = vfs_getvfs_by_mntonname(nxfs->nxfs_path);
		/* find exported FS root vnode */
		NDINIT(&mnd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1, 
			UIO_SYSSPACE, nxfs->nxfs_path, ctx);
		error = namei(&mnd);
		if (error)
			goto unlock_out;
		mvp = mnd.ni_vp;
		/* make sure it's (still) the root of a file system */
		if ((mvp->v_flag & VROOT) == 0) {
			error = EINVAL;
			goto out;
		}
		/* sanity check: this should be same mount */
		if (mp != vnode_mount(mvp)) {
			error = EINVAL;
			goto out;
		}
	} else {
		/* no current exported file system with that ID */
		if (!(unxa->nxa_flags & NXA_ADD)) {
			error = ENOENT;
			goto unlock_out;
		}

		/* find exported FS root vnode */
		NDINIT(&mnd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1, 
			UIO_SYSSPACE, path, ctx);
		error = namei(&mnd);
		if (error)
			goto unlock_out;
		mvp = mnd.ni_vp;
		/* make sure it's the root of a file system */
		if ((mvp->v_flag & VROOT) == 0) {
			error = EINVAL;
			goto out;
		}
		mp = vnode_mount(mvp);

		/* make sure the file system is NFS-exportable */
		nfh.nfh_len = NFS_MAX_FID_SIZE;
		error = VFS_VPTOFH(mvp, &nfh.nfh_len, &nfh.nfh_fid[0], NULL);
		if (!error && (nfh.nfh_len > (int)NFS_MAX_FID_SIZE))
			error = EIO;
		if (error)
			goto out;

		/* add an exportfs for it */
		MALLOC(nxfs, struct nfs_exportfs *, sizeof(struct nfs_exportfs), M_TEMP, M_WAITOK);
		if (!nxfs) {
			error = ENOMEM;
			goto out;
		}
		bzero(nxfs, sizeof(struct nfs_exportfs));
		nxfs->nxfs_id = unxa->nxa_fsid;
		MALLOC(nxfs->nxfs_path, char*, pathlen, M_TEMP, M_WAITOK);
		if (!nxfs->nxfs_path) {
			FREE(nxfs, M_TEMP);
			error = ENOMEM;
			goto out;
		}
		bcopy(path, nxfs->nxfs_path, pathlen);
		/* insert into list in reverse-sorted order */
		nxfs3 = NULL;
		LIST_FOREACH(nxfs2, &nfs_exports, nxfs_next) {
			if (strcmp(nxfs->nxfs_path, nxfs2->nxfs_path) > 0)
				break;
			nxfs3 = nxfs2;
		}
		if (nxfs2)
			LIST_INSERT_BEFORE(nxfs2, nxfs, nxfs_next);
		else if (nxfs3)
			LIST_INSERT_AFTER(nxfs3, nxfs, nxfs_next);
		else
			LIST_INSERT_HEAD(&nfs_exports, nxfs, nxfs_next);

		/* make sure any quotas are enabled before we export the file system */
		enablequotas(mp, ctx);
	}

	if (unxa->nxa_exppath) {
		error = copyinstr(unxa->nxa_exppath, path, MAXPATHLEN, (size_t *)&pathlen);
		if (error)
			goto out;
		LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
			if (nx->nx_id == unxa->nxa_expid)
				break;
		}
		if (nx) {
			/* verify exported FS path matches given path */
			if (strcmp(path, nx->nx_path)) {
				error = EEXIST;
				goto out;
			}
		} else {
			/* no current export with that ID */
			if (!(unxa->nxa_flags & NXA_ADD)) {
				error = ENOENT;
				goto out;
			}
			/* add an export for it */
			MALLOC(nx, struct nfs_export *, sizeof(struct nfs_export), M_TEMP, M_WAITOK);
			if (!nx) {
				error = ENOMEM;
				goto out1;
			}
			bzero(nx, sizeof(struct nfs_export));
			nx->nx_id = unxa->nxa_expid;
			nx->nx_fs = nxfs;
			MALLOC(nx->nx_path, char*, pathlen, M_TEMP, M_WAITOK);
			if (!nx->nx_path) {
				error = ENOMEM;
				FREE(nx, M_TEMP);
				nx = NULL;
				goto out1;
			}
			bcopy(path, nx->nx_path, pathlen);
			/* insert into list in reverse-sorted order */
			nx3 = NULL;
			LIST_FOREACH(nx2, &nxfs->nxfs_exports, nx_next) {
				if (strcmp(nx->nx_path, nx2->nx_path) > 0)
					break;
				nx3 = nx2;
			}
			if (nx2)
				LIST_INSERT_BEFORE(nx2, nx, nx_next);
			else if (nx3)
				LIST_INSERT_AFTER(nx3, nx, nx_next);
			else
				LIST_INSERT_HEAD(&nxfs->nxfs_exports, nx, nx_next);
			/* insert into hash */
			LIST_INSERT_HEAD(NFSEXPHASH(nxfs->nxfs_id, nx->nx_id), nx, nx_hash);

			/*
			 * We don't allow nested exports.  Check if the new entry
			 * nests with the entries before and after or if there's an
			 * entry for the file system root and subdirs.
			 */
			error = 0;
			if ((nx3 && !strncmp(nx3->nx_path, nx->nx_path, pathlen - 1) &&
				    (nx3->nx_path[pathlen-1] == '/')) ||
			    (nx2 && !strncmp(nx2->nx_path, nx->nx_path, strlen(nx2->nx_path)) &&
			    	    (nx->nx_path[strlen(nx2->nx_path)] == '/')))
				error = EINVAL;
			if (!error) {
				/* check export conflict with fs root export and vice versa */
				expisroot = !nx->nx_path[0] ||
					    ((nx->nx_path[0] == '.') && !nx->nx_path[1]);
				LIST_FOREACH(nx2, &nxfs->nxfs_exports, nx_next) {
					if (expisroot) {
						if (nx2 != nx)
							break;
					} else if (!nx2->nx_path[0])
						break;
					else if ((nx2->nx_path[0] == '.') && !nx2->nx_path[1])
						break;
				}
				if (nx2)
					error = EINVAL;
			}
			if (error) {
				printf("nfsrv_export: attempt to register nested exports: %s/%s\n",
					nxfs->nxfs_path, nx->nx_path);
				goto out1;
			}

			/* find export root vnode */
			if (!nx->nx_path[0] || ((nx->nx_path[0] == '.') && !nx->nx_path[1])) {
				/* exporting file system's root directory */
				xvp = mvp;
				vnode_get(xvp);
			} else {
				xnd.ni_cnd.cn_nameiop = LOOKUP;
				xnd.ni_cnd.cn_flags = LOCKLEAF;
				xnd.ni_pathlen = pathlen - 1;
				xnd.ni_cnd.cn_nameptr = xnd.ni_cnd.cn_pnbuf = path;
				xnd.ni_startdir = mvp;
				xnd.ni_usedvp   = mvp;
				xnd.ni_cnd.cn_context = ctx;
				error = lookup(&xnd);
				if (error)
					goto out1;
				xvp = xnd.ni_vp;
			}

			if (vnode_vtype(xvp) != VDIR) {
				error = EINVAL;
				vnode_put(xvp);
				goto out1;
			}

			/* grab file handle */
			nx->nx_fh.nfh_xh.nxh_version = NFS_FH_VERSION;
			nx->nx_fh.nfh_xh.nxh_fsid = nx->nx_fs->nxfs_id;
			nx->nx_fh.nfh_xh.nxh_expid = nx->nx_id;
			nx->nx_fh.nfh_xh.nxh_flags = 0;
			nx->nx_fh.nfh_xh.nxh_reserved = 0;
			nx->nx_fh.nfh_len = NFS_MAX_FID_SIZE;
			error = VFS_VPTOFH(xvp, &nx->nx_fh.nfh_len, &nx->nx_fh.nfh_fid[0], NULL);
			if (!error && (nx->nx_fh.nfh_len > (int)NFS_MAX_FID_SIZE)) {
				error = EIO;
			} else {
				nx->nx_fh.nfh_xh.nxh_fidlen = nx->nx_fh.nfh_len;
				nx->nx_fh.nfh_len += sizeof(nx->nx_fh.nfh_xh);
			}

			vnode_put(xvp);
			if (error)
				goto out1;
		}
	} else {
		nx = NULL;
	}

	/* perform the export changes */
	if (unxa->nxa_flags & NXA_DELETE) {
		if (!nx) {
			/* delete all exports on this file system */
			while ((nx = LIST_FIRST(&nxfs->nxfs_exports))) {
				LIST_REMOVE(nx, nx_next);
				LIST_REMOVE(nx, nx_hash);
				/* delete all netopts for this export */
				nfsrv_free_addrlist(nx);
				nx->nx_flags &= ~NX_DEFAULTEXPORT;
				if (nx->nx_defopt.nxo_cred) {
					kauth_cred_rele(nx->nx_defopt.nxo_cred);
					nx->nx_defopt.nxo_cred = NULL;
				}
				FREE(nx->nx_path, M_TEMP);
				FREE(nx, M_TEMP);
			}
			goto out1;
		} else {
			/* delete all netopts for this export */
			nfsrv_free_addrlist(nx);
			nx->nx_flags &= ~NX_DEFAULTEXPORT;
			if (nx->nx_defopt.nxo_cred) {
				kauth_cred_rele(nx->nx_defopt.nxo_cred);
				nx->nx_defopt.nxo_cred = NULL;
			}
		}
	}
	if (unxa->nxa_flags & NXA_ADD) {
		error = nfsrv_hang_addrlist(nx, unxa);
		if (!error)
			mp->mnt_flag |= MNT_EXPORTED;
	}

out1:
	if (nx && !nx->nx_expcnt) {
		/* export has no export options */
		LIST_REMOVE(nx, nx_next);
		LIST_REMOVE(nx, nx_hash);
		FREE(nx->nx_path, M_TEMP);
		FREE(nx, M_TEMP);
	}
	if (LIST_EMPTY(&nxfs->nxfs_exports)) {
		/* exported file system has no more exports */
		LIST_REMOVE(nxfs, nxfs_next);
		FREE(nxfs->nxfs_path, M_TEMP);
		FREE(nxfs, M_TEMP);
		mp->mnt_flag &= ~MNT_EXPORTED;
	}

out:
	if (mvp) {
		vnode_put(mvp);
		nameidone(&mnd);
	}
unlock_out:
	lck_rw_done(&nfs_export_rwlock);
	return (error);
}

static struct nfs_export_options *
nfsrv_export_lookup(struct nfs_export *nx, mbuf_t nam)
{
	struct nfs_export_options *nxo = NULL;
	struct nfs_netopt *no = NULL;
	struct radix_node_head *rnh;
	struct sockaddr *saddr;

	/* Lookup in the export list first. */
	if (nam != NULL) {
		saddr = mbuf_data(nam);
		rnh = nx->nx_rtable[saddr->sa_family];
		if (rnh != NULL) {
			no = (struct nfs_netopt *)
				(*rnh->rnh_matchaddr)((caddr_t)saddr, rnh);
			if (no && no->no_rnodes->rn_flags & RNF_ROOT)
				no = NULL;
			if (no)
				nxo = &no->no_opt;
		}
	}
	/* If no address match, use the default if it exists. */
	if ((nxo == NULL) && (nx->nx_flags & NX_DEFAULTEXPORT))
		nxo = &nx->nx_defopt;
	return (nxo);
}

/* find an export for the given handle */
static struct nfs_export *
nfsrv_fhtoexport(struct nfs_filehandle *nfhp)
{
	struct nfs_export *nx;
	nx = NFSEXPHASH(nfhp->nfh_xh.nxh_fsid, nfhp->nfh_xh.nxh_expid)->lh_first;
	for (; nx; nx = LIST_NEXT(nx, nx_hash)) {
		if (nx->nx_fs->nxfs_id != nfhp->nfh_xh.nxh_fsid)
			continue;
		if (nx->nx_id != nfhp->nfh_xh.nxh_expid)
			continue;
		break;
	}
	return nx;
}

/*
 * nfsrv_fhtovp() - convert FH to vnode and export info
 */
int
nfsrv_fhtovp(
	struct nfs_filehandle *nfhp,
	mbuf_t nam,
	__unused int pubflag,
	vnode_t *vpp,
	struct nfs_export **nxp,
	struct nfs_export_options **nxop)
{
	int error;
	struct mount *mp;

	*vpp = NULL;
	*nxp = NULL;
	*nxop = NULL;

	if (nfhp->nfh_xh.nxh_version != NFS_FH_VERSION) {
		/* file handle format not supported */
		return (ESTALE);
	}
	if (nfhp->nfh_len > NFS_MAX_FH_SIZE)
		return (EBADRPC);
	if (nfhp->nfh_len < (int)sizeof(nfhp->nfh_xh))
		return (ESTALE);
	if (nfhp->nfh_xh.nxh_flags & NXHF_INVALIDFH)
		return (ESTALE);

/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	if (nfs_ispublicfh(nfhp)) {
		if (!pubflag || !nfs_pub.np_valid)
			return (ESTALE);
		nfhp = &nfs_pub.np_handle;
	}
#endif

	*nxp = nfsrv_fhtoexport(nfhp);
	if (!*nxp)
		return (ESTALE);

	/* Get the export option structure for this <export, client> tuple. */
	*nxop = nfsrv_export_lookup(*nxp, nam);
	if (nam && (*nxop == NULL))
		return (EACCES);

	/* find mount structure */
	mp = vfs_getvfs_by_mntonname((*nxp)->nx_fs->nxfs_path);
	if (!mp)
		return (ESTALE);

	error = VFS_FHTOVP(mp, nfhp->nfh_xh.nxh_fidlen, &nfhp->nfh_fid[0], vpp, NULL);
	if (error)
		return (error);
	/* vnode pointer should be good at this point or ... */
	if (*vpp == NULL)
		return (ESTALE);
	return (0);
}

/*
 * nfsrv_credcheck() - check/map credentials according to given export options
 */
int
nfsrv_credcheck(
	struct nfsrv_descript *nfsd,
	__unused struct nfs_export *nx,
	struct nfs_export_options *nxo)
{
	if (nxo && nxo->nxo_cred) {
		if ((nxo->nxo_flags & NX_MAPALL) ||
		    ((nxo->nxo_flags & NX_MAPROOT) && !suser(nfsd->nd_cr, NULL))) {
			kauth_cred_rele(nfsd->nd_cr);
			nfsd->nd_cr = nxo->nxo_cred;
			kauth_cred_ref(nfsd->nd_cr);
		}
	}
	return (0);
}


/*
 * WebNFS: check if a filehandle is a public filehandle. For v3, this
 * means a length of 0, for v2 it means all zeroes. nfsm_srvmtofh has
 * transformed this to all zeroes in both cases, so check for it.
 */
int
nfs_ispublicfh(struct nfs_filehandle *nfhp)
{
	char *cp = (char *)nfhp;
	unsigned int i;

	if (nfhp->nfh_len == 0)
		return (TRUE);
	if (nfhp->nfh_len != NFSX_V2FH)
		return (FALSE);
	for (i = 0; i < NFSX_V2FH; i++)
		if (*cp++ != 0)
			return (FALSE);
	return (TRUE);
}

/*
 * nfsrv_vptofh() - convert vnode to file handle for given export
 *
 * If the caller is passing in a vnode for a ".." directory entry,
 * they can pass a directory NFS file handle (dnfhp) which will be
 * checked against the root export file handle.  If it matches, we
 * refuse to provide the file handle for the out-of-export directory.
 */
int
nfsrv_vptofh(
	struct nfs_export *nx,
	int v2,
	struct nfs_filehandle *dnfhp,
	vnode_t vp,
	struct vfs_context *ctx,
	struct nfs_filehandle *nfhp)
{
	int error;

	nfhp->nfh_xh.nxh_version = NFS_FH_VERSION;
	nfhp->nfh_xh.nxh_fsid = nx->nx_fs->nxfs_id;
	nfhp->nfh_xh.nxh_expid = nx->nx_id;
	nfhp->nfh_xh.nxh_flags = 0;
	nfhp->nfh_xh.nxh_reserved = 0;

	if (v2)
		bzero(&nfhp->nfh_fid[0], NFSV2_MAX_FID_SIZE);

	/* if directory FH matches export root, return invalid FH */
	if (dnfhp && nfsrv_fhmatch(dnfhp, &nx->nx_fh)) {
		nfhp->nfh_len = v2 ? NFSX_V2FH : sizeof(nfhp->nfh_xh);
		nfhp->nfh_xh.nxh_fidlen = 0;
		nfhp->nfh_xh.nxh_flags = NXHF_INVALIDFH;
		return (0);
	}

	nfhp->nfh_len = v2 ? NFSV2_MAX_FID_SIZE : NFS_MAX_FID_SIZE;
	error = VFS_VPTOFH(vp, &nfhp->nfh_len, &nfhp->nfh_fid[0], ctx);
	if (error)
		return (error);
	if (nfhp->nfh_len > (int)(v2 ? NFSV2_MAX_FID_SIZE : NFS_MAX_FID_SIZE))
		return (EOVERFLOW);
	nfhp->nfh_xh.nxh_fidlen = nfhp->nfh_len;
	nfhp->nfh_len += sizeof(nfhp->nfh_xh);
	if (v2 && (nfhp->nfh_len < NFSX_V2FH))
		nfhp->nfh_len = NFSX_V2FH;

	return (0);
}

int
nfsrv_fhmatch(struct nfs_filehandle *fh1, struct nfs_filehandle *fh2)
{
	int len1, len2;

	len1 = sizeof(fh1->nfh_xh) + fh1->nfh_xh.nxh_fidlen;
	len2 = sizeof(fh2->nfh_xh) + fh2->nfh_xh.nxh_fidlen;
	if (len1 != len2)
		return (0);
	if (bcmp(&fh1->nfh_xh, &fh2->nfh_xh, len1))
		return (0);
	return (1);
}
  
#endif /* NFS_NOSERVER */
/*
 * This function compares two net addresses by family and returns TRUE
 * if they are the same host.
 * If there is any doubt, return FALSE.
 * The AF_INET family is handled as a special case so that address mbufs
 * don't need to be saved to store "struct in_addr", which is only 4 bytes.
 */
int
netaddr_match(family, haddr, nam)
	int family;
	union nethostaddr *haddr;
	mbuf_t nam;
{
	struct sockaddr_in *inetaddr;

	switch (family) {
	case AF_INET:
		inetaddr = mbuf_data(nam);
		if (inetaddr->sin_family == AF_INET &&
		    inetaddr->sin_addr.s_addr == haddr->had_inetaddr)
			return (1);
		break;
#if ISO
	case AF_ISO:
	    {
		struct sockaddr_iso *isoaddr1, *isoaddr2;

		isoaddr1 = mbuf_data(nam);
		isoaddr2 = mbuf_data(haddr->had_nam);
		if (isoaddr1->siso_family == AF_ISO &&
		    isoaddr1->siso_nlen > 0 &&
		    isoaddr1->siso_nlen == isoaddr2->siso_nlen &&
		    SAME_ISOADDR(isoaddr1, isoaddr2))
			return (1);
		break;
	    }
#endif	/* ISO */
	default:
		break;
	};
	return (0);
}

static nfsuint64 nfs_nullcookie = { { 0, 0 } };
/*
 * This function finds the directory cookie that corresponds to the
 * logical byte offset given.
 */
nfsuint64 *
nfs_getcookie(np, off, add)
	struct nfsnode *np;
	off_t off;
	int add;
{
	struct nfsdmap *dp, *dp2;
	int pos;

	pos = off / NFS_DIRBLKSIZ;
	if (pos == 0) {
#if DIAGNOSTIC
		if (add)
			panic("nfs getcookie add at 0");
#endif
		return (&nfs_nullcookie);
	}
	pos--;
	dp = np->n_cookies.lh_first;
	if (!dp) {
		if (add) {
			MALLOC_ZONE(dp, struct nfsdmap *, sizeof(struct nfsdmap),
					M_NFSDIROFF, M_WAITOK);
			if (!dp)
				return ((nfsuint64 *)0);
			dp->ndm_eocookie = 0;
			LIST_INSERT_HEAD(&np->n_cookies, dp, ndm_list);
		} else
			return ((nfsuint64 *)0);
	}
	while (pos >= NFSNUMCOOKIES) {
		pos -= NFSNUMCOOKIES;
		if (dp->ndm_list.le_next) {
			if (!add && dp->ndm_eocookie < NFSNUMCOOKIES &&
				pos >= dp->ndm_eocookie)
				return ((nfsuint64 *)0);
			dp = dp->ndm_list.le_next;
		} else if (add) {
			MALLOC_ZONE(dp2, struct nfsdmap *, sizeof(struct nfsdmap),
					M_NFSDIROFF, M_WAITOK);
			if (!dp2)
				return ((nfsuint64 *)0);
			dp2->ndm_eocookie = 0;
			LIST_INSERT_AFTER(dp, dp2, ndm_list);
			dp = dp2;
		} else
			return ((nfsuint64 *)0);
	}
	if (pos >= dp->ndm_eocookie) {
		if (add)
			dp->ndm_eocookie = pos + 1;
		else
			return ((nfsuint64 *)0);
	}
	return (&dp->ndm_cookies[pos]);
}

/*
 * Invalidate cached directory information, except for the actual directory
 * blocks (which are invalidated separately).
 * Done mainly to avoid the use of stale offset cookies.
 */
void
nfs_invaldir(vp)
	vnode_t vp;
{
	struct nfsnode *np = VTONFS(vp);

#if DIAGNOSTIC
	if (vnode_vtype(vp) != VDIR)
		panic("nfs: invaldir not dir");
#endif
	np->n_direofoffset = 0;
	np->n_cookieverf.nfsuquad[0] = 0;
	np->n_cookieverf.nfsuquad[1] = 0;
	if (np->n_cookies.lh_first)
		np->n_cookies.lh_first->ndm_eocookie = 0;
}

/*
 * The write verifier has changed (probably due to a server reboot), so all
 * NB_NEEDCOMMIT blocks will have to be written again. Since they are on the
 * dirty block list as NB_DELWRI, all this takes is clearing the NB_NEEDCOMMIT
 * flag. Once done the new write verifier can be set for the mount point.
 */
static int
nfs_clearcommit_callout(vnode_t vp, __unused void *arg)
{
	struct nfsnode *np = VTONFS(vp);
	struct nfsbuflists blist;
	struct nfsbuf *bp;

	lck_mtx_lock(nfs_buf_mutex);
	if (nfs_buf_iterprepare(np, &blist, NBI_DIRTY)) {
		lck_mtx_unlock(nfs_buf_mutex);
		return (VNODE_RETURNED);
	}
	LIST_FOREACH(bp, &blist, nb_vnbufs) {
		if (nfs_buf_acquire(bp, NBAC_NOWAIT, 0, 0))
			continue;
		if ((bp->nb_flags & (NB_DELWRI | NB_NEEDCOMMIT))
			== (NB_DELWRI | NB_NEEDCOMMIT)) {
			bp->nb_flags &= ~NB_NEEDCOMMIT;
			np->n_needcommitcnt--;
		}
		nfs_buf_drop(bp);
	}
	CHECK_NEEDCOMMITCNT(np);
	nfs_buf_itercomplete(np, &blist, NBI_DIRTY);
	lck_mtx_unlock(nfs_buf_mutex);
	return (VNODE_RETURNED);
}

void
nfs_clearcommit(mount_t mp)
{
	vnode_iterate(mp, VNODE_NOLOCK_INTERNAL, nfs_clearcommit_callout, NULL);
}

#ifndef NFS_NOSERVER
/*
 * Map errnos to NFS error numbers. For Version 3 also filter out error
 * numbers not specified for the associated procedure.
 */
int
nfsrv_errmap(nd, err)
	struct nfsrv_descript *nd;
	int err;
{
	short *defaulterrp, *errp;

	if (nd->nd_flag & ND_NFSV3) {
	    if (nd->nd_procnum <= NFSPROC_COMMIT) {
		errp = defaulterrp = nfsrv_v3errmap[nd->nd_procnum];
		while (*++errp) {
			if (*errp == err)
				return (err);
			else if (*errp > err)
				break;
		}
		return ((int)*defaulterrp);
	    } else
		return (err & 0xffff);
	}
	if (err <= ELAST)
		return ((int)nfsrv_v2errmap[err - 1]);
	return (NFSERR_IO);
}

#endif /* NFS_NOSERVER */

