/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

/*
 * nfs version 2 and 3 server calls to vnode ops
 * - these routines generally have 3 phases
 *   1 - break down and validate rpc request in mbuf list
 *   2 - do the vnode ops for the request
 *       (surprisingly ?? many are very similar to syscalls in vfs_syscalls.c)
 *   3 - build the rpc reply in an mbuf list
 *   nb:
 *	- do not mix the phases, since the nfsm_?? macros can return failures
 *	  on a bad rpc or similar and do not do any vnode_rele()s or vnode_put()s
 *
 *      - the nfsm_reply() macro generates an nfs rpc reply with the nfs
 *	error number iff error != 0 whereas
 *	returning an error from the server function implies a fatal error
 *	such as a badly constructed rpc request that should be dropped without
 *	a reply.
 *	For Version 3, nfsm_reply() does not return for the error case, since
 *	most version 3 rpcs return more than the status for error cases.
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
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/vnode_internal.h>
#include <sys/uio_internal.h>
#include <libkern/OSAtomic.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#include <nfs/nfsproto.h>
#include <nfs/rpcv2.h>
#include <nfs/nfs.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>

nfstype nfsv3_type[9] = { NFNON, NFREG, NFDIR, NFBLK, NFCHR, NFLNK, NFSOCK,
		      NFFIFO, NFNON };
#ifndef NFS_NOSERVER 
nfstype nfsv2_type[9] = { NFNON, NFREG, NFDIR, NFBLK, NFCHR, NFLNK, NFNON,
		      NFCHR, NFNON };
/* Global vars */
extern u_long nfs_xdrneg1;
extern u_long nfs_false, nfs_true;
extern enum vtype nv3tov_type[8];
extern struct nfsstats nfsstats;

int nfsrvw_procrastinate = NFS_GATHERDELAY * 1000;
int nfsrvw_procrastinate_v3 = 0;

int nfs_async = 0;
#ifdef notyet
/* XXX CSM 11/25/97 Upgrade sysctl.h someday */
SYSCTL_INT(_vfs_nfs, OID_AUTO, async, CTLFLAG_RW, &nfs_async, 0, "");
#endif

static int nfsrv_authorize(vnode_t,vnode_t,kauth_action_t,vfs_context_t,struct nfs_export_options*,int);
static void nfsrvw_coalesce(struct nfsrv_descript *, struct nfsrv_descript *);

#define THREAD_SAFE_FS(VP)  \
        ((VP)->v_mount ? (VP)->v_mount->mnt_vtable->vfc_threadsafe : 0)

/*
 * nfs v3 access service
 */
int
nfsrv3_access(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	vnode_t vp;
	struct nfs_filehandle nfh;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, getret;
	char *cp2;
	mbuf_t mb, mreq, mb2;
	struct vnode_attr vattr, *vap = &vattr;
	u_long nfsmode;
	kauth_action_t testaction;
	struct vfs_context context;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;

	nfsm_srvmtofh(&nfh);
	nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, NULL);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, NULL);
		return (0);
	}
	nfsmode = fxdr_unsigned(u_long, *tl);

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	/*
	 * Each NFS mode bit is tested separately.
	 *
	 * XXX this code is nominally correct, but returns a pessimistic
	 *     rather than optimistic result.  It will be necessary to add
	 *     an NFS-specific interface to the vnode_authorize code to
	 *     obtain good performance in the optimistic mode.
	 */
	if (nfsmode & NFSV3ACCESS_READ) {
		if (vnode_isdir(vp)) {
			testaction =
			    KAUTH_VNODE_LIST_DIRECTORY |
			    KAUTH_VNODE_READ_EXTATTRIBUTES;
		} else {
			testaction =
			    KAUTH_VNODE_READ_DATA |
			    KAUTH_VNODE_READ_EXTATTRIBUTES;
		}
		if (nfsrv_authorize(vp, NULL, testaction, &context, nxo, 0))
			nfsmode &= ~NFSV3ACCESS_READ;
	}
	if ((nfsmode & NFSV3ACCESS_LOOKUP) &&
	    (!vnode_isdir(vp) ||
	    nfsrv_authorize(vp, NULL, KAUTH_VNODE_SEARCH, &context, nxo, 0)))
		nfsmode &= ~NFSV3ACCESS_LOOKUP;
	if (nfsmode & NFSV3ACCESS_MODIFY) {
		if (vnode_isdir(vp)) {
			testaction =
			    KAUTH_VNODE_ADD_FILE |
			    KAUTH_VNODE_ADD_SUBDIRECTORY |
			    KAUTH_VNODE_DELETE_CHILD;
		} else {
			testaction =
                           KAUTH_VNODE_WRITE_DATA;
		}
		if (nfsrv_authorize(vp, NULL, testaction, &context, nxo, 0))
			nfsmode &= ~NFSV3ACCESS_MODIFY;
	}
	if (nfsmode & NFSV3ACCESS_EXTEND) {
		if (vnode_isdir(vp)) {
			testaction =
			    KAUTH_VNODE_ADD_FILE |
			    KAUTH_VNODE_ADD_SUBDIRECTORY;
		} else {
			testaction =
			    KAUTH_VNODE_WRITE_DATA |
			    KAUTH_VNODE_APPEND_DATA;
		}
		if (nfsrv_authorize(vp, NULL, testaction, &context, nxo, 0))
			nfsmode &= ~NFSV3ACCESS_EXTEND;
	}

	/*
	 * Note concerning NFSV3ACCESS_DELETE:
	 * For hard links, the answer may be wrong if the vnode
	 * has multiple parents with different permissions.
	 * Also, some clients (e.g. MacOSX 10.3) may incorrectly
	 * interpret the missing/cleared DELETE bit.
	 * So we'll just leave the DELETE bit alone.  At worst,
	 * we're telling the client it might be able to do
	 * something it really can't.
	 */

	if ((nfsmode & NFSV3ACCESS_EXECUTE) &&
	    (vnode_isdir(vp) ||
	    nfsrv_authorize(vp, NULL, KAUTH_VNODE_EXECUTE, &context, nxo, 0)))
		nfsmode &= ~NFSV3ACCESS_EXECUTE;

	nfsm_srv_vattr_init(vap, 1);
	getret = vnode_getattr(vp, vap, &context);
	vnode_put(vp);
	nfsm_reply(NFSX_POSTOPATTR(1) + NFSX_UNSIGNED);
	nfsm_srvpostop_attr(getret, vap);
	nfsm_build(tl, u_long *, NFSX_UNSIGNED);
	*tl = txdr_unsigned(nfsmode);
nfsmout:
	return (error);
}

/*
 * nfs getattr service
 */
int
nfsrv_getattr(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct nfs_fattr *fp;
	struct vnode_attr va;
	struct vnode_attr *vap = &va;
	vnode_t vp;
	struct nfs_filehandle nfh;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	struct vfs_context context;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	int v3 = (nfsd->nd_flag & ND_NFSV3);

	nfsm_srvmtofh(&nfh);
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(0);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(0);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	nfsm_srv_vattr_init(vap, v3);
	error = vnode_getattr(vp, vap, &context);
	vnode_put(vp);
	nfsm_reply(NFSX_FATTR(v3));
	if (error)
		return (0);
	nfsm_build(fp, struct nfs_fattr *, NFSX_FATTR(v3));
	nfsm_srvfillattr(vap, fp);
nfsmout:
	return (error);
}

/*
 * nfs setattr service
 */
int
nfsrv_setattr(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct vnode_attr preat;
	struct vnode_attr postat;
	struct vnode_attr va;
	struct vnode_attr *vap = &va;
	struct nfsv2_sattr *sp;
	struct nfs_fattr *fp;
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, preat_ret = 1, postat_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3), gcheck = 0;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	struct timespec guard;
	struct vfs_context context;
	kauth_action_t action;
	uid_t saved_uid;

	nfsm_srvmtofh(&nfh);
	VATTR_INIT(vap);
	if (v3) {
		nfsm_srvsattr(vap);
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		gcheck = fxdr_unsigned(int, *tl);
		if (gcheck) {
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
			fxdr_nfsv3time(tl, &guard);
		}
	} else {
		nfsm_dissect(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		/*
		 * Nah nah nah nah na nah
		 * There is a bug in the Sun client that puts 0xffff in the mode
		 * field of sattr when it should put in 0xffffffff. The u_short
		 * doesn't sign extend.
		 * --> check the low order 2 bytes for 0xffff
		 */
		if ((fxdr_unsigned(int, sp->sa_mode) & 0xffff) != 0xffff)
			VATTR_SET(vap, va_mode, nfstov_mode(sp->sa_mode));
		if (sp->sa_uid != nfs_xdrneg1)
			VATTR_SET(vap, va_uid, fxdr_unsigned(uid_t, sp->sa_uid));
		if (sp->sa_gid != nfs_xdrneg1)
			VATTR_SET(vap, va_gid, fxdr_unsigned(gid_t, sp->sa_gid));
		if (sp->sa_size != nfs_xdrneg1)
			VATTR_SET(vap, va_data_size, fxdr_unsigned(u_quad_t, sp->sa_size));
		if (sp->sa_atime.nfsv2_sec != nfs_xdrneg1) {
			fxdr_nfsv2time(&sp->sa_atime, &vap->va_access_time);
			VATTR_SET_ACTIVE(vap, va_access_time);
		}
		if (sp->sa_mtime.nfsv2_sec != nfs_xdrneg1) {
			fxdr_nfsv2time(&sp->sa_mtime, &vap->va_modify_time);
			VATTR_SET_ACTIVE(vap, va_modify_time);
		}
	}

	/*
	 * Save the original credential UID in case they are
	 * mapped and we need to map the IDs in the attributes.
	 */
	saved_uid = kauth_cred_getuid(nfsd->nd_cr);

	/*
	 * Now that we have all the fields, lets do it.
	 */
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(preat_ret, &preat, postat_ret, &postat);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(preat_ret, &preat, postat_ret, &postat);
		return (0);
	}

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	if (v3) {
		nfsm_srv_pre_vattr_init(&preat, v3);
		error = preat_ret = vnode_getattr(vp, &preat, &context);
		if (!error && gcheck && VATTR_IS_SUPPORTED(&preat, va_change_time) &&
			(preat.va_change_time.tv_sec != guard.tv_sec ||
			 preat.va_change_time.tv_nsec != guard.tv_nsec))
			error = NFSERR_NOT_SYNC;
		if (!preat_ret && !VATTR_ALL_SUPPORTED(&preat))
			preat_ret = 1;
		if (error) {
			vnode_put(vp);
			nfsm_reply(NFSX_WCCDATA(v3));
			nfsm_srvwcc_data(preat_ret, &preat, postat_ret, &postat);
			return (0);
		}
	}

	/*
	 * If the credentials were mapped, we should
	 * map the same values in the attributes.
	 */
	if ((vap->va_uid == saved_uid) && (kauth_cred_getuid(nfsd->nd_cr) != saved_uid)) {
		int ismember;
		VATTR_SET(vap, va_uid, kauth_cred_getuid(nfsd->nd_cr));
		if (kauth_cred_ismember_gid(nfsd->nd_cr, vap->va_gid, &ismember) || !ismember)
			VATTR_SET(vap, va_gid, kauth_cred_getgid(nfsd->nd_cr));
	}

	/*
	 * Authorize the attribute changes.
	 */
	if (((error = vnode_authattr(vp, vap, &action, &context))) ||
	    ((error = nfsrv_authorize(vp, NULL, action, &context, nxo, 0))))
		goto out;
	error = vnode_setattr(vp, vap, &context);

	nfsm_srv_vattr_init(&postat, v3);
	postat_ret = vnode_getattr(vp, &postat, &context);
	if (!error)
		error = postat_ret;
out:
	vnode_put(vp);
	nfsm_reply(NFSX_WCCORFATTR(v3));
	if (v3) {
		nfsm_srvwcc_data(preat_ret, &preat, postat_ret, &postat);
		return (0);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(&postat, fp);
	}
nfsmout:
	return (error);
}

/*
 * nfs lookup rpc
 */
int
nfsrv_lookup(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct nfs_fattr *fp;
	struct nameidata nd, *ndp = &nd;
/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	struct nameidata ind;
#endif
	vnode_t vp, dirp = NULL;
	struct nfs_filehandle dnfh, nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	caddr_t cp;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, len, dirattr_ret = 1, isdotdot;
	int v3 = (nfsd->nd_flag & ND_NFSV3), pubflag;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	struct vnode_attr va, dirattr, *vap = &va;
	struct vfs_context context;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	nfsm_srvmtofh(&dnfh);
	nfsm_srvnamesiz(len, v3);

	pubflag = nfs_ispublicfh(&dnfh);

	nd.ni_cnd.cn_nameiop = LOOKUP;
	nd.ni_cnd.cn_flags = LOCKLEAF;
	error = nfsm_path_mbuftond(&md, &dpos, v3, pubflag, &len, &nd);
	isdotdot = ((len == 2) && (nd.ni_cnd.cn_pnbuf[0] == '.') && (nd.ni_cnd.cn_pnbuf[1] == '.'));
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &dnfh, nam, pubflag, &dirp, &nx, &nxo);

/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	if (!error && pubflag) {
		if (vnode_vtype(nd.ni_vp) == VDIR && nfs_pub.np_index != NULL) {
			/*
			 * Setup call to lookup() to see if we can find
			 * the index file. Arguably, this doesn't belong
			 * in a kernel.. Ugh.
			 */
			ind = nd;
			ind.ni_pathlen = strlen(nfs_pub.np_index);
			ind.ni_cnd.cn_nameptr = ind.ni_cnd.cn_pnbuf =
			    nfs_pub.np_index;
			ind.ni_startdir = nd.ni_vp;
			ind.ni_usedvp   = nd.ni_vp;

			if (!(error = lookup(&ind))) {
				/*
				 * Found an index file. Get rid of
				 * the old references.
				 */
				if (dirp)	
					vnode_put(dirp);
				dirp = nd.ni_vp;
				vnode_put(nd.ni_startdir);
				ndp = &ind;
			} else
				error = 0;
		}
		/*
		 * If the public filehandle was used, check that this lookup
		 * didn't result in a filehandle outside the publicly exported
		 * filesystem.
		 */

		if (!error && vnode_mount(ndp->ni_vp) != nfs_pub.np_mount) {
			vnode_put(nd.ni_vp);
			nameidone(&nd);
			error = EPERM;
		}
	}
#endif

	if (dirp) {
		if (v3) {
			nfsm_srv_vattr_init(&dirattr, v3);
			dirattr_ret = vnode_getattr(dirp, &dirattr, &context);
		}
		vnode_put(dirp);
	}

	if (error) {
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
		return (0);
	}
	nameidone(&nd);

	vp = ndp->ni_vp;
	error = nfsrv_vptofh(nx, !v3, (isdotdot ? &dnfh : NULL), vp, &context, &nfh);
	if (!error) {
		nfsm_srv_vattr_init(vap, v3);
		error = vnode_getattr(vp, vap, &context);
	}
	vnode_put(vp);
	nfsm_reply(NFSX_SRVFH(v3, &nfh) + NFSX_POSTOPORFATTR(v3) + NFSX_POSTOPATTR(v3));
	if (error) {
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
		return (0);
	}
	nfsm_srvfhtom(&nfh, v3);
	if (v3) {
		nfsm_srvpostop_attr(0, vap);
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(vap, fp);
	}
nfsmout:
	return (error);
}

/*
 * nfs readlink service
 */
int
nfsrv_readlink(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	mbuf_t mp;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, i, tlen, len, getret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	mbuf_t mb, mb2, mp2, mp3, mreq;
	vnode_t vp;
	struct vnode_attr attr;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t uiop = NULL;
	char uio_buf[ UIO_SIZEOF(4) ];
	char *uio_bufp = &uio_buf[0];
	int uio_buflen = UIO_SIZEOF(4);
	int mblen;
	struct vfs_context context;

	nfsm_srvmtofh(&nfh);
	len = 0;
	i = 0;

	mp2 = mp3 = NULL;
	vp = NULL;
	while (len < NFS_MAXPATHLEN) {
		mp = NULL;
		if ((error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &mp)))
			goto out;
		mblen = mbuf_maxlen(mp);
		mbuf_setlen(mp, mblen);
		if (len == 0)
			mp3 = mp2 = mp;
		else {
			if ((error = mbuf_setnext(mp2, mp))) {
				mbuf_free(mp);
				goto out;
			}
			mp2 = mp;
		}
		if ((len + mblen) > NFS_MAXPATHLEN) {
			mbuf_setlen(mp, NFS_MAXPATHLEN - len);
			len = NFS_MAXPATHLEN;
		} else
			len += mblen;
  		i++;
	}
	if (i > 4) {
		uio_buflen = UIO_SIZEOF(i);
		MALLOC(uio_bufp, char*, uio_buflen, M_TEMP, M_WAITOK);
		if (!uio_bufp) {
			error = ENOMEM;
			mbuf_freem(mp3);
			nfsm_reply(2 * NFSX_UNSIGNED);
			nfsm_srvpostop_attr(1, NULL);
			return (0);
		}
	}
	uiop = uio_createwithbuffer(i, 0, UIO_SYSSPACE, UIO_READ, uio_bufp, uio_buflen);
	if (!uiop) {
		error = ENOMEM;
		mbuf_freem(mp3);
		if (uio_bufp != &uio_buf[0]) {
			FREE(uio_bufp, M_TEMP);
			uio_bufp = &uio_buf[0];
		}
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, NULL);
		return (0);
	}
	mp = mp3;
	while (mp) {
		uio_addiov(uiop, CAST_USER_ADDR_T((caddr_t)mbuf_data(mp)), mbuf_len(mp));
		mp = mbuf_next(mp);
	}

	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		mbuf_freem(mp3);
		if (uio_bufp != &uio_buf[0]) {
			FREE(uio_bufp, M_TEMP);
			uio_bufp = &uio_buf[0];
		}
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, NULL);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		mbuf_freem(mp3);
		if (uio_bufp != &uio_buf[0]) {
			FREE(uio_bufp, M_TEMP);
			uio_bufp = &uio_buf[0];
		}
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, NULL);
		return (0);
	}
	if (vnode_vtype(vp) != VLNK) {
		if (v3)
			error = EINVAL;
		else
			error = ENXIO;
		goto out;
	}

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	if ((error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, &context, nxo, 0)))
		goto out;
	error = VNOP_READLINK(vp, uiop, &context);
out:
	if (vp) {
		if (v3) {
			nfsm_srv_vattr_init(&attr, v3);
			getret = vnode_getattr(vp, &attr, &context);
		}
		vnode_put(vp);
	}
	if (error) {
		mbuf_freem(mp3);
		mp3 = NULL;
	}
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_UNSIGNED);
	if (v3) {
		nfsm_srvpostop_attr(getret, &attr);
		if (error) {
			if (uio_bufp != &uio_buf[0])
				FREE(uio_bufp, M_TEMP);
			return (0);
		}
	}
	if (!error) {
		if (uiop && (uio_resid(uiop) > 0)) {
			// LP64todo - fix this
			len -= uio_resid(uiop);
			tlen = nfsm_rndup(len);
			nfsm_adj(mp3, NFS_MAXPATHLEN-tlen, tlen-len);
		}
		nfsm_build(tl, u_long *, NFSX_UNSIGNED);
		*tl = txdr_unsigned(len);
		mbuf_setnext(mb, mp3);
	}
nfsmout:
	if (uio_bufp != &uio_buf[0])
		FREE(uio_bufp, M_TEMP);
	return (error);
}

/*
 * nfs read service
 */
int
nfsrv_read(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	mbuf_t m;
	struct nfs_fattr *fp;
	u_long *tl;
	long t1;
	int i;
	caddr_t bpos;
	int error = 0, count, len, left, siz, tlen, getret;
	int v3 = (nfsd->nd_flag & ND_NFSV3), reqlen, maxlen;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	mbuf_t m2;
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t uiop = NULL;
	char *uio_bufp = NULL;
	struct vnode_attr va, *vap = &va;
	off_t off;
	char uio_buf[ UIO_SIZEOF(0) ];
	struct vfs_context context;

	nfsm_srvmtofh(&nfh);
	if (v3) {
		nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
		fxdr_hyper(tl, &off);
	} else {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		off = (off_t)fxdr_unsigned(u_long, *tl);
	}
	nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
	reqlen = fxdr_unsigned(u_long, *tl);
	maxlen = NFS_SRVMAXDATA(nfsd);
	if (reqlen > maxlen)
		reqlen = maxlen;

	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, NULL);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, NULL);
		return (0);
	}
	if (vnode_vtype(vp) != VREG) {
		if (v3)
			error = EINVAL;
		else
			error = (vnode_vtype(vp) == VDIR) ? EISDIR : EACCES;
	}

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	if (!error) {
	    if ((error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, &context, nxo, 1)))
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_EXECUTE, &context, nxo, 1);
	}
	nfsm_srv_vattr_init(vap, v3);
	getret = vnode_getattr(vp, vap, &context);
	if (!error)
		error = getret;
	if (error) {
		vnode_put(vp);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, vap);
		return (0);
	}
	if ((u_quad_t)off >= vap->va_data_size)
		count = 0;
	else if (((u_quad_t)off + reqlen) > vap->va_data_size)
		count = nfsm_rndup(vap->va_data_size - off);
	else
		count = reqlen;
	nfsm_reply(NFSX_POSTOPORFATTR(v3) + 3 * NFSX_UNSIGNED+nfsm_rndup(count));
	if (v3) {
		nfsm_build(tl, u_long *, NFSX_V3FATTR + 4 * NFSX_UNSIGNED);
		*tl++ = nfs_true;
		fp = (struct nfs_fattr *)tl;
		tl += (NFSX_V3FATTR / sizeof (u_long));
	} else {
		nfsm_build(tl, u_long *, NFSX_V2FATTR + NFSX_UNSIGNED);
		fp = (struct nfs_fattr *)tl;
		tl += (NFSX_V2FATTR / sizeof (u_long));
	}
	len = left = count;
	if (count > 0) {
		/*
		 * Generate the mbuf list with the uio_iov ref. to it.
		 */
		i = 0;
		m = m2 = mb;
		while (left > 0) {
			siz = min(mbuf_trailingspace(m), left);
			if (siz > 0) {
				left -= siz;
				i++;
			}
			if (left > 0) {
				m = NULL;
				if ((error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &m)))
					goto errorexit;
				mbuf_setnext(m2, m);
				m2 = m;
			}
		}
		MALLOC(uio_bufp, char *, UIO_SIZEOF(i), M_TEMP, M_WAITOK);
		if (!uio_bufp) {
			error = ENOMEM;
			goto errorexit;
		}
		uiop = uio_createwithbuffer(i, off, UIO_SYSSPACE, UIO_READ, 
					uio_bufp, UIO_SIZEOF(i));
		if (!uiop) {
			error = ENOMEM;
			goto errorexit;
		}
		m = mb;
		left = count;
		i = 0;
		while (left > 0) {
			if (m == NULL)
				panic("nfsrv_read iov");
			siz = min(mbuf_trailingspace(m), left);
			if (siz > 0) {
				tlen = mbuf_len(m);
				uio_addiov(uiop, CAST_USER_ADDR_T((char *)mbuf_data(m) + tlen), siz);
				mbuf_setlen(m, tlen + siz);
				left -= siz;
				i++;
			}
			m = mbuf_next(m);
		}
		error = VNOP_READ(vp, uiop, IO_NODELOCKED, &context);
		off = uio_offset(uiop);
errorexit:
		/*
		 * This may seem a little weird that we drop the whole
		 * successful read if we get an error on the getattr.
		 * The reason is because we've already set up the reply
		 * to have postop attrs and omitting these optional bits
		 * would require shifting all the data in the reply.
		 *
		 * It would be more correct if we would simply drop the
		 * postop attrs if the getattr fails.  We might be able to
		 * do that easier if we allocated separate mbufs for the data.
		 */
		nfsm_srv_vattr_init(vap, v3);
		if (error || (getret = vnode_getattr(vp, vap, &context))) {
			if (!error)
				error = getret;
			mbuf_freem(mreq);
			vnode_put(vp);
			nfsm_reply(NFSX_POSTOPATTR(v3));
			nfsm_srvpostop_attr(getret, vap);
			if (uio_bufp != NULL) {
				FREE(uio_bufp, M_TEMP);
			}
			return (0);
		}
	} else {
		uiop = uio_createwithbuffer(0, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
		if (!uiop) {
			error = ENOMEM;
			goto errorexit;
		}
	}
	vnode_put(vp);
	nfsm_srvfillattr(vap, fp);
	// LP64todo - fix this
	len -= uio_resid(uiop);
	tlen = nfsm_rndup(len);
	if (count != tlen || tlen != len)
		nfsm_adj(mb, count - tlen, tlen - len);
	if (v3) {
		*tl++ = txdr_unsigned(len);
		if (len < reqlen)
			*tl++ = nfs_true;
		else
			*tl++ = nfs_false;
	}
	*tl = txdr_unsigned(len);
nfsmout:
	if (uio_bufp != NULL) {
		FREE(uio_bufp, M_TEMP);
	}
	return (error);
}

/*
 * nfs write service
 */
int
nfsrv_write(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	int i, count;
	mbuf_t mp;
	struct nfs_fattr *fp;
	struct vnode_attr va, forat;
	struct vnode_attr *vap = &va;
	u_long *tl;
	long t1;
	caddr_t bpos, tpos;
	int error = 0, len, forat_ret = 1;
	int ioflags, aftat_ret = 1, retlen, zeroing, adjust, tlen;
	int stable = NFSV3WRITE_FILESYNC;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	mbuf_t mb, mb2, mreq;
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t uiop;
	off_t off;
	char *uio_bufp = NULL;
	struct vfs_context context;

	if (mrep == NULL) {
		*mrq = NULL;
		return (0);
	}
	nfsm_srvmtofh(&nfh);
	if (v3) {
		nfsm_dissect(tl, u_long *, 5 * NFSX_UNSIGNED);
		fxdr_hyper(tl, &off);
		tl += 3;
		stable = fxdr_unsigned(int, *tl++);
	} else {
		nfsm_dissect(tl, u_long *, 4 * NFSX_UNSIGNED);
		off = (off_t)fxdr_unsigned(u_long, *++tl);
		tl += 2;
		if (nfs_async)
	    		stable = NFSV3WRITE_UNSTABLE;
	}
	retlen = len = fxdr_unsigned(long, *tl);
	count = i = 0;

	/*
	 * For NFS Version 2, it is not obvious what a write of zero length
	 * should do, but I might as well be consistent with Version 3,
	 * which is to return ok so long as there are no permission problems.
	 */
	if (len > 0) {
	    zeroing = 1;
	    mp = mrep;
	    while (mp) {
		if (mp == md) {
			zeroing = 0;
			tpos = mbuf_data(mp);
			tlen = mbuf_len(mp);
			adjust = dpos - tpos;
			tlen -= adjust;
			mbuf_setlen(mp, tlen);
			if (tlen > 0 && adjust > 0) {
				tpos += adjust;
				if ((error = mbuf_setdata(mp, tpos, tlen))) {
					nfsm_reply(2 * NFSX_UNSIGNED);
					nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
					return (0);
				}
			}
		}
		if (zeroing)
			mbuf_setlen(mp, 0);
		else if ((tlen = mbuf_len(mp)) > 0) {
			i += tlen;
			if (i > len) {
				mbuf_setlen(mp, tlen - (i - len));
				zeroing	= 1;
			}
			if (mbuf_len(mp) > 0)
				count++;
		}
		mp = mbuf_next(mp);
	    }
	}
	if (len > NFS_MAXDATA || len < 0 || i < len) {
		error = EIO;
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	}
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	if (v3) {
		nfsm_srv_pre_vattr_init(&forat, v3);
		forat_ret = vnode_getattr(vp, &forat, &context);
	}
	if (vnode_vtype(vp) != VREG) {
		if (v3)
			error = EINVAL;
		else
			error = (vnode_vtype(vp) == VDIR) ? EISDIR : EACCES;
	}
	if (!error) {
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA, &context, nxo, 1);
	}
	if (error) {
		vnode_put(vp);
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	}

	if (len > 0) {
	    MALLOC(uio_bufp, char *, UIO_SIZEOF(count), M_TEMP, M_WAITOK);
	    if (!uio_bufp) {
		error = ENOMEM;
		vnode_put(vp);
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	    }
	    uiop = uio_createwithbuffer(count, off, UIO_SYSSPACE, UIO_WRITE, uio_bufp, UIO_SIZEOF(count));
	    if (!uiop) {
		error = ENOMEM;
		vnode_put(vp);
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		if (uio_bufp != NULL) {
		    FREE(uio_bufp, M_TEMP);
		}
		return (0);
	    }
	    mp = mrep;
	    while (mp) {
		if ((tlen = mbuf_len(mp)) > 0)
		    uio_addiov(uiop, CAST_USER_ADDR_T((caddr_t)mbuf_data(mp)), tlen);
		mp = mbuf_next(mp);
	    }

	    /*
	     * XXX
	     * The IO_METASYNC flag indicates that all metadata (and not just
	     * enough to ensure data integrity) mus be written to stable storage
	     * synchronously.
	     * (IO_METASYNC is not yet implemented in 4.4BSD-Lite.)
	     */
	    if (stable == NFSV3WRITE_UNSTABLE)
		ioflags = IO_NODELOCKED;
	    else if (stable == NFSV3WRITE_DATASYNC)
		ioflags = (IO_SYNC | IO_NODELOCKED);
	    else
		ioflags = (IO_METASYNC | IO_SYNC | IO_NODELOCKED);
	
	    error = VNOP_WRITE(vp, uiop, ioflags, &context);
	    OSAddAtomic(1, (SInt32*)(SInt32*)&nfsstats.srvvop_writes);
	}
	nfsm_srv_vattr_init(vap, v3);
	aftat_ret = vnode_getattr(vp, vap, &context);
	vnode_put(vp);
	if (!error)
		error = aftat_ret;
	nfsm_reply(NFSX_PREOPATTR(v3) + NFSX_POSTOPORFATTR(v3) +
		2 * NFSX_UNSIGNED + NFSX_WRITEVERF(v3));
	if (v3) {
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		if (error) {
			if (uio_bufp != NULL) {
				FREE(uio_bufp, M_TEMP);
			}
			return (0);
		}
		nfsm_build(tl, u_long *, 4 * NFSX_UNSIGNED);
		*tl++ = txdr_unsigned(retlen);
		/*
		 * If nfs_async is set, then pretend the write was FILESYNC.
		 */
		if (stable == NFSV3WRITE_UNSTABLE && !nfs_async)
			*tl++ = txdr_unsigned(stable);
		else
			*tl++ = txdr_unsigned(NFSV3WRITE_FILESYNC);
		/*
		 * Actually, there is no need to txdr these fields,
		 * but it may make the values more human readable,
		 * for debugging purposes.
		 */
		*tl++ = txdr_unsigned(boottime_sec());
		*tl = txdr_unsigned(0);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(vap, fp);
	}
nfsmout:
	if (uio_bufp != NULL) {
		FREE(uio_bufp, M_TEMP);
	}
	return (error);
}

/*
 * NFS write service with write gathering support. Called when
 * nfsrvw_procrastinate > 0.
 * See: Chet Juszczak, "Improving the Write Performance of an NFS Server",
 * in Proc. of the Winter 1994 Usenix Conference, pg. 247-259, San Franscisco,
 * Jan. 1994.
 */
int
nfsrv_writegather(ndp, slp, procp, mrq)
	struct nfsrv_descript **ndp;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mp;
	struct nfsrv_descript *wp, *nfsd, *owp, *swp;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct nfs_fattr *fp;
	int i;
	struct nfsrvw_delayhash *wpp;
	kauth_cred_t cred;
	struct vnode_attr va, forat;
	u_long *tl;
	long t1;
	caddr_t bpos, dpos, tpos;
	int error = 0, len, forat_ret = 1;
	int ioflags, aftat_ret = 1, adjust, v3, zeroing, tlen;
	char *cp2;
	mbuf_t mb, mb2, mreq, mrep, md;
	vnode_t vp;
	uio_t uiop = NULL;
	char *uio_bufp = NULL;
	u_quad_t cur_usec;
	struct timeval now;
	struct vfs_context context;

	context.vc_proc = procp;

#ifndef nolint
	i = 0;
	len = 0;
#endif

	*mrq = NULL;
	if (*ndp) {
	    nfsd = *ndp;
	    *ndp = NULL;
	    mrep = nfsd->nd_mrep;
	    md = nfsd->nd_md;
	    dpos = nfsd->nd_dpos;
	    cred = nfsd->nd_cr;
	    context.vc_ucred = cred;
	    v3 = (nfsd->nd_flag & ND_NFSV3);
	    LIST_INIT(&nfsd->nd_coalesce);
	    nfsd->nd_mreq = NULL;
	    nfsd->nd_stable = NFSV3WRITE_FILESYNC;
	    microuptime(&now);
	    cur_usec = (u_quad_t)now.tv_sec * 1000000 + (u_quad_t)now.tv_usec;
	    nfsd->nd_time = cur_usec +
		(v3 ? nfsrvw_procrastinate_v3 : nfsrvw_procrastinate);
    
	    /*
	     * Now, get the write header..
	     */
	    nfsm_srvmtofh(&nfsd->nd_fh);
	    /* XXX shouldn't we be checking for invalid FHs before doing any more work? */
	    if (v3) {
		nfsm_dissect(tl, u_long *, 5 * NFSX_UNSIGNED);
		fxdr_hyper(tl, &nfsd->nd_off);
		tl += 3;
		nfsd->nd_stable = fxdr_unsigned(int, *tl++);
	    } else {
		nfsm_dissect(tl, u_long *, 4 * NFSX_UNSIGNED);
		nfsd->nd_off = (off_t)fxdr_unsigned(u_long, *++tl);
		tl += 2;
		if (nfs_async)
			nfsd->nd_stable = NFSV3WRITE_UNSTABLE;
	    }
	    len = fxdr_unsigned(long, *tl);
	    nfsd->nd_len = len;
	    nfsd->nd_eoff = nfsd->nd_off + len;
    
	    /*
	     * Trim the header out of the mbuf list and trim off any trailing
	     * junk so that the mbuf list has only the write data.
	     */
	    zeroing = 1;
	    i = 0;
	    mp = mrep;
	    while (mp) {
		if (mp == md) {
		    zeroing = 0;
		    tpos = mbuf_data(mp);
		    tlen = mbuf_len(mp);
		    adjust = dpos - tpos;
		    tlen -= adjust;
		    mbuf_setlen(mp, tlen);
		    if (tlen > 0 && adjust > 0) {
			tpos += adjust;
			if ((error = mbuf_setdata(mp, tpos, tlen)))
				goto nfsmout;
		    }
		}
		if (zeroing)
		    mbuf_setlen(mp, 0);
		else {
		    tlen = mbuf_len(mp);
		    i += tlen;
		    if (i > len) {
			mbuf_setlen(mp, tlen - (i - len));
			zeroing = 1;
		    }
		}
		mp = mbuf_next(mp);
	    }
	    if (len > NFS_MAXDATA || len < 0  || i < len) {
nfsmout:
		mbuf_freem(mrep);
		mrep = NULL;
		error = EIO;
		nfsm_writereply(2 * NFSX_UNSIGNED, v3);
		if (v3)
		    nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, &va);
		nfsd->nd_mreq = mreq;
		nfsd->nd_mrep = NULL;
		nfsd->nd_time = 1;
	    }
    
	    /*
	     * Add this entry to the hash and time queues.
	     */
	    lck_mtx_lock(&slp->ns_wgmutex);
	    owp = NULL;
	    wp = slp->ns_tq.lh_first;
	    while (wp && wp->nd_time < nfsd->nd_time) {
		owp = wp;
		wp = wp->nd_tq.le_next;
	    }
	    if (owp) {
		LIST_INSERT_AFTER(owp, nfsd, nd_tq);
	    } else {
		LIST_INSERT_HEAD(&slp->ns_tq, nfsd, nd_tq);
	    }
	    if (nfsd->nd_mrep) {
		wpp = NWDELAYHASH(slp, nfsd->nd_fh.nfh_fid);
		owp = NULL;
		wp = wpp->lh_first;
		while (wp && !nfsrv_fhmatch(&nfsd->nd_fh, &wp->nd_fh)) {
		    owp = wp;
		    wp = wp->nd_hash.le_next;
		}
		while (wp && (wp->nd_off < nfsd->nd_off) &&
		    nfsrv_fhmatch(&nfsd->nd_fh, &wp->nd_fh)) {
		    owp = wp;
		    wp = wp->nd_hash.le_next;
		}
		if (owp) {
		    LIST_INSERT_AFTER(owp, nfsd, nd_hash);

		    /*
		     * Search the hash list for overlapping entries and
		     * coalesce.
		     */
		    for(; nfsd && NFSW_CONTIG(owp, nfsd); nfsd = wp) {
			wp = nfsd->nd_hash.le_next;
			if (NFSW_SAMECRED(owp, nfsd))
			    nfsrvw_coalesce(owp, nfsd);
		    }
		} else {
		    LIST_INSERT_HEAD(wpp, nfsd, nd_hash);
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
	for (nfsd = slp->ns_tq.lh_first; nfsd; nfsd = owp) {
		owp = nfsd->nd_tq.le_next;
		if (nfsd->nd_time > cur_usec)
		    break;
		if (nfsd->nd_mreq)
		    continue;
		LIST_REMOVE(nfsd, nd_tq);
		LIST_REMOVE(nfsd, nd_hash);
		mrep = nfsd->nd_mrep;
		nfsd->nd_mrep = NULL;
		v3 = (nfsd->nd_flag & ND_NFSV3);
		forat_ret = aftat_ret = 1;
		error = nfsrv_fhtovp(&nfsd->nd_fh, nfsd->nd_nam, TRUE, &vp, &nx, &nxo);
		if (!error) {
			error = nfsrv_credcheck(nfsd, nx, nxo);
			if (error)
				vnode_put(vp);
		}
		cred = nfsd->nd_cr;
		context.vc_ucred = cred;
		if (!error) {
		    if (v3) {
			nfsm_srv_pre_vattr_init(&forat, v3);
			forat_ret = vnode_getattr(vp, &forat, &context);
		    }
		    if (vnode_vtype(vp) != VREG) {
			if (v3)
			    error = EINVAL;
			else
			    error = (vnode_vtype(vp) == VDIR) ? EISDIR : EACCES;
		    }
		} else
		    vp = NULL;
		if (!error) {
		    error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA, &context, nxo, 1);
		}
    
		if (nfsd->nd_stable == NFSV3WRITE_UNSTABLE)
		    ioflags = IO_NODELOCKED;
		else if (nfsd->nd_stable == NFSV3WRITE_DATASYNC)
		    ioflags = (IO_SYNC | IO_NODELOCKED);
		else
		    ioflags = (IO_METASYNC | IO_SYNC | IO_NODELOCKED);

		if (!error && ((nfsd->nd_eoff - nfsd->nd_off) > 0)) {
		    mp = mrep;
		    i = 0;
		    while (mp) {
			if (mbuf_len(mp) > 0)
			    i++;
			mp = mbuf_next(mp);
		    }

		    MALLOC(uio_bufp, char *, UIO_SIZEOF(i), M_TEMP, M_WAITOK);
		    if (uio_bufp)
			uiop = uio_createwithbuffer(i, nfsd->nd_off, UIO_SYSSPACE,
						UIO_WRITE, uio_bufp, UIO_SIZEOF(i));
		    if (!uio_bufp || !uiop)
			error = ENOMEM;
		    if (!error) {
			mp = mrep;
			while (mp) {
			    if ((tlen = mbuf_len(mp)) > 0)
				uio_addiov(uiop, CAST_USER_ADDR_T((caddr_t)mbuf_data(mp)), tlen);
			    mp = mbuf_next(mp);
			}
			error = VNOP_WRITE(vp, uiop, ioflags, &context);
			OSAddAtomic(1, (SInt32*)&nfsstats.srvvop_writes);
		    }
		    if (uio_bufp) {
			FREE(uio_bufp, M_TEMP);
			uio_bufp = NULL;
		    }
		}
		mbuf_freem(mrep);
		mrep = NULL;
		if (vp) {
		    nfsm_srv_pre_vattr_init(&va, v3);
		    aftat_ret = vnode_getattr(vp, &va, &context);
		    vnode_put(vp);
		}

		/*
		 * Loop around generating replies for all write rpcs that have
		 * now been completed.
		 */
		swp = nfsd;
		do {
		    if (error) {
			nfsm_writereply(NFSX_WCCDATA(v3), v3);
			if (v3) {
			    nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, &va);
			}
		    } else {
			nfsm_writereply(NFSX_PREOPATTR(v3) +
			    NFSX_POSTOPORFATTR(v3) + 2 * NFSX_UNSIGNED +
			    NFSX_WRITEVERF(v3), v3);
			if (v3) {
			    nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, &va);
			    nfsm_build(tl, u_long *, 4 * NFSX_UNSIGNED);
			    *tl++ = txdr_unsigned(nfsd->nd_len);
			    *tl++ = txdr_unsigned(swp->nd_stable);
			    /*
			     * Actually, there is no need to txdr these fields,
			     * but it may make the values more human readable,
			     * for debugging purposes.
			     */
			    *tl++ = txdr_unsigned(boottime_sec());
			    *tl = txdr_unsigned(0);
			} else {
			    nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
			    nfsm_srvfillattr(&va, fp);
			}
		    }
		    nfsd->nd_mreq = mreq;
		    if (nfsd->nd_mrep)
			panic("nfsrv_write: nd_mrep not free");

		    /*
		     * Done. Put it at the head of the timer queue so that
		     * the final phase can return the reply.
		     */
		    if (nfsd != swp) {
			nfsd->nd_time = 1;
			LIST_INSERT_HEAD(&slp->ns_tq, nfsd, nd_tq);
		    }
		    nfsd = swp->nd_coalesce.lh_first;
		    if (nfsd) {
			LIST_REMOVE(nfsd, nd_tq);
		    }
		} while (nfsd);
		swp->nd_time = 1;
		LIST_INSERT_HEAD(&slp->ns_tq, swp, nd_tq);
		goto loop1;
	}

	/*
	 * Search for a reply to return.
	 */
	for (nfsd = slp->ns_tq.lh_first; nfsd; nfsd = nfsd->nd_tq.le_next)
		if (nfsd->nd_mreq) {
		    LIST_REMOVE(nfsd, nd_tq);
		    *mrq = nfsd->nd_mreq;
		    *ndp = nfsd;
		    break;
		}
	slp->ns_wgtime = slp->ns_tq.lh_first ? slp->ns_tq.lh_first->nd_time : 0;
	lck_mtx_unlock(&slp->ns_wgmutex);
	return (0);
}

/*
 * Coalesce the write request nfsd into owp. To do this we must:
 * - remove nfsd from the queues
 * - merge nfsd->nd_mrep into owp->nd_mrep
 * - update the nd_eoff and nd_stable for owp
 * - put nfsd on owp's nd_coalesce list
 */
static void
nfsrvw_coalesce(
        struct nfsrv_descript *owp,
        struct nfsrv_descript *nfsd)
{
        int overlap, error;
        mbuf_t mp, mpnext;
	struct nfsrv_descript *p;

        LIST_REMOVE(nfsd, nd_hash);
        LIST_REMOVE(nfsd, nd_tq);
        if (owp->nd_eoff < nfsd->nd_eoff) {
            overlap = owp->nd_eoff - nfsd->nd_off;
            if (overlap < 0)
                panic("nfsrv_coalesce: bad off");
            if (overlap > 0)
                mbuf_adj(nfsd->nd_mrep, overlap);
            mp = owp->nd_mrep;
            while ((mpnext = mbuf_next(mp)))
                mp = mpnext;
            error = mbuf_setnext(mp, nfsd->nd_mrep);
	    if (error)
	    	panic("nfsrvw_coalesce: mbuf_setnext failed: %d", error);
            owp->nd_eoff = nfsd->nd_eoff;
        } else {
            mbuf_freem(nfsd->nd_mrep);
	}
        nfsd->nd_mrep = NULL;
        if (nfsd->nd_stable == NFSV3WRITE_FILESYNC)
            owp->nd_stable = NFSV3WRITE_FILESYNC;
        else if (nfsd->nd_stable == NFSV3WRITE_DATASYNC &&
            owp->nd_stable == NFSV3WRITE_UNSTABLE)
            owp->nd_stable = NFSV3WRITE_DATASYNC;
        LIST_INSERT_HEAD(&owp->nd_coalesce, nfsd, nd_tq);

	/*
	 * If nfsd had anything else coalesced into it, transfer them
	 * to owp, otherwise their replies will never get sent.
	 */
	for (p = nfsd->nd_coalesce.lh_first; p;
	     p = nfsd->nd_coalesce.lh_first) {
	    LIST_REMOVE(p, nd_tq);
	    LIST_INSERT_HEAD(&owp->nd_coalesce, p, nd_tq);
	}
}

/*
 * Sort the group list in increasing numerical order.
 * (Insertion sort by Chris Torek, who was grossed out by the bubble sort
 *  that used to be here.)
 *
 * XXX ILLEGAL
 */
void
nfsrvw_sort(list, num)
        gid_t *list;
        int num;
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
 * copy credentials making sure that the result can be compared with bcmp().
 *
 * XXX ILLEGAL
 */
void
nfsrv_setcred(kauth_cred_t incred, kauth_cred_t outcred)
{
	int i;

	bzero((caddr_t)outcred, sizeof (*outcred));
	outcred->cr_ref = 1;
	outcred->cr_uid = kauth_cred_getuid(incred);
	outcred->cr_ngroups = incred->cr_ngroups;
	for (i = 0; i < incred->cr_ngroups; i++)
		outcred->cr_groups[i] = incred->cr_groups[i];
	nfsrvw_sort(outcred->cr_groups, outcred->cr_ngroups);
}

/*
 * nfs create service
 * now does a truncate to 0 length via. setattr if it already exists
 */
int
nfsrv_create(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct nfs_fattr *fp;
	struct vnode_attr dirfor, diraft, postat;
	struct vnode_attr va;
	struct vnode_attr *vap = &va;
	struct nfsv2_sattr *sp;
	u_long *tl;
	struct nameidata nd;
	caddr_t cp;
	long t1;
	caddr_t bpos;
	int error = 0, rdev, len, tsize, dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3), how, exclusive_flag = 0;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	vnode_t vp, dvp, dirp = NULL;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	u_quad_t tempsize;
	u_char cverf[NFSX_V3CREATEVERF];
	struct vfs_context context;
	uid_t saved_uid;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	/*
	 * Save the original credential UID in case they are
	 * mapped and we need to map the IDs in the attributes.
	 */
	saved_uid = kauth_cred_getuid(nfsd->nd_cr);

#ifndef nolint
	rdev = 0;
#endif
	nd.ni_cnd.cn_nameiop = 0;
	vp = dvp = NULL;
	nfsm_srvmtofh(&nfh);
	nfsm_srvnamesiz(len, v3);

	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &len, &nd);
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &nfh, nam, FALSE, &dirp, &nx, &nxo);
	if (dirp) {
		if (v3) {
			nfsm_srv_pre_vattr_init(&dirfor, v3);
			dirfor_ret = vnode_getattr(dirp, &dirfor, &context);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error) {
		nd.ni_cnd.cn_nameiop = 0;
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vnode_put(dirp);
		return (0);
	}
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	VATTR_INIT(vap);

	if (v3) {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		how = fxdr_unsigned(int, *tl);
		switch (how) {
		case NFSV3CREATE_GUARDED:
			if (vp) {
				error = EEXIST;
				break;
			}
		case NFSV3CREATE_UNCHECKED:
			nfsm_srvsattr(vap);
			break;
		case NFSV3CREATE_EXCLUSIVE:
			nfsm_dissect(cp, caddr_t, NFSX_V3CREATEVERF);
			bcopy(cp, cverf, NFSX_V3CREATEVERF);
			exclusive_flag = 1;
			if (vp == NULL)
				VATTR_SET(vap, va_mode, 0);
			break;
		};
		VATTR_SET(vap, va_type, VREG);
	} else {
	        enum vtype v_type;

		nfsm_dissect(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		v_type = IFTOVT(fxdr_unsigned(u_long, sp->sa_mode));
		if (v_type == VNON)
			v_type = VREG;
		VATTR_SET(vap, va_type, v_type);
		VATTR_SET(vap, va_mode, nfstov_mode(sp->sa_mode));

		switch (v_type) {
		case VREG:
			tsize = fxdr_unsigned(long, sp->sa_size);
			if (tsize != -1)
				VATTR_SET(vap, va_data_size, (u_quad_t)tsize);
			break;
		case VCHR:
		case VBLK:
		case VFIFO:
			rdev = fxdr_unsigned(long, sp->sa_size);
			break;
		default:
			break;
		};
	}

	/*
	 * If it doesn't exist, create it
	 * otherwise just truncate to 0 length
	 *   should I set the mode too ??
	 */
	if (vp == NULL) {
	        kauth_acl_t xacl = NULL;

		/*
		 * If the credentials were mapped, we should
		 * map the same values in the attributes.
		 */
		if ((vap->va_uid == saved_uid) && (kauth_cred_getuid(nfsd->nd_cr) != saved_uid)) {
			int ismember;
			VATTR_SET(vap, va_uid, kauth_cred_getuid(nfsd->nd_cr));
			if (kauth_cred_ismember_gid(nfsd->nd_cr, vap->va_gid, &ismember) || !ismember)
				VATTR_SET(vap, va_gid, kauth_cred_getgid(nfsd->nd_cr));
		}

		/* authorize before creating */
		error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context, nxo, 0);

		/* construct ACL and handle inheritance */
		if (!error) {
			error = kauth_acl_inherit(dvp,
			    NULL,
			    &xacl,
			    0 /* !isdir */,
			    &context);

			if (!error && xacl != NULL)
			        VATTR_SET(vap, va_acl, xacl);
		}
		VATTR_CLEAR_ACTIVE(vap, va_data_size);
		VATTR_CLEAR_ACTIVE(vap, va_access_time);

		/* validate new-file security information */
		if (!error) {
			error = vnode_authattr_new(dvp, vap, 0, &context);
			if (error && (VATTR_IS_ACTIVE(vap, va_uid) || VATTR_IS_ACTIVE(vap, va_gid))) {
				/*
				 * Most NFS servers just ignore the UID/GID attributes, so we   
				 * try ignoring them if that'll help the request succeed.
				 */
				VATTR_CLEAR_ACTIVE(vap, va_uid);
				VATTR_CLEAR_ACTIVE(vap, va_gid);
				error = vnode_authattr_new(dvp, vap, 0, &context);
			}
		}

		if (vap->va_type == VREG || vap->va_type == VSOCK) {

			if (!error)
				error = VNOP_CREATE(dvp, &vp, &nd.ni_cnd, vap, &context);
  
 			if (!error && !VATTR_ALL_SUPPORTED(vap))
			        /*
				 * If some of the requested attributes weren't handled by the VNOP,
				 * use our fallback code.
				 */
 				error = vnode_setattr_fallback(vp, vap, &context);

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
					error = vnode_setattr(vp, vap, &context);
				}
			}

		} else if (vap->va_type == VCHR || vap->va_type == VBLK ||
			vap->va_type == VFIFO) {
			if (vap->va_type == VCHR && rdev == (int)0xffffffff)
				VATTR_SET(vap, va_type, VFIFO);
			if (vap->va_type != VFIFO &&
			    (error = suser(nfsd->nd_cr, (u_short *)0))) {
				nfsm_reply(0);
			} else
				VATTR_SET(vap, va_rdev, (dev_t)rdev);

			error = VNOP_MKNOD(dvp, &vp, &nd.ni_cnd, vap, &context);

 			if (xacl != NULL)
 				kauth_acl_free(xacl);

			if (error) {
				nfsm_reply(0);
			}
			if (vp) {
				vnode_recycle(vp);
				vnode_put(vp);
				vp = NULL;
			}
			nd.ni_cnd.cn_nameiop = LOOKUP;
			nd.ni_cnd.cn_flags &= ~LOCKPARENT;
			nd.ni_cnd.cn_context = &context;
			nd.ni_startdir = dvp;
			nd.ni_usedvp   = dvp;
			error = lookup(&nd);
			if (!error) {
			        if (nd.ni_cnd.cn_flags & ISSYMLINK)
				        error = EINVAL;
				vp = nd.ni_vp;
			}
			if (error)
				nfsm_reply(0);
		} else {
			error = ENXIO;
		}
		/*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);
		nd.ni_cnd.cn_nameiop = 0;

		vnode_put(dvp);
	} else {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
	        nameidone(&nd);
		nd.ni_cnd.cn_nameiop = 0;

		vnode_put(dvp);

		if (!error && VATTR_IS_ACTIVE(vap, va_data_size)) {
			error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_WRITE_DATA,
			    &context, nxo, 0);
			if (!error) {
				tempsize = vap->va_data_size;
				VATTR_INIT(vap);
				VATTR_SET(vap, va_data_size, tempsize);
				error = vnode_setattr(vp, vap, &context);
			}
		}
	}
	if (!error) {
		error = nfsrv_vptofh(nx, !v3, NULL, vp, &context, &nfh);
		if (!error) {
			nfsm_srv_vattr_init(&postat, v3);
			error = vnode_getattr(vp, &postat, &context);
		}
	}
	if (vp)
	        vnode_put(vp);

	if (v3) {
		if (exclusive_flag && !error &&
			bcmp(cverf, (caddr_t)&postat.va_access_time, NFSX_V3CREATEVERF))
			error = EEXIST;
		nfsm_srv_vattr_init(&diraft, v3);
		diraft_ret = vnode_getattr(dirp, &diraft, &context);
		vnode_put(dirp);
		dirp = NULL;
	}
	nfsm_reply(NFSX_SRVFH(v3, &nfh) + NFSX_FATTR(v3) + NFSX_WCCDATA(v3));

	if (v3) {
		if (!error) {
			nfsm_srvpostop_fh(&nfh);
			nfsm_srvpostop_attr(0, &postat);
		}
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	} else {
		nfsm_srvfhtom(&nfh, v3);
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(&postat, fp);
	}
	return (0);
nfsmout:
	if (nd.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);

		if (vp)
			vnode_put(vp);
		vnode_put(dvp);
	}
	if (dirp)
		vnode_put(dirp);
	return (error);
}

/*
 * nfs v3 mknod service
 */
int
nfsrv_mknod(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct vnode_attr dirfor, diraft, postat;
	struct vnode_attr va;
	struct vnode_attr *vap = &va;
	u_long *tl;
	struct nameidata nd;
	long t1;
	caddr_t bpos;
	int error = 0, len, dirfor_ret = 1, diraft_ret = 1;
	u_long major, minor;
	enum vtype vtyp;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	vnode_t vp, dvp, dirp = NULL;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct vfs_context hacked_context;	/* XXX should we have this? */
	struct vfs_context context;
	uid_t saved_uid;
        kauth_acl_t xacl = NULL;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;
	hacked_context.vc_proc = procp;
	hacked_context.vc_ucred = proc_ucred(procp);

	/*
	 * Save the original credential UID in case they are
	 * mapped and we need to map the IDs in the attributes.
	 */
	saved_uid = kauth_cred_getuid(nfsd->nd_cr);

	vp = dvp = NULL;
	nd.ni_cnd.cn_nameiop = 0;
	nfsm_srvmtofh(&nfh);
	nfsm_srvnamesiz(len, 1);

	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_path_mbuftond(&md, &dpos, 1, FALSE, &len, &nd);
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &nfh, nam, FALSE, &dirp, &nx, &nxo);
	if (dirp) {
		nfsm_srv_pre_vattr_init(&dirfor, 1);
		dirfor_ret = vnode_getattr(dirp, &dirfor, &context);
	}
	if (error) {
		nd.ni_cnd.cn_nameiop = 0;
		nfsm_reply(NFSX_WCCDATA(1));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vnode_put(dirp);
		return (0);
	}
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
	vtyp = nfsv3tov_type(*tl);
	if (vtyp != VCHR && vtyp != VBLK && vtyp != VSOCK && vtyp != VFIFO) {
		error = NFSERR_BADTYPE;
		goto out;
	}
	VATTR_INIT(vap);
	nfsm_srvsattr(vap);

	if (vtyp == VCHR || vtyp == VBLK) {
		nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
		major = fxdr_unsigned(u_long, *tl++);
		minor = fxdr_unsigned(u_long, *tl);
		VATTR_SET(vap, va_rdev, makedev(major, minor));
	}

	/*
	 * If it doesn't exist, create it.
	 */
	if (vp) {
		error = EEXIST;
		goto out;
	}
	VATTR_SET(vap, va_type, vtyp);

	/*
	 * If the credentials were mapped, we should
	 * map the same values in the attributes.
	 */
	if ((vap->va_uid == saved_uid) && (kauth_cred_getuid(nfsd->nd_cr) != saved_uid)) {
		int ismember;
		VATTR_SET(vap, va_uid, kauth_cred_getuid(nfsd->nd_cr));
		if (kauth_cred_ismember_gid(nfsd->nd_cr, vap->va_gid, &ismember) || !ismember)
			VATTR_SET(vap, va_gid, kauth_cred_getgid(nfsd->nd_cr));
	}

	/* authorize before creating */
	error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context, nxo, 0);

	/* construct ACL and handle inheritance */
	if (!error) {
		error = kauth_acl_inherit(dvp,
		    NULL,
		    &xacl,
		    0 /* !isdir */,
		    &context);

		if (!error && xacl != NULL)
		        VATTR_SET(vap, va_acl, xacl);
	}
	VATTR_CLEAR_ACTIVE(vap, va_data_size);
	VATTR_CLEAR_ACTIVE(vap, va_access_time);

	/* validate new-file security information */
	if (!error) {
		error = vnode_authattr_new(dvp, vap, 0, &context);
		if (error && (VATTR_IS_ACTIVE(vap, va_uid) || VATTR_IS_ACTIVE(vap, va_gid))) {
			/*
			 * Most NFS servers just ignore the UID/GID attributes, so we   
			 * try ignoring them if that'll help the request succeed.
			 */
			VATTR_CLEAR_ACTIVE(vap, va_uid);
			VATTR_CLEAR_ACTIVE(vap, va_gid);
			error = vnode_authattr_new(dvp, vap, 0, &context);
		}
	}

	if (vtyp == VSOCK) {
		error = VNOP_CREATE(dvp, &vp, &nd.ni_cnd, vap, &context);

		if (!error && !VATTR_ALL_SUPPORTED(vap))
		        /*
			 * If some of the requested attributes weren't handled by the VNOP,
			 * use our fallback code.
			 */
			error = vnode_setattr_fallback(vp, vap, &context);
	} else {
		if (vtyp != VFIFO && (error = suser(nfsd->nd_cr, (u_short *)0))) {
			goto out1;
		}
		if ((error = VNOP_MKNOD(dvp, &vp, &nd.ni_cnd, vap, &context))) {
			goto out1;
		}
		if (vp) {
			vnode_recycle(vp);
			vnode_put(vp);
			vp = NULL;
		}
		nd.ni_cnd.cn_nameiop = LOOKUP;
		nd.ni_cnd.cn_flags &= ~LOCKPARENT;
		nd.ni_cnd.cn_context = &hacked_context;
		nd.ni_startdir = dvp;
		nd.ni_usedvp   = dvp;
		error = lookup(&nd);
		if (!error) {
		        vp = nd.ni_vp;
			if (nd.ni_cnd.cn_flags & ISSYMLINK)
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
	nameidone(&nd);
	nd.ni_cnd.cn_nameiop = 0;

	vnode_put(dvp);

	if (!error) {
		error = nfsrv_vptofh(nx, 0, NULL, vp, &context, &nfh);
		if (!error) {
			nfsm_srv_vattr_init(&postat, 1);
			error = vnode_getattr(vp, &postat, &context);
		}
	}
	if (vp)
		vnode_put(vp);

	nfsm_srv_vattr_init(&diraft, 1);
	diraft_ret = vnode_getattr(dirp, &diraft, &context);
	vnode_put(dirp);
	dirp = NULL;

	nfsm_reply(NFSX_SRVFH(1, &nfh) + NFSX_POSTOPATTR(1) + NFSX_WCCDATA(1));
	if (!error) {
		nfsm_srvpostop_fh(&nfh);
		nfsm_srvpostop_attr(0, &postat);
	}
	nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	return (0);
nfsmout:
	if (nd.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);

		if (vp)
			vnode_put(vp);
		vnode_put(dvp);
	}
	if (dirp)
		vnode_put(dirp);
	return (error);
}

/*
 * nfs remove service
 */
int
nfsrv_remove(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct nameidata nd;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, len, dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	mbuf_t mb, mreq;
	vnode_t vp, dvp, dirp = NULL;
	struct vnode_attr dirfor, diraft;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct vfs_context context;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	dvp = vp = NULL;
	nfsm_srvmtofh(&nfh);
	nfsm_srvnamesiz(len, v3);

	nd.ni_cnd.cn_nameiop = DELETE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &len, &nd);
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &nfh, nam, FALSE, &dirp, &nx, &nxo);
	if (dirp) {
	        if (v3) {
			nfsm_srv_pre_vattr_init(&dirfor, v3);
			dirfor_ret = vnode_getattr(dirp, &dirfor, &context);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (!error) {
		dvp = nd.ni_dvp;
		vp = nd.ni_vp;

		if (vnode_vtype(vp) == VDIR)
			error = EPERM;		/* POSIX */
		else if (vnode_isvroot(vp))
		        /*
			 * The root of a mounted filesystem cannot be deleted.
			 */
			error = EBUSY;
		else
			error = nfsrv_authorize(vp, dvp, KAUTH_VNODE_DELETE, &context, nxo, 0);

		if (!error)
			error = VNOP_REMOVE(dvp, vp, &nd.ni_cnd, 0, &context);

		/*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);

		vnode_put(vp);
	        vnode_put(dvp);
	}
	if (dirp) {
		nfsm_srv_vattr_init(&diraft, v3);
	        diraft_ret = vnode_getattr(dirp, &diraft, &context);
		vnode_put(dirp);
	}
	nfsm_reply(NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
nfsmout:
	return (error);
}

/*
 * nfs rename service
 */
int
nfsrv_rename(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	kauth_cred_t saved_cred = NULL;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, fromlen, tolen;
	int fdirfor_ret = 1, fdiraft_ret = 1;
	int tdirfor_ret = 1, tdiraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2, *frompath = NULL, *topath = NULL;
	mbuf_t mb, mreq;
	struct nameidata fromnd, tond;
	vnode_t fvp, tvp, tdvp, fdvp, fdirp = NULL;
	vnode_t tdirp = NULL;
	struct vnode_attr fdirfor, fdiraft, tdirfor, tdiraft;
	struct nfs_filehandle fnfh, tnfh;
	struct nfs_export *fnx, *tnx;
	struct nfs_export_options *fnxo, *tnxo;
	enum vtype fvtype, tvtype;
	int holding_mntlock;
	mount_t locked_mp;
	struct vfs_context context;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

#ifndef nolint
	fvp = (vnode_t)0;
#endif

	/*
	 * these need to be set before
	 * calling any nfsm_xxxx macros
	 * since they may take us out
	 * through the error path
	 */
	holding_mntlock = 0;
	fvp = tvp = NULL;
	fdvp = tdvp = NULL;
	locked_mp = NULL;

	nfsm_srvmtofh(&fnfh);
	nfsm_srvnamesiz(fromlen, v3);
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &fromlen, &fromnd);
	if (error) {
		nfsm_reply(0);
		return (0);
	}
	frompath = fromnd.ni_cnd.cn_pnbuf;
	nfsm_srvmtofh(&tnfh);
	nfsm_strsiz(tolen, NFS_MAXNAMLEN, v3);
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &tolen, &tond);
	if (error) {
		nfsm_reply(0);
		FREE_ZONE(frompath, MAXPATHLEN, M_NAMEI);
		return (0);
	}
	topath = tond.ni_cnd.cn_pnbuf;

	/*
	 * Remember our original uid so that we can reset cr_uid before
	 * the second nfs_namei() call, in case it is remapped.
	 */
	saved_cred = nfsd->nd_cr;
	kauth_cred_ref(saved_cred);
retry:
	fromnd.ni_cnd.cn_nameiop = DELETE;
	fromnd.ni_cnd.cn_flags = WANTPARENT;

	fromnd.ni_cnd.cn_pnbuf = frompath;
	frompath = NULL;
	fromnd.ni_cnd.cn_pnlen = MAXPATHLEN;
	fromnd.ni_cnd.cn_flags |= HASBUF;

	error = nfs_namei(nfsd, &context, &fromnd, &fnfh, nam, FALSE, &fdirp, &fnx, &fnxo);
	if (error)
		goto out;
	fdvp = fromnd.ni_dvp;
	fvp  = fromnd.ni_vp;

	if (fdirp) {
		if (v3) {
			nfsm_srv_pre_vattr_init(&fdirfor, v3);
			fdirfor_ret = vnode_getattr(fdirp, &fdirfor, &context);
		} else {
			vnode_put(fdirp);
			fdirp = NULL;
		}
	}
	fvtype = vnode_vtype(fvp);

	/* reset credential if it was remapped */
	if (nfsd->nd_cr != saved_cred) {
		kauth_cred_rele(nfsd->nd_cr);
		nfsd->nd_cr = saved_cred;
		kauth_cred_ref(nfsd->nd_cr);
	}

	tond.ni_cnd.cn_nameiop = RENAME;
	tond.ni_cnd.cn_flags = WANTPARENT;

	tond.ni_cnd.cn_pnbuf = topath;
	topath = NULL;
	tond.ni_cnd.cn_pnlen = MAXPATHLEN;
	tond.ni_cnd.cn_flags |= HASBUF;

	if (fvtype == VDIR)
		tond.ni_cnd.cn_flags |= WILLBEDIR;

	error = nfs_namei(nfsd, &context, &tond, &tnfh, nam, FALSE, &tdirp, &tnx, &tnxo);
	if (error) {
		/*
		 * Translate error code for rename("dir1", "dir2/.").
		 */
	        if (error == EISDIR && fvtype == VDIR) {
		        if (v3)
			        error = EINVAL;
			else
			        error = ENOTEMPTY;
		}
		goto out;
	}
	tdvp = tond.ni_dvp;
	tvp  = tond.ni_vp;

	if (tdirp) {
		if (v3) {
			nfsm_srv_pre_vattr_init(&tdirfor, v3);
			tdirfor_ret = vnode_getattr(tdirp, &tdirfor, &context);
		} else {
			vnode_put(tdirp);
			tdirp = NULL;
		}
	}

	if (tvp != NULL) {
		tvtype = vnode_vtype(tvp);

		if (fvtype == VDIR && tvtype != VDIR) {
			if (v3)
				error = EEXIST;
			else
				error = EISDIR;
			goto out;
		} else if (fvtype != VDIR && tvtype == VDIR) {
			if (v3)
				error = EEXIST;
			else
				error = ENOTDIR;
			goto out;
		}
		if (tvtype == VDIR && vnode_mountedhere(tvp)) {
			if (v3)
				error = EXDEV;
			else
				error = ENOTEMPTY;
			goto out;
		}
	}
	if (fvp == tdvp) {
		if (v3)
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
			if ((error = nfsrv_authorize(fvp, fdvp, KAUTH_VNODE_DELETE, &context, fnxo, 0)) != 0)
				goto auth_exit;
			/* moving into tdvp or tvp, must have rights to add */
			if ((error = nfsrv_authorize(((tvp != NULL) && vnode_isdir(tvp)) ? tvp : tdvp,
				 NULL, 
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE,
				 &context, tnxo, 0)) != 0)
				goto auth_exit;
		} else {
			/* node staying in same directory, must be allowed to add new name */
			if ((error = nfsrv_authorize(fdvp, NULL,
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE,
				 &context, fnxo, 0)) != 0)
				goto auth_exit;
		}
		/* overwriting tvp */
		if ((tvp != NULL) && !vnode_isdir(tvp) &&
		    ((error = nfsrv_authorize(tvp, tdvp, KAUTH_VNODE_DELETE, &context, tnxo, 0)) != 0))
			goto auth_exit;

		/* XXX more checks? */

auth_exit:
		/* authorization denied */
		if (error != 0)
			goto out;
	}

	if ((vnode_mount(fvp) != vnode_mount(tdvp)) ||
	    (tvp && (vnode_mount(fvp) != vnode_mount(tvp)))) {
		if (v3)
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
		if (v3)
			error = EXDEV;
		else
			error = ENOTEMPTY;
		goto out;
	}
	if (fvtype == VDIR && vnode_mountedhere(fvp)) {
		if (v3)
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
		if (fromnd.ni_cnd.cn_namelen == tond.ni_cnd.cn_namelen &&
	       	    !bcmp(fromnd.ni_cnd.cn_nameptr, tond.ni_cnd.cn_nameptr,
			  fromnd.ni_cnd.cn_namelen)) {
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

			/* make a copy of to path to pass to nfs_namei() again */
			MALLOC_ZONE(topath, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
			if (topath)
				bcopy(tond.ni_cnd.cn_pnbuf, topath, tolen + 1);

			/*
			 * nameidone has to happen before we vnode_put(tdvp)
			 * since it may need to release the fs_nodelock on the tdvp
			 */
			nameidone(&tond);

			if (tvp)
			        vnode_put(tvp);
			vnode_put(tdvp);

			/* make a copy of from path to pass to nfs_namei() again */
			MALLOC_ZONE(frompath, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
			if (frompath)
				bcopy(fromnd.ni_cnd.cn_pnbuf, frompath, fromlen + 1);

			/*
			 * nameidone has to happen before we vnode_put(fdvp)
			 * since it may need to release the fs_nodelock on the fdvp
			 */
			nameidone(&fromnd);

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

			fdirfor_ret = tdirfor_ret = 1;

			if (!topath || !frompath) {
				/* we couldn't allocate a path, so bail */
				error = ENOMEM;
				goto out;
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
	char *oname;
	vnode_t oparent;
	oname   = fvp->v_name;
	oparent = fvp->v_parent;

	error = VNOP_RENAME(fromnd.ni_dvp, fromnd.ni_vp, &fromnd.ni_cnd,
			    tond.ni_dvp, tond.ni_vp, &tond.ni_cnd, &context);
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
		vnode_update_identity(fvp, tdvp, tond.ni_cnd.cn_nameptr, tond.ni_cnd.cn_namelen, tond.ni_cnd.cn_hash, update_flags);
	}
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
		nameidone(&tond);
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
		nameidone(&fromnd);

		if (fvp)
		        vnode_put(fvp);
	        vnode_put(fdvp);

		fdvp = NULL;
	}
	if (fdirp) {
		nfsm_srv_vattr_init(&fdiraft, v3);
		fdiraft_ret = vnode_getattr(fdirp, &fdiraft, &context);
		vnode_put(fdirp);
		fdirp = NULL;
	}
	if (tdirp) {
		nfsm_srv_vattr_init(&tdiraft, v3);
		tdiraft_ret = vnode_getattr(tdirp, &tdiraft, &context);
		vnode_put(tdirp);
		tdirp = NULL;
	}
	nfsm_reply(2 * NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvwcc_data(fdirfor_ret, &fdirfor, fdiraft_ret, &fdiraft);
		nfsm_srvwcc_data(tdirfor_ret, &tdirfor, tdiraft_ret, &tdiraft);
	}
	if (frompath)
		FREE_ZONE(frompath, MAXPATHLEN, M_NAMEI);
	if (topath)
		FREE_ZONE(topath, MAXPATHLEN, M_NAMEI);
	if (saved_cred)
		kauth_cred_rele(saved_cred);
	return (0);

nfsmout:
	if (holding_mntlock) {
	        mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
	}
	if (tdvp) {
		/*
		 * nameidone has to happen before we vnode_put(tdvp)
		 * since it may need to release the fs_nodelock on the tdvp
		 */
		nameidone(&tond);

		if (tvp)
		        vnode_put(tvp);
	        vnode_put(tdvp);
	}
	if (fdvp) {
		/*
		 * nameidone has to happen before we vnode_put(fdvp)
		 * since it may need to release the fs_nodelock on the fdvp
		 */
       		nameidone(&fromnd);

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
		kauth_cred_rele(saved_cred);
	return (error);
}

/*
 * nfs link service
 */
int
nfsrv_link(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct nameidata nd;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, len, dirfor_ret = 1, diraft_ret = 1;
	int getret = 1, v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	mbuf_t mb, mreq;
	vnode_t vp, xp, dvp, dirp = NULL;
	struct vnode_attr dirfor, diraft, at;
	struct nfs_filehandle nfh, dnfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct vfs_context context;

	vp = xp = dvp = NULL;
	nfsm_srvmtofh(&nfh);
	nfsm_srvmtofh(&dnfh);
	nfsm_srvnamesiz(len, v3);
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
		nfsm_srvpostop_attr(getret, &at);
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
		nfsm_srvpostop_attr(getret, &at);
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}

	/* we're not allowed to link to directories... */
	if (vnode_vtype(vp) == VDIR) {
		error = EPERM;		/* POSIX */
		goto out1;
	}

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

  	/* ...or to anything that kauth doesn't want us to (eg. immutable items) */
  	if ((error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_LINKTARGET, &context, nxo, 0)) != 0)
 		goto out1;

	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT;
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &len, &nd);
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &dnfh, nam, FALSE, &dirp, &nx, &nxo);
	if (dirp) {
		if (v3) {
			nfsm_srv_pre_vattr_init(&dirfor, v3);
			dirfor_ret = vnode_getattr(dirp, &dirfor, &context);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error)
		goto out1;
	dvp = nd.ni_dvp;
	xp = nd.ni_vp;

	if (xp != NULL)
		error = EEXIST;
	else if (vnode_mount(vp) != vnode_mount(dvp))
		error = EXDEV;
	else 
		error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context, nxo, 0);

	if (!error)
		error = VNOP_LINK(vp, dvp, &nd.ni_cnd, &context);

        /*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	if (xp)
		vnode_put(xp);
	vnode_put(dvp);
out1:
	if (v3) {
		nfsm_srv_vattr_init(&at, v3);
		getret = vnode_getattr(vp, &at, &context);
	}
	if (dirp) {
		nfsm_srv_vattr_init(&diraft, v3);
		diraft_ret = vnode_getattr(dirp, &diraft, &context);
		vnode_put(dirp);
	}
	vnode_put(vp);

	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvpostop_attr(getret, &at);
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
nfsmout:
	return (error);
}

/*
 * nfs symbolic link service
 */
int
nfsrv_symlink(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct vnode_attr dirfor, diraft, postat;
	struct nameidata nd;
	struct vnode_attr va;
	struct vnode_attr *vap = &va;
	u_long *tl;
	long t1;
	struct nfsv2_sattr *sp;
	char *bpos, *linkdata = NULL, *cp2;
	int error = 0, len, linkdatalen;
	int dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	mbuf_t mb, mreq, mb2;
	vnode_t vp, dvp, dirp = NULL;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t auio;
	char uio_buf[ UIO_SIZEOF(1) ];
	struct vfs_context context;
	uid_t saved_uid;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	/*
	 * Save the original credential UID in case they are
	 * mapped and we need to map the IDs in the attributes.
	 */
	saved_uid = kauth_cred_getuid(nfsd->nd_cr);

	nd.ni_cnd.cn_nameiop = 0;
	vp = dvp = NULL;
	nfsm_srvmtofh(&nfh);
	nfsm_srvnamesiz(len, v3);

	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT;
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &len, &nd);
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &nfh, nam, FALSE, &dirp, &nx, &nxo);
	if (dirp) {
		if (v3) {
			nfsm_srv_pre_vattr_init(&dirfor, v3);
			dirfor_ret = vnode_getattr(dirp, &dirfor, &context);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error) {
		nd.ni_cnd.cn_nameiop = 0;
		goto out1;
	}
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	VATTR_INIT(vap);
	if (v3)
		nfsm_srvsattr(vap);
	nfsm_strsiz(linkdatalen, NFS_MAXPATHLEN, v3);
	MALLOC(linkdata, caddr_t, linkdatalen + 1, M_TEMP, M_WAITOK);
	if (!linkdata) {
		nameidone(&nd);
		nd.ni_cnd.cn_nameiop = 0;
		vnode_put(nd.ni_dvp);
		vnode_put(nd.ni_vp);
		error = ENOMEM;
		goto out;
	}
	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
				&uio_buf[0], sizeof(uio_buf));
	if (!auio) {
		nameidone(&nd);
		nd.ni_cnd.cn_nameiop = 0;
		vnode_put(nd.ni_dvp);
		vnode_put(nd.ni_vp);
		error = ENOMEM;
		goto out;
	}
	uio_addiov(auio, CAST_USER_ADDR_T(linkdata), linkdatalen);
	nfsm_mtouio(auio, linkdatalen);
	if (!v3) {
		nfsm_dissect(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		VATTR_SET(vap, va_mode, fxdr_unsigned(u_short, sp->sa_mode));
	}
	*(linkdata + linkdatalen) = '\0';
	if (vp) {
		error = EEXIST;
		goto out;
	}

	/*
	 * If the credentials were mapped, we should
	 * map the same values in the attributes.
	 */
	if ((vap->va_uid == saved_uid) && (kauth_cred_getuid(nfsd->nd_cr) != saved_uid)) {
		int ismember;
		VATTR_SET(vap, va_uid, kauth_cred_getuid(nfsd->nd_cr));
		if (kauth_cred_ismember_gid(nfsd->nd_cr, vap->va_gid, &ismember) || !ismember)
			VATTR_SET(vap, va_gid, kauth_cred_getgid(nfsd->nd_cr));
	}
	VATTR_SET(vap, va_type, VLNK);
	VATTR_CLEAR_ACTIVE(vap, va_data_size);
	VATTR_CLEAR_ACTIVE(vap, va_access_time);

	/* authorize before creating */
	error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context, nxo, 0);

	/* validate given attributes */
	if (!error) {
		error = vnode_authattr_new(dvp, vap, 0, &context);
		if (error && (VATTR_IS_ACTIVE(vap, va_uid) || VATTR_IS_ACTIVE(vap, va_gid))) {
			/*
			 * Most NFS servers just ignore the UID/GID attributes, so we   
			 * try ignoring them if that'll help the request succeed.
			 */
			VATTR_CLEAR_ACTIVE(vap, va_uid);
			VATTR_CLEAR_ACTIVE(vap, va_gid);
			error = vnode_authattr_new(dvp, vap, 0, &context);
		}
	}
	if (!error)
		error = VNOP_SYMLINK(dvp, &vp, &nd.ni_cnd, vap, linkdata, &context);

	if (!error && v3) {
		if (vp == NULL) {
			nd.ni_cnd.cn_nameiop = LOOKUP;
			nd.ni_cnd.cn_flags &= ~(LOCKPARENT | FOLLOW);
			nd.ni_cnd.cn_flags |= (NOFOLLOW | LOCKLEAF);
			nd.ni_cnd.cn_context = &context;
			nd.ni_startdir = dvp;
			nd.ni_usedvp   = dvp;
			error = lookup(&nd);
			if (!error)
			        vp = nd.ni_vp;
		}
		if (!error) {
			error = nfsrv_vptofh(nx, !v3, NULL, vp, &context, &nfh);
			if (!error) {
				nfsm_srv_vattr_init(&postat, v3);
				error = vnode_getattr(vp, &postat, &context);
			}
		}
	}
out:
        /*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);
	nd.ni_cnd.cn_nameiop = 0;

	if (vp)
	        vnode_put(vp);
	vnode_put(dvp);
out1:
	if (linkdata)
		FREE(linkdata, M_TEMP);
	if (dirp) {
		nfsm_srv_vattr_init(&diraft, v3);
		diraft_ret = vnode_getattr(dirp, &diraft, &context);
		vnode_put(dirp);
	}
	nfsm_reply(NFSX_SRVFH(v3, &nfh) + NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		if (!error) {
			nfsm_srvpostop_fh(&nfh);
			nfsm_srvpostop_attr(0, &postat);
		}
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	}
	return (0);
nfsmout:
	if (nd.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);

		if (vp)
			vnode_put(vp);
		vnode_put(dvp);
	}
	if (dirp)
		vnode_put(dirp);
	if (linkdata)
		FREE(linkdata, M_TEMP);
	return (error);
}

/*
 * nfs mkdir service
 */
int
nfsrv_mkdir(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct vnode_attr dirfor, diraft, postat;
	struct vnode_attr va;
	struct vnode_attr *vap = &va;
	struct nfs_fattr *fp;
	struct nameidata nd;
	caddr_t cp;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, len;
	int dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	mbuf_t mb, mb2, mreq;
	vnode_t vp, dvp, dirp = NULL;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct vfs_context context;
	uid_t saved_uid;
        kauth_acl_t xacl = NULL;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	/*
	 * Save the original credential UID in case they are
	 * mapped and we need to map the IDs in the attributes.
	 */
	saved_uid = kauth_cred_getuid(nfsd->nd_cr);

	nd.ni_cnd.cn_nameiop = 0;
	vp = dvp = NULL;
	nfsm_srvmtofh(&nfh);
	nfsm_srvnamesiz(len, v3);

	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT;
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &len, &nd);
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &nfh, nam, FALSE, &dirp, &nx, &nxo);
	if (dirp) {
		if (v3) {
			nfsm_srv_pre_vattr_init(&dirfor, v3);
			dirfor_ret = vnode_getattr(dirp, &dirfor, &context);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error) {
		nd.ni_cnd.cn_nameiop = 0;
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vnode_put(dirp);
		return (0);
	}
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	VATTR_INIT(vap);
	if (v3) {
		nfsm_srvsattr(vap);
	} else {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		VATTR_SET(vap, va_mode, nfstov_mode(*tl++));
	}
	VATTR_SET(vap, va_type, VDIR);

	if (vp != NULL) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
	        nameidone(&nd);

		vnode_put(dvp);
		vnode_put(vp);
		error = EEXIST;
		goto out;
	}

	/*
	 * If the credentials were mapped, we should
	 * map the same values in the attributes.
	 */
	if ((vap->va_uid == saved_uid) && (kauth_cred_getuid(nfsd->nd_cr) != saved_uid)) {
		int ismember;
		VATTR_SET(vap, va_uid, kauth_cred_getuid(nfsd->nd_cr));
		if (kauth_cred_ismember_gid(nfsd->nd_cr, vap->va_gid, &ismember) || !ismember)
			VATTR_SET(vap, va_gid, kauth_cred_getgid(nfsd->nd_cr));
	}

	error = nfsrv_authorize(dvp, NULL, KAUTH_VNODE_ADD_SUBDIRECTORY, &context, nxo, 0);

  	/* construct ACL and handle inheritance */
	if (!error) {
		error = kauth_acl_inherit(dvp,
		    NULL,
		    &xacl,	/* isdir */
		    1,
		    &context);
		
		if (!error && xacl != NULL)
		        VATTR_SET(vap, va_acl, xacl);
	}
	VATTR_CLEAR_ACTIVE(vap, va_data_size);
	VATTR_CLEAR_ACTIVE(vap, va_access_time);

  	/* validate new-file security information */
	if (!error) {
		error = vnode_authattr_new(dvp, vap, 0, &context);
		if (error && (VATTR_IS_ACTIVE(vap, va_uid) || VATTR_IS_ACTIVE(vap, va_gid))) {
			/*
			 * Most NFS servers just ignore the UID/GID attributes, so we   
			 * try ignoring them if that'll help the request succeed.
			 */
			VATTR_CLEAR_ACTIVE(vap, va_uid);
			VATTR_CLEAR_ACTIVE(vap, va_gid);
			error = vnode_authattr_new(dvp, vap, 0, &context);
		}
	}

	if (!error)
		error = VNOP_MKDIR(dvp, &vp, &nd.ni_cnd, vap, &context);

	if (!error && !VATTR_ALL_SUPPORTED(vap))
	        /*
		 * If some of the requested attributes weren't handled by the VNOP,
		 * use our fallback code.
		 */
		error = vnode_setattr_fallback(vp, vap, &context);

	if (xacl != NULL)
		kauth_acl_free(xacl);
	
	if (!error) {
		error = nfsrv_vptofh(nx, !v3, NULL, vp, &context, &nfh);
		if (!error) {
			nfsm_srv_vattr_init(&postat, v3);
			error = vnode_getattr(vp, &postat, &context);
		}
		vnode_put(vp);
		vp = NULL;
	}
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	vnode_put(dvp);
out:
	nd.ni_cnd.cn_nameiop = 0;

	if (dirp) {
		nfsm_srv_vattr_init(&diraft, v3);
		diraft_ret = vnode_getattr(dirp, &diraft, &context);
		vnode_put(dirp);
	}
	nfsm_reply(NFSX_SRVFH(v3, &nfh) + NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		if (!error) {
			nfsm_srvpostop_fh(&nfh);
			nfsm_srvpostop_attr(0, &postat);
		}
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	} else {
		nfsm_srvfhtom(&nfh, v3);
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(&postat, fp);
	}
	return (0);
nfsmout:
	if (nd.ni_cnd.cn_nameiop) {
	        /*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);
		vnode_put(dvp);
		if (vp)
			vnode_put(vp);
	}
	if (dirp)
		vnode_put(dirp);
	return (error);
}

/*
 * nfs rmdir service
 */
int
nfsrv_rmdir(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, len;
	int dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	mbuf_t mb, mreq;
	vnode_t vp, dvp, dirp = NULL;
	struct vnode_attr dirfor, diraft;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct nameidata nd;
	struct vfs_context context;

	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	vp = dvp = NULL;
	nfsm_srvmtofh(&nfh);
	nfsm_srvnamesiz(len, v3);

	nd.ni_cnd.cn_nameiop = DELETE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfsm_path_mbuftond(&md, &dpos, v3, FALSE, &len, &nd);
	if (!error)
		error = nfs_namei(nfsd, &context, &nd, &nfh, nam, FALSE, &dirp, &nx, &nxo);
	if (dirp) {
	        if (v3) {
			nfsm_srv_pre_vattr_init(&dirfor, v3);
			dirfor_ret = vnode_getattr(dirp, &dirfor, &context);
		} else {
			vnode_put(dirp);
			dirp = NULL;
		}
	}
	if (error) {
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vnode_put(dirp);
		return (0);
	}
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

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
		error = nfsrv_authorize(vp, dvp, KAUTH_VNODE_DELETE, &context, nxo, 0);
	if (!error)
		error = VNOP_RMDIR(dvp, vp, &nd.ni_cnd, &context);
out:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	vnode_put(dvp);
	vnode_put(vp);

	if (dirp) {
		nfsm_srv_vattr_init(&diraft, v3);
		diraft_ret = vnode_getattr(dirp, &diraft, &context);
		vnode_put(dirp);
	}
	nfsm_reply(NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
nfsmout:
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
nfsrv_readdir(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	char *bp, *be;
	mbuf_t mp;
	struct direntry *dp;
	caddr_t cp;
	u_long *tl;
	long t1;
	caddr_t bpos;
	mbuf_t mb, mb2, mreq, mp2;
	char *cpos, *cend, *cp2, *rbuf;
	vnode_t vp;
	struct vnode_attr at;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t auio;
	char uio_buf[ UIO_SIZEOF(1) ];
	int len, nlen, rem, xfer, tsiz, i, error = 0, getret = 1;
	int siz, count, fullsiz, eofflag, nentries = 0;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	u_quad_t off, toff, verf;
	nfsuint64 tquad;
	int vnopflag;
	struct vfs_context context;

	vnopflag = VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF;

	nfsm_srvmtofh(&nfh);
	if (v3) {
		nfsm_dissect(tl, u_long *, 5 * NFSX_UNSIGNED);
		fxdr_hyper(tl, &toff);
		tl += 2;
		fxdr_hyper(tl, &verf);
		tl += 2;
	} else {
		nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
		toff = fxdr_unsigned(u_quad_t, *tl++);
	}
	off = toff;
	count = fxdr_unsigned(int, *tl);
	siz = ((count + DIRBLKSIZ - 1) & ~(DIRBLKSIZ - 1));
	xfer = NFS_SRVMAXDATA(nfsd);
	if (siz > xfer)
		siz = xfer;
	fullsiz = siz;
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;
	if (!v3 || (nxo->nxo_flags & NX_32BITCLIENTS))
		vnopflag |= VNODE_READDIR_SEEKOFF32;
	if (v3) {
		nfsm_srv_vattr_init(&at, v3);
		error = getret = vnode_getattr(vp, &at, &context);
		if (!error && toff && verf && verf != at.va_filerev)
			error = NFSERR_BAD_COOKIE;
	}
	if (!error)
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_LIST_DIRECTORY, &context, nxo, 0);
	if (error) {
		vnode_put(vp);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	MALLOC(rbuf, caddr_t, siz, M_TEMP, M_WAITOK);
	if (!rbuf) {
		error = ENOMEM;
		vnode_put(vp);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
				    &uio_buf[0], sizeof(uio_buf));
	if (!auio) {
		error = ENOMEM;
		FREE(rbuf, M_TEMP);
		vnode_put(vp);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
again:
	uio_reset(auio, off, UIO_SYSSPACE, UIO_READ);
	uio_addiov(auio, CAST_USER_ADDR_T(rbuf), fullsiz);

	eofflag = 0;
	error = VNOP_READDIR(vp, auio, vnopflag, &eofflag, &nentries, &context);
	off = uio_offset(auio);

	if (v3) {
		nfsm_srv_vattr_init(&at, v3);
		getret = vnode_getattr(vp, &at, &context);
		if (!error)
			error = getret;
	}
	if (error) {
		vnode_put(vp);
		FREE(rbuf, M_TEMP);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if (uio_resid(auio) != 0) {
		// LP64todo - fix this
		siz -= uio_resid(auio);

		/*
		 * If nothing read, return eof
		 * rpc reply
		 */
		if (siz == 0) {
			vnode_put(vp);
			nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_COOKIEVERF(v3) +
				2 * NFSX_UNSIGNED);
			if (v3) {
				nfsm_srvpostop_attr(getret, &at);
				nfsm_build(tl, u_long *, 4 * NFSX_UNSIGNED);
				txdr_hyper(&at.va_filerev, tl);
				tl += 2;
			} else
				nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_false;
			*tl = nfs_true;
			FREE(rbuf, M_TEMP);
			return (0);
		}
	}

	/*
	 * Check for degenerate cases of nothing useful read.
	 * If so go try again
	 */
	cpos = rbuf;
	cend = rbuf + siz;
	dp = (struct direntry *)cpos;
	while (dp->d_fileno == 0 && cpos < cend && nentries > 0) {
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	if (cpos >= cend || nentries == 0) {
		toff = off;
		siz = fullsiz;
		goto again;
	}

	vnode_put(vp);
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_COOKIEVERF(v3) + siz);
	if (v3) {
		len = NFSX_V3POSTOPATTR + NFSX_V3COOKIEVERF + 2 * NFSX_UNSIGNED;
		nfsm_srvpostop_attr(getret, &at);
		nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
		txdr_hyper(&at.va_filerev, tl);
	} else
		len = 2 * NFSX_UNSIGNED;
	mp = mp2 = mb;
	bp = bpos;
	be = bp + mbuf_trailingspace(mp);

	/* Loop through the records and build reply */
	while (cpos < cend && nentries > 0) {
		if (dp->d_fileno != 0) {
			nlen = dp->d_namlen;
			if (!v3 && (nlen > NFS_MAXNAMLEN))
				nlen = NFS_MAXNAMLEN;
			rem = nfsm_rndup(nlen)-nlen;
			len += (4 * NFSX_UNSIGNED + nlen + rem);
			if (v3)
				len += 2 * NFSX_UNSIGNED;
			if (len > count) {
				eofflag = 0;
				break;
			}
			/*
			 * Build the directory record xdr from
			 * the direntry entry.
			 */
			nfsm_clget;
			*tl = nfs_true;
			bp += NFSX_UNSIGNED;
			nfsm_clget;
			if (v3) {
				txdr_hyper(&dp->d_fileno, &tquad);
				*tl = tquad.nfsuquad[0];
				bp += NFSX_UNSIGNED;
				nfsm_clget;
				*tl = tquad.nfsuquad[1];
				bp += NFSX_UNSIGNED;
			} else {
				*tl = txdr_unsigned(dp->d_fileno);
				bp += NFSX_UNSIGNED;
			}
			nfsm_clget;
			*tl = txdr_unsigned(nlen);
			bp += NFSX_UNSIGNED;

			/* And loop around copying the name */
			xfer = nlen;
			cp = dp->d_name;
			while (xfer > 0) {
				nfsm_clget;
				if ((bp+xfer) > be)
					tsiz = be-bp;
				else
					tsiz = xfer;
				bcopy(cp, bp, tsiz);
				bp += tsiz;
				xfer -= tsiz;
				if (xfer > 0)
					cp += tsiz;
			}
			/* And null pad to a long boundary */
			for (i = 0; i < rem; i++)
				*bp++ = '\0';

			/* Finish off the record with the cookie */
			nfsm_clget;
			if (v3) {
				if (vnopflag & VNODE_READDIR_SEEKOFF32)
					dp->d_seekoff &= 0x00000000ffffffffULL;
				txdr_hyper(&dp->d_seekoff, &tquad);
				*tl = tquad.nfsuquad[0];
				bp += NFSX_UNSIGNED;
				nfsm_clget;
				*tl = tquad.nfsuquad[1];
				bp += NFSX_UNSIGNED;
			} else {
				*tl = txdr_unsigned(dp->d_seekoff);
				bp += NFSX_UNSIGNED;
			}
		}
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	nfsm_clget;
	*tl = nfs_false;
	bp += NFSX_UNSIGNED;
	nfsm_clget;
	if (eofflag)
		*tl = nfs_true;
	else
		*tl = nfs_false;
	bp += NFSX_UNSIGNED;
	if (mp != mb) {
		if (bp < be)
			mbuf_setlen(mp, bp - (char*)mbuf_data(mp));
	} else
		mbuf_setlen(mp, mbuf_len(mp) + (bp - bpos));
	FREE(rbuf, M_TEMP);
nfsmout:
	return (error);
}

struct flrep {
	nfsuint64	fl_off;
	u_long		fl_postopok;
	u_long		fl_fattr[NFSX_V3FATTR / sizeof (u_long)];
	u_long		fl_fhok;
	u_long		fl_fhsize;
	u_long		fl_nfh[NFSX_V3FHMAX / sizeof (u_long)];
};

int
nfsrv_readdirplus(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	char *bp, *be;
	mbuf_t mp;
	struct direntry *dp;
	caddr_t cp;
	u_long *tl;
	long t1;
	caddr_t bpos;
	mbuf_t mb, mb2, mreq, mp2;
	char *cpos, *cend, *cp2, *rbuf;
	vnode_t vp, nvp;
	struct flrep fl;
	struct nfs_filehandle dnfh, *nfhp = (struct nfs_filehandle *)&fl.fl_fhsize;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	uio_t auio;
	char uio_buf[ UIO_SIZEOF(1) ];
	struct vnode_attr va, at, *vap = &va;
	struct nfs_fattr *fp;
	int len, nlen, rem, xfer, tsiz, i, error = 0, getret = 1;
	int siz, count, fullsiz, eofflag, dirlen, nentries = 0, isdotdot;
	u_quad_t off, toff, verf;
	nfsuint64 tquad;
	int vnopflag;
	struct vfs_context context;

	vnopflag = VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF;
	vp = NULL;
	nfsm_srvmtofh(&dnfh);
	nfsm_dissect(tl, u_long *, 6 * NFSX_UNSIGNED);
	fxdr_hyper(tl, &toff);
	tl += 2;
	fxdr_hyper(tl, &verf);
	tl += 2;
	siz = fxdr_unsigned(int, *tl++);
	count = fxdr_unsigned(int, *tl);
	off = toff;
	siz = ((siz + DIRBLKSIZ - 1) & ~(DIRBLKSIZ - 1));
	xfer = NFS_SRVMAXDATA(nfsd);
	if (siz > xfer)
		siz = xfer;
	fullsiz = siz;
	if ((error = nfsrv_fhtovp(&dnfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;
	if (nxo->nxo_flags & NX_32BITCLIENTS)
		vnopflag |= VNODE_READDIR_SEEKOFF32;
	nfsm_srv_vattr_init(&at, 1);
	error = getret = vnode_getattr(vp, &at, &context);
	if (!error && toff && verf && verf != at.va_filerev)
		error = NFSERR_BAD_COOKIE;
	if (!error)
		error = nfsrv_authorize(vp, NULL, KAUTH_VNODE_LIST_DIRECTORY, &context, nxo, 0);
	if (error) {
		vnode_put(vp);
		vp = NULL;
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	MALLOC(rbuf, caddr_t, siz, M_TEMP, M_WAITOK);
	if (!rbuf) {
		error = ENOMEM;
		vnode_put(vp);
		vp = NULL;
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
				    &uio_buf[0], sizeof(uio_buf));
	if (!auio) {
		error = ENOMEM;
		FREE(rbuf, M_TEMP);
		vnode_put(vp);
		vp = NULL;
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
again:
	uio_reset(auio, off, UIO_SYSSPACE, UIO_READ);
	uio_addiov(auio, CAST_USER_ADDR_T(rbuf), fullsiz);
	eofflag = 0;
	error = VNOP_READDIR(vp, auio, vnopflag, &eofflag, &nentries, &context);
	off = uio_offset(auio);
	nfsm_srv_vattr_init(&at, 1);
	getret = vnode_getattr(vp, &at, &context);

	if (!error)
		error = getret;
	if (error) {
		vnode_put(vp);
		vp = NULL;
		FREE(rbuf, M_TEMP);
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if (uio_resid(auio) != 0) {
		// LP64todo - fix this
		siz -= uio_resid(auio);

		/*
		 * If nothing read, return eof
		 * rpc reply
		 */
		if (siz == 0) {
			vnode_put(vp);
			vp = NULL;
			nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3COOKIEVERF +
				2 * NFSX_UNSIGNED);
			nfsm_srvpostop_attr(getret, &at);
			nfsm_build(tl, u_long *, 4 * NFSX_UNSIGNED);
			txdr_hyper(&at.va_filerev, tl);
			tl += 2;
			*tl++ = nfs_false;
			*tl = nfs_true;
			FREE(rbuf, M_TEMP);
			return (0);
		}
	}

	/*
	 * Check for degenerate cases of nothing useful read.
	 * If so go try again
	 */
	cpos = rbuf;
	cend = rbuf + siz;
	dp = (struct direntry *)cpos;
	while (dp->d_fileno == 0 && cpos < cend && nentries > 0) {
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	if (cpos >= cend || nentries == 0) {
		toff = off;
		siz = fullsiz;
		goto again;
	}

	/*
	 * Probe one of the directory entries to see if the filesystem
	 * supports VGET.
	 */
	if ((error = VFS_VGET(vnode_mount(vp), (ino64_t)dp->d_fileno, &nvp, &context))) {
		if (error == ENOTSUP) /* let others get passed back */
			error = NFSERR_NOTSUPP; 
		vnode_put(vp);
		vp = NULL;
		FREE(rbuf, M_TEMP);
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	vnode_put(nvp);
	    
	dirlen = len = NFSX_V3POSTOPATTR + NFSX_V3COOKIEVERF + 2 * NFSX_UNSIGNED;
	nfsm_reply(count);
	nfsm_srvpostop_attr(getret, &at);
	nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
	txdr_hyper(&at.va_filerev, tl);
	mp = mp2 = mb;
	bp = bpos;
	be = bp + mbuf_trailingspace(mp);

	/* Loop through the records and build reply */
	while (cpos < cend && nentries > 0) {
		if (dp->d_fileno != 0) {
			nlen = dp->d_namlen;
			rem = nfsm_rndup(nlen)-nlen;

			/* 
			 * Got to get the vnode for lookup per entry.
			 */
			if (VFS_VGET(vnode_mount(vp), (ino64_t)dp->d_fileno, &nvp, &context))
				goto invalid;
			isdotdot = ((dp->d_namlen == 2) &&
				    (dp->d_name[0] == '.') && (dp->d_name[1] == '.'));
			if (nfsrv_vptofh(nx, 0, (isdotdot ? &dnfh : NULL), nvp, &context, nfhp)) {
				// XXX file handle is optional, so we should be able to
				// XXX return this entry without the file handle
				vnode_put(nvp);
				goto invalid;
			}
			nfsm_srv_vattr_init(vap, 1);
			if (vnode_getattr(nvp, vap, &context)) {
				// XXX attributes are optional, so we should be able to
				// XXX return this entry without the attributes
				vnode_put(nvp);
				goto invalid;
			}
			vnode_put(nvp);

			/*
			 * If either the dircount or maxcount will be
			 * exceeded, get out now. Both of these lengths
			 * are calculated conservatively, including all
			 * XDR overheads.
			 */
			len += (8 * NFSX_UNSIGNED + nlen + rem + nfhp->nfh_len +
				NFSX_V3POSTOPATTR);
			dirlen += (6 * NFSX_UNSIGNED + nlen + rem);
			if (len > count || dirlen > fullsiz) {
				eofflag = 0;
				break;
			}

			/*
			 * Build the directory record xdr from
			 * the direntry entry.
			 */
			fp = (struct nfs_fattr *)&fl.fl_fattr;
			nfsm_srvfillattr(vap, fp);
			fl.fl_fhsize = txdr_unsigned(nfhp->nfh_len);
			fl.fl_fhok = nfs_true;
			fl.fl_postopok = nfs_true;
			if (vnopflag & VNODE_READDIR_SEEKOFF32)
				dp->d_seekoff &= 0x00000000ffffffffULL;
			txdr_hyper(&dp->d_seekoff, &fl.fl_off);

			nfsm_clget;
			*tl = nfs_true;
			bp += NFSX_UNSIGNED;

			nfsm_clget;
			txdr_hyper(&dp->d_fileno, &tquad);
			*tl = tquad.nfsuquad[0];
			bp += NFSX_UNSIGNED;
			nfsm_clget;
			*tl = tquad.nfsuquad[1];
			bp += NFSX_UNSIGNED;

			nfsm_clget;
			*tl = txdr_unsigned(nlen);
			bp += NFSX_UNSIGNED;

			/* And loop around copying the name */
			xfer = nlen;
			cp = dp->d_name;
			while (xfer > 0) {
				nfsm_clget;
				if ((bp + xfer) > be)
					tsiz = be - bp;
				else
					tsiz = xfer;
				bcopy(cp, bp, tsiz);
				bp += tsiz;
				xfer -= tsiz;
				if (xfer > 0)
					cp += tsiz;
			}
			/* And null pad to a long boundary */
			for (i = 0; i < rem; i++)
				*bp++ = '\0';
	
			/*
			 * Now copy the flrep structure out.
			 */
			xfer = sizeof(struct flrep) - sizeof(fl.fl_nfh) + fl.fl_fhsize;
			cp = (caddr_t)&fl;
			while (xfer > 0) {
				nfsm_clget;
				if ((bp + xfer) > be)
					tsiz = be - bp;
				else
					tsiz = xfer;
				bcopy(cp, bp, tsiz);
				bp += tsiz;
				xfer -= tsiz;
				if (xfer > 0)
					cp += tsiz;
			}
		}
invalid:
		cpos += dp->d_reclen;
		dp = (struct direntry *)cpos;
		nentries--;
	}
	vnode_put(vp);
	vp = NULL;
	nfsm_clget;
	*tl = nfs_false;
	bp += NFSX_UNSIGNED;
	nfsm_clget;
	if (eofflag)
		*tl = nfs_true;
	else
		*tl = nfs_false;
	bp += NFSX_UNSIGNED;
	if (mp != mb) {
		if (bp < be)
			mbuf_setlen(mp, bp - (char*)mbuf_data(mp));
	} else
		mbuf_setlen(mp, mbuf_len(mp) + (bp - bpos));
	FREE(rbuf, M_TEMP);
nfsmout:
	if (vp)
		vnode_put(vp);
	return (error);
}

/*
 * nfs commit service
 */
int
nfsrv_commit(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct vnode_attr bfor, aft;
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, for_ret = 1, aft_ret = 1, count;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	u_quad_t off;
	struct vfs_context context;

	nfsm_srvmtofh(&nfh);
	nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);

	/*
	 * XXX At this time VNOP_FSYNC() does not accept offset and byte
	 * count parameters, so these arguments are useless (someday maybe).
	 */
	fxdr_hyper(tl, &off);
	tl += 2;
	count = fxdr_unsigned(int, *tl);
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(for_ret, &bfor, aft_ret, &aft);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(for_ret, &bfor, aft_ret, &aft);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	nfsm_srv_pre_vattr_init(&bfor, 1);
	for_ret = vnode_getattr(vp, &bfor, &context);
	error = VNOP_FSYNC(vp, MNT_WAIT, &context);
	nfsm_srv_vattr_init(&aft, 1);
	aft_ret = vnode_getattr(vp, &aft, &context);
	vnode_put(vp);
	nfsm_reply(NFSX_V3WCCDATA + NFSX_V3WRITEVERF);
	nfsm_srvwcc_data(for_ret, &bfor, aft_ret, &aft);
	if (!error) {
		nfsm_build(tl, u_long *, NFSX_V3WRITEVERF);
		*tl++ = txdr_unsigned(boottime_sec());
		*tl = txdr_unsigned(0);
	} else
		return (0);
nfsmout:
	return (error);
}

/*
 * nfs statfs service
 */
int
nfsrv_statfs(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct vfs_attr va;
	struct nfs_statfs *sfp;
	u_long *tl;
	long t1;
	caddr_t bpos;
	int error = 0, getret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	mbuf_t mb, mb2, mreq;
	vnode_t vp;
	struct vnode_attr at;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	u_quad_t tval;
	off_t blksize;
	struct vfs_context context;

	nfsm_srvmtofh(&nfh);
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	VFSATTR_INIT(&va);
	VFSATTR_WANTED(&va, f_blocks);
	VFSATTR_WANTED(&va, f_bavail);
	VFSATTR_WANTED(&va, f_files);
	VFSATTR_WANTED(&va, f_ffree);
	error = vfs_getattr(vnode_mount(vp), &va, &context);
	blksize = vnode_mount(vp)->mnt_vfsstat.f_bsize;
	nfsm_srv_vattr_init(&at, v3);
	getret = vnode_getattr(vp, &at, &context);
	vnode_put(vp);
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_STATFS(v3));
	if (v3)
		nfsm_srvpostop_attr(getret, &at);
	if (error)
		return (0);
	nfsm_build(sfp, struct nfs_statfs *, NFSX_STATFS(v3));
	if (v3) {
		tval = (u_quad_t)(va.f_blocks * blksize);
		txdr_hyper(&tval, &sfp->sf_tbytes);
		tval = (u_quad_t)(va.f_bfree * blksize);
		txdr_hyper(&tval, &sfp->sf_fbytes);
		tval = (u_quad_t)(va.f_bavail * blksize);
		txdr_hyper(&tval, &sfp->sf_abytes);
		txdr_hyper(&va.f_files, &sfp->sf_tfiles);
		txdr_hyper(&va.f_ffree, &sfp->sf_ffiles);
		txdr_hyper(&va.f_ffree, &sfp->sf_afiles);
		sfp->sf_invarsec = 0;
	} else {
		sfp->sf_tsize = txdr_unsigned(NFS_V2MAXDATA);
		sfp->sf_bsize = txdr_unsigned((unsigned)blksize);
		sfp->sf_blocks = txdr_unsigned((unsigned)va.f_blocks);
		sfp->sf_bfree = txdr_unsigned((unsigned)va.f_bfree);
		sfp->sf_bavail = txdr_unsigned((unsigned)va.f_bavail);
	}
nfsmout:
	return (error);
}

/*
 * nfs fsinfo service
 */
int
nfsrv_fsinfo(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	u_long *tl;
	struct nfsv3_fsinfo *sip;
	long t1;
	caddr_t bpos;
	int error = 0, getret = 1, prefsize, maxsize;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	vnode_t vp;
	struct vnode_attr at;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct vfs_context context;

	nfsm_srvmtofh(&nfh);
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	nfsm_srv_vattr_init(&at, 1);
	getret = vnode_getattr(vp, &at, &context);
	vnode_put(vp);
	nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3FSINFO);
	nfsm_srvpostop_attr(getret, &at);
	nfsm_build(sip, struct nfsv3_fsinfo *, NFSX_V3FSINFO);

	/*
	 * XXX
	 * There should be file system VFS OP(s) to get this information.
	 * For now, assume our usual NFS defaults.
	 */
	if (slp->ns_sotype == SOCK_DGRAM) {
		maxsize = NFS_MAXDGRAMDATA;
		prefsize = NFS_PREFDGRAMDATA;
	} else
		maxsize = prefsize = NFS_MAXDATA;
	sip->fs_rtmax = txdr_unsigned(maxsize);
	sip->fs_rtpref = txdr_unsigned(prefsize);
	sip->fs_rtmult = txdr_unsigned(NFS_FABLKSIZE);
	sip->fs_wtmax = txdr_unsigned(maxsize);
	sip->fs_wtpref = txdr_unsigned(prefsize);
	sip->fs_wtmult = txdr_unsigned(NFS_FABLKSIZE);
	sip->fs_dtpref = txdr_unsigned(prefsize);
	sip->fs_maxfilesize.nfsuquad[0] = 0xffffffff;
	sip->fs_maxfilesize.nfsuquad[1] = 0xffffffff;
	sip->fs_timedelta.nfsv3_sec = 0;
	sip->fs_timedelta.nfsv3_nsec = txdr_unsigned(1);
	sip->fs_properties = txdr_unsigned(NFSV3FSINFO_LINK |
		NFSV3FSINFO_SYMLINK | NFSV3FSINFO_HOMOGENEOUS |
		NFSV3FSINFO_CANSETTIME);
nfsmout:
	return (error);
}

/*
 * nfs pathconf service
 */
int
nfsrv_pathconf(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	proc_t procp;
	mbuf_t *mrq;
{
	mbuf_t mrep = nfsd->nd_mrep, md = nfsd->nd_md;
	mbuf_t nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	u_long *tl;
	struct nfsv3_pathconf *pc;
	long t1;
	caddr_t bpos;
	int error = 0, getret = 1, linkmax, namemax;
	int chownres, notrunc, case_sensitive, case_preserving;
	char *cp2;
	mbuf_t mb, mb2, mreq;
	vnode_t vp;
	struct vnode_attr at;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct vfs_context context;

	nfsm_srvmtofh(&nfh);
	if ((error = nfsrv_fhtovp(&nfh, nam, TRUE, &vp, &nx, &nxo))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if ((error = nfsrv_credcheck(nfsd, nx, nxo))) {
		vnode_put(vp);
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	context.vc_proc = procp;
	context.vc_ucred = nfsd->nd_cr;

	error = VNOP_PATHCONF(vp, _PC_LINK_MAX, &linkmax, &context);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_NAME_MAX, &namemax, &context);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_CHOWN_RESTRICTED, &chownres, &context);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_NO_TRUNC, &notrunc, &context);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_CASE_SENSITIVE, &case_sensitive, &context);
	if (!error)
		error = VNOP_PATHCONF(vp, _PC_CASE_PRESERVING, &case_preserving, &context);
	nfsm_srv_vattr_init(&at, 1);
	getret = vnode_getattr(vp, &at, &context);
	vnode_put(vp);
	nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3PATHCONF);
	nfsm_srvpostop_attr(getret, &at);
	if (error)
		return (0);
	nfsm_build(pc, struct nfsv3_pathconf *, NFSX_V3PATHCONF);

	pc->pc_linkmax = txdr_unsigned(linkmax);
	pc->pc_namemax = txdr_unsigned(namemax);
	pc->pc_notrunc = txdr_unsigned(notrunc);
	pc->pc_chownrestricted = txdr_unsigned(chownres);
	pc->pc_caseinsensitive = txdr_unsigned(!case_sensitive);
	pc->pc_casepreserving = txdr_unsigned(case_preserving);

nfsmout:
	return (error);
}

/*
 * Null operation, used by clients to ping server
 */
/* ARGSUSED */
int
nfsrv_null(
	struct nfsrv_descript *nfsd,
	struct nfssvc_sock *slp,
	__unused proc_t procp,
	mbuf_t *mrq)
{
	mbuf_t mrep = nfsd->nd_mrep;
	caddr_t bpos;
	int error = NFSERR_RETVOID;
	mbuf_t mb, mreq;

	nfsm_reply(0);
nfsmout:
	return (0);
}

/*
 * No operation, used for obsolete procedures
 */
/* ARGSUSED */
int
nfsrv_noop(
	struct nfsrv_descript *nfsd,
	struct nfssvc_sock *slp,
	__unused proc_t procp,
	mbuf_t *mrq)
{
	mbuf_t mrep = nfsd->nd_mrep;
	caddr_t bpos;
	int error;
	mbuf_t mb, mreq;

	if (nfsd->nd_repstat)
		error = nfsd->nd_repstat;
	else
		error = EPROCUNAVAIL;
	nfsm_reply(0);
nfsmout:
	return (0);
}

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

static int
nfsrv_authorize(
	vnode_t vp,
	vnode_t dvp,
	kauth_action_t action,
	vfs_context_t context,
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
	error = vnode_authorize(vp, dvp, action, context);
        /*
         * Allow certain operations for the owner (reads and writes
         * on files that are already open). Picking up from FreeBSD.
         */
	if (override && (error == EACCES)) {
		VATTR_INIT(&vattr);
		VATTR_WANTED(&vattr, va_uid);
		if ((vnode_getattr(vp, &vattr, context) == 0) &&
		    (kauth_cred_getuid(vfs_context_ucred(context)) == vattr.va_uid))
			error = 0;
	}
        return error;
}
#endif /* NFS_NOSERVER */

