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
 *	  on a bad rpc or similar and do not do any vrele() or vput()'s
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
#include <sys/namei.h>
#include <sys/unistd.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>

#include <ufs/ufs/dir.h>

#include <sys/vm.h>
#include <sys/vmparam.h>
#include <machine/spl.h>

#include <nfs/nfsproto.h>
#include <nfs/rpcv2.h>
#include <nfs/nfs.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nqnfs.h>

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

static int nfsrv_access __P((struct vnode *,int,struct ucred *,int,
		struct proc *, int));
static void nfsrvw_coalesce __P((struct nfsrv_descript *,
		struct nfsrv_descript *));

/*
 * nfs v3 access service
 */
int
nfsrv3_access(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct vnode *vp;
	nfsfh_t nfh;
	fhandle_t *fhp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, getret;
	char *cp2;
	struct mbuf *mb, *mreq, *mb2;
	struct vattr vattr, *vap = &vattr;
	u_long testmode, nfsmode;
	u_quad_t frev;

#ifndef nolint
	cache = 0;
#endif
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, (struct vattr *)0);
		return (0);
	}
	nfsmode = fxdr_unsigned(u_long, *tl);
	if ((nfsmode & NFSV3ACCESS_READ) &&
		nfsrv_access(vp, VREAD, cred, rdonly, procp, 0))
		nfsmode &= ~NFSV3ACCESS_READ;
	if (vp->v_type == VDIR)
		testmode = (NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND |
			NFSV3ACCESS_DELETE);
	else
		testmode = (NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND);
	if ((nfsmode & testmode) &&
		nfsrv_access(vp, VWRITE, cred, rdonly, procp, 0))
		nfsmode &= ~testmode;
	if (vp->v_type == VDIR)
		testmode = NFSV3ACCESS_LOOKUP;
	else
		testmode = NFSV3ACCESS_EXECUTE;
	if ((nfsmode & testmode) &&
		nfsrv_access(vp, VEXEC, cred, rdonly, procp, 0))
		nfsmode &= ~testmode;
	getret = VOP_GETATTR(vp, vap, cred, procp);
	vput(vp);
	nfsm_reply(NFSX_POSTOPATTR(1) + NFSX_UNSIGNED);
	nfsm_srvpostop_attr(getret, vap);
	nfsm_build(tl, u_long *, NFSX_UNSIGNED);
	*tl = txdr_unsigned(nfsmode);
	nfsm_srvdone;
}

/*
 * nfs getattr service
 */
int
nfsrv_getattr(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register struct nfs_fattr *fp;
	struct vattr va;
	register struct vattr *vap = &va;
	struct vnode *vp;
	nfsfh_t nfh;
	fhandle_t *fhp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	u_quad_t frev;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(0);
		return (0);
	}
	nqsrv_getl(vp, ND_READ);
	error = VOP_GETATTR(vp, vap, cred, procp);
	vput(vp);
	nfsm_reply(NFSX_FATTR(nfsd->nd_flag & ND_NFSV3));
	if (error)
		return (0);
	nfsm_build(fp, struct nfs_fattr *, NFSX_FATTR(nfsd->nd_flag & ND_NFSV3));
	nfsm_srvfillattr(vap, fp);
	nfsm_srvdone;
}

/*
 * nfs setattr service
 */
int
nfsrv_setattr(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct vattr va, preat;
	register struct vattr *vap = &va;
	register struct nfsv2_sattr *sp;
	register struct nfs_fattr *fp;
	struct vnode *vp;
	nfsfh_t nfh;
	fhandle_t *fhp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, preat_ret = 1, postat_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3), gcheck = 0;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	u_quad_t frev;
	struct timespec guard;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	VATTR_NULL(vap);
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
			vap->va_mode = nfstov_mode(sp->sa_mode);
		if (sp->sa_uid != nfs_xdrneg1)
			vap->va_uid = fxdr_unsigned(uid_t, sp->sa_uid);
		if (sp->sa_gid != nfs_xdrneg1)
			vap->va_gid = fxdr_unsigned(gid_t, sp->sa_gid);
		if (sp->sa_size != nfs_xdrneg1)
			vap->va_size = fxdr_unsigned(u_quad_t, sp->sa_size);
		if (sp->sa_atime.nfsv2_sec != nfs_xdrneg1) {
#ifdef notyet
			fxdr_nfsv2time(&sp->sa_atime, &vap->va_atime);
#else
			vap->va_atime.tv_sec =
				fxdr_unsigned(long, sp->sa_atime.nfsv2_sec);
			vap->va_atime.tv_nsec = 0;
#endif
		}
		if (sp->sa_mtime.nfsv2_sec != nfs_xdrneg1)
			fxdr_nfsv2time(&sp->sa_mtime, &vap->va_mtime);

	}

	/*
	 * Now that we have all the fields, lets do it.
	 */
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(preat_ret, &preat, postat_ret, vap);
		return (0);
	}
	nqsrv_getl(vp, ND_WRITE);
	if (v3) {
		error = preat_ret = VOP_GETATTR(vp, &preat, cred, procp);
		if (!error && gcheck &&
			(preat.va_ctime.tv_sec != guard.tv_sec ||
			 preat.va_ctime.tv_nsec != guard.tv_nsec))
			error = NFSERR_NOT_SYNC;
		if (error) {
			vput(vp);
			nfsm_reply(NFSX_WCCDATA(v3));
			nfsm_srvwcc_data(preat_ret, &preat, postat_ret, vap);
			return (0);
		}
	}

	/*
	 * If the size is being changed write acces is required, otherwise
	 * just check for a read only file system.
	 */
	if (vap->va_size == ((u_quad_t)((quad_t) -1))) {
		if (rdonly || (vp->v_mount->mnt_flag & MNT_RDONLY)) {
			error = EROFS;
			goto out;
		}
	} else {
		if (vp->v_type == VDIR) {
			error = EISDIR;
			goto out;
		} else if ((error = nfsrv_access(vp, VWRITE, cred, rdonly,
			procp, 0)))
			goto out;
	}
	error = VOP_SETATTR(vp, vap, cred, procp);
	postat_ret = VOP_GETATTR(vp, vap, cred, procp);
	if (!error)
		error = postat_ret;
out:
	vput(vp);
	nfsm_reply(NFSX_WCCORFATTR(v3));
	if (v3) {
		nfsm_srvwcc_data(preat_ret, &preat, postat_ret, vap);
		return (0);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(vap, fp);
	}
	nfsm_srvdone;
}

/*
 * nfs lookup rpc
 */
int
nfsrv_lookup(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register struct nfs_fattr *fp;
	struct nameidata nd, *ndp = &nd;
#ifdef notdef
	struct nameidata ind;
#endif
	struct vnode *vp, *dirp;
	nfsfh_t nfh;
	fhandle_t *fhp;
	register caddr_t cp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, cache, len, dirattr_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3), pubflag;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vattr va, dirattr, *vap = &va;
	u_quad_t frev;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvnamesiz(len);

	pubflag = nfs_ispublicfh(fhp);

	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = LOOKUP;
	nd.ni_cnd.cn_flags = LOCKLEAF | SAVESTART;
	error = nfs_namei(&nd, fhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), pubflag);

/* XXX CSM 12/4/97 Revisit when enabling WebNFS */
#ifdef notyet
	if (!error && pubflag) {
		if (nd.ni_vp->v_type == VDIR && nfs_pub.np_index != NULL) {
			/*
			 * Setup call to lookup() to see if we can find
			 * the index file. Arguably, this doesn't belong
			 * in a kernel.. Ugh.
			 */
			ind = nd;
			VOP_UNLOCK(nd.ni_vp, 0, procp);
			ind.ni_pathlen = strlen(nfs_pub.np_index);
			ind.ni_cnd.cn_nameptr = ind.ni_cnd.cn_pnbuf =
			    nfs_pub.np_index;
			ind.ni_startdir = nd.ni_vp;
			VREF(ind.ni_startdir);
			error = lookup(&ind);
			if (!error) {
				/*
				 * Found an index file. Get rid of
				 * the old references.
				 */
				if (dirp)	
					vrele(dirp);
				dirp = nd.ni_vp;
				vrele(nd.ni_startdir);
				ndp = &ind;
			} else
				error = 0;
		}
		/*
		 * If the public filehandle was used, check that this lookup
		 * didn't result in a filehandle outside the publicly exported
		 * filesystem.
		 */

		if (!error && ndp->ni_vp->v_mount != nfs_pub.np_mount) {
			vput(nd.ni_vp);
			error = EPERM;
		}
	}
#endif

	if (dirp) {
		if (v3)
			dirattr_ret = VOP_GETATTR(dirp, &dirattr, cred,
				procp);
		vrele(dirp);
	}

	if (error) {
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
		return (0);
	}

	nqsrv_getl(ndp->ni_startdir, ND_READ);
	vrele(ndp->ni_startdir);
	FREE_ZONE(nd.ni_cnd.cn_pnbuf, nd.ni_cnd.cn_pnlen, M_NAMEI);
	vp = ndp->ni_vp;
	bzero((caddr_t)fhp, sizeof(nfh));
	fhp->fh_fsid = vp->v_mount->mnt_stat.f_fsid;
	error = VFS_VPTOFH(vp, &fhp->fh_fid);
	if (!error)
		error = VOP_GETATTR(vp, vap, cred, procp);
	vput(vp);
	nfsm_reply(NFSX_SRVFH(v3) + NFSX_POSTOPORFATTR(v3) + NFSX_POSTOPATTR(v3));
	if (error) {
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
		return (0);
	}
	nfsm_srvfhtom(fhp, v3);
	if (v3) {
		nfsm_srvpostop_attr(0, vap);
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(vap, fp);
	}
	nfsm_srvdone;
}

/*
 * nfs readlink service
 */
int
nfsrv_readlink(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct iovec iv[(NFS_MAXPATHLEN+MLEN-1)/MLEN];
	register struct iovec *ivp = iv;
	register struct mbuf *mp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, i, tlen, len, getret;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mb2, *mp2, *mp3, *mreq;
	struct vnode *vp;
	struct vattr attr;
	nfsfh_t nfh;
	fhandle_t *fhp;
	struct uio io, *uiop = &io;
	u_quad_t frev;

#ifndef nolint
	mp2 = mp3 = (struct mbuf *)0;
#endif
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	len = 0;
	i = 0;
	while (len < NFS_MAXPATHLEN) {
		MGET(mp, M_WAIT, MT_DATA);
		MCLGET(mp, M_WAIT);
		mp->m_len = NFSMSIZ(mp);
		if (len == 0)
			mp3 = mp2 = mp;
		else {
			mp2->m_next = mp;
			mp2 = mp;
		}
		if ((len+mp->m_len) > NFS_MAXPATHLEN) {
			mp->m_len = NFS_MAXPATHLEN-len;
			len = NFS_MAXPATHLEN;
		} else
			len += mp->m_len;
		ivp->iov_base = mtod(mp, caddr_t);
		ivp->iov_len = mp->m_len;
		i++;
		ivp++;
	}
	uiop->uio_iov = iv;
	uiop->uio_iovcnt = i;
	uiop->uio_offset = 0;
	uiop->uio_resid = len;
	uiop->uio_rw = UIO_READ;
	uiop->uio_segflg = UIO_SYSSPACE;
	uiop->uio_procp = (struct proc *)0;
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		m_freem(mp3);
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, (struct vattr *)0);
		return (0);
	}
	if (vp->v_type != VLNK) {
		if (v3)
			error = EINVAL;
		else
			error = ENXIO;
		goto out;
	}
	nqsrv_getl(vp, ND_READ);
	error = VOP_READLINK(vp, uiop, cred);
out:
	getret = VOP_GETATTR(vp, &attr, cred, procp);
	vput(vp);
	if (error)
		m_freem(mp3);
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_UNSIGNED);
	if (v3) {
		nfsm_srvpostop_attr(getret, &attr);
		if (error)
			return (0);
	}
	if (uiop->uio_resid > 0) {
		len -= uiop->uio_resid;
		tlen = nfsm_rndup(len);
		nfsm_adj(mp3, NFS_MAXPATHLEN-tlen, tlen-len);
	}
	nfsm_build(tl, u_long *, NFSX_UNSIGNED);
	*tl = txdr_unsigned(len);
	mb->m_next = mp3;
	nfsm_srvdone;
}

/*
 * nfs read service
 */
int
nfsrv_read(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register struct iovec *iv;
	struct iovec *iv2;
	register struct mbuf *m;
	register struct nfs_fattr *fp;
	register u_long *tl;
	register long t1;
	register int i;
	caddr_t bpos;
	int error = 0, rdonly, cache, cnt, len, left, siz, tlen, getret;
	int v3 = (nfsd->nd_flag & ND_NFSV3), reqlen;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct mbuf *m2;
	struct vnode *vp;
	nfsfh_t nfh;
	fhandle_t *fhp;
	struct uio io, *uiop = &io;
	struct vattr va, *vap = &va;
	off_t off;
	u_quad_t frev;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	if (v3) {
		nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
		fxdr_hyper(tl, &off);
	} else {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		off = (off_t)fxdr_unsigned(u_long, *tl);
	}
	nfsm_srvstrsiz(reqlen, NFS_SRVMAXDATA(nfsd));
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvpostop_attr(1, (struct vattr *)0);
		return (0);
	}
	if (vp->v_type != VREG) {
		if (v3)
			error = EINVAL;
		else
			error = (vp->v_type == VDIR) ? EISDIR : EACCES;
	}
	if (!error) {
	    nqsrv_getl(vp, ND_READ);
	    if ((error = nfsrv_access(vp, VREAD, cred, rdonly, procp, 1)))
		error = nfsrv_access(vp, VEXEC, cred, rdonly, procp, 1);
	}
	getret = VOP_GETATTR(vp, vap, cred, procp);
	if (!error)
		error = getret;
	if (error) {
		vput(vp);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, vap);
		return (0);
	}
	if (off >= vap->va_size)
		cnt = 0;
	else if ((off + reqlen) > vap->va_size)
		cnt = nfsm_rndup(vap->va_size - off);
	else
		cnt = reqlen;
	nfsm_reply(NFSX_POSTOPORFATTR(v3) + 3 * NFSX_UNSIGNED+nfsm_rndup(cnt));
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
	len = left = cnt;
	if (cnt > 0) {
		/*
		 * Generate the mbuf list with the uio_iov ref. to it.
		 */
		i = 0;
		m = m2 = mb;
		while (left > 0) {
			siz = min(M_TRAILINGSPACE(m), left);
			if (siz > 0) {
				left -= siz;
				i++;
			}
			if (left > 0) {
				MGET(m, M_WAIT, MT_DATA);
				MCLGET(m, M_WAIT);
				m->m_len = 0;
				m2->m_next = m;
				m2 = m;
			}
		}
		MALLOC(iv, struct iovec *, i * sizeof (struct iovec),
		       M_TEMP, M_WAITOK);
		uiop->uio_iov = iv2 = iv;
		m = mb;
		left = cnt;
		i = 0;
		while (left > 0) {
			if (m == NULL)
				panic("nfsrv_read iov");
			siz = min(M_TRAILINGSPACE(m), left);
			if (siz > 0) {
				iv->iov_base = mtod(m, caddr_t) + m->m_len;
				iv->iov_len = siz;
				m->m_len += siz;
				left -= siz;
				iv++;
				i++;
			}
			m = m->m_next;
		}
		uiop->uio_iovcnt = i;
		uiop->uio_offset = off;
		uiop->uio_resid = cnt;
		uiop->uio_rw = UIO_READ;
		uiop->uio_segflg = UIO_SYSSPACE;
		error = VOP_READ(vp, uiop, IO_NODELOCKED, cred);
		off = uiop->uio_offset;
		FREE((caddr_t)iv2, M_TEMP);
		/* Though our code replaces error with getret, the way I read
		* the v3 spec, it appears you should leave the error alone, but
		* still return vap and not assign error = getret. But leaving
		* that alone. m_freem(mreq) looks bogus. Taking it out. Should be
		* mrep or not there at all. Causes panic.  ekn */
		if (error || (getret = VOP_GETATTR(vp, vap, cred, procp))) {
			if (!error)
				error = getret;
			/* 	m_freem(mreq);*/
			vput(vp);
			nfsm_reply(NFSX_POSTOPATTR(v3));
			nfsm_srvpostop_attr(getret, vap);
			return (0);
		}
	} else
		uiop->uio_resid = 0;
	vput(vp);
	nfsm_srvfillattr(vap, fp);
	len -= uiop->uio_resid;
	tlen = nfsm_rndup(len);
	if (cnt != tlen || tlen != len)
		nfsm_adj(mb, cnt - tlen, tlen - len);
	if (v3) {
		*tl++ = txdr_unsigned(len);
		if (len < reqlen)
			*tl++ = nfs_true;
		else
			*tl++ = nfs_false;
	}
	*tl = txdr_unsigned(len);
	nfsm_srvdone;
}

/*
 * nfs write service
 */
int
nfsrv_write(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register struct iovec *ivp;
	register int i, cnt;
	register struct mbuf *mp;
	register struct nfs_fattr *fp;
	struct iovec *iv;
	struct vattr va, forat;
	register struct vattr *vap = &va;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, len, forat_ret = 1;
	int ioflags, aftat_ret = 1, retlen, zeroing, adjust;
	int stable = NFSV3WRITE_FILESYNC;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vnode *vp;
	nfsfh_t nfh;
	fhandle_t *fhp;
	struct uio io, *uiop = &io;
	off_t off;
	u_quad_t frev;

	if (mrep == NULL) {
		*mrq = NULL;
		return (0);
	}
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
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
	cnt = i = 0;

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
			adjust = dpos - mtod(mp, caddr_t);
			mp->m_len -= adjust;
			if (mp->m_len > 0 && adjust > 0)
				NFSMADV(mp, adjust);
		}
		if (zeroing)
			mp->m_len = 0;
		else if (mp->m_len > 0) {
			i += mp->m_len;
			if (i > len) {
				mp->m_len -= (i - len);
				zeroing	= 1;
			}
			if (mp->m_len > 0)
				cnt++;
		}
		mp = mp->m_next;
	    }
	}
	if (len > NFS_MAXDATA || len < 0 || i < len) {
		error = EIO;
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	}
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	}
	if (v3)
		forat_ret = VOP_GETATTR(vp, &forat, cred, procp);
	if (vp->v_type != VREG) {
		if (v3)
			error = EINVAL;
		else
			error = (vp->v_type == VDIR) ? EISDIR : EACCES;
	}
	if (!error) {
		nqsrv_getl(vp, ND_WRITE);
		error = nfsrv_access(vp, VWRITE, cred, rdonly, procp, 1);
	}
	if (error) {
		vput(vp);
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		return (0);
	}

	if (len > 0) {
	    MALLOC(ivp, struct iovec *, cnt * sizeof (struct iovec), M_TEMP,
		M_WAITOK);
	    uiop->uio_iov = iv = ivp;
	    uiop->uio_iovcnt = cnt;
	    mp = mrep;
	    while (mp) {
		if (mp->m_len > 0) {
			ivp->iov_base = mtod(mp, caddr_t);
			ivp->iov_len = mp->m_len;
			ivp++;
		}
		mp = mp->m_next;
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
	    uiop->uio_resid = len;
	    uiop->uio_rw = UIO_WRITE;
	    uiop->uio_segflg = UIO_SYSSPACE;
	    uiop->uio_procp = (struct proc *)0;
	    uiop->uio_offset = off;
	    error = VOP_WRITE(vp, uiop, ioflags, cred);
	    nfsstats.srvvop_writes++;
	    FREE((caddr_t)iv, M_TEMP);
	}
	aftat_ret = VOP_GETATTR(vp, vap, cred, procp);
	vput(vp);
	if (!error)
		error = aftat_ret;
	nfsm_reply(NFSX_PREOPATTR(v3) + NFSX_POSTOPORFATTR(v3) +
		2 * NFSX_UNSIGNED + NFSX_WRITEVERF(v3));
	if (v3) {
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, vap);
		if (error)
			return (0);
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
		*tl++ = txdr_unsigned(boottime.tv_sec);
		*tl = txdr_unsigned(boottime.tv_usec);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(vap, fp);
	}
	nfsm_srvdone;
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
	struct proc *procp;
	struct mbuf **mrq;
{
	register struct iovec *ivp;
	register struct mbuf *mp;
	register struct nfsrv_descript *wp, *nfsd, *owp, *swp;
	register struct nfs_fattr *fp;
	register int i;
	struct iovec *iov;
	struct nfsrvw_delayhash *wpp;
	struct ucred *cred;
	struct vattr va, forat;
	register u_long *tl;
	register long t1;
	caddr_t bpos, dpos;
	int error = 0, rdonly, cache, len, forat_ret = 1;
	int ioflags, aftat_ret = 1, s, adjust, v3, zeroing;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq, *mrep, *md;
	struct vnode *vp;
	struct uio io, *uiop = &io;
	u_quad_t frev, cur_usec;

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
	    cred = &nfsd->nd_cr;
	    v3 = (nfsd->nd_flag & ND_NFSV3);
	    LIST_INIT(&nfsd->nd_coalesce);
	    nfsd->nd_mreq = NULL;
	    nfsd->nd_stable = NFSV3WRITE_FILESYNC;
	    cur_usec = (u_quad_t)time.tv_sec * 1000000 + (u_quad_t)time.tv_usec;
	    nfsd->nd_time = cur_usec +
		(v3 ? nfsrvw_procrastinate_v3 : nfsrvw_procrastinate);
    
	    /*
	     * Now, get the write header..
	     */
	    nfsm_srvmtofh(&nfsd->nd_fh);
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
		    adjust = dpos - mtod(mp, caddr_t);
		    mp->m_len -= adjust;
		    if (mp->m_len > 0 && adjust > 0)
			NFSMADV(mp, adjust);
		}
		if (zeroing)
		    mp->m_len = 0;
		else {
		    i += mp->m_len;
		    if (i > len) {
			mp->m_len -= (i - len);
			zeroing = 1;
		    }
		}
		mp = mp->m_next;
	    }
	    if (len > NFS_MAXDATA || len < 0  || i < len) {
nfsmout:
		m_freem(mrep);
		error = EIO;
		nfsm_writereply(2 * NFSX_UNSIGNED, v3);
		if (v3)
		    nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, &va);
		nfsd->nd_mreq = mreq;
		nfsd->nd_mrep = NULL;
		nfsd->nd_time = 0;
	    }
    
	    /*
	     * Add this entry to the hash and time queues.
	     */
	    s = splsoftclock();
	    owp = NULL;
	    wp = slp->ns_tq.lh_first;
	    while (wp && wp->nd_time < nfsd->nd_time) {
		owp = wp;
		wp = wp->nd_tq.le_next;
	    }
	    NFS_DPF(WG, ("Q%03x", nfsd->nd_retxid & 0xfff));
	    if (owp) {
		LIST_INSERT_AFTER(owp, nfsd, nd_tq);
	    } else {
		LIST_INSERT_HEAD(&slp->ns_tq, nfsd, nd_tq);
	    }
	    if (nfsd->nd_mrep) {
		wpp = NWDELAYHASH(slp, nfsd->nd_fh.fh_fid.fid_data);
		owp = NULL;
		wp = wpp->lh_first;
		while (wp &&
		    bcmp((caddr_t)&nfsd->nd_fh,(caddr_t)&wp->nd_fh,NFSX_V3FH)) {
		    owp = wp;
		    wp = wp->nd_hash.le_next;
		}
		while (wp && wp->nd_off < nfsd->nd_off &&
		    !bcmp((caddr_t)&nfsd->nd_fh,(caddr_t)&wp->nd_fh,NFSX_V3FH)) {
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
	    splx(s);
	}
    
	/*
	 * Now, do VOP_WRITE()s for any one(s) that need to be done now
	 * and generate the associated reply mbuf list(s).
	 */
loop1:
	cur_usec = (u_quad_t)time.tv_sec * 1000000 + (u_quad_t)time.tv_usec;
	s = splsoftclock();
	for (nfsd = slp->ns_tq.lh_first; nfsd; nfsd = owp) {
		owp = nfsd->nd_tq.le_next;
		if (nfsd->nd_time > cur_usec)
		    break;
		if (nfsd->nd_mreq)
		    continue;
		NFS_DPF(WG, ("P%03x", nfsd->nd_retxid & 0xfff));
		LIST_REMOVE(nfsd, nd_tq);
		LIST_REMOVE(nfsd, nd_hash);
		splx(s);
		mrep = nfsd->nd_mrep;
		nfsd->nd_mrep = NULL;
		cred = &nfsd->nd_cr;
		v3 = (nfsd->nd_flag & ND_NFSV3);
		forat_ret = aftat_ret = 1;
		error = nfsrv_fhtovp(&nfsd->nd_fh, 1, &vp, cred, slp, 
		    nfsd->nd_nam, &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE);
		if (!error) {
		    if (v3)
			forat_ret = VOP_GETATTR(vp, &forat, cred, procp);
		    if (vp->v_type != VREG) {
			if (v3)
			    error = EINVAL;
			else
			    error = (vp->v_type == VDIR) ? EISDIR : EACCES;
		    }
		} else
		    vp = NULL;
		if (!error) {
		    nqsrv_getl(vp, ND_WRITE);
		    error = nfsrv_access(vp, VWRITE, cred, rdonly, procp, 1);
		}
    
		if (nfsd->nd_stable == NFSV3WRITE_UNSTABLE)
		    ioflags = IO_NODELOCKED;
		else if (nfsd->nd_stable == NFSV3WRITE_DATASYNC)
		    ioflags = (IO_SYNC | IO_NODELOCKED);
		else
		    ioflags = (IO_METASYNC | IO_SYNC | IO_NODELOCKED);
		uiop->uio_rw = UIO_WRITE;
		uiop->uio_segflg = UIO_SYSSPACE;
		uiop->uio_procp = (struct proc *)0;
		uiop->uio_offset = nfsd->nd_off;
		uiop->uio_resid = nfsd->nd_eoff - nfsd->nd_off;
		if (uiop->uio_resid > 0) {
		    mp = mrep;
		    i = 0;
		    while (mp) {
			if (mp->m_len > 0)
			    i++;
			mp = mp->m_next;
		    }
		    uiop->uio_iovcnt = i;
		    MALLOC(iov, struct iovec *, i * sizeof (struct iovec), 
			M_TEMP, M_WAITOK);
		    uiop->uio_iov = ivp = iov;
		    mp = mrep;
		    while (mp) {
			if (mp->m_len > 0) {
			    ivp->iov_base = mtod(mp, caddr_t);
			    ivp->iov_len = mp->m_len;
			    ivp++;
			}
			mp = mp->m_next;
		    }
		    if (!error) {
			error = VOP_WRITE(vp, uiop, ioflags, cred);
			nfsstats.srvvop_writes++;
		    }
		    FREE((caddr_t)iov, M_TEMP);
		}
		m_freem(mrep);
		if (vp) {
		    aftat_ret = VOP_GETATTR(vp, &va, cred, procp);
		    vput(vp);
		}

		/*
		 * Loop around generating replies for all write rpcs that have
		 * now been completed.
		 */
		swp = nfsd;
		do {
		    NFS_DPF(WG, ("R%03x", nfsd->nd_retxid & 0xfff));
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
			    *tl++ = txdr_unsigned(boottime.tv_sec);
			    *tl = txdr_unsigned(boottime.tv_usec);
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
		    s = splsoftclock();
		    if (nfsd != swp) {
			nfsd->nd_time = 0;
			LIST_INSERT_HEAD(&slp->ns_tq, nfsd, nd_tq);
		    }
		    nfsd = swp->nd_coalesce.lh_first;
		    if (nfsd) {
			LIST_REMOVE(nfsd, nd_tq);
		    }
		    splx(s);
		} while (nfsd);
		s = splsoftclock();
		swp->nd_time = 0;
		LIST_INSERT_HEAD(&slp->ns_tq, swp, nd_tq);
		splx(s);
		goto loop1;
	}
	splx(s);

	/*
	 * Search for a reply to return.
	 */
	s = splsoftclock();
	for (nfsd = slp->ns_tq.lh_first; nfsd; nfsd = nfsd->nd_tq.le_next)
		if (nfsd->nd_mreq) {
		    NFS_DPF(WG, ("X%03x", nfsd->nd_retxid & 0xfff));
		    LIST_REMOVE(nfsd, nd_tq);
		    *mrq = nfsd->nd_mreq;
		    *ndp = nfsd;
		    break;
		}
	splx(s);
	return (0);
}

/*
 * Coalesce the write request nfsd into owp. To do this we must:
 * - remove nfsd from the queues
 * - merge nfsd->nd_mrep into owp->nd_mrep
 * - update the nd_eoff and nd_stable for owp
 * - put nfsd on owp's nd_coalesce list
 * NB: Must be called at splsoftclock().
 */
static void
nfsrvw_coalesce(owp, nfsd)
        register struct nfsrv_descript *owp;
        register struct nfsrv_descript *nfsd;
{
        register int overlap;
        register struct mbuf *mp;
	struct nfsrv_descript *p;

	NFS_DPF(WG, ("C%03x-%03x",
		     nfsd->nd_retxid & 0xfff, owp->nd_retxid & 0xfff));
        LIST_REMOVE(nfsd, nd_hash);
        LIST_REMOVE(nfsd, nd_tq);
        if (owp->nd_eoff < nfsd->nd_eoff) {
            overlap = owp->nd_eoff - nfsd->nd_off;
            if (overlap < 0)
                panic("nfsrv_coalesce: bad off");
            if (overlap > 0)
                m_adj(nfsd->nd_mrep, overlap);
            mp = owp->nd_mrep;
            while (mp->m_next)
                mp = mp->m_next;
            mp->m_next = nfsd->nd_mrep;
            owp->nd_eoff = nfsd->nd_eoff;
        } else
            m_freem(nfsd->nd_mrep);
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
 */
void
nfsrvw_sort(list, num)
        register gid_t *list;
        register int num;
{
	register int i, j;
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
 */
void
nfsrv_setcred(incred, outcred)
	register struct ucred *incred, *outcred;
{
	register int i;

	bzero((caddr_t)outcred, sizeof (struct ucred));
	outcred->cr_ref = 1;
	outcred->cr_uid = incred->cr_uid;
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
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register struct nfs_fattr *fp;
	struct vattr va, dirfor, diraft;
	register struct vattr *vap = &va;
	register struct nfsv2_sattr *sp;
	register u_long *tl;
	struct nameidata nd;
	register caddr_t cp;
	register long t1;
	caddr_t bpos;
	int error = 0, rdev, cache, len, tsize, dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3), how, exclusive_flag = 0;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vnode *vp, *dirp = (struct vnode *)0;
	nfsfh_t nfh;
	fhandle_t *fhp;
	u_quad_t frev, tempsize;
	u_char cverf[NFSX_V3CREATEVERF];

#ifndef nolint
	rdev = 0;
#endif
	nd.ni_cnd.cn_nameiop = 0;
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvnamesiz(len);
	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF | SAVESTART;
	error = nfs_namei(&nd, fhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (dirp) {
		if (v3)
			dirfor_ret = VOP_GETATTR(dirp, &dirfor, cred,
				procp);
		else {
			vrele(dirp);
			dirp = (struct vnode *)0;
		}
	}
	if (error) {
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vrele(dirp);
		return (0);
	}
	VATTR_NULL(vap);
	if (v3) {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		how = fxdr_unsigned(int, *tl);
		switch (how) {
		case NFSV3CREATE_GUARDED:
			if (nd.ni_vp) {
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
			if (nd.ni_vp == NULL)
				vap->va_mode = 0;
			break;
		};
		vap->va_type = VREG;
	} else {
		nfsm_dissect(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		vap->va_type = IFTOVT(fxdr_unsigned(u_long, sp->sa_mode));
		if (vap->va_type == VNON)
			vap->va_type = VREG;
		vap->va_mode = nfstov_mode(sp->sa_mode);
		switch (vap->va_type) {
		case VREG:
			tsize = fxdr_unsigned(long, sp->sa_size);
			if (tsize != -1)
				vap->va_size = (u_quad_t)tsize;
			break;
		case VCHR:
		case VBLK:
		case VFIFO:
			rdev = fxdr_unsigned(long, sp->sa_size);
			break;
		};
	}

	/*
	 * Iff doesn't exist, create it
	 * otherwise just truncate to 0 length
	 *   should I set the mode too ??
	 */
	if (nd.ni_vp == NULL) {
		if (vap->va_type == VREG || vap->va_type == VSOCK) {
			vrele(nd.ni_startdir);
			nqsrv_getl(nd.ni_dvp, ND_WRITE);
			error = VOP_CREATE(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, vap);
			if (!error) {
			    	nfsrv_object_create(nd.ni_vp);
				FREE_ZONE(nd.ni_cnd.cn_pnbuf,
						nd.ni_cnd.cn_pnlen, M_NAMEI);
				if (exclusive_flag) {
					exclusive_flag = 0;
					VATTR_NULL(vap);
					bcopy(cverf, (caddr_t)&vap->va_atime,
						NFSX_V3CREATEVERF);
					error = VOP_SETATTR(nd.ni_vp, vap, cred,
						procp);
				}
			}
		} else if (vap->va_type == VCHR || vap->va_type == VBLK ||
			vap->va_type == VFIFO) {
			if (vap->va_type == VCHR && rdev == 0xffffffff)
				vap->va_type = VFIFO;
			if (vap->va_type != VFIFO &&
			    (error = suser(cred, (u_short *)0))) {
				vrele(nd.ni_startdir);
				_FREE_ZONE(nd.ni_cnd.cn_pnbuf,
						nd.ni_cnd.cn_pnlen, M_NAMEI);
				VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
				vput(nd.ni_dvp);
				nfsm_reply(0);
				return (error);
			} else
				vap->va_rdev = (dev_t)rdev;
			nqsrv_getl(nd.ni_dvp, ND_WRITE);
			if ((error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, vap))) {
				vrele(nd.ni_startdir);
				nfsm_reply(0);
			}
			nd.ni_cnd.cn_nameiop = LOOKUP;
			nd.ni_cnd.cn_flags &= ~(LOCKPARENT | SAVESTART);
			nd.ni_cnd.cn_proc = procp;
			nd.ni_cnd.cn_cred = cred;
			if ((error = lookup(&nd))) {
				_FREE_ZONE(nd.ni_cnd.cn_pnbuf,
					   nd.ni_cnd.cn_pnlen, M_NAMEI);
				nfsm_reply(0);
			}
			nfsrv_object_create(nd.ni_vp);
			FREE_ZONE(nd.ni_cnd.cn_pnbuf,
					nd.ni_cnd.cn_pnlen, M_NAMEI);
			if (nd.ni_cnd.cn_flags & ISSYMLINK) {
				vrele(nd.ni_dvp);
				vput(nd.ni_vp);
				VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
				error = EINVAL;
				nfsm_reply(0);
			}
		} else {
			vrele(nd.ni_startdir);
			_FREE_ZONE(nd.ni_cnd.cn_pnbuf,
					nd.ni_cnd.cn_pnlen, M_NAMEI);
			VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
			vput(nd.ni_dvp);
			error = ENXIO;
		}
		vp = nd.ni_vp;
	} else {
		vrele(nd.ni_startdir);
		_FREE_ZONE(nd.ni_cnd.cn_pnbuf, nd.ni_cnd.cn_pnlen, M_NAMEI);
		vp = nd.ni_vp;
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (vap->va_size != -1) {
			error = nfsrv_access(vp, VWRITE, cred,
			    (nd.ni_cnd.cn_flags & RDONLY), procp, 0);
			if (!error) {
				nqsrv_getl(vp, ND_WRITE);
				tempsize = vap->va_size;
				VATTR_NULL(vap);
				vap->va_size = tempsize;
				error = VOP_SETATTR(vp, vap, cred,
					 procp);
			}
			if (error)
				vput(vp);
		} else {
			if (error) 
				vput(vp); /* make sure we catch the EEXIST for nfsv3 */
		}
	}
	if (!error) {
		bzero((caddr_t)fhp, sizeof(nfh));
		fhp->fh_fsid = vp->v_mount->mnt_stat.f_fsid;
		error = VFS_VPTOFH(vp, &fhp->fh_fid);
		if (!error)
			error = VOP_GETATTR(vp, vap, cred, procp);
		vput(vp);
	}
	if (v3) {
		if (exclusive_flag && !error &&
			bcmp(cverf, (caddr_t)&vap->va_atime, NFSX_V3CREATEVERF))
			error = EEXIST;
		diraft_ret = VOP_GETATTR(dirp, &diraft, cred, procp);
		vrele(dirp);
	}
	nfsm_reply(NFSX_SRVFH(v3) + NFSX_FATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		if (!error) {
			nfsm_srvpostop_fh(fhp);
			nfsm_srvpostop_attr(0, vap);
		}
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	} else {
		nfsm_srvfhtom(fhp, v3);
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(vap, fp);
	}
	return (error);
nfsmout:
	if (dirp)
		vrele(dirp);
	if (nd.ni_cnd.cn_nameiop) {
		vrele(nd.ni_startdir);
		_FREE_ZONE((caddr_t)nd.ni_cnd.cn_pnbuf,
					nd.ni_cnd.cn_pnlen, M_NAMEI);
	}
	VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
	if (nd.ni_dvp == nd.ni_vp)
		vrele(nd.ni_dvp);
	else
		vput(nd.ni_dvp);
	if (nd.ni_vp)
		vput(nd.ni_vp);
	return (error);
}

/*
 * nfs v3 mknod service
 */
int
nfsrv_mknod(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct vattr va, dirfor, diraft;
	register struct vattr *vap = &va;
	register u_long *tl;
	struct nameidata nd;
	register long t1;
	caddr_t bpos;
	int error = 0, cache, len, dirfor_ret = 1, diraft_ret = 1;
	u_long major, minor;
	enum vtype vtyp;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vnode *vp, *dirp = (struct vnode *)0;
	nfsfh_t nfh;
	fhandle_t *fhp;
	u_quad_t frev;

	nd.ni_cnd.cn_nameiop = 0;
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvnamesiz(len);
	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF | SAVESTART;
	error = nfs_namei(&nd, fhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (dirp)
		dirfor_ret = VOP_GETATTR(dirp, &dirfor, cred, procp);
	if (error) {
		nfsm_reply(NFSX_WCCDATA(1));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vrele(dirp);
		return (0);
	}
	nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
	vtyp = nfsv3tov_type(*tl);
	if (vtyp != VCHR && vtyp != VBLK && vtyp != VSOCK && vtyp != VFIFO) {
		vrele(nd.ni_startdir);
		_FREE_ZONE((caddr_t)nd.ni_cnd.cn_pnbuf,
					nd.ni_cnd.cn_pnlen, M_NAMEI);
		error = NFSERR_BADTYPE;
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		vput(nd.ni_dvp);
		goto out;
	}
	VATTR_NULL(vap);
	nfsm_srvsattr(vap);
	if (vtyp == VCHR || vtyp == VBLK) {
		nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED);
		major = fxdr_unsigned(u_long, *tl++);
		minor = fxdr_unsigned(u_long, *tl);
		vap->va_rdev = makedev(major, minor);
	}

	/*
	 * Iff doesn't exist, create it.
	 */
	if (nd.ni_vp) {
		vrele(nd.ni_startdir);
		_FREE_ZONE((caddr_t)nd.ni_cnd.cn_pnbuf,
					nd.ni_cnd.cn_pnlen, M_NAMEI);
		error = EEXIST;
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		vput(nd.ni_dvp);
		goto out;
	}
	vap->va_type = vtyp;
	if (vtyp == VSOCK) {
		vrele(nd.ni_startdir);
		nqsrv_getl(nd.ni_dvp, ND_WRITE);
		error = VOP_CREATE(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, vap);
		if (!error)
			FREE_ZONE(nd.ni_cnd.cn_pnbuf,
					nd.ni_cnd.cn_pnlen, M_NAMEI);
	} else {
		if (vtyp != VFIFO && (error = suser(cred, (u_short *)0))) {
			vrele(nd.ni_startdir);
			_FREE_ZONE((caddr_t)nd.ni_cnd.cn_pnbuf,
						nd.ni_cnd.cn_pnlen, M_NAMEI);
			VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
			vput(nd.ni_dvp);
			goto out;
		}
		nqsrv_getl(nd.ni_dvp, ND_WRITE);
		if ((error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, vap))) {
			vrele(nd.ni_startdir);
			goto out;
		}
		nd.ni_cnd.cn_nameiop = LOOKUP;
		nd.ni_cnd.cn_flags &= ~(LOCKPARENT | SAVESTART);
		nd.ni_cnd.cn_proc = procp;
		nd.ni_cnd.cn_cred = procp->p_ucred;
		error = lookup(&nd);
		FREE_ZONE(nd.ni_cnd.cn_pnbuf, nd.ni_cnd.cn_pnlen, M_NAMEI);
		if (error)
			goto out;
		if (nd.ni_cnd.cn_flags & ISSYMLINK) {
			vrele(nd.ni_dvp);
			vput(nd.ni_vp);
			VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
			error = EINVAL;
		}
	}
out:
	vp = nd.ni_vp;
	if (!error) {
		bzero((caddr_t)fhp, sizeof(nfh));
		fhp->fh_fsid = vp->v_mount->mnt_stat.f_fsid;
		error = VFS_VPTOFH(vp, &fhp->fh_fid);
		if (!error)
			error = VOP_GETATTR(vp, vap, cred, procp);
		vput(vp);
	}
	diraft_ret = VOP_GETATTR(dirp, &diraft, cred, procp);
	vrele(dirp);
	nfsm_reply(NFSX_SRVFH(1) + NFSX_POSTOPATTR(1) + NFSX_WCCDATA(1));
	if (!error) {
		nfsm_srvpostop_fh(fhp);
		nfsm_srvpostop_attr(0, vap);
	}
	nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	return (0);
nfsmout:
	if (dirp)
		vrele(dirp);
	if (nd.ni_cnd.cn_nameiop) {
		vrele(nd.ni_startdir);
		_FREE_ZONE((caddr_t)nd.ni_cnd.cn_pnbuf,
					nd.ni_cnd.cn_pnlen, M_NAMEI);
	}
	VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
	if (nd.ni_dvp == nd.ni_vp)
		vrele(nd.ni_dvp);
	else
		vput(nd.ni_dvp);
	if (nd.ni_vp)
		vput(nd.ni_vp);
	return (error);
}

/*
 * nfs remove service
 */
int
nfsrv_remove(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct nameidata nd;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, cache, len, dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mreq;
	struct vnode *vp, *dirp;
	struct vattr dirfor, diraft;
	nfsfh_t nfh;
	fhandle_t *fhp;
	u_quad_t frev;

#ifndef nolint
	vp = (struct vnode *)0;
#endif
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvnamesiz(len);
	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = DELETE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfs_namei(&nd, fhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (dirp) {
		if (v3)
			dirfor_ret = VOP_GETATTR(dirp, &dirfor, cred,
				procp);
		else
			vrele(dirp);
	}
	if (!error) {
		vp = nd.ni_vp;
		if (vp->v_type == VDIR) {
			error = EPERM;		/* POSIX */
			goto out;
		}
		/*
		 * The root of a mounted filesystem cannot be deleted.
		 */
		if (vp->v_flag & VROOT) {
			error = EBUSY;
			goto out;
		}
out:
		if (!error) {
			nqsrv_getl(nd.ni_dvp, ND_WRITE);
			nqsrv_getl(vp, ND_WRITE);

			error = VOP_REMOVE(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);

		} else {
			VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
			if (nd.ni_dvp == vp)
				vrele(nd.ni_dvp);
			else
				vput(nd.ni_dvp);
			vput(vp);
		}
	}
	if (dirp && v3) {
		diraft_ret = VOP_GETATTR(dirp, &diraft, cred, procp);
		vrele(dirp);
	}
	nfsm_reply(NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
	nfsm_srvdone;
}

/*
 * nfs rename service
 */
int
nfsrv_rename(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, cache, len, len2, fdirfor_ret = 1, fdiraft_ret = 1;
	int tdirfor_ret = 1, tdiraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mreq;
	struct nameidata fromnd, tond;
	struct vnode *fvp, *tvp, *tdvp, *fdirp = (struct vnode *)0;
	struct vnode *tdirp = (struct vnode *)0;
	struct vattr fdirfor, fdiraft, tdirfor, tdiraft;
	nfsfh_t fnfh, tnfh;
	fhandle_t *ffhp, *tfhp;
	u_quad_t frev;
	uid_t saved_uid;

#ifndef nolint
	fvp = (struct vnode *)0;
#endif
	ffhp = &fnfh.fh_generic;
	tfhp = &tnfh.fh_generic;
	fromnd.ni_cnd.cn_nameiop = 0;
	tond.ni_cnd.cn_nameiop = 0;
	nfsm_srvmtofh(ffhp);
	nfsm_srvnamesiz(len);
	/*
	 * Remember our original uid so that we can reset cr_uid before
	 * the second nfs_namei() call, in case it is remapped.
	 */
	saved_uid = cred->cr_uid;
	fromnd.ni_cnd.cn_cred = cred;
	fromnd.ni_cnd.cn_nameiop = DELETE;
	fromnd.ni_cnd.cn_flags = WANTPARENT | SAVESTART;
	error = nfs_namei(&fromnd, ffhp, len, slp, nam, &md,
		&dpos, &fdirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (fdirp) {
		if (v3)
			fdirfor_ret = VOP_GETATTR(fdirp, &fdirfor, cred,
				procp);
		else {
			vrele(fdirp);
			fdirp = (struct vnode *)0;
		}
	}
	if (error) {
		nfsm_reply(2 * NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(fdirfor_ret, &fdirfor, fdiraft_ret, &fdiraft);
		nfsm_srvwcc_data(tdirfor_ret, &tdirfor, tdiraft_ret, &tdiraft);
		if (fdirp)
			vrele(fdirp);
		return (0);
	}
	fvp = fromnd.ni_vp;
	nfsm_srvmtofh(tfhp);
	nfsm_strsiz(len2, NFS_MAXNAMLEN);
	cred->cr_uid = saved_uid;
	tond.ni_cnd.cn_cred = cred;
	tond.ni_cnd.cn_nameiop = RENAME;
	tond.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF | NOCACHE | SAVESTART;
	error = nfs_namei(&tond, tfhp, len2, slp, nam, &md,
		&dpos, &tdirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (tdirp) {
		if (v3)
			tdirfor_ret = VOP_GETATTR(tdirp, &tdirfor, cred,
				procp);
		else {
			vrele(tdirp);
			tdirp = (struct vnode *)0;
		}
	}
	if (error) {
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		goto out1;
	}
	tdvp = tond.ni_dvp;
	tvp = tond.ni_vp;
	if (tvp != NULL) {
		if (fvp->v_type == VDIR && tvp->v_type != VDIR) {
			if (v3)
				error = EEXIST;
			else
				error = EISDIR;
			goto out;
		} else if (fvp->v_type != VDIR && tvp->v_type == VDIR) {
			if (v3)
				error = EEXIST;
			else
				error = ENOTDIR;
			goto out;
		}
		if (tvp->v_type == VDIR && tvp->v_mountedhere) {
			if (v3)
				error = EXDEV;
			else
				error = ENOTEMPTY;
			goto out;
		}
	}
	if (fvp->v_type == VDIR && fvp->v_mountedhere) {
		if (v3)
			error = EXDEV;
		else
			error = ENOTEMPTY;
		goto out;
	}
	if (fvp->v_mount != tdvp->v_mount) {
		if (v3)
			error = EXDEV;
		else
			error = ENOTEMPTY;
		goto out;
	}
	if (fvp == tdvp)
		if (v3)
			error = EINVAL;
		else
			error = ENOTEMPTY;
	/*
	 * If source is the same as the destination (that is the
	 * same vnode) then there is nothing to do.
	 * (fixed to have POSIX semantics - CSM 3/2/98)
	 */
	if (fvp == tvp)
		error = -1;
out:
	if (!error) {
		nqsrv_getl(fromnd.ni_dvp, ND_WRITE);
		nqsrv_getl(tdvp, ND_WRITE);
		if (tvp) 
			nqsrv_getl(tvp, ND_WRITE);
		error = VOP_RENAME(fromnd.ni_dvp, fromnd.ni_vp, &fromnd.ni_cnd,
				   tond.ni_dvp, tond.ni_vp, &tond.ni_cnd);
	} else {
		VOP_ABORTOP(tond.ni_dvp, &tond.ni_cnd);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		if (tvp)
			vput(tvp);
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		if (error == -1)
			error = 0;
	}
	vrele(tond.ni_startdir);
	FREE_ZONE(tond.ni_cnd.cn_pnbuf, tond.ni_cnd.cn_pnlen, M_NAMEI);
out1:
	if (fdirp) {
		fdiraft_ret = VOP_GETATTR(fdirp, &fdiraft, cred, procp);
		vrele(fdirp);
	}
	if (tdirp) {
		tdiraft_ret = VOP_GETATTR(tdirp, &tdiraft, cred, procp);
		vrele(tdirp);
	}
	vrele(fromnd.ni_startdir);
	FREE_ZONE(fromnd.ni_cnd.cn_pnbuf, fromnd.ni_cnd.cn_pnlen, M_NAMEI);
	nfsm_reply(2 * NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvwcc_data(fdirfor_ret, &fdirfor, fdiraft_ret, &fdiraft);
		nfsm_srvwcc_data(tdirfor_ret, &tdirfor, tdiraft_ret, &tdiraft);
	}
	return (0);

nfsmout:
	if (fdirp)
		vrele(fdirp);
	if (tdirp)
		vrele(tdirp);
	if (tond.ni_cnd.cn_nameiop) {
		vrele(tond.ni_startdir);
		FREE_ZONE(tond.ni_cnd.cn_pnbuf, tond.ni_cnd.cn_pnlen, M_NAMEI);
	}
	if (fromnd.ni_cnd.cn_nameiop) {
		vrele(fromnd.ni_startdir);
		FREE_ZONE(fromnd.ni_cnd.cn_pnbuf,
				fromnd.ni_cnd.cn_pnlen, M_NAMEI);
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
	}
	return (error);
}

/*
 * nfs link service
 */
int
nfsrv_link(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct nameidata nd;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, len, dirfor_ret = 1, diraft_ret = 1;
	int getret = 1, v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mreq;
	struct vnode *vp, *xp, *dirp = (struct vnode *)0;
	struct vattr dirfor, diraft, at;
	nfsfh_t nfh, dnfh;
	fhandle_t *fhp, *dfhp;
	u_quad_t frev;

	fhp = &nfh.fh_generic;
	dfhp = &dnfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvmtofh(dfhp);
	nfsm_srvnamesiz(len);
	if ((error = nfsrv_fhtovp(fhp, FALSE, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
		nfsm_srvpostop_attr(getret, &at);
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
	if (vp->v_type == VDIR) {
		error = EPERM;		/* POSIX */
		goto out1;
	}
	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT;
	error = nfs_namei(&nd, dfhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (dirp) {
		if (v3)
			dirfor_ret = VOP_GETATTR(dirp, &dirfor, cred,
				procp);
		else {
			vrele(dirp);
			dirp = (struct vnode *)0;
		}
	}
	if (error)
		goto out1;
	xp = nd.ni_vp;
	if (xp != NULL) {
		error = EEXIST;
		goto out;
	}
	xp = nd.ni_dvp;
	if (vp->v_mount != xp->v_mount)
		error = EXDEV;
out:
	if (!error) {
		nqsrv_getl(vp, ND_WRITE);
		nqsrv_getl(xp, ND_WRITE);
		error = VOP_LINK(vp, nd.ni_dvp, &nd.ni_cnd);
	} else {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (nd.ni_vp)
			vrele(nd.ni_vp);
	}
out1:
	if (v3)
		getret = VOP_GETATTR(vp, &at, cred, procp);
	if (dirp) {
		diraft_ret = VOP_GETATTR(dirp, &diraft, cred, procp);
		vrele(dirp);
	}
	vrele(vp);
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvpostop_attr(getret, &at);
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
	nfsm_srvdone;
}

/*
 * nfs symbolic link service
 */
int
nfsrv_symlink(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct vattr va, dirfor, diraft;
	struct nameidata nd;
	register struct vattr *vap = &va;
	register u_long *tl;
	register long t1;
	struct nfsv2_sattr *sp;
	char *bpos, *pathcp = (char *)0, *cp2;
	struct uio io;
	struct iovec iv;
	int error = 0, cache, len, len2, dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	struct mbuf *mb, *mreq, *mb2;
	struct vnode *dirp = (struct vnode *)0;
	nfsfh_t nfh;
	fhandle_t *fhp;
	u_quad_t frev;

	nd.ni_cnd.cn_nameiop = 0;
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvnamesiz(len);
	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | SAVESTART;
	error = nfs_namei(&nd, fhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (dirp) {
		if (v3)
			dirfor_ret = VOP_GETATTR(dirp, &dirfor, cred,
				procp);
		else {
			vrele(dirp);
			dirp = (struct vnode *)0;
		}
	}
	if (error)
		goto out;
	VATTR_NULL(vap);
	if (v3)
		nfsm_srvsattr(vap);
	nfsm_strsiz(len2, NFS_MAXPATHLEN);
	MALLOC(pathcp, caddr_t, len2 + 1, M_TEMP, M_WAITOK);
	iv.iov_base = pathcp;
	iv.iov_len = len2;
	io.uio_resid = len2;
	io.uio_offset = 0;
	io.uio_iov = &iv;
	io.uio_iovcnt = 1;
	io.uio_segflg = UIO_SYSSPACE;
	io.uio_rw = UIO_READ;
	io.uio_procp = (struct proc *)0;
	nfsm_mtouio(&io, len2);
	if (!v3) {
		nfsm_dissect(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		vap->va_mode = fxdr_unsigned(u_short, sp->sa_mode);
	}
	*(pathcp + len2) = '\0';
	if (nd.ni_vp) {
		vrele(nd.ni_startdir);
		_FREE_ZONE(nd.ni_cnd.cn_pnbuf, nd.ni_cnd.cn_pnlen, M_NAMEI);
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		error = EEXIST;
		goto out;
	}
	nqsrv_getl(nd.ni_dvp, ND_WRITE);
	error = VOP_SYMLINK(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, vap, pathcp);
	if (error)
		vrele(nd.ni_startdir);
	else {
	    if (v3) {
		nd.ni_cnd.cn_nameiop = LOOKUP;
		nd.ni_cnd.cn_flags &= ~(LOCKPARENT | SAVESTART | FOLLOW);
		nd.ni_cnd.cn_flags |= (NOFOLLOW | LOCKLEAF);
		nd.ni_cnd.cn_proc = procp;
		nd.ni_cnd.cn_cred = cred;
		error = lookup(&nd);
		if (!error) {
			bzero((caddr_t)fhp, sizeof(nfh));
			fhp->fh_fsid = nd.ni_vp->v_mount->mnt_stat.f_fsid;
			error = VFS_VPTOFH(nd.ni_vp, &fhp->fh_fid);
			if (!error)
				error = VOP_GETATTR(nd.ni_vp, vap, cred,
					procp);
			vput(nd.ni_vp);
		}
	    } else
		vrele(nd.ni_startdir);
	    FREE_ZONE(nd.ni_cnd.cn_pnbuf, nd.ni_cnd.cn_pnlen, M_NAMEI);
	}
out:
	if (pathcp)
		FREE(pathcp, M_TEMP);
	if (dirp) {
		diraft_ret = VOP_GETATTR(dirp, &diraft, cred, procp);
		vrele(dirp);
	}
	nfsm_reply(NFSX_SRVFH(v3) + NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		if (!error) {
			nfsm_srvpostop_fh(fhp);
			nfsm_srvpostop_attr(0, vap);
		}
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	}
	return (0);
nfsmout:
	if (nd.ni_cnd.cn_nameiop) {
		vrele(nd.ni_startdir);
		_FREE_ZONE(nd.ni_cnd.cn_pnbuf, nd.ni_cnd.cn_pnlen, M_NAMEI);
	}
	if (dirp)
		vrele(dirp);
	VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
	if (nd.ni_dvp == nd.ni_vp)
		vrele(nd.ni_dvp);
	else
		vput(nd.ni_dvp);
	if (nd.ni_vp)
		vrele(nd.ni_vp);
	if (pathcp)
		FREE(pathcp, M_TEMP);
	return (error);
}

/*
 * nfs mkdir service
 */
int
nfsrv_mkdir(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct vattr va, dirfor, diraft;
	register struct vattr *vap = &va;
	register struct nfs_fattr *fp;
	struct nameidata nd;
	register caddr_t cp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, cache, len, dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vnode *vp, *dirp = (struct vnode *)0;
	nfsfh_t nfh;
	fhandle_t *fhp;
	u_quad_t frev;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvnamesiz(len);
	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT;
	error = nfs_namei(&nd, fhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (dirp) {
		if (v3)
			dirfor_ret = VOP_GETATTR(dirp, &dirfor, cred,
				procp);
		else {
			vrele(dirp);
			dirp = (struct vnode *)0;
		}
	}
	if (error) {
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vrele(dirp);
		return (0);
	}
	VATTR_NULL(vap);
	if (v3) {
		nfsm_srvsattr(vap);
	} else {
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED);
		vap->va_mode = nfstov_mode(*tl++);
	}
	vap->va_type = VDIR;
	vp = nd.ni_vp;
	if (vp != NULL) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		error = EEXIST;
		goto out;
	}
	nqsrv_getl(nd.ni_dvp, ND_WRITE);
	error = VOP_MKDIR(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, vap);
	if (!error) {
		vp = nd.ni_vp;
		bzero((caddr_t)fhp, sizeof(nfh));
		fhp->fh_fsid = vp->v_mount->mnt_stat.f_fsid;
		error = VFS_VPTOFH(vp, &fhp->fh_fid);
		if (!error)
			error = VOP_GETATTR(vp, vap, cred, procp);
		vput(vp);
	}
out:
	if (dirp) {
		diraft_ret = VOP_GETATTR(dirp, &diraft, cred, procp);
		vrele(dirp);
	}
	nfsm_reply(NFSX_SRVFH(v3) + NFSX_POSTOPATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		if (!error) {
			nfsm_srvpostop_fh(fhp);
			nfsm_srvpostop_attr(0, vap);
		}
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	} else {
		nfsm_srvfhtom(fhp, v3);
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(vap, fp);
	}
	return (0);
nfsmout:
	if (dirp)
		vrele(dirp);
	VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
	if (nd.ni_dvp == nd.ni_vp)
		vrele(nd.ni_dvp);
	else
		vput(nd.ni_dvp);
	if (nd.ni_vp)
		vrele(nd.ni_vp);
	return (error);
}

/*
 * nfs rmdir service
 */
int
nfsrv_rmdir(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, cache, len, dirfor_ret = 1, diraft_ret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mreq;
	struct vnode *vp, *dirp = (struct vnode *)0;
	struct vattr dirfor, diraft;
	nfsfh_t nfh;
	fhandle_t *fhp;
	struct nameidata nd;
	u_quad_t frev;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_srvnamesiz(len);
	nd.ni_cnd.cn_cred = cred;
	nd.ni_cnd.cn_nameiop = DELETE;
	nd.ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
	error = nfs_namei(&nd, fhp, len, slp, nam, &md, &dpos,
		&dirp, procp, (nfsd->nd_flag & ND_KERBAUTH), FALSE);
	if (dirp) {
		if (v3)
			dirfor_ret = VOP_GETATTR(dirp, &dirfor, cred,
				procp);
		else {
			vrele(dirp);
			dirp = (struct vnode *)0;
		}
	}
	if (error) {
		nfsm_reply(NFSX_WCCDATA(v3));
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		if (dirp)
			vrele(dirp);
		return (0);
	}
	vp = nd.ni_vp;
	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}
	/*
	 * No rmdir "." please.
	 */
	if (nd.ni_dvp == vp) {
		error = EINVAL;
		goto out;
	}
	/*
	 * The root of a mounted filesystem cannot be deleted.
	 */
	if (vp->v_flag & VROOT)
		error = EBUSY;
out:
	if (!error) {
		nqsrv_getl(nd.ni_dvp, ND_WRITE);
		nqsrv_getl(vp, ND_WRITE);
		error = VOP_RMDIR(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);
	} else {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vput(vp);
	}
	if (dirp) {
		diraft_ret = VOP_GETATTR(dirp, &diraft, cred, procp);
		vrele(dirp);
	}
	nfsm_reply(NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		return (0);
	}
	nfsm_srvdone;
}

/*
 * nfs readdir service
 * - mallocs what it thinks is enough to read
 *	count rounded up to a multiple of NFS_DIRBLKSIZ <= NFS_MAXREADDIR
 * - calls VOP_READDIR()
 * - loops around building the reply
 *	if the output generated exceeds count break out of loop
 *	The nfsm_clget macro is used here so that the reply will be packed
 *	tightly in mbuf clusters.
 * - it only knows that it has encountered eof when the VOP_READDIR()
 *	reads nothing
 * - as such one readdir rpc will return eof false although you are there
 *	and then the next will return eof
 * - it trims out records with d_fileno == 0
 *	this doesn't matter for Unix clients, but they might confuse clients
 *	for other os'.
 * NB: It is tempting to set eof to true if the VOP_READDIR() reads less
 *	than requested, but this may not apply to all filesystems. For
 *	example, client NFS does not { although it is never remote mounted
 *	anyhow }
 *     The alternate call nfsrv_readdirplus() does lookups as well.
 * PS: The NFS protocol spec. does not clarify what the "count" byte
 *	argument is a count of.. just name strings and file id's or the
 *	entire reply rpc or ...
 *	I tried just file name and id sizes and it confused the Sun client,
 *	so I am using the full rpc size now. The "paranoia.." comment refers
 *	to including the status longwords that are not a part of the dir.
 *	"entry" structures, but are in the rpc.
 */
struct flrep {
	nfsuint64	fl_off;
	u_long		fl_postopok;
	u_long		fl_fattr[NFSX_V3FATTR / sizeof (u_long)];
	u_long		fl_fhok;
	u_long		fl_fhsize;
	u_long		fl_nfh[NFSX_V3FH / sizeof (u_long)];
};

int
nfsrv_readdir(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register char *bp, *be;
	register struct mbuf *mp;
	register struct dirent *dp;
	register caddr_t cp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	struct mbuf *mb, *mb2, *mreq, *mp2;
	char *cpos, *cend, *cp2, *rbuf;
	struct vnode *vp;
	struct vattr at;
	nfsfh_t nfh;
	fhandle_t *fhp;
	struct uio io;
	struct iovec iv;
	int len, nlen, rem, xfer, tsiz, i, error = 0, getret = 1;
	int siz, cnt, fullsiz, eofflag, rdonly, cache, ncookies = 0;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	u_quad_t frev, off, toff, verf;
	u_long *cookies = NULL, *cookiep;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
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
	cnt = fxdr_unsigned(int, *tl);
	siz = ((cnt + DIRBLKSIZ - 1) & ~(DIRBLKSIZ - 1));
	xfer = NFS_SRVMAXDATA(nfsd);
	if (siz > xfer)
		siz = xfer;
	fullsiz = siz;
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	nqsrv_getl(vp, ND_READ);
	if (v3) {
		error = getret = VOP_GETATTR(vp, &at, cred, procp);
		if (!error && toff && verf && verf != at.va_filerev)
			error = NFSERR_BAD_COOKIE;
	}
	if (!error)
		error = nfsrv_access(vp, VEXEC, cred, rdonly, procp, 0);
	if (error) {
		vput(vp);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	VOP_UNLOCK(vp, 0, procp);
	MALLOC(rbuf, caddr_t, siz, M_TEMP, M_WAITOK);
again:
	iv.iov_base = rbuf;
	iv.iov_len = fullsiz;
	io.uio_iov = &iv;
	io.uio_iovcnt = 1;
	io.uio_offset = (off_t)off;
	io.uio_resid = fullsiz;
	io.uio_segflg = UIO_SYSSPACE;
	io.uio_rw = UIO_READ;
	io.uio_procp = (struct proc *)0;
	eofflag = 0;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, procp);
	if (cookies) {
		_FREE((caddr_t)cookies, M_TEMP);
		cookies = NULL;
	}
	error = VOP_READDIR(vp, &io, cred, &eofflag, &ncookies, &cookies);
	off = (off_t)io.uio_offset;
        /*
         * We cannot set the error in the case where there are no cookies 
         * and no error, only, as FreeBSD. In the scenario the client is
         * calling us back being told there were "more" entries on last readdir
         * return, and we have no more entries, our VOP_READDIR can give 
         * cookies = NULL and no error. This is due to a zero size to MALLOC
         * returning NULL unlike FreeBSD which returns a pointer.
         * With FreeBSD it makes sense if the MALLOC failed and you get in that
         * bind. For us, we need something more. Thus, we should make sure we
         * had some cookies to return, but no pointer and no error for EPERM case.
         * Otherwise, go thru normal processing of sending back the eofflag. This check
         * is also legit on first call to the routine by client since . and ..
         * should be returned. Make same change to nfsrv_readdirplus. 
         */
	if ((ncookies != 0) && !cookies && !error)
         	error = NFSERR_PERM;
                
	if (v3) {
		getret = VOP_GETATTR(vp, &at, cred, procp);
		if (!error)
			error = getret;
	}
	VOP_UNLOCK(vp, 0, procp);
	if (error) {
		vrele(vp);
		_FREE((caddr_t)rbuf, M_TEMP);
		if (cookies)
			_FREE((caddr_t)cookies, M_TEMP);
		nfsm_reply(NFSX_POSTOPATTR(v3));
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if (io.uio_resid) {
		siz -= io.uio_resid;

		/*
		 * If nothing read, return eof
		 * rpc reply
		 */
		if (siz == 0) {
			vrele(vp);
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
			FREE((caddr_t)rbuf, M_TEMP);
			FREE((caddr_t)cookies, M_TEMP);
			return (0);
		}
	}

	/*
	 * Check for degenerate cases of nothing useful read.
	 * If so go try again
	 */
	cpos = rbuf;
	cend = rbuf + siz;
	dp = (struct dirent *)cpos;
	cookiep = cookies;
#ifdef __FreeBSD__
	/*
	 * For some reason FreeBSD's ufs_readdir() chooses to back the
	 * directory offset up to a block boundary, so it is necessary to
	 * skip over the records that preceed the requested offset. This
	 * requires the assumption that file offset cookies monotonically
	 * increase.
	 */
	while (cpos < cend && ncookies > 0 &&
		(dp->d_fileno == 0 || ((u_quad_t)(*cookiep)) <= toff)) {
#else
	while (dp->d_fileno == 0 && cpos < cend && ncookies > 0) {
#endif
		cpos += dp->d_reclen;
		dp = (struct dirent *)cpos;
		cookiep++;
		ncookies--;
	}
	if (cpos >= cend || ncookies == 0) {
		toff = off;
		siz = fullsiz;
		goto again;
	}

	len = 3 * NFSX_UNSIGNED;	/* paranoia, probably can be 0 */
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_COOKIEVERF(v3) + siz);
	if (v3) {
		nfsm_srvpostop_attr(getret, &at);
		nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
		txdr_hyper(&at.va_filerev, tl);
	}
	mp = mp2 = mb;
	bp = bpos;
	be = bp + M_TRAILINGSPACE(mp);

	/* Loop through the records and build reply */
	while (cpos < cend && ncookies > 0) {
		if (dp->d_fileno != 0) {
			nlen = dp->d_namlen;
			rem = nfsm_rndup(nlen)-nlen;
			len += (4 * NFSX_UNSIGNED + nlen + rem);
			if (v3)
				len += 2 * NFSX_UNSIGNED;
			if (len > cnt) {
				eofflag = 0;
				break;
			}
			/*
			 * Build the directory record xdr from
			 * the dirent entry.
			 */
			nfsm_clget;
			*tl = nfs_true;
			bp += NFSX_UNSIGNED;
			if (v3) {
				nfsm_clget;
				*tl = 0;
				bp += NFSX_UNSIGNED;
			}
			nfsm_clget;
			*tl = txdr_unsigned(dp->d_fileno);
			bp += NFSX_UNSIGNED;
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
			nfsm_clget;

			/* Finish off the record */
			if (v3) {
				*tl = 0;
				bp += NFSX_UNSIGNED;
				nfsm_clget;
			}
			*tl = txdr_unsigned(*cookiep);
			bp += NFSX_UNSIGNED;
		}
		cpos += dp->d_reclen;
		dp = (struct dirent *)cpos;
		cookiep++;
		ncookies--;
	}
	vrele(vp);
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
			mp->m_len = bp - mtod(mp, caddr_t);
	} else
		mp->m_len += bp - bpos;
	FREE((caddr_t)rbuf, M_TEMP);
	FREE((caddr_t)cookies, M_TEMP);
	nfsm_srvdone;
}

int
nfsrv_readdirplus(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register char *bp, *be;
	register struct mbuf *mp;
	register struct dirent *dp;
	register caddr_t cp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	struct mbuf *mb, *mb2, *mreq, *mp2;
	char *cpos, *cend, *cp2, *rbuf;
	struct vnode *vp, *nvp;
	struct flrep fl;
	nfsfh_t nfh;
	fhandle_t *fhp, *nfhp = (fhandle_t *)fl.fl_nfh;
	struct uio io;
	struct iovec iv;
	struct vattr va, at, *vap = &va;
	struct nfs_fattr *fp;
	int len, nlen, rem, xfer, tsiz, i, error = 0, getret = 1;
	int siz, cnt, fullsiz, eofflag, rdonly, cache, dirlen, ncookies = 0;
	u_quad_t frev, off, toff, verf;
	u_long *cookies = NULL, *cookiep;
	void *file;

	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_dissect(tl, u_long *, 6 * NFSX_UNSIGNED);
	fxdr_hyper(tl, &toff);
	tl += 2;
	fxdr_hyper(tl, &verf);
	tl += 2;
	siz = fxdr_unsigned(int, *tl++);
	cnt = fxdr_unsigned(int, *tl);
	off = toff;
	siz = ((siz + DIRBLKSIZ - 1) & ~(DIRBLKSIZ - 1));
	xfer = NFS_SRVMAXDATA(nfsd);
	if (siz > xfer)
		siz = xfer;
	fullsiz = siz;
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	error = getret = VOP_GETATTR(vp, &at, cred, procp);
	if (!error && toff && verf && verf != at.va_filerev)
		error = NFSERR_BAD_COOKIE;
	if (!error) {
		nqsrv_getl(vp, ND_READ);
		error = nfsrv_access(vp, VEXEC, cred, rdonly, procp, 0);
	}
	if (error) {
		vput(vp);
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	VOP_UNLOCK(vp, 0, procp);
	MALLOC(rbuf, caddr_t, siz, M_TEMP, M_WAITOK);
again:
	iv.iov_base = rbuf;
	iv.iov_len = fullsiz;
	io.uio_iov = &iv;
	io.uio_iovcnt = 1;
	io.uio_offset = (off_t)off;
	io.uio_resid = fullsiz;
	io.uio_segflg = UIO_SYSSPACE;
	io.uio_rw = UIO_READ;
	io.uio_procp = (struct proc *)0;
	eofflag = 0;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, procp);
	if (cookies) {
		_FREE((caddr_t)cookies, M_TEMP);
		cookies = NULL;
	}
	error = VOP_READDIR(vp, &io, cred, &eofflag, &ncookies, &cookies);
	off = (u_quad_t)io.uio_offset;
	getret = VOP_GETATTR(vp, &at, cred, procp);
	VOP_UNLOCK(vp, 0, procp);
        /*
         * See nfsrv_readdir comment above on this
         */
        if ((ncookies != 0) && !cookies && !error)
         	error = NFSERR_PERM;

	if (!error)
		error = getret;
	if (error) {
		vrele(vp);
		if (cookies)
			_FREE((caddr_t)cookies, M_TEMP);
		_FREE((caddr_t)rbuf, M_TEMP);
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	if (io.uio_resid) {
		siz -= io.uio_resid;

		/*
		 * If nothing read, return eof
		 * rpc reply
		 */
		if (siz == 0) {
			vrele(vp);
			nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3COOKIEVERF +
				2 * NFSX_UNSIGNED);
			nfsm_srvpostop_attr(getret, &at);
			nfsm_build(tl, u_long *, 4 * NFSX_UNSIGNED);
			txdr_hyper(&at.va_filerev, tl);
			tl += 2;
			*tl++ = nfs_false;
			*tl = nfs_true;
			FREE((caddr_t)cookies, M_TEMP);
			FREE((caddr_t)rbuf, M_TEMP);
			return (0);
		}
	}

	/*
	 * Check for degenerate cases of nothing useful read.
	 * If so go try again
	 */
	cpos = rbuf;
	cend = rbuf + siz;
	dp = (struct dirent *)cpos;
	cookiep = cookies;
#ifdef __FreeBSD__
	/*
	 * For some reason FreeBSD's ufs_readdir() chooses to back the
	 * directory offset up to a block boundary, so it is necessary to
	 * skip over the records that preceed the requested offset. This
	 * requires the assumption that file offset cookies monotonically
	 * increase.
	 */
	while (cpos < cend && ncookies > 0 &&
		(dp->d_fileno == 0 || ((u_quad_t)(*cookiep)) <= toff)) {
#else
	while (dp->d_fileno == 0 && cpos < cend && ncookies > 0) {
#endif
		cpos += dp->d_reclen;
		dp = (struct dirent *)cpos;
		cookiep++;
		ncookies--;
	}
	if (cpos >= cend || ncookies == 0) {
		toff = off;
		siz = fullsiz;
		goto again;
	}

	/*
	 * Probe one of the directory entries to see if the filesystem
	 * supports VGET. See later comment for VFS_VGET changes.
	 */
	if (vp->v_tag == VT_UFS) 
		file = (void *) dp->d_fileno;
	else {
		file = &dp->d_fileno;
	}
	
	if (error = VFS_VGET(vp->v_mount, file, &nvp)) {
		if (error == EOPNOTSUPP) /* let others get passed back */
			error = NFSERR_NOTSUPP; 
		vrele(vp);
		_FREE((caddr_t)cookies, M_TEMP);
		_FREE((caddr_t)rbuf, M_TEMP);
		nfsm_reply(NFSX_V3POSTOPATTR);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	vput(nvp);
	    
	dirlen = len = NFSX_V3POSTOPATTR + NFSX_V3COOKIEVERF + 2 * NFSX_UNSIGNED;
	nfsm_reply(cnt);
	nfsm_srvpostop_attr(getret, &at);
	nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED);
	txdr_hyper(&at.va_filerev, tl);
	mp = mp2 = mb;
	bp = bpos;
	be = bp + M_TRAILINGSPACE(mp);

	/* Loop through the records and build reply */
	while (cpos < cend && ncookies > 0) {
		if (dp->d_fileno != 0) {
			nlen = dp->d_namlen;
			rem = nfsm_rndup(nlen)-nlen;

			/* 
			 * Got to get the vnode for lookup per entry.
			 * HFS+/volfs and others use address of file identifier to VGET
			 * UFS, nullfs, umapfs use inode (u_int32_t)
			 * until they are consistent, we must differentiate now. 
			 * UFS is the only one of the latter class that is exported.
			 * Note this will be pulled out as we resolve the VGET issue
			 * of which it should use u_in32_t or addresses. 
			 */
			  
			if (vp->v_tag == VT_UFS) 
				file = (void *) dp->d_fileno;
			else 
				file = &dp->d_fileno;
				
			if (VFS_VGET(vp->v_mount, file, &nvp))
				goto invalid;
			bzero((caddr_t)nfhp, NFSX_V3FH);
			nfhp->fh_fsid =
				nvp->v_mount->mnt_stat.f_fsid;
			if (VFS_VPTOFH(nvp, &nfhp->fh_fid)) {
				vput(nvp);
				goto invalid;
			}
			if (VOP_GETATTR(nvp, vap, cred, procp)) {
				vput(nvp);
				goto invalid;
			}
			vput(nvp);

			/*
			 * If either the dircount or maxcount will be
			 * exceeded, get out now. Both of these lengths
			 * are calculated conservatively, including all
			 * XDR overheads.
			 */
			len += (7 * NFSX_UNSIGNED + nlen + rem + NFSX_V3FH +
				NFSX_V3POSTOPATTR);
			dirlen += (6 * NFSX_UNSIGNED + nlen + rem);
			if (len > cnt || dirlen > fullsiz) {
				eofflag = 0;
				break;
			}

			/*
			 * Build the directory record xdr from
			 * the dirent entry.
			 */
			fp = (struct nfs_fattr *)&fl.fl_fattr;
			nfsm_srvfillattr(vap, fp);
			fl.fl_fhsize = txdr_unsigned(NFSX_V3FH);
			fl.fl_fhok = nfs_true;
			fl.fl_postopok = nfs_true;
			fl.fl_off.nfsuquad[0] = 0;
			fl.fl_off.nfsuquad[1] = txdr_unsigned(*cookiep);

			nfsm_clget;
			*tl = nfs_true;
			bp += NFSX_UNSIGNED;
			nfsm_clget;
			*tl = 0;
			bp += NFSX_UNSIGNED;
			nfsm_clget;
			*tl = txdr_unsigned(dp->d_fileno);
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
			xfer = sizeof (struct flrep);
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
		dp = (struct dirent *)cpos;
		cookiep++;
		ncookies--;
	}
	vrele(vp);
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
			mp->m_len = bp - mtod(mp, caddr_t);
	} else
		mp->m_len += bp - bpos;
	FREE((caddr_t)cookies, M_TEMP);
	FREE((caddr_t)rbuf, M_TEMP);
	nfsm_srvdone;
}

/*
 * nfs commit service
 */
int
nfsrv_commit(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	struct vattr bfor, aft;
	struct vnode *vp;
	nfsfh_t nfh;
	fhandle_t *fhp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, for_ret = 1, aft_ret = 1, cnt, cache;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	u_quad_t frev, off;

#ifndef nolint
	cache = 0;
#endif
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);

	/*
	 * XXX At this time VOP_FSYNC() does not accept offset and byte
	 * count parameters, so these arguments are useless (someday maybe).
	 */
	fxdr_hyper(tl, &off);
	tl += 2;
	cnt = fxdr_unsigned(int, *tl);
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(2 * NFSX_UNSIGNED);
		nfsm_srvwcc_data(for_ret, &bfor, aft_ret, &aft);
		return (0);
	}
	for_ret = VOP_GETATTR(vp, &bfor, cred, procp);
	error = VOP_FSYNC(vp, cred, MNT_WAIT, procp);
	aft_ret = VOP_GETATTR(vp, &aft, cred, procp);
	vput(vp);
	nfsm_reply(NFSX_V3WCCDATA + NFSX_V3WRITEVERF);
	nfsm_srvwcc_data(for_ret, &bfor, aft_ret, &aft);
	if (!error) {
		nfsm_build(tl, u_long *, NFSX_V3WRITEVERF);
		*tl++ = txdr_unsigned(boottime.tv_sec);
		*tl = txdr_unsigned(boottime.tv_usec);
	} else
		return (0);
	nfsm_srvdone;
}

/*
 * nfs statfs service
 */
int
nfsrv_statfs(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register struct statfs *sf;
	register struct nfs_statfs *sfp;
	register u_long *tl;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, getret = 1;
	int v3 = (nfsd->nd_flag & ND_NFSV3);
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vnode *vp;
	struct vattr at;
	nfsfh_t nfh;
	fhandle_t *fhp;
	struct statfs statfs;
	u_quad_t frev, tval;

#ifndef nolint
	cache = 0;
#endif
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	sf = &statfs;
	error = VFS_STATFS(vp->v_mount, sf, procp);
	getret = VOP_GETATTR(vp, &at, cred, procp);
	vput(vp);
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_STATFS(v3));
	if (v3)
		nfsm_srvpostop_attr(getret, &at);
	if (error)
		return (0);
	nfsm_build(sfp, struct nfs_statfs *, NFSX_STATFS(v3));
	if (v3) {
		tval = (u_quad_t)sf->f_blocks;
		tval *= (u_quad_t)sf->f_bsize;
		txdr_hyper(&tval, &sfp->sf_tbytes);
		tval = (u_quad_t)sf->f_bfree;
		tval *= (u_quad_t)sf->f_bsize;
		txdr_hyper(&tval, &sfp->sf_fbytes);
		tval = (u_quad_t)sf->f_bavail;
		tval *= (u_quad_t)sf->f_bsize;
		txdr_hyper(&tval, &sfp->sf_abytes);
		sfp->sf_tfiles.nfsuquad[0] = 0;
		sfp->sf_tfiles.nfsuquad[1] = txdr_unsigned(sf->f_files);
		sfp->sf_ffiles.nfsuquad[0] = 0;
		sfp->sf_ffiles.nfsuquad[1] = txdr_unsigned(sf->f_ffree);
		sfp->sf_afiles.nfsuquad[0] = 0;
		sfp->sf_afiles.nfsuquad[1] = txdr_unsigned(sf->f_ffree);
		sfp->sf_invarsec = 0;
	} else {
		sfp->sf_tsize = txdr_unsigned(NFS_MAXDGRAMDATA);
		sfp->sf_bsize = txdr_unsigned(sf->f_bsize);
		sfp->sf_blocks = txdr_unsigned(sf->f_blocks);
		sfp->sf_bfree = txdr_unsigned(sf->f_bfree);
		sfp->sf_bavail = txdr_unsigned(sf->f_bavail);
	}
	nfsm_srvdone;
}

/*
 * nfs fsinfo service
 */
int
nfsrv_fsinfo(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register u_long *tl;
	register struct nfsv3_fsinfo *sip;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, getret = 1, pref;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vnode *vp;
	struct vattr at;
	nfsfh_t nfh;
	fhandle_t *fhp;
	u_quad_t frev;

#ifndef nolint
	cache = 0;
#endif
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	getret = VOP_GETATTR(vp, &at, cred, procp);
	vput(vp);
	nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3FSINFO);
	nfsm_srvpostop_attr(getret, &at);
	nfsm_build(sip, struct nfsv3_fsinfo *, NFSX_V3FSINFO);

	/*
	 * XXX
	 * There should be file system VFS OP(s) to get this information.
	 * For now, assume ufs.
	 */
	if (slp->ns_so->so_type == SOCK_DGRAM)
		pref = NFS_MAXDGRAMDATA;
	else
		pref = NFS_MAXDATA;
	sip->fs_rtmax = txdr_unsigned(NFS_MAXDATA);
	sip->fs_rtpref = txdr_unsigned(pref);
	sip->fs_rtmult = txdr_unsigned(NFS_FABLKSIZE);
	sip->fs_wtmax = txdr_unsigned(NFS_MAXDATA);
	sip->fs_wtpref = txdr_unsigned(pref);
	sip->fs_wtmult = txdr_unsigned(NFS_FABLKSIZE);
	sip->fs_dtpref = txdr_unsigned(pref);
	sip->fs_maxfilesize.nfsuquad[0] = 0xffffffff;
	sip->fs_maxfilesize.nfsuquad[1] = 0xffffffff;
	sip->fs_timedelta.nfsv3_sec = 0;
	sip->fs_timedelta.nfsv3_nsec = txdr_unsigned(1);
	sip->fs_properties = txdr_unsigned(NFSV3FSINFO_LINK |
		NFSV3FSINFO_SYMLINK | NFSV3FSINFO_HOMOGENEOUS |
		NFSV3FSINFO_CANSETTIME);
	nfsm_srvdone;
}

/*
 * nfs pathconf service
 */
int
nfsrv_pathconf(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;
	struct mbuf *nam = nfsd->nd_nam;
	caddr_t dpos = nfsd->nd_dpos;
	struct ucred *cred = &nfsd->nd_cr;
	register u_long *tl;
	register struct nfsv3_pathconf *pc;
	register long t1;
	caddr_t bpos;
	int error = 0, rdonly, cache, getret = 1, linkmax, namemax;
	int chownres, notrunc;
	char *cp2;
	struct mbuf *mb, *mb2, *mreq;
	struct vnode *vp;
	struct vattr at;
	nfsfh_t nfh;
	fhandle_t *fhp;
	u_quad_t frev;

#ifndef nolint
	cache = 0;
#endif
	fhp = &nfh.fh_generic;
	nfsm_srvmtofh(fhp);
	if ((error = nfsrv_fhtovp(fhp, 1, &vp, cred, slp, nam,
		 &rdonly, (nfsd->nd_flag & ND_KERBAUTH), TRUE))) {
		nfsm_reply(NFSX_UNSIGNED);
		nfsm_srvpostop_attr(getret, &at);
		return (0);
	}
	error = VOP_PATHCONF(vp, _PC_LINK_MAX, &linkmax);
	if (!error)
		error = VOP_PATHCONF(vp, _PC_NAME_MAX, &namemax);
	if (!error)
		error = VOP_PATHCONF(vp, _PC_CHOWN_RESTRICTED, &chownres);
	if (!error)
		error = VOP_PATHCONF(vp, _PC_NO_TRUNC, &notrunc);
	getret = VOP_GETATTR(vp, &at, cred, procp);
	vput(vp);
	nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3PATHCONF);
	nfsm_srvpostop_attr(getret, &at);
	if (error)
		return (0);
	nfsm_build(pc, struct nfsv3_pathconf *, NFSX_V3PATHCONF);

	pc->pc_linkmax = txdr_unsigned(linkmax);
	pc->pc_namemax = txdr_unsigned(namemax);
	pc->pc_notrunc = txdr_unsigned(notrunc);
	pc->pc_chownrestricted = txdr_unsigned(chownres);

	/*
	 * These should probably be supported by VOP_PATHCONF(), but
	 * until msdosfs is exportable (why would you want to?), the
	 * Unix defaults should be ok.
	 */
	pc->pc_caseinsensitive = nfs_false;
	pc->pc_casepreserving = nfs_true;
	nfsm_srvdone;
}

/*
 * Null operation, used by clients to ping server
 */
/* ARGSUSED */
int
nfsrv_null(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep;
	caddr_t bpos;
	int error = NFSERR_RETVOID, cache;
	struct mbuf *mb, *mreq;
	u_quad_t frev;

#ifndef nolint
	cache = 0;
#endif
	nfsm_reply(0);
	return (0);
}

/*
 * No operation, used for obsolete procedures
 */
/* ARGSUSED */
int
nfsrv_noop(nfsd, slp, procp, mrq)
	struct nfsrv_descript *nfsd;
	struct nfssvc_sock *slp;
	struct proc *procp;
	struct mbuf **mrq;
{
	struct mbuf *mrep = nfsd->nd_mrep;
	caddr_t bpos;
	int error, cache;
	struct mbuf *mb, *mreq;
	u_quad_t frev;

#ifndef nolint
	cache = 0;
#endif
	if (nfsd->nd_repstat)
		error = nfsd->nd_repstat;
	else
		error = EPROCUNAVAIL;
	nfsm_reply(0);
	return (0);
}

/*
 * Perform access checking for vnodes obtained from file handles that would
 * refer to files already opened by a Unix client. You cannot just use
 * vn_writechk() and VOP_ACCESS() for two reasons.
 * 1 - You must check for exported rdonly as well as MNT_RDONLY for the write case
 * 2 - The owner is to be given access irrespective of mode bits so that
 *     processes that chmod after opening a file don't break. I don't like
 *     this because it opens a security hole, but since the nfs server opens
 *     a security hole the size of a barn door anyhow, what the heck.
 
 * The exception to rule 2 is EPERM. If a file is IMMUTABLE, VOP_ACCESS()
 * will return EPERM instead of EACCESS. EPERM is always an error.
 */

static int
nfsrv_access(vp, flags, cred, rdonly, p, override)
	register struct vnode *vp;
	int flags;
	register struct ucred *cred;
	int rdonly;
	struct proc *p;
        int override;
{
	struct vattr vattr;
	int error;
	if (flags & VWRITE) {
		/* Just vn_writechk() changed to check rdonly */
		/*
		 * Disallow write attempts on read-only file systems;
		 * unless the file is a socket or a block or character
		 * device resident on the file system.
		 */
		if (rdonly || (vp->v_mount->mnt_flag & MNT_RDONLY)) {
			switch (vp->v_type) {
			case VREG: case VDIR: case VLNK: case VCPLX:
				return (EROFS);
			}
		}
		/*
		 * If there's shared text associated with
		 * the inode, we can't allow writing.
		 */
		if (vp->v_flag & VTEXT)
			return (ETXTBSY);
	}
	if ((error = VOP_GETATTR(vp, &vattr, cred, p)))
		return (error);
        error = VOP_ACCESS(vp, flags, cred, p);
        /*
         * Allow certain operations for the owner (reads and writes
         * on files that are already open). Picking up from FreeBSD.
         */
        if (override && error == EACCES && cred->cr_uid == vattr.va_uid)
                error = 0;
        return error;
}
#endif /* NFS_NOSERVER */

