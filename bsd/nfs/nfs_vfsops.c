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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#if !defined(NO_MOUNT_PRIVATE)
#include <sys/filedesc.h>
#endif /* NO_MOUNT_PRIVATE */

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsdiskless.h>
#include <nfs/nqnfs.h>

extern int	nfs_mountroot __P((void));

extern int	nfs_ticks;

struct nfsstats	nfsstats;
static int nfs_sysctl(int *, u_int, void *, size_t *, void *, size_t,
		      struct proc *);
/* XXX CSM 11/25/97 Upgrade sysctl.h someday */
#ifdef notyet
SYSCTL_NODE(_vfs, MOUNT_NFS, nfs, CTLFLAG_RW, 0, "NFS filesystem");
SYSCTL_STRUCT(_vfs_nfs, NFS_NFSSTATS, nfsstats, CTLFLAG_RD,
	&nfsstats, nfsstats, "");
#endif
#if NFSDIAG
int nfs_debug;
/* XXX CSM 11/25/97 Upgrade sysctl.h someday */
#ifdef notyet
SYSCTL_INT(_vfs_nfs, OID_AUTO, debug, CTLFLAG_RW, &nfs_debug, 0, "");
#endif
#endif

SYSCTL_DECL(_vfs_generic_nfs);
SYSCTL_NODE(_vfs_generic_nfs, OID_AUTO, client, CTLFLAG_RW, 0,
    "nfs client hinge");
/* how long NFS will wait before signalling vfs that it's down. */
static int nfs_tprintf_initial_delay = NFS_TPRINTF_INITIAL_DELAY;
SYSCTL_INT(_vfs_generic_nfs_client, NFS_TPRINTF_INITIAL_DELAY,
    initialdowndelay, CTLFLAG_RW, &nfs_tprintf_initial_delay, 0, "");
/* how long between console messages "nfs server foo not responding" */
static int nfs_tprintf_delay = NFS_TPRINTF_DELAY;
SYSCTL_INT(_vfs_generic_nfs_client, NFS_TPRINTF_DELAY,
    nextdowndelay, CTLFLAG_RW, &nfs_tprintf_delay, 0, "");

static int	nfs_iosize __P((struct nfsmount *nmp));
static int	mountnfs __P((struct nfs_args *,struct mount *,
			struct mbuf *,char *,char *,struct vnode **));
static int	nfs_mount __P(( struct mount *mp, char *path, caddr_t data,
			struct nameidata *ndp, struct proc *p));
static int	nfs_start __P(( struct mount *mp, int flags,
			struct proc *p));
static int	nfs_unmount __P(( struct mount *mp, int mntflags,
			struct proc *p));
static int	nfs_root __P(( struct mount *mp, struct vnode **vpp));
static int	nfs_quotactl __P(( struct mount *mp, int cmds, uid_t uid,
			caddr_t arg, struct proc *p));
static int	nfs_statfs __P(( struct mount *mp, struct statfs *sbp,
			struct proc *p));
static int	nfs_sync __P(( struct mount *mp, int waitfor,
			struct ucred *cred, struct proc *p));
static int	nfs_vptofh __P(( struct vnode *vp, struct fid *fhp));
static int	nfs_fhtovp __P((struct mount *mp, struct fid *fhp,
			struct mbuf *nam, struct vnode **vpp,
			int *exflagsp, struct ucred **credanonp));
static int	nfs_vget __P((struct mount *, void *, struct vnode **));


/*
 * nfs vfs operations.
 */
struct vfsops nfs_vfsops = {
	nfs_mount,
	nfs_start,
	nfs_unmount,
	nfs_root,
	nfs_quotactl,
	nfs_statfs,
	nfs_sync,
	nfs_vget,
	nfs_fhtovp,
	nfs_vptofh,
	nfs_init,
	nfs_sysctl
};
/* XXX CSM 11/25/97 Mysterious kernel.h ld crud */
#ifdef notyet
VFS_SET(nfs_vfsops, nfs, MOUNT_NFS, VFCF_NETWORK);
#endif


void nfsargs_ntoh __P((struct nfs_args *));
static int
nfs_mount_diskless __P((struct nfs_dlmount *, char *, int, struct vnode **,
						struct mount **));
#if !defined(NO_MOUNT_PRIVATE)
static int
nfs_mount_diskless_private __P((struct nfs_dlmount *, char *, int,
				struct vnode **, struct mount **));
#endif /* NO_MOUNT_PRIVATE */
static void nfs_convert_oargs __P((struct nfs_args *args,
				   struct onfs_args *oargs));
#if NFSDIAG
int nfsreqqusers = 0;
extern int nfsbtlen, nfsbtcpu, nfsbtthread, nfsbt[32];
#endif

static int nfs_iosize(nmp)
	struct nfsmount* nmp;
{
	int iosize;

	/*
	 * Calculate the size used for io buffers.  Use the larger
	 * of the two sizes to minimise nfs requests but make sure
	 * that it is at least one VM page to avoid wasting buffer
	 * space and to allow easy mmapping of I/O buffers.
	 * The read/write rpc calls handle the splitting up of
	 * buffers into multiple requests if the buffer size is
	 * larger than the I/O size.
	 */
	iosize = max(nmp->nm_rsize, nmp->nm_wsize);
	if (iosize < PAGE_SIZE)
		iosize = PAGE_SIZE;
	return (trunc_page_32(iosize));
}

static void nfs_convert_oargs(args,oargs)
     struct nfs_args *args;
     struct onfs_args *oargs;
{
  args->version = NFS_ARGSVERSION;
  args->addr = oargs->addr;
  args->addrlen = oargs->addrlen;
  args->sotype = oargs->sotype;
  args->proto = oargs->proto;
  args->fh = oargs->fh;
  args->fhsize = oargs->fhsize;
  args->flags = oargs->flags;
  args->wsize = oargs->wsize;
  args->rsize = oargs->rsize;
  args->readdirsize = oargs->readdirsize;
  args->timeo = oargs->timeo;
  args->retrans = oargs->retrans;
  args->maxgrouplist = oargs->maxgrouplist;
  args->readahead = oargs->readahead;
  args->leaseterm = oargs->leaseterm;
  args->deadthresh = oargs->deadthresh;
  args->hostname = oargs->hostname;
}

/*
 * nfs statfs call
 */
int
nfs_statfs(mp, sbp, p)
	struct mount *mp;
	register struct statfs *sbp;
	struct proc *p;
{
	register struct vnode *vp;
	register struct nfs_statfs *sfp;
	register caddr_t cp;
	register u_long *tl;
	register long t1, t2;
	caddr_t bpos, dpos, cp2;
	struct nfsmount *nmp = VFSTONFS(mp);
	int error = 0, v3 = (nmp->nm_flag & NFSMNT_NFSV3), retattr;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	struct ucred *cred;
	u_quad_t tquad;
	extern int nfs_mount_type;
	u_int64_t xid;

#ifndef nolint
	sfp = (struct nfs_statfs *)0;
#endif
	vp = nmp->nm_dvp;
	if (error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p))
		return(error);
	cred = crget();
	cred->cr_ngroups = 1;
	if (v3 && (nmp->nm_state & NFSSTA_GOTFSINFO) == 0)
		(void)nfs_fsinfo(nmp, vp, cred, p);
	nfsstats.rpccnt[NFSPROC_FSSTAT]++;
	nfsm_reqhead(vp, NFSPROC_FSSTAT, NFSX_FH(v3));
	nfsm_fhtom(vp, v3);
	nfsm_request(vp, NFSPROC_FSSTAT, p, cred, &xid);
	if (v3)
		nfsm_postop_attr(vp, retattr, &xid);
	nfsm_dissect(sfp, struct nfs_statfs *, NFSX_STATFS(v3));

/* XXX CSM 12/2/97 Cleanup when/if we integrate FreeBSD mount.h */
#ifdef notyet
	sbp->f_type = MOUNT_NFS;
#else
	sbp->f_type = nfs_mount_type;
#endif
	sbp->f_flags = nmp->nm_flag;
	sbp->f_iosize = nfs_iosize(nmp);
	if (v3) {
		sbp->f_bsize = NFS_FABLKSIZE;
		fxdr_hyper(&sfp->sf_tbytes, &tquad);
		sbp->f_blocks = (long)(tquad / ((u_quad_t)NFS_FABLKSIZE));
		fxdr_hyper(&sfp->sf_fbytes, &tquad);
		sbp->f_bfree = (long)(tquad / ((u_quad_t)NFS_FABLKSIZE));
		fxdr_hyper(&sfp->sf_abytes, &tquad);
		sbp->f_bavail = (long)(tquad / ((u_quad_t)NFS_FABLKSIZE));
		sbp->f_files = (fxdr_unsigned(long, sfp->sf_tfiles.nfsuquad[1])
			& 0x7fffffff);
		sbp->f_ffree = (fxdr_unsigned(long, sfp->sf_ffiles.nfsuquad[1])
			& 0x7fffffff);
	} else {
		sbp->f_bsize = fxdr_unsigned(long, sfp->sf_bsize);
		sbp->f_blocks = fxdr_unsigned(long, sfp->sf_blocks);
		sbp->f_bfree = fxdr_unsigned(long, sfp->sf_bfree);
		sbp->f_bavail = fxdr_unsigned(long, sfp->sf_bavail);
		sbp->f_files = 0;
		sbp->f_ffree = 0;
	}
	if (sbp != &mp->mnt_stat) {
		bcopy(mp->mnt_stat.f_mntonname, sbp->f_mntonname, MNAMELEN);
		bcopy(mp->mnt_stat.f_mntfromname, sbp->f_mntfromname, MNAMELEN);
	}
	nfsm_reqdone;
	VOP_UNLOCK(vp, 0, p);
	crfree(cred);
	return (error);
}

/*
 * nfs version 3 fsinfo rpc call
 */
int
nfs_fsinfo(nmp, vp, cred, p)
	register struct nfsmount *nmp;
	register struct vnode *vp;
	struct ucred *cred;
	struct proc *p;
{
	register struct nfsv3_fsinfo *fsp;
	register caddr_t cp;
	register long t1, t2;
	register u_long *tl, pref, max;
	caddr_t bpos, dpos, cp2;
	int error = 0, retattr;
	struct mbuf *mreq, *mrep, *md, *mb, *mb2;
	u_int64_t xid;

	nfsstats.rpccnt[NFSPROC_FSINFO]++;
	nfsm_reqhead(vp, NFSPROC_FSINFO, NFSX_FH(1));
	nfsm_fhtom(vp, 1);
	nfsm_request(vp, NFSPROC_FSINFO, p, cred, &xid);
	nfsm_postop_attr(vp, retattr, &xid);
	if (!error) {
		nfsm_dissect(fsp, struct nfsv3_fsinfo *, NFSX_V3FSINFO);
		pref = fxdr_unsigned(u_long, fsp->fs_wtpref);
		if (pref < nmp->nm_wsize)
			nmp->nm_wsize = (pref + NFS_FABLKSIZE - 1) &
				~(NFS_FABLKSIZE - 1);
		max = fxdr_unsigned(u_long, fsp->fs_wtmax);
		if (max < nmp->nm_wsize) {
			nmp->nm_wsize = max & ~(NFS_FABLKSIZE - 1);
			if (nmp->nm_wsize == 0)
				nmp->nm_wsize = max;
		}
		pref = fxdr_unsigned(u_long, fsp->fs_rtpref);
		if (pref < nmp->nm_rsize)
			nmp->nm_rsize = (pref + NFS_FABLKSIZE - 1) &
				~(NFS_FABLKSIZE - 1);
		max = fxdr_unsigned(u_long, fsp->fs_rtmax);
		if (max < nmp->nm_rsize) {
			nmp->nm_rsize = max & ~(NFS_FABLKSIZE - 1);
			if (nmp->nm_rsize == 0)
				nmp->nm_rsize = max;
		}
		pref = fxdr_unsigned(u_long, fsp->fs_dtpref);
		if (pref < nmp->nm_readdirsize)
			nmp->nm_readdirsize = pref;
		if (max < nmp->nm_readdirsize) {
			nmp->nm_readdirsize = max;
		}
		nmp->nm_state |= NFSSTA_GOTFSINFO;
	}
	nfsm_reqdone;
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
nfs_mountroot()
{
	struct nfs_diskless nd;
	struct vattr attr;
	struct mount *mp;
	struct vnode *vp;
	struct proc *procp;
	long n;
	int error;
#if !defined(NO_MOUNT_PRIVATE)
	struct mount *mppriv;
	struct vnode *vppriv;
#endif /* NO_MOUNT_PRIVATE */
	int v3;

	procp = current_proc(); /* XXX */

	/*
	 * Call nfs_boot_init() to fill in the nfs_diskless struct.
	 * Note: networking must already have been configured before
	 * we're called.
	 */
	bzero((caddr_t) &nd, sizeof(nd));
	error = nfs_boot_init(&nd, procp);
	if (error) {
		panic("nfs_boot_init failed with %d\n", error);
	}

	/* try NFSv3 first, if that fails then try NFSv2 */
	v3 = 1;

tryagain:
	error = nfs_boot_getfh(&nd, procp, v3);
	if (error) {
		if (v3) {
			printf("nfs_boot_getfh(v3) failed with %d, trying v2...\n", error);
			v3 = 0;
			goto tryagain;
		}
		panic("nfs_boot_getfh(v2) failed with %d\n", error);
	}

	/*
	 * Create the root mount point.
	 */
#if !defined(NO_MOUNT_PRIVATE)
	if ((error = nfs_mount_diskless(&nd.nd_root, "/", MNT_RDONLY, &vp, &mp))) {
#else
	if (error = nfs_mount_diskless(&nd.nd_root, "/", NULL, &vp, &mp)) {
#endif /* NO_MOUNT_PRIVATE */
		if (v3) {
			printf("nfs_mount_diskless(v3) failed with %d, trying v2...\n", error);
			v3 = 0;
			goto tryagain;
		}
		panic("nfs_mount_diskless root failed with %d\n", error);
	}
	printf("root on %s\n", (char *)&nd.nd_root.ndm_host);

	simple_lock(&mountlist_slock);
	CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	simple_unlock(&mountlist_slock);
	vfs_unbusy(mp, procp);
	rootvp = vp;
	
#if !defined(NO_MOUNT_PRIVATE)
	if (nd.nd_private.ndm_saddr.sin_addr.s_addr) {
	    error = nfs_mount_diskless_private(&nd.nd_private, "/private",
					       NULL, &vppriv, &mppriv);
	    if (error) {
		panic("nfs_mount_diskless private failed with %d\n", error);
	    }
	    printf("private on %s\n", (char *)&nd.nd_private.ndm_host);
	    
	    simple_lock(&mountlist_slock);
	    CIRCLEQ_INSERT_TAIL(&mountlist, mppriv, mnt_list);
	    simple_unlock(&mountlist_slock);
	    vfs_unbusy(mppriv, procp);
	}

#endif /* NO_MOUNT_PRIVATE */

	if (nd.nd_root.ndm_path)
		FREE_ZONE(nd.nd_root.ndm_path, MAXPATHLEN, M_NAMEI);
	if (nd.nd_private.ndm_path)
		FREE_ZONE(nd.nd_private.ndm_path, MAXPATHLEN, M_NAMEI);

	/* Get root attributes (for the time). */
	error = VOP_GETATTR(vp, &attr, procp->p_ucred, procp);
	if (error) panic("nfs_mountroot: getattr for root");
	n = attr.va_mtime.tv_sec;
	inittodr(n);
	return (0);
}

/*
 * Internal version of mount system call for diskless setup.
 */
static int
nfs_mount_diskless(ndmntp, mntname, mntflag, vpp, mpp)
	struct nfs_dlmount *ndmntp;
	char *mntname;
	int mntflag;
	struct vnode **vpp;
	struct mount **mpp;
{
	struct nfs_args args;
	struct mount *mp;
	struct mbuf *m;
	int error;
	struct proc *procp;

	procp = current_proc(); /* XXX */

	if ((error = vfs_rootmountalloc("nfs", ndmntp->ndm_host, &mp))) {
		printf("nfs_mountroot: NFS not configured");
		return (error);
	}
	mp->mnt_flag = mntflag;

	/* Initialize mount args. */
	bzero((caddr_t) &args, sizeof(args));
	args.addr     = (struct sockaddr *)&ndmntp->ndm_saddr;
	args.addrlen  = args.addr->sa_len;
	args.sotype   = SOCK_DGRAM;
	args.fh       = ndmntp->ndm_fh;
	args.fhsize   = ndmntp->ndm_fhlen;
	args.hostname = ndmntp->ndm_host;
	args.flags    = NFSMNT_RESVPORT;
	if (ndmntp->ndm_nfsv3)
		args.flags |= NFSMNT_NFSV3;

	MGET(m, M_DONTWAIT, MT_SONAME);
	bcopy((caddr_t)args.addr, mtod(m, caddr_t), 
				(m->m_len = args.addr->sa_len));
	if ((error = mountnfs(&args, mp, m, mntname, args.hostname, vpp))) {
		printf("nfs_mountroot: mount %s failed: %d", mntname, error);
		mp->mnt_vfc->vfc_refcount--;

		if (mp->mnt_kern_flag & MNTK_IO_XINFO)
		        FREE(mp->mnt_xinfo_ptr, M_TEMP);
		vfs_unbusy(mp, procp);

		FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		return (error);
	}
#if 0  /* Causes incorrect reporting of "mounted on" */
	(void) copystr(args.hostname, mp->mnt_stat.f_mntonname, MNAMELEN - 1, 0);
#endif /* 0 */
	*mpp = mp;
	return (0);
}

#if !defined(NO_MOUNT_PRIVATE)
/*
 * Internal version of mount system call to mount "/private"
 * separately in diskless setup
 */
static int
nfs_mount_diskless_private(ndmntp, mntname, mntflag, vpp, mpp)
	struct nfs_dlmount *ndmntp;
	char *mntname;
	int mntflag;
	struct vnode **vpp;
	struct mount **mpp;
{
	struct nfs_args args;
	struct mount *mp;
	struct mbuf *m;
	int error;
	struct proc *procp;
	struct vfsconf *vfsp;
	struct nameidata nd;
	struct vnode *vp;

	procp = current_proc(); /* XXX */

	{
	/*
	 * mimic main()!. Temporarily set up rootvnode and other stuff so
	 * that namei works. Need to undo this because main() does it, too
	 */
		struct filedesc *fdp;	/* pointer to file descriptor state */
		fdp = procp->p_fd;
		mountlist.cqh_first->mnt_flag |= MNT_ROOTFS;

		/* Get the vnode for '/'. Set fdp->fd_cdir to reference it. */
		if (VFS_ROOT(mountlist.cqh_first, &rootvnode))
			panic("cannot find root vnode");
		VREF(rootvnode);
		fdp->fd_cdir = rootvnode;
		VOP_UNLOCK(rootvnode, 0, procp);
		fdp->fd_rdir = NULL;
	}

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
	    mntname, procp);
	if ((error = namei(&nd))) {
		printf("nfs_mountroot: private namei failed!");
		return (error);
	}
	{
		/* undo VREF in mimic main()! */
		vrele(rootvnode);
	}
	vp = nd.ni_vp;
	if ((error = vinvalbuf(vp, V_SAVE, procp->p_ucred, procp, 0, 0))) {
		vput(vp);
		return (error);
	}
	if (vp->v_type != VDIR) {
		vput(vp);
		return (ENOTDIR);
	}
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strcmp(vfsp->vfc_name, "nfs"))
			break;
	if (vfsp == NULL) {
		printf("nfs_mountroot: private NFS not configured");
		vput(vp);
		return (ENODEV);
	}
	if (vp->v_mountedhere != NULL) {
		vput(vp);
		return (EBUSY);
	}

	/*
	 * Allocate and initialize the filesystem.
	 */
	mp = _MALLOC_ZONE((u_long)sizeof(struct mount), M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));

	/* Initialize the default IO constraints */
	mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
	mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

	lockinit(&mp->mnt_lock, PVFS, "vfslock", 0, 0);
	(void)vfs_busy(mp, LK_NOWAIT, 0, procp);
	LIST_INIT(&mp->mnt_vnodelist);
	mp->mnt_op = vfsp->vfc_vfsops;
	mp->mnt_vfc = vfsp;
	vfsp->vfc_refcount++;
	mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag = mntflag;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_stat.f_fstypename, vfsp->vfc_name, MFSNAMELEN);
	vp->v_mountedhere = mp;
	mp->mnt_vnodecovered = vp;
	mp->mnt_stat.f_owner = procp->p_ucred->cr_uid;
	(void) copystr(mntname, mp->mnt_stat.f_mntonname, MNAMELEN - 1, 0);
	(void) copystr(ndmntp->ndm_host, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, 0);

	/* Initialize mount args. */
	bzero((caddr_t) &args, sizeof(args));
	args.addr     = (struct sockaddr *)&ndmntp->ndm_saddr;
	args.addrlen  = args.addr->sa_len;
	args.sotype   = SOCK_DGRAM;
	args.fh       = ndmntp->ndm_fh;
	args.fhsize   = ndmntp->ndm_fhlen;
	args.hostname = ndmntp->ndm_host;
	args.flags    = NFSMNT_RESVPORT;
	if (ndmntp->ndm_nfsv3)
		args.flags |= NFSMNT_NFSV3;

	MGET(m, M_DONTWAIT, MT_SONAME);
	bcopy((caddr_t)args.addr, mtod(m, caddr_t), 
				(m->m_len = args.addr->sa_len));
	if ((error = mountnfs(&args, mp, m, mntname, args.hostname, &vp))) {
		printf("nfs_mountroot: mount %s failed: %d", mntname, error);
		mp->mnt_vfc->vfc_refcount--;

		if (mp->mnt_kern_flag & MNTK_IO_XINFO)
		        FREE(mp->mnt_xinfo_ptr, M_TEMP);
		vfs_unbusy(mp, procp);

		FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		return (error);
	}

	*mpp = mp;
	*vpp = vp;
	return (0);
}
#endif /* NO_MOUNT_PRIVATE */

/*
 * VFS Operations.
 *
 * mount system call
 * It seems a bit dumb to copyinstr() the host and path here and then
 * bcopy() them in mountnfs(), but I wanted to detect errors before
 * doing the sockargs() call because sockargs() allocates an mbuf and
 * an error after that means that I have to release the mbuf.
 */
/* ARGSUSED */
static int
nfs_mount(mp, path, data, ndp, p)
	struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	int error;
	struct nfs_args args;
	struct mbuf *nam;
	struct vnode *vp;
	char pth[MNAMELEN], hst[MNAMELEN];
	size_t len;
	u_char nfh[NFSX_V3FHMAX];

	error = copyin(data, (caddr_t)&args, sizeof (struct nfs_args));
	if (error)
		return (error);
	if (args.version != NFS_ARGSVERSION) {
#ifndef NO_COMPAT_PRELITE2
		/*
		 * If the argument version is unknown, then assume the
		 * caller is a pre-lite2 4.4BSD client and convert its
		 * arguments.
		 */
		struct onfs_args oargs;
		error = copyin(data, (caddr_t)&oargs, sizeof (struct onfs_args));
		if (error)
			return (error);
		nfs_convert_oargs(&args,&oargs);
#else /* NO_COMPAT_PRELITE2 */
		return (EPROGMISMATCH);
#endif /* !NO_COMPAT_PRELITE2 */
	}
	if (args.fhsize > NFSX_V3FHMAX)
		return (EINVAL);
	error = copyin((caddr_t)args.fh, (caddr_t)nfh, args.fhsize);
	if (error)
		return (error);
	error = copyinstr(path, pth, MNAMELEN-1, &len);
	if (error)
		return (error);
	bzero(&pth[len], MNAMELEN - len);
	error = copyinstr(args.hostname, hst, MNAMELEN-1, &len);
	if (error)
		return (error);
	bzero(&hst[len], MNAMELEN - len);
	/* sockargs() call must be after above copyin() calls */
	error = sockargs(&nam, (caddr_t)args.addr, args.addrlen, MT_SONAME);
	if (error)
		return (error);
	args.fh = nfh;
	error = mountnfs(&args, mp, nam, pth, hst, &vp);
	return (error);
}

/*
 * Common code for mount and mountroot
 */
static int
mountnfs(argp, mp, nam, pth, hst, vpp)
	register struct nfs_args *argp;
	register struct mount *mp;
	struct mbuf *nam;
	char *pth, *hst;
	struct vnode **vpp;
{
	register struct nfsmount *nmp;
	struct nfsnode *np;
	int error, maxio;
	struct vattr attrs;
	struct proc *curproc;

	/*
	 * turning off NQNFS until we have further testing
	 * with UBC changes, in particular, nfs_pagein and nfs_pageout.
	 * Those have NQNFS defined out in conjunction with this
	 * returning an error. Remove when fully tested.
	 */
	if (argp->flags & NFSMNT_NQNFS) {
		error = NFSERR_NOTSUPP;
		goto bad2;
	}

	/*
	 * Silently clear NFSMNT_NOCONN if it's a TCP mount, it makes
	 * no sense in that context.
	 */
	if (argp->sotype == SOCK_STREAM)
		argp->flags &= ~NFSMNT_NOCONN;
        
	if (mp->mnt_flag & MNT_UPDATE) {
		nmp = VFSTONFS(mp);
		/* update paths, file handles, etc, here	XXX */
		m_freem(nam);
		return (0);
	} else {
		MALLOC_ZONE(nmp, struct nfsmount *,
				sizeof (struct nfsmount), M_NFSMNT, M_WAITOK);
		bzero((caddr_t)nmp, sizeof (struct nfsmount));
		TAILQ_INIT(&nmp->nm_uidlruhead);
		TAILQ_INIT(&nmp->nm_bufq);
		mp->mnt_data = (qaddr_t)nmp;
	}
	vfs_getnewfsid(mp);
	nmp->nm_mountp = mp;
	nmp->nm_flag = argp->flags;
	if (nmp->nm_flag & NFSMNT_NQNFS)
		/*
		 * We have to set mnt_maxsymlink to a non-zero value so
		 * that COMPAT_43 routines will know that we are setting
		 * the d_type field in directories (and can zero it for
		 * unsuspecting binaries).
		 */
		mp->mnt_maxsymlinklen = 1;
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
	nmp->nm_leaseterm = NQ_DEFLEASE;
	nmp->nm_deadthresh = NQ_DEADTHRESH;
	nmp->nm_tprintf_delay = nfs_tprintf_delay;
	if (nmp->nm_tprintf_delay < 0)
		nmp->nm_tprintf_delay = 0;
	nmp->nm_tprintf_initial_delay = nfs_tprintf_initial_delay;
	if (nmp->nm_tprintf_initial_delay < 0)
		nmp->nm_tprintf_initial_delay = 0;
	CIRCLEQ_INIT(&nmp->nm_timerhead);
	nmp->nm_inprog = NULLVP;
	bcopy(hst, mp->mnt_stat.f_mntfromname, MNAMELEN);
	bcopy(pth, mp->mnt_stat.f_mntonname, MNAMELEN);
	nmp->nm_nam = nam;

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

	if (argp->flags & NFSMNT_NFSV3) {
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
	if (nmp->nm_wsize > MAXBSIZE)
		nmp->nm_wsize = MAXBSIZE;

	if ((argp->flags & NFSMNT_RSIZE) && argp->rsize > 0) {
		nmp->nm_rsize = argp->rsize;
		/* Round down to multiple of blocksize */
		nmp->nm_rsize &= ~(NFS_FABLKSIZE - 1);
		if (nmp->nm_rsize <= 0)
			nmp->nm_rsize = NFS_FABLKSIZE;
	}
	if (nmp->nm_rsize > maxio)
		nmp->nm_rsize = maxio;
	if (nmp->nm_rsize > MAXBSIZE)
		nmp->nm_rsize = MAXBSIZE;

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
	if ((argp->flags & NFSMNT_LEASETERM) && argp->leaseterm >= 2 &&
		argp->leaseterm <= NQ_MAXLEASE)
		nmp->nm_leaseterm = argp->leaseterm;
	if ((argp->flags & NFSMNT_DEADTHRESH) && argp->deadthresh >= 1 &&
		argp->deadthresh <= NQ_NEVERDEAD)
		nmp->nm_deadthresh = argp->deadthresh;
	/* Set up the sockets and per-host congestion */
	nmp->nm_sotype = argp->sotype;
	nmp->nm_soproto = argp->proto;

	/*
	 * For Connection based sockets (TCP,...) defer the connect until
	 * the first request, in case the server is not responding.
	 */
	if (nmp->nm_sotype == SOCK_DGRAM &&
		(error = nfs_connect(nmp, (struct nfsreq *)0)))
		goto bad;

	/*
	 * A reference count is needed on the nfsnode representing the
	 * remote root.  If this object is not persistent, then backward
	 * traversals of the mount point (i.e. "..") will not work if
	 * the nfsnode gets flushed out of the cache. UFS does not have
	 * this problem, because one can identify root inodes by their
	 * number == ROOTINO (2).
	 */
	error = nfs_nget(mp, (nfsfh_t *)argp->fh, argp->fhsize, &np);
	if (error)
		goto bad;

	/*
	 * save this vnode pointer. That way nfs_unmount()
	 * does not need to call nfs_net() just get it to drop
	 * this vnode reference.
	 */
	nmp->nm_dvp = *vpp = NFSTOV(np);

	/*
	 * Get file attributes for the mountpoint.  This has the side
	 * effect of filling in (*vpp)->v_type with the correct value.
	 */
	curproc = current_proc();
	error = VOP_GETATTR(*vpp, &attrs, curproc->p_ucred, curproc);
	if (error) {
		/*
		 * we got problems... we couldn't get the attributes
		 * from the NFS server... so the mount fails.
		 */
		vput(*vpp);
		goto bad;
	}

	/*
	 * Set the mount point's block I/O size.
	 * We really need to do this after we get info back from
	 * the server about what its preferred I/O sizes are.
	 */
	if (nmp->nm_flag & NFSMNT_NFSV3)
		nfs_fsinfo(nmp, *vpp, curproc->p_ucred, curproc);
	mp->mnt_stat.f_iosize = nfs_iosize(nmp);

	/*
	 * Lose the lock but keep the ref.
	 */
	VOP_UNLOCK(*vpp, 0, curproc);

	return (0);
bad:
	nfs_disconnect(nmp);
	FREE_ZONE((caddr_t)nmp, sizeof (struct nfsmount), M_NFSMNT);
bad2:
	m_freem(nam);
	return (error);
}


/*
 * unmount system call
 */
static int
nfs_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
{
	register struct nfsmount *nmp;
	struct vnode *vp;
	int error, flags = 0;

	nmp = VFSTONFS(mp);
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
	 *   It will do vgone making the vnode VBAD at that time.
	 * - Decrement reference on the vnode representing remote root.
	 * - Close the socket
	 * - Free up the data structures
	 */
	vp = nmp->nm_dvp;
	
	/*
	 * Must handshake with nqnfs_clientd() if it is active.
	 */
	nmp->nm_state |= NFSSTA_DISMINPROG;
	while (nmp->nm_inprog != NULLVP)
		(void) tsleep((caddr_t)&lbolt, PSOCK, "nfsdism", 0);
	/*
	 * vflush will check for busy vnodes on mountpoint. 
	 * Will do the right thing for MNT_FORCE. That is, we should
	 * not get EBUSY back.
	 */
	error = vflush(mp, vp, SKIPSWAP | flags);
	if (mntflags & MNT_FORCE) {
		error = vflush(mp, NULLVP, flags); /* locks vp in the process */
	} else {
		if (vp->v_usecount > 1) {
			nmp->nm_state &= ~NFSSTA_DISMINPROG;
			return (EBUSY);
		}
		error = vflush(mp, vp, flags);
	}

	if (error) {
		nmp->nm_state &= ~NFSSTA_DISMINPROG;
		return (error);
	}

	/*
	 * We are now committed to the unmount.
	 * For NQNFS, let the server daemon free the nfsmount structure.
	 */
	if (nmp->nm_flag & (NFSMNT_NQNFS | NFSMNT_KERB))
		nmp->nm_state |= NFSSTA_DISMNT;

	/*
	 * Release the root vnode reference held by mountnfs()
	 * vflush did the vgone for us when we didn't skip over
	 * it in the MNT_FORCE case. (Thus vp can't be locked when
	 * called vflush in non-skip vp case.)
	 */
	vrele(vp);
	if (!(mntflags & MNT_FORCE))
		vgone(vp);
	mp->mnt_data = 0; /* don't want to end up using stale vp */
	nfs_disconnect(nmp);
	m_freem(nmp->nm_nam);

	if ((nmp->nm_flag & (NFSMNT_NQNFS | NFSMNT_KERB)) == 0) {
		register struct nfsreq *rp;
		/*
		 * Loop through outstanding request list and remove dangling
		 * references to defunct nfsmount struct
		 */
#if NFSDIAG && 0
		if (hw_atomic_add(&nfsreqqusers, 1) != 1)
			nfsatompanic("unmount add");
		nfsbtlen = backtrace(&nfsbt, sizeof(nfsbt));
		nfsbtcpu = cpu_number();
		nfsbtthread = (int)(current_thread());
#endif

		for (rp = nfs_reqq.tqh_first; rp; rp = rp->r_chain.tqe_next)
			if (rp->r_nmp == nmp)
				rp->r_nmp = (struct nfsmount *)0;
#if NFSDIAG && 0
		if (hw_atomic_sub(&nfsreqqusers, 1) != 0)
			nfsatompanic("unmount sub");
#endif
		FREE_ZONE((caddr_t)nmp, sizeof (struct nfsmount), M_NFSMNT);
	}
	return (0);
}

/*
 * Return root of a filesystem
 */
static int
nfs_root(mp, vpp)
	struct mount *mp;
	struct vnode **vpp;
{
	register struct vnode *vp;
	struct nfsmount *nmp;
	int error, vpid;

	nmp = VFSTONFS(mp);
	vp = nmp->nm_dvp;
	vpid = vp->v_id;
	while (error = vget(vp, LK_EXCLUSIVE, current_proc())) {
		/* vget may return ENOENT if the dir changes while in vget */
		/* If that happens, try vget again, else return the error */
		if ((error != ENOENT) || (vp->v_id == vpid))
			return (error);
		vpid = vp->v_id;
	}
	if (vp->v_type == VNON)
	    vp->v_type = VDIR;
	vp->v_flag |= VROOT;
	*vpp = vp;
	return (0);
}

extern int syncprt;

/*
 * Flush out the buffer cache
 */
/* ARGSUSED */
static int
nfs_sync(mp, waitfor, cred, p)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct proc *p;
{
	register struct vnode *vp;
	int error, allerror = 0;

	/*
	 * Force stale buffer cache information to be flushed.
	 */
loop:
	LIST_FOREACH(vp, &mp->mnt_vnodelist, v_mntvnodes) {
		 int didhold;
		/*
		 * If the vnode that we are about to sync is no longer
		 * associated with this mount point, start over.
		 */
		if (vp->v_mount != mp)
			goto loop;
		if (VOP_ISLOCKED(vp) || LIST_FIRST(&VTONFS(vp)->n_dirtyblkhd) == NULL)
			continue;
		if (vget(vp, LK_EXCLUSIVE, p))
			goto loop;
		didhold = ubc_hold(vp);
		error = VOP_FSYNC(vp, cred, waitfor, p);
		if (error)
			allerror = error;
		VOP_UNLOCK(vp, 0, p);
		if (didhold)
			ubc_rele(vp);
		vrele(vp);
	}
	return (allerror);
}

/*
 * NFS flat namespace lookup.
 * Currently unsupported.
 */
/* ARGSUSED */
static int
nfs_vget(mp, ino, vpp)
	struct mount *mp;
	void *ino; /* XXX void* or ino_t? */
	struct vnode **vpp;
{

	return (EOPNOTSUPP);
}

/*
 * At this point, this should never happen
 */
/* ARGSUSED */
static int
nfs_fhtovp(mp, fhp, nam, vpp, exflagsp, credanonp)
	register struct mount *mp;
	struct fid *fhp;
	struct mbuf *nam;
	struct vnode **vpp;
	int *exflagsp;
	struct ucred **credanonp;
{

	return (EINVAL);
}

/*
 * Vnode pointer to File handle, should never happen either
 */
/* ARGSUSED */
static int
nfs_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{

	return (EINVAL);
}

/*
 * Vfs start routine, a no-op.
 */
/* ARGSUSED */
static int
nfs_start(mp, flags, p)
	struct mount *mp;
	int flags;
	struct proc *p;
{

	return (0);
}

/*
 * Do operations associated with quotas, not supported
 */
/* ARGSUSED */
static int
nfs_quotactl(mp, cmd, uid, arg, p)
	struct mount *mp;
	int cmd;
	uid_t uid;
	caddr_t arg;
	struct proc *p;
{

	return (EOPNOTSUPP);
}

/*
 * Do that sysctl thang...
 */
static int
nfs_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp,
	   size_t newlen, struct proc *p)
{
	int error;
	struct sysctl_req *req;
	struct vfsidctl vc;
	struct mount *mp;
	struct nfsmount *nmp;
	struct vfsquery vq;

	/*
	 * All names at this level are terminal.
	 */
	if(namelen > 1)
		return ENOTDIR;	/* overloaded */

	/* common code for "new style" VFS_CTL sysctl, get the mount. */
	switch (name[0]) {
	case VFS_CTL_TIMEO:
	case VFS_CTL_QUERY:
		req = oldp;
		error = SYSCTL_IN(req, &vc, sizeof(vc));
		if (error)
			return (error);
		mp = vfs_getvfs(&vc.vc_fsid);
		if (mp == NULL)
			return (ENOENT);
		nmp = VFSTONFS(mp);
		if (nmp == NULL)
			return (ENOENT);
		bzero(&vq, sizeof(vq));
		VCTLTOREQ(&vc, req);
	}

	switch(name[0]) {
	case NFS_NFSSTATS:
		if(!oldp) {
			*oldlenp = sizeof nfsstats;
			return 0;
		}

		if(*oldlenp < sizeof nfsstats) {
			*oldlenp = sizeof nfsstats;
			return ENOMEM;
		}

		error = copyout(&nfsstats, oldp, sizeof nfsstats);
		if (error)
			return (error);

		if(newp && newlen != sizeof nfsstats)
			return EINVAL;

		if(newp) {
			return copyin(newp, &nfsstats, sizeof nfsstats);
		}
		return 0;
	case VFS_CTL_QUERY:
		if ((nmp->nm_state & NFSSTA_TIMEO))
			vq.vq_flags |= VQ_NOTRESP;
		error = SYSCTL_OUT(req, &vq, sizeof(vq));
		break;
 	case VFS_CTL_TIMEO:
 		if (req->oldptr != NULL) {
 			error = SYSCTL_OUT(req, &nmp->nm_tprintf_initial_delay,
 			    sizeof(nmp->nm_tprintf_initial_delay));
 			if (error)
 				return (error);
 		}
 		if (req->newptr != NULL) {
 			error = SYSCTL_IN(req, &nmp->nm_tprintf_initial_delay,
 			    sizeof(nmp->nm_tprintf_initial_delay));
 			if (error)
 				return (error);
 			if (nmp->nm_tprintf_initial_delay < 0)
 				nmp->nm_tprintf_initial_delay = 0;
 		}
		break;
	default:
		return (ENOTSUP);
	}
	return (error);
}

