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
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsdiskless.h>
#include <nfs/nfs_lock.h>

extern int	nfs_mountroot(void);

extern int	nfs_ticks;
extern int	nfs_mount_type;
extern int	nfs_resv_mounts;

struct nfsstats	nfsstats;
static int nfs_sysctl(int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t);
/* XXX CSM 11/25/97 Upgrade sysctl.h someday */
#ifdef notyet
SYSCTL_NODE(_vfs, MOUNT_NFS, nfs, CTLFLAG_RW, 0, "NFS filesystem");
SYSCTL_STRUCT(_vfs_nfs, NFS_NFSSTATS, nfsstats, CTLFLAG_RD,
	&nfsstats, nfsstats, "");
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

static int	nfs_iosize(struct nfsmount *nmp);
static int	mountnfs(struct user_nfs_args *,mount_t,mbuf_t,proc_t,vnode_t *);
static int	nfs_mount(mount_t mp, vnode_t vp, user_addr_t data, vfs_context_t context);
static int	nfs_start(mount_t mp, int flags, vfs_context_t context);
static int	nfs_unmount(mount_t mp, int mntflags, vfs_context_t context);
static int	nfs_root(mount_t mp, vnode_t *vpp, vfs_context_t context);
static int	nfs_statfs(mount_t mp, struct vfsstatfs *sbp, vfs_context_t context);
static int	nfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context);
static int	nfs_sync( mount_t mp, int waitfor, vfs_context_t context);
static int	nfs_vptofh(vnode_t vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);
static int	nfs_fhtovp(mount_t mp, int fhlen, unsigned char *fhp, vnode_t *vpp, vfs_context_t context);
static int	nfs_vget(mount_t , ino64_t, vnode_t *, vfs_context_t context);


/*
 * nfs vfs operations.
 */
struct vfsops nfs_vfsops = {
	nfs_mount,
	nfs_start,
	nfs_unmount,
	nfs_root,
	NULL,		/* quotactl */
	nfs_vfs_getattr,
	nfs_sync,
	nfs_vget,
	nfs_fhtovp,
	nfs_vptofh,
	nfs_init,
	nfs_sysctl,
	NULL		/* setattr */
};


static int
nfs_mount_diskless(struct nfs_dlmount *, const char *, int, vnode_t *, mount_t *);
#if !defined(NO_MOUNT_PRIVATE)
static int
nfs_mount_diskless_private(struct nfs_dlmount *, const char *, int, vnode_t *, mount_t *);
#endif /* NO_MOUNT_PRIVATE */

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

/*
 * nfs statfs call
 */
int
nfs_statfs(mount_t mp, struct vfsstatfs *sbp, vfs_context_t context)
{
	proc_t p = vfs_context_proc(context);
	vnode_t vp;
	struct nfs_statfs *sfp;
	caddr_t cp;
	u_long *tl;
	long t1, t2;
	caddr_t bpos, dpos, cp2;
	struct nfsmount *nmp = VFSTONFS(mp);
	int error = 0, v3 = (nmp->nm_flag & NFSMNT_NFSV3), retattr;
	mbuf_t mreq, mrep, md, mb, mb2;
	u_int64_t xid;
	kauth_cred_t cred;
	struct ucred temp_cred;

#ifndef nolint
	sfp = (struct nfs_statfs *)0;
#endif
	vp = nmp->nm_dvp;
	if ((error = vnode_get(vp)))
		return(error);

	bzero(&temp_cred, sizeof(temp_cred));
	temp_cred.cr_ngroups = 1;
	cred = kauth_cred_create(&temp_cred);

	if (v3 && (nmp->nm_state & NFSSTA_GOTFSINFO) == 0)
		nfs_fsinfo(nmp, vp, cred, p);
	nfsm_reqhead(NFSX_FH(v3));
	if (error) {
		kauth_cred_rele(cred);
		vnode_put(vp);
		return (error);
	}
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_FSSTAT]);
	nfsm_fhtom(vp, v3);
	nfsm_request(vp, NFSPROC_FSSTAT, p, cred, &xid);
	if (v3 && mrep)
		nfsm_postop_attr_update(vp, v3, retattr, &xid);
	nfsm_dissect(sfp, struct nfs_statfs *, NFSX_STATFS(v3));

	sbp->f_flags = nmp->nm_flag;
	sbp->f_iosize = nfs_iosize(nmp);
	if (v3) {
		/*
		 * Adjust block size to get total block count to fit in a long.
		 * If we can't increase block size enough, clamp to max long.
		 */
		u_quad_t tquad, tquad2, bsize;
		bsize = NFS_FABLKSIZE;

		fxdr_hyper(&sfp->sf_tbytes, &tquad);
		tquad /= bsize;
		while ((tquad & ~0x7fffffff) && (bsize < 0x40000000)) {
			bsize <<= 1;
			tquad >>= 1;
		}
		sbp->f_blocks = (tquad & ~0x7fffffff) ? 0x7fffffff : (long)tquad;

		fxdr_hyper(&sfp->sf_fbytes, &tquad);
		tquad /= bsize;
		sbp->f_bfree = (tquad & ~0x7fffffff) ? 0x7fffffff : (long)tquad;

		fxdr_hyper(&sfp->sf_abytes, &tquad);
		tquad /= bsize;
		sbp->f_bavail = (tquad & ~0x7fffffff) ? 0x7fffffff : (long)tquad;

		sbp->f_bsize = (long)bsize;

		/* adjust file slots too... */
		fxdr_hyper(&sfp->sf_tfiles, &tquad);
		fxdr_hyper(&sfp->sf_ffiles, &tquad2);
		while (tquad & ~0x7fffffff) {
			tquad >>= 1;
			tquad2 >>= 1;
		}
		sbp->f_files = tquad;
		sbp->f_ffree = tquad2;
	} else {
		sbp->f_bsize = fxdr_unsigned(long, sfp->sf_bsize);
		sbp->f_blocks = fxdr_unsigned(long, sfp->sf_blocks);
		sbp->f_bfree = fxdr_unsigned(long, sfp->sf_bfree);
		sbp->f_bavail = fxdr_unsigned(long, sfp->sf_bavail);
		sbp->f_files = 0;
		sbp->f_ffree = 0;
	}
	nfsm_reqdone;
 	kauth_cred_rele(cred);
	vnode_put(vp);
	return (error);
}

/*
 * The nfs_statfs code is complicated, and used by mountnfs(), so leave it as-is
 * and handle VFS_GETATTR by calling nfs_statfs and copying fields.
 */
static int
nfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context)
{
	int error = 0;
	
	if (VFSATTR_IS_ACTIVE(fsap, f_bsize)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_iosize) ||
	    VFSATTR_IS_ACTIVE(fsap, f_blocks) ||
	    VFSATTR_IS_ACTIVE(fsap, f_bfree)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_bavail) ||
	    VFSATTR_IS_ACTIVE(fsap, f_bused)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_files)  ||
	    VFSATTR_IS_ACTIVE(fsap, f_ffree)) {
		struct vfsstatfs sb;

		error = nfs_statfs(mp, &sb, context);
		if (!error) {
			VFSATTR_RETURN(fsap, f_bsize, sb.f_bsize);
			VFSATTR_RETURN(fsap, f_iosize, sb.f_iosize);
			VFSATTR_RETURN(fsap, f_blocks, sb.f_blocks);
			VFSATTR_RETURN(fsap, f_bfree, sb.f_bfree);
			VFSATTR_RETURN(fsap, f_bavail, sb.f_bavail);
			VFSATTR_RETURN(fsap, f_bused, sb.f_blocks - sb.f_bfree);
			VFSATTR_RETURN(fsap, f_files, sb.f_files);
			VFSATTR_RETURN(fsap, f_ffree, sb.f_ffree);
		}
	}

	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		struct nfsmount *nmp;
		struct nfsv3_pathconf pc;
		u_int32_t caps, valid;
		vnode_t vp;
		int v3;

		if (!(nmp = VFSTONFS(mp)))
			return (ENXIO);
		vp = nmp->nm_dvp;
		v3 = (nmp->nm_flag & NFSMNT_NFSV3);

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
		if (v3) {
			/* try to get fsinfo if we haven't already */
			if (!(nmp->nm_state & NFSSTA_GOTFSINFO)) {
				nfs_fsinfo(nmp, vp, vfs_context_ucred(context),
					vfs_context_proc(context));
				if (!(nmp = VFSTONFS(vnode_mount(vp))))
					return (ENXIO);
			}
			if (nmp->nm_state & NFSSTA_GOTFSINFO) {
				/* fsinfo indicates (non)support of links and symlinks */
				valid |= VOL_CAP_FMT_SYMBOLICLINKS |
					 VOL_CAP_FMT_HARDLINKS;
				if (nmp->nm_fsinfo.fsproperties & NFSV3FSINFO_SYMLINK)
					caps |= VOL_CAP_FMT_SYMBOLICLINKS;
				if (nmp->nm_fsinfo.fsproperties & NFSV3FSINFO_LINK)
					caps |= VOL_CAP_FMT_HARDLINKS;
				/* if fsinfo indicates all pathconf info is the same, */
				/* we can use it to report case attributes */
				if ((nmp->nm_fsinfo.fsproperties & NFSV3FSINFO_HOMOGENEOUS) &&
				    !(nmp->nm_state & NFSSTA_GOTPATHCONF)) {
					/* no cached pathconf info, try to get now */
					error = nfs_pathconfrpc(vp, &pc,
							vfs_context_ucred(context),
							vfs_context_proc(context));
					if (!(nmp = VFSTONFS(vnode_mount(vp))))
						return (ENXIO);
					if (!error) {
						/* all files have the same pathconf info, */
						/* so cache a copy of the results */
						nfs_pathconf_cache(nmp, &pc);
					}
				}
				if (nmp->nm_state & NFSSTA_GOTPATHCONF) {
					valid |= VOL_CAP_FMT_CASE_SENSITIVE |
						 VOL_CAP_FMT_CASE_PRESERVING;
					if (!(nmp->nm_fsinfo.pcflags &
						NFSPCINFO_CASE_INSENSITIVE))
						caps |= VOL_CAP_FMT_CASE_SENSITIVE;
					if (nmp->nm_fsinfo.pcflags &
						NFSPCINFO_CASE_PRESERVING)
						caps |= VOL_CAP_FMT_CASE_PRESERVING;
				}
				/* Is server's max file size at least 2TB? */
				if (nmp->nm_fsinfo.maxfilesize >= 0x20000000000ULL)
					caps |= VOL_CAP_FMT_2TB_FILESIZE;
			} else {
				/*
				 * NFSv3 supports 64 bits of file size.
				 * Without FSINFO from the server, we'll
				 * just assume maxfilesize >= 2TB
				 */
				caps |= VOL_CAP_FMT_2TB_FILESIZE;
			}
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
		if ((!nfslockdvnode && !nfslockdwaiting) ||
		    (nmp->nm_flag & NFSMNT_NOLOCKS)) {
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
			valid;

		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED1] = 0;

		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2] = 0;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED2] = 0;

		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
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
int
nfs_fsinfo(nmp, vp, cred, p)
	struct nfsmount *nmp;
	vnode_t vp;
	kauth_cred_t cred;
	proc_t p;
{
	struct nfsv3_fsinfo *fsp;
	caddr_t cp;
	long t1, t2;
	u_long *tl;
	int prefsize, maxsize;
	caddr_t bpos, dpos, cp2;
	int error = 0, retattr;
	mbuf_t mreq, mrep, md, mb, mb2;
	u_int64_t xid;

	nfsm_reqhead(NFSX_FH(1));
	if (error)
		return (error);
	OSAddAtomic(1, (SInt32*)&nfsstats.rpccnt[NFSPROC_FSINFO]);
	nfsm_fhtom(vp, 1);
	nfsm_request(vp, NFSPROC_FSINFO, p, cred, &xid);
	if (mrep) {
		nfsm_postop_attr_update(vp, 1, retattr, &xid);
	}
	if (!error) {
		nfsm_dissect(fsp, struct nfsv3_fsinfo *, NFSX_V3FSINFO);
		prefsize = fxdr_unsigned(u_long, fsp->fs_wtpref);
		if (prefsize < nmp->nm_wsize)
			nmp->nm_wsize = (prefsize + NFS_FABLKSIZE - 1) &
				~(NFS_FABLKSIZE - 1);
		maxsize = fxdr_unsigned(u_long, fsp->fs_wtmax);
		if (maxsize < nmp->nm_wsize) {
			nmp->nm_wsize = maxsize & ~(NFS_FABLKSIZE - 1);
			if (nmp->nm_wsize == 0)
				nmp->nm_wsize = maxsize;
		}
		prefsize = fxdr_unsigned(u_long, fsp->fs_rtpref);
		if (prefsize < nmp->nm_rsize)
			nmp->nm_rsize = (prefsize + NFS_FABLKSIZE - 1) &
				~(NFS_FABLKSIZE - 1);
		maxsize = fxdr_unsigned(u_long, fsp->fs_rtmax);
		if (maxsize < nmp->nm_rsize) {
			nmp->nm_rsize = maxsize & ~(NFS_FABLKSIZE - 1);
			if (nmp->nm_rsize == 0)
				nmp->nm_rsize = maxsize;
		}
		prefsize = fxdr_unsigned(u_long, fsp->fs_dtpref);
		if (prefsize < nmp->nm_readdirsize)
			nmp->nm_readdirsize = prefsize;
		if (maxsize < nmp->nm_readdirsize) {
			nmp->nm_readdirsize = maxsize;
		}
		fxdr_hyper(&fsp->fs_maxfilesize, &nmp->nm_fsinfo.maxfilesize);
		nmp->nm_fsinfo.fsproperties = fxdr_unsigned(u_long, fsp->fs_properties);
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
	struct nfs_vattr nvattr;
	mount_t mp;
	vnode_t vp;
	proc_t procp;
	int error;
#if !defined(NO_MOUNT_PRIVATE)
	mount_t mppriv;
	vnode_t vppriv;
#endif /* NO_MOUNT_PRIVATE */
	int v3, sotype;

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

	/*
	 * Try NFSv3 first, then fallback to NFSv2.
	 * Likewise, try TCP first, then fall back to UDP.
	 */
	v3 = 1;
	sotype = SOCK_STREAM;

tryagain:
	error = nfs_boot_getfh(&nd, procp, v3, sotype);
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
		panic("nfs_boot_getfh(v2,UDP) failed with %d\n", error);
	}

	/*
	 * Create the root mount point.
	 */
#if !defined(NO_MOUNT_PRIVATE)
	if ((error = nfs_mount_diskless(&nd.nd_root, "/", MNT_RDONLY|MNT_ROOTFS, &vp, &mp)))
#else
	if ((error = nfs_mount_diskless(&nd.nd_root, "/", MNT_ROOTFS, &vp, &mp)))
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
		panic("nfs_mount_diskless(v2,UDP) root failed with %d\n", error);
	}
	printf("root on %s\n", (char *)&nd.nd_root.ndm_host);

	vfs_unbusy(mp);
	mount_list_add(mp);
	rootvp = vp;
	
#if !defined(NO_MOUNT_PRIVATE)
	if (nd.nd_private.ndm_saddr.sin_addr.s_addr) {
	    error = nfs_mount_diskless_private(&nd.nd_private, "/private",
					       0, &vppriv, &mppriv);
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
	error = nfs_getattr(vp, &nvattr, kauth_cred_get(), procp);
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
	mount_t *mpp)
{
	struct user_nfs_args args;
	mount_t mp;
	mbuf_t m;
	int error;
	proc_t procp;

	procp = current_proc(); /* XXX */

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
	bcopy((caddr_t)args.addr, mbuf_data(m), ndmntp->ndm_saddr.sin_len);
	if ((error = mountnfs(&args, mp, m, procp, vpp))) {
		printf("nfs_mountroot: mount %s failed: %d\n", mntname, error);
		// XXX vfs_rootmountfailed(mp);
		mount_list_lock();
		mp->mnt_vtable->vfc_refcount--;
		mount_list_unlock();
		vfs_unbusy(mp);
		mount_lock_destroy(mp);
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
	mount_t *mpp)
{
	struct user_nfs_args args;
	mount_t mp;
	mbuf_t m;
	int error;
	proc_t procp;
	struct vfstable *vfsp;
	struct nameidata nd;
	vnode_t vp;
	struct vfs_context context;

	procp = current_proc(); /* XXX */
	context.vc_proc = procp;
	context.vc_ucred = kauth_cred_get();

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
			return (error);
		}
		fdp->fd_cdir = rootvnode;
		fdp->fd_rdir = NULL;
	}

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE32,
	    mntname, &context);
	if ((error = namei(&nd))) {
		printf("nfs_mountroot: private namei failed!\n");
		return (error);
	}
	{
		/* undo vnode_ref() in mimic main()! */
		vnode_rele(rootvnode);
	}
	nameidone(&nd);
	vp = nd.ni_vp;

	if ((error = VNOP_FSYNC(vp, MNT_WAIT, &context)) ||
	    (error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0))) {
		vnode_put(vp);
		return (error);
	}
	if (vnode_vtype(vp) != VDIR) {
		vnode_put(vp);
		return (ENOTDIR);
	}
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strcmp(vfsp->vfc_name, "nfs"))
			break;
	if (vfsp == NULL) {
		printf("nfs_mountroot: private NFS not configured\n");
		vnode_put(vp);
		return (ENODEV);
	}
	if (vnode_mountedhere(vp) != NULL) {
		vnode_put(vp);
		return (EBUSY);
	}

	/*
	 * Allocate and initialize the filesystem.
	 */
	mp = _MALLOC_ZONE((u_long)sizeof(struct mount), M_MOUNT, M_WAITOK);
	if (!mp) {
		printf("nfs_mountroot: unable to allocate mount structure\n");
		vnode_put(vp);
		return (ENOMEM);
	}
	bzero((char *)mp, (u_long)sizeof(struct mount));

	/* Initialize the default IO constraints */
	mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
	mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

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
		return (error);
	}
	mbuf_setlen(m, ndmntp->ndm_saddr.sin_len);
	bcopy((caddr_t)args.addr, mbuf_data(m), ndmntp->ndm_saddr.sin_len);
	if ((error = mountnfs(&args, mp, m, procp, &vp))) {
		printf("nfs_mountroot: mount %s failed: %d\n", mntname, error);
		mount_list_lock();
		vfsp->vfc_refcount--;
		mount_list_unlock();
		vfs_unbusy(mp);
		mount_lock_destroy(mp);
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
 */
static int
nfs_mount(mount_t mp, vnode_t vp, user_addr_t data, vfs_context_t context)
{
	proc_t p = vfs_context_proc(context);
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
		if (vfs_context_is64bit(context))
			error = copyin(data, (caddr_t)&args, sizeof (struct user_nfs_args3));
		else
			error = copyin(data, (caddr_t)&tempargs, sizeof (struct nfs_args3));
		break;
	case 4:
		if (vfs_context_is64bit(context))
			error = copyin(data, (caddr_t)&args, sizeof (args));
		else
			error = copyin(data, (caddr_t)&tempargs, sizeof (tempargs));
		break;
	default:
		return (EPROGMISMATCH);
	}
	if (error)
		return (error);

	if (!vfs_context_is64bit(context)) {
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
	}

	if (args.fhsize < 0 || args.fhsize > NFSX_V3FHMAX)
		return (EINVAL);
	error = copyin(args.fh, (caddr_t)nfh, args.fhsize);
	if (error)
		return (error);

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
	error = mountnfs(&args, mp, nam, p, &vp);
	return (error);
}

/*
 * Common code for mount and mountroot
 */
static int
mountnfs(
	struct user_nfs_args *argp,
	mount_t mp,
	mbuf_t nam,
	proc_t p,
	vnode_t *vpp)
{
	struct nfsmount *nmp;
	struct nfsnode *np;
	int error, maxio;
	struct nfs_vattr nvattrs;
	struct vfs_context context; /* XXX get from caller? */
	u_int64_t xid;

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
		TAILQ_INIT(&nmp->nm_uidlruhead);
		TAILQ_INIT(&nmp->nm_bufq);
		vfs_setfsprivate(mp, nmp);
	}

	/* setup defaults */
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

	vfs_getnewfsid(mp);
	nmp->nm_mountp = mp;
	vfs_setauthopaque(mp);
	nmp->nm_flag = argp->flags;
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

	/* Set up the sockets and per-host congestion */
	nmp->nm_sotype = argp->sotype;
	nmp->nm_soproto = argp->proto;

	/* make sure mbuf constants are set up */
	if (!nfs_mbuf_mlen)
		nfs_mbuf_init();

	/*
	 * For Connection based sockets (TCP,...) defer the connect until
	 * the first request, in case the server is not responding.
	 */
	if (nmp->nm_sotype == SOCK_DGRAM &&
		(error = nfs_connect(nmp, (struct nfsreq *)0)))
		goto bad;

	/*
	 * Get file attributes for the mountpoint.  These are needed
	 * in order to properly create the root vnode.
	 */
	// LP64todo - fix CAST_DOWN of argp->fh
	error = nfs_getattr_no_vnode(mp, CAST_DOWN(caddr_t, argp->fh), argp->fhsize,
			proc_ucred(p), p, &nvattrs, &xid);
	if (error) {
		/*
		 * we got problems... we couldn't get the attributes
		 * from the NFS server... so the mount fails.
		 */
		goto bad;
	}

	/*
	 * A reference count is needed on the nfsnode representing the
	 * remote root.  If this object is not persistent, then backward
	 * traversals of the mount point (i.e. "..") will not work if
	 * the nfsnode gets flushed out of the cache. UFS does not have
	 * this problem, because one can identify root inodes by their
	 * number == ROOTINO (2).
	 */
	error = nfs_nget(mp, NULL, NULL, CAST_DOWN(caddr_t, argp->fh), argp->fhsize,
			&nvattrs, &xid, NG_MARKROOT, &np);
	if (error)
		goto bad;

	/*
	 * save this vnode pointer. That way nfs_unmount()
	 * does not need to call nfs_nget() just get it to drop
	 * this vnode reference.
	 */
	nmp->nm_dvp = *vpp = NFSTOV(np);
	/* get usecount and drop iocount */
	error = vnode_ref(*vpp);
	if (error) {
		vnode_put(*vpp);
		goto bad;
	}
	vnode_put(*vpp);

	/*
	 * Set the mount point's block I/O size.
	 * We really need to do this after we get info back from
	 * the server about what its preferred I/O sizes are.
	 */
	if (nmp->nm_flag & NFSMNT_NFSV3)
		nfs_fsinfo(nmp, *vpp, proc_ucred(p), p);
	vfs_statfs(mp)->f_iosize = nfs_iosize(nmp);

	/*
	 * V3 mounts give us a (relatively) reliable remote access(2)
	 * call, so advertise the fact.
	 *
	 * XXX this may not be the best way to go, as the granularity
	 *     offered isn't a good match to our needs.
	 */
	if (nmp->nm_flag & NFSMNT_NFSV3)
		vfs_setauthopaqueaccess(mp);

	/*
	 * Do statfs to ensure static info gets set to reasonable values.
	 */
	context.vc_proc = p;
	context.vc_ucred = proc_ucred(p);
	nfs_statfs(mp, vfs_statfs(mp), &context);

	if (nmp->nm_flag & NFSMNT_RESVPORT)
		nfs_resv_mounts++;
	nmp->nm_state |= NFSSTA_MOUNTED;
	return (0);
bad:
	nfs_disconnect(nmp);
	FREE_ZONE((caddr_t)nmp, sizeof (struct nfsmount), M_NFSMNT);
	mbuf_freem(nam);
	return (error);
}


/*
 * unmount system call
 */
static int
nfs_unmount(
	mount_t mp,
	int mntflags,
	__unused vfs_context_t context)
{
	register struct nfsmount *nmp;
	vnode_t vp;
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
	 * - Decrement reference on the vnode representing remote root.
	 * - Close the socket
	 * - Free up the data structures
	 */
	vp = nmp->nm_dvp;
	
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

	nmp->nm_state &= ~NFSSTA_MOUNTED;
	if (nmp->nm_flag & NFSMNT_RESVPORT) {
		if (--nfs_resv_mounts == 0)
			nfs_bind_resv_thread_wake();
	}

	/*
	 * Release the root vnode reference held by mountnfs()
	 */
	vnode_rele(vp);

	(void)vflush(mp, NULLVP, FORCECLOSE);
	vfs_setfsprivate(mp, 0); /* don't want to end up using stale vp */

	nfs_disconnect(nmp);
	mbuf_freem(nmp->nm_nam);

	if ((nmp->nm_flag & NFSMNT_KERB) == 0) {
		struct nfsreq *rp;
		/*
		 * Loop through outstanding request list and remove dangling
		 * references to defunct nfsmount struct
		 */
		for (rp = nfs_reqq.tqh_first; rp; rp = rp->r_chain.tqe_next)
			if (rp->r_nmp == nmp)
				rp->r_nmp = (struct nfsmount *)0;
		/* Need to wake up any rcvlock waiters so they notice the unmount. */
		if (nmp->nm_state & NFSSTA_WANTRCV) {
			nmp->nm_state &= ~NFSSTA_WANTRCV;
			wakeup(&nmp->nm_state);
		}
		FREE_ZONE((caddr_t)nmp, sizeof (struct nfsmount), M_NFSMNT);
	}
	return (0);
}

/*
 * Return root of a filesystem
 */
static int
nfs_root(mount_t mp, vnode_t *vpp, __unused vfs_context_t context)
{
	vnode_t vp;
	struct nfsmount *nmp;
	int error;
	u_long vpid;

	nmp = VFSTONFS(mp);
	vp = nmp->nm_dvp;
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
 * Flush out the buffer cache
 */

struct nfs_sync_cargs {
        vfs_context_t context;
        int    waitfor;
        int    error;
};

static int
nfs_sync_callout(vnode_t vp, void *arg)
{
	struct nfs_sync_cargs *cargs = (struct nfs_sync_cargs*)arg;
	int error;

	if (LIST_EMPTY(&VTONFS(vp)->n_dirtyblkhd))
		return (VNODE_RETURNED);
	if (VTONFS(vp)->n_flag & NWRBUSY)
		return (VNODE_RETURNED);

	error = nfs_flush(vp, cargs->waitfor,
			vfs_context_ucred(cargs->context),
			vfs_context_proc(cargs->context), 0);
	if (error)
		cargs->error = error;

	return (VNODE_RETURNED);
}

static int
nfs_sync(mount_t mp, int waitfor, vfs_context_t context)
{
	struct nfs_sync_cargs cargs;

	cargs.waitfor = waitfor;
	cargs.context = context;
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
nfs_vget(
	__unused mount_t mp,
	__unused ino64_t ino,
	__unused vnode_t *vpp,
	__unused vfs_context_t context)
{

	return (ENOTSUP);
}

/*
 * At this point, this should never happen
 */
/*ARGSUSED*/
static int
nfs_fhtovp(
	__unused mount_t mp,
	__unused int fhlen,
	__unused unsigned char *fhp,
	__unused vnode_t *vpp,
	__unused vfs_context_t context)
{

	return (ENOTSUP);
}

/*
 * Vnode pointer to File handle, should never happen either
 */
/*ARGSUSED*/
static int
nfs_vptofh(
	__unused vnode_t vp,
	__unused int *fhlenp,
	__unused unsigned char *fhp,
	__unused vfs_context_t context)
{

	return (ENOTSUP);
}

/*
 * Vfs start routine, a no-op.
 */
/*ARGSUSED*/
static int
nfs_start(
	__unused mount_t mp,
	__unused int flags,
	__unused vfs_context_t context)
{

	return (0);
}

/*
 * Do that sysctl thang...
 */
static int
nfs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
           user_addr_t newp, size_t newlen, vfs_context_t context)
{
	int error = 0, val;
	struct sysctl_req *req = NULL;
	struct vfsidctl vc;
	struct user_vfsidctl user_vc;
	mount_t mp;
	struct nfsmount *nmp = NULL;
	struct vfsquery vq;
	boolean_t is_64_bit;

	/*
	 * All names at this level are terminal.
	 */
	if(namelen > 1)
		return ENOTDIR;	/* overloaded */

	is_64_bit = vfs_context_is64bit(context);

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
		} 
		else {
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
		}
		else {
			req->newptr = CAST_USER_ADDR_T(vc.vc_ptr);
			req->newlen = vc.vc_len;
		}
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
	case VFS_CTL_NOLOCKS:
		val = (nmp->nm_flag & NFSMNT_NOLOCKS) ? 1 : 0;
 		if (req->oldptr != USER_ADDR_NULL) {
 			error = SYSCTL_OUT(req, &val, sizeof(val));
 			if (error)
 				return (error);
 		}
 		if (req->newptr != USER_ADDR_NULL) {
 			error = SYSCTL_IN(req, &val, sizeof(val));
 			if (error)
 				return (error);
			if (val)
				nmp->nm_flag |= NFSMNT_NOLOCKS;
			else
				nmp->nm_flag &= ~NFSMNT_NOLOCKS;
 		}
		break;
	case VFS_CTL_QUERY:
		if (nmp->nm_state & NFSSTA_TIMEO)
			vq.vq_flags |= VQ_NOTRESP;
		if (!(nmp->nm_flag & NFSMNT_NOLOCKS) &&
		    (nmp->nm_state & NFSSTA_LOCKTIMEO))
			vq.vq_flags |= VQ_NOTRESPLOCK;
		error = SYSCTL_OUT(req, &vq, sizeof(vq));
		break;
 	case VFS_CTL_TIMEO:
 		if (req->oldptr != USER_ADDR_NULL) {
 			error = SYSCTL_OUT(req, &nmp->nm_tprintf_initial_delay,
 			    sizeof(nmp->nm_tprintf_initial_delay));
 			if (error)
 				return (error);
 		}
 		if (req->newptr != USER_ADDR_NULL) {
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

