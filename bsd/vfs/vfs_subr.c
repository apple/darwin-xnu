/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)vfs_subr.c	8.31 (Berkeley) 5/26/95
 */

/*
 * External virtual filesystem routines
 */

#undef	DIAGNOSTIC
#define DIAGNOSTIC 1

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/namei.h>
#include <sys/ucred.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/ubc.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/filedesc.h>
#include <sys/event.h>

#include <string.h>
#include <machine/spl.h>


#include <kern/assert.h>

#include <miscfs/specfs/specdev.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>


enum vtype iftovt_tab[16] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};
int	vttoif_tab[9] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK,
	S_IFSOCK, S_IFIFO, S_IFMT,
};

static void vfree(struct vnode *vp);
static void vinactive(struct vnode *vp);
static int vnreclaim(int count);
extern kern_return_t 
	adjust_vm_object_cache(vm_size_t oval, vm_size_t nval);

TAILQ_HEAD(freelst, vnode) vnode_free_list;	/* vnode free list */
TAILQ_HEAD(inactivelst, vnode) vnode_inactive_list;	/* vnode inactive list */
struct mntlist mountlist;			/* mounted filesystem list */

#if DIAGNOSTIC
#define VLISTCHECK(fun, vp, list)	\
	if ((vp)->v_freelist.tqe_prev == (struct vnode **)0xdeadb) \
		panic("%s: %s vnode not on %slist", (fun), (list), (list));

#define VINACTIVECHECK(fun, vp, expected)	\
	do {	\
		int __is_inactive = ISSET((vp)->v_flag, VUINACTIVE);	\
		if (__is_inactive ^ expected)	\
			panic("%s: %sinactive vnode, expected %s", (fun),	\
				__is_inactive? "" : "not ",	\
				expected? "inactive": "not inactive"); \
	} while(0)
#else
#define VLISTCHECK(fun, vp, list)
#define VINACTIVECHECK(fun, vp, expected)
#endif /* DIAGNOSTIC */

#define VLISTNONE(vp)	\
	do {	\
		(vp)->v_freelist.tqe_next = (struct vnode *)0;	\
		(vp)->v_freelist.tqe_prev = (struct vnode **)0xdeadb;	\
	} while(0)

#define VONLIST(vp)	\
	((vp)->v_freelist.tqe_prev != (struct vnode **)0xdeadb)

/* remove a vnode from free vnode list */
#define VREMFREE(fun, vp)	\
	do {	\
		VLISTCHECK((fun), (vp), "free");	\
		TAILQ_REMOVE(&vnode_free_list, (vp), v_freelist);	\
		VLISTNONE((vp));	\
		freevnodes--;	\
	} while(0)

/* remove a vnode from inactive vnode list */
#define VREMINACTIVE(fun, vp)	\
	do {	\
		VLISTCHECK((fun), (vp), "inactive"); \
		VINACTIVECHECK((fun), (vp), VUINACTIVE); \
		TAILQ_REMOVE(&vnode_inactive_list, (vp), v_freelist); \
		CLR((vp)->v_flag, VUINACTIVE); \
		VLISTNONE((vp));	\
		inactivevnodes--;	\
	} while(0)

#define VORECLAIM_ENABLE(vp)   \
	do {	\
		if (ISSET((vp)->v_flag, VORECLAIM))	\
			panic("vm_object_reclaim already");	\
		SET((vp)->v_flag, VORECLAIM);	\
	} while(0)

#define VORECLAIM_DISABLE(vp)	\
	do {	\
		CLR((vp)->v_flag, VORECLAIM);	\
		if (ISSET((vp)->v_flag, VXWANT)) {	\
			CLR((vp)->v_flag, VXWANT);	\
			wakeup((caddr_t)(vp));	\
		}	\
	} while(0)

/*
 * Have to declare first two locks as actual data even if !MACH_SLOCKS, since
 * a pointers to them get passed around.
 */
simple_lock_data_t mountlist_slock;
simple_lock_data_t mntvnode_slock;
decl_simple_lock_data(,mntid_slock);
decl_simple_lock_data(,vnode_free_list_slock);
decl_simple_lock_data(,spechash_slock);

/*
 * vnodetarget is the amount of vnodes we expect to get back 
 * from the the inactive vnode list and VM object cache.
 * As vnreclaim() is a mainly cpu bound operation for faster 
 * processers this number could be higher.
 * Having this number too high introduces longer delays in 
 * the execution of getnewvnode().
 */
unsigned long vnodetarget;		/* target for vnreclaim() */
#define VNODE_FREE_TARGET	20	/* Default value for vnodetarget */

/*
 * We need quite a few vnodes on the free list to sustain the
 * rapid stat() the compilation process does, and still benefit from the name
 * cache. Having too few vnodes on the free list causes serious disk
 * thrashing as we cycle through them.
 */
#define VNODE_FREE_MIN		300	/* freelist should have at least these many */

/*
 * We need to get vnodes back from the VM object cache when a certain #
 * of vnodes are reused from the freelist. This is essential for the
 * caching to be effective in the namecache and the buffer cache [for the
 * metadata].
 */
#define	VNODE_TOOMANY_REUSED	(VNODE_FREE_MIN/4)

/*
 * If we have enough vnodes on the freelist we do not want to reclaim
 * the vnodes from the VM object cache.
 */
#define VNODE_FREE_ENOUGH	(VNODE_FREE_MIN + (VNODE_FREE_MIN/2))

/*
 * Initialize the vnode management data structures.
 */
__private_extern__ void
vntblinit()
{
	extern struct lock__bsd__	exchangelock;

	simple_lock_init(&mountlist_slock);
	simple_lock_init(&mntvnode_slock);
	simple_lock_init(&mntid_slock);
	simple_lock_init(&spechash_slock);
	TAILQ_INIT(&vnode_free_list);
	simple_lock_init(&vnode_free_list_slock);
	TAILQ_INIT(&vnode_inactive_list);
	CIRCLEQ_INIT(&mountlist);
    lockinit(&exchangelock, PVFS, "exchange", 0, 0);

	if (!vnodetarget)
		vnodetarget = VNODE_FREE_TARGET;

	/*
	 * Scale the vm_object_cache to accomodate the vnodes 
	 * we want to cache
	 */
	(void) adjust_vm_object_cache(0, desiredvnodes - VNODE_FREE_MIN);
}

/* Reset the VM Object Cache with the values passed in */
__private_extern__ kern_return_t
reset_vmobjectcache(unsigned int val1, unsigned int val2)
{
	vm_size_t oval = val1 - VNODE_FREE_MIN;
	vm_size_t nval;
	
	if(val2 < VNODE_FREE_MIN)
		nval = 0;
	else
		nval = val2 - VNODE_FREE_MIN;

	return(adjust_vm_object_cache(oval, nval));
}

/*
 * Mark a mount point as busy. Used to synchronize access and to delay
 * unmounting. Interlock is not released on failure.
 */
int
vfs_busy(mp, flags, interlkp, p)
	struct mount *mp;
	int flags;
	struct slock *interlkp;
	struct proc *p;
{
	int lkflags;

	if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
		if (flags & LK_NOWAIT)
			return (ENOENT);
		mp->mnt_kern_flag |= MNTK_MWAIT;
		if (interlkp)
			simple_unlock(interlkp);
		/*
		 * Since all busy locks are shared except the exclusive
		 * lock granted when unmounting, the only place that a
		 * wakeup needs to be done is at the release of the
		 * exclusive lock at the end of dounmount.
		 */
		sleep((caddr_t)mp, PVFS);
		if (interlkp)
			simple_lock(interlkp);
		return (ENOENT);
	}
	lkflags = LK_SHARED;
	if (interlkp)
		lkflags |= LK_INTERLOCK;
	if (lockmgr(&mp->mnt_lock, lkflags, interlkp, p))
		panic("vfs_busy: unexpected lock failure");
	return (0);
}

/*
 * Free a busy filesystem.
 */
void
vfs_unbusy(mp, p)
	struct mount *mp;
	struct proc *p;
{

	lockmgr(&mp->mnt_lock, LK_RELEASE, NULL, p);
}

/*
 * Lookup a filesystem type, and if found allocate and initialize
 * a mount structure for it.
 *
 * Devname is usually updated by mount(8) after booting.
 */
int
vfs_rootmountalloc(fstypename, devname, mpp)
	char *fstypename;
	char *devname;
	struct mount **mpp;
{
	struct proc *p = current_proc();	/* XXX */
	struct vfsconf *vfsp;
	struct mount *mp;

	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strcmp(vfsp->vfc_name, fstypename))
			break;
	if (vfsp == NULL)
		return (ENODEV);
	mp = _MALLOC_ZONE((u_long)sizeof(struct mount), M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));

    /* Initialize the default IO constraints */
    mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
    mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

	lockinit(&mp->mnt_lock, PVFS, "vfslock", 0, 0);
	(void)vfs_busy(mp, LK_NOWAIT, 0, p);
	LIST_INIT(&mp->mnt_vnodelist);
	mp->mnt_vfc = vfsp;
	mp->mnt_op = vfsp->vfc_vfsops;
	mp->mnt_flag = MNT_RDONLY;
	mp->mnt_vnodecovered = NULLVP;
	vfsp->vfc_refcount++;
	mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_stat.f_fstypename, vfsp->vfc_name, MFSNAMELEN);
	mp->mnt_stat.f_mntonname[0] = '/';
	(void) copystr(devname, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, 0);
	*mpp = mp;
	return (0);
}

/*
 * Find an appropriate filesystem to use for the root. If a filesystem
 * has not been preselected, walk through the list of known filesystems
 * trying those that have mountroot routines, and try them until one
 * works or we have tried them all.
 */
int
vfs_mountroot()
{
	struct vfsconf *vfsp;
	extern int (*mountroot)(void);
	int error;

	if (mountroot != NULL) {
		error = (*mountroot)();
		return (error);
	}
	
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next) {
		if (vfsp->vfc_mountroot == NULL)
			continue;
		if ((error = (*vfsp->vfc_mountroot)()) == 0)
			return (0);
		if (error != EINVAL)
			printf("%s_mountroot failed: %d\n", vfsp->vfc_name, error);
	}
	return (ENODEV);
}

/*
 * Lookup a mount point by filesystem identifier.
 */
struct mount *
vfs_getvfs(fsid)
	fsid_t *fsid;
{
	register struct mount *mp;

	simple_lock(&mountlist_slock);
	CIRCLEQ_FOREACH(mp, &mountlist, mnt_list) {
		if (mp->mnt_stat.f_fsid.val[0] == fsid->val[0] &&
		    mp->mnt_stat.f_fsid.val[1] == fsid->val[1]) {
			simple_unlock(&mountlist_slock);
			return (mp);
		}
	}
	simple_unlock(&mountlist_slock);
	return ((struct mount *)0);
}

/*
 * Get a new unique fsid
 */
void
vfs_getnewfsid(mp)
	struct mount *mp;
{
static u_short xxxfs_mntid;

	fsid_t tfsid;
	int mtype;

	simple_lock(&mntid_slock);
	mtype = mp->mnt_vfc->vfc_typenum;
	mp->mnt_stat.f_fsid.val[0] = makedev(nblkdev + mtype, 0);
	mp->mnt_stat.f_fsid.val[1] = mtype;
	if (xxxfs_mntid == 0)
		++xxxfs_mntid;
	tfsid.val[0] = makedev(nblkdev + mtype, xxxfs_mntid);
	tfsid.val[1] = mtype;
	if (!CIRCLEQ_EMPTY(&mountlist)) {
		while (vfs_getvfs(&tfsid)) {
			tfsid.val[0]++;
			xxxfs_mntid++;
		}
	}
	mp->mnt_stat.f_fsid.val[0] = tfsid.val[0];
	simple_unlock(&mntid_slock);
}

/*
 * Set vnode attributes to VNOVAL
 */
void
vattr_null(vap)
	register struct vattr *vap;
{

	vap->va_type = VNON;
	vap->va_size = vap->va_bytes = VNOVAL;
	vap->va_mode = vap->va_nlink = vap->va_uid = vap->va_gid =
		vap->va_fsid = vap->va_fileid =
		vap->va_blocksize = vap->va_rdev =
		vap->va_atime.tv_sec = vap->va_atime.tv_nsec =
		vap->va_mtime.tv_sec = vap->va_mtime.tv_nsec =
		vap->va_ctime.tv_sec = vap->va_ctime.tv_nsec =
		vap->va_flags = vap->va_gen = VNOVAL;
	vap->va_vaflags = 0;
}

/*
 * Routines having to do with the management of the vnode table.
 */
extern int (**dead_vnodeop_p)(void *);
static void vclean __P((struct vnode *vp, int flag, struct proc *p));
extern void vgonel __P((struct vnode *vp, struct proc *p));
long numvnodes, freevnodes;
long inactivevnodes;
long vnode_reclaim_tried;
long vnode_objects_reclaimed;


extern struct vattr va_null;

/*
 * Return the next vnode from the free list.
 */
int
getnewvnode(tag, mp, vops, vpp)
	enum vtagtype tag;
	struct mount *mp;
	int (**vops)(void *);
	struct vnode **vpp;
{
	struct proc *p = current_proc();	/* XXX */
	struct vnode *vp;
	int cnt, didretry = 0;
	static int reused = 0;				/* track the reuse rate */
	int reclaimhits = 0;

retry:
	simple_lock(&vnode_free_list_slock);
	/*
	 * MALLOC a vnode if the number of vnodes has not reached the desired
	 * value and the number on the free list is still reasonable...
	 * reuse from the freelist even though we may evict a name cache entry
	 * to reduce the number of vnodes that accumulate.... vnodes tie up
	 * wired memory and are never garbage collected
	 */
	if (numvnodes < desiredvnodes && (freevnodes < (2 * VNODE_FREE_MIN))) {
		numvnodes++;
		simple_unlock(&vnode_free_list_slock);
		MALLOC_ZONE(vp, struct vnode *, sizeof *vp, M_VNODE, M_WAITOK);
		bzero((char *)vp, sizeof *vp);
		VLISTNONE(vp);		/* avoid double queue removal */
		simple_lock_init(&vp->v_interlock);
		goto done;
	}

	/*
	 * Once the desired number of vnodes are allocated,
	 * we start reusing the vnodes.
	 */
	if (freevnodes < VNODE_FREE_MIN) {
		/*
		 * if we are low on vnodes on the freelist attempt to get
		 * some back from the inactive list and VM object cache
		 */
		simple_unlock(&vnode_free_list_slock);
		(void)vnreclaim(vnodetarget);
		simple_lock(&vnode_free_list_slock);
	}
	if (numvnodes >= desiredvnodes && reused > VNODE_TOOMANY_REUSED) {
		reused = 0;
		if (freevnodes < VNODE_FREE_ENOUGH) {
			simple_unlock(&vnode_free_list_slock);
			(void)vnreclaim(vnodetarget);
			simple_lock(&vnode_free_list_slock);
		}
	}

	for (cnt = 0, vp = vnode_free_list.tqh_first;
			vp != NULLVP; cnt++, vp = vp->v_freelist.tqe_next) {
		if (simple_lock_try(&vp->v_interlock)) {
			/* got the interlock */
			if (ISSET(vp->v_flag, VORECLAIM)) {
				/* skip over the vnodes that are being reclaimed */
				simple_unlock(&vp->v_interlock);
				reclaimhits++;
			} else
				break;
		}
	}

	/*
	 * Unless this is a bad time of the month, at most
	 * the first NCPUS items on the free list are
	 * locked, so this is close enough to being empty.
	 */
	if (vp == NULLVP) {
		simple_unlock(&vnode_free_list_slock);
		if (!(didretry++) && (vnreclaim(vnodetarget) > 0))
			goto retry;
		tablefull("vnode");
		log(LOG_EMERG, "%d vnodes locked, %d desired, %d numvnodes, "
			"%d free, %d inactive, %d being reclaimed\n",
			cnt, desiredvnodes, numvnodes, freevnodes, inactivevnodes,
			reclaimhits);
		*vpp = 0;
		return (ENFILE);
	}

	if (vp->v_usecount)
		panic("free vnode isn't: v_type = %d, v_usecount = %d?",
				vp->v_type, vp->v_usecount);

	VREMFREE("getnewvnode", vp);
	reused++;
	simple_unlock(&vnode_free_list_slock);
	vp->v_lease = NULL;
	cache_purge(vp);
	if (vp->v_type != VBAD)
		vgonel(vp, p);	/* clean and reclaim the vnode */
	else
		simple_unlock(&vp->v_interlock);
#if DIAGNOSTIC
	if (vp->v_data)
		panic("cleaned vnode isn't");
	{
	int s = splbio();
	if (vp->v_numoutput)
		panic("Clean vnode has pending I/O's");
	splx(s);
	}
#endif
	if (UBCINFOEXISTS(vp))
		panic("getnewvnode: ubcinfo not cleaned");
	else
		vp->v_ubcinfo = UBC_INFO_NULL;

	if (vp->v_flag & VHASDIRTY)
	        cluster_release(vp);

	// make sure all these fields are cleared out as the
	// name/parent stuff uses them and assumes they're
	// cleared to null/0.
	if (vp->v_scmap != NULL) {
	    panic("getnewvnode: vp @ 0x%x has non-null scmap.\n", vp);
	}
	vp->v_un.vu_name = NULL;
	vp->v_scdirty = 0;
	vp->v_un1.v_cl.v_pad = 0;
	
	
	vp->v_lastr = -1;
	vp->v_ralen = 0;
	vp->v_maxra = 0;
	vp->v_ciosiz = 0;
	vp->v_clen = 0;
	vp->v_socket = 0;

	/* we may have blocked, re-evaluate state */
	simple_lock(&vnode_free_list_slock);
	if (VONLIST(vp)) {
		if (vp->v_usecount == 0)
			VREMFREE("getnewvnode", vp);
		 else if (ISSET((vp)->v_flag, VUINACTIVE))
			VREMINACTIVE("getnewvnode", vp);
	}
	simple_unlock(&vnode_free_list_slock);

done:
	vp->v_flag = VSTANDARD;
	vp->v_type = VNON;
	vp->v_tag = tag;
	vp->v_op = vops;
	insmntque(vp, mp);
	*vpp = vp;
	vp->v_usecount = 1;
	vp->v_data = 0;
	return (0);
}

/*
 * Move a vnode from one mount queue to another.
 */
void
insmntque(vp, mp)
	struct vnode *vp;
	struct mount *mp;
{

	simple_lock(&mntvnode_slock);
	/*
	 * Delete from old mount point vnode list, if on one.
	 */
	if (vp->v_mount != NULL)
		LIST_REMOVE(vp, v_mntvnodes);
	/*
	 * Insert into list of vnodes for the new mount point, if available.
	 */
	if ((vp->v_mount = mp) != NULL)
		LIST_INSERT_HEAD(&mp->mnt_vnodelist, vp, v_mntvnodes);
	simple_unlock(&mntvnode_slock);
}

__inline void
vpwakeup(struct vnode *vp)
{
	if (vp) {
		if (--vp->v_numoutput < 0)
			panic("vpwakeup: neg numoutput");
		if ((vp->v_flag & VBWAIT || vp->v_flag & VTHROTTLED)
		    && vp->v_numoutput <= 0) {
			vp->v_flag &= ~(VBWAIT|VTHROTTLED);
			wakeup((caddr_t)&vp->v_numoutput);
		}
	}
}

/*
 * Update outstanding I/O count and do wakeup if requested.
 */
void
vwakeup(bp)
	register struct buf *bp;
{
	CLR(bp->b_flags, B_WRITEINPROG);
	vpwakeup(bp->b_vp);
}

/*
 * Flush out and invalidate all buffers associated with a vnode.
 * Called with the underlying object locked.
 */
int
vinvalbuf(vp, flags, cred, p, slpflag, slptimeo)
	register struct vnode *vp;
	int flags;
	struct ucred *cred;
	struct proc *p;
	int slpflag, slptimeo;
{
	register struct buf *bp;
	struct buf *nbp, *blist;
	int s, error = 0;

	if (flags & V_SAVE) {
		if (error = VOP_FSYNC(vp, cred, MNT_WAIT, p)) {
			return (error);
		}
		if (vp->v_dirtyblkhd.lh_first)
			panic("vinvalbuf: dirty bufs (vp 0x%x, bp 0x%x)", vp, vp->v_dirtyblkhd.lh_first);
	}

	for (;;) {
		if ((blist = vp->v_cleanblkhd.lh_first) && (flags & V_SAVEMETA))
			while (blist && blist->b_lblkno < 0)
				blist = blist->b_vnbufs.le_next;
		if (!blist && (blist = vp->v_dirtyblkhd.lh_first) &&
		    (flags & V_SAVEMETA))
			while (blist && blist->b_lblkno < 0)
				blist = blist->b_vnbufs.le_next;
		if (!blist)
			break;

		for (bp = blist; bp; bp = nbp) {
			nbp = bp->b_vnbufs.le_next;
			if ((flags & V_SAVEMETA) && bp->b_lblkno < 0)
				continue;
			s = splbio();
			if (ISSET(bp->b_flags, B_BUSY)) {
				SET(bp->b_flags, B_WANTED);
				error = tsleep((caddr_t)bp,
					slpflag | (PRIBIO + 1), "vinvalbuf",
					slptimeo);
				splx(s);
				if (error) {
					return (error);
				}
				break;
			}
			bremfree(bp);
			SET(bp->b_flags, B_BUSY);
			splx(s);
			/*
			 * XXX Since there are no node locks for NFS, I believe
			 * there is a slight chance that a delayed write will
			 * occur while sleeping just above, so check for it.
			 */
			if (ISSET(bp->b_flags, B_DELWRI) && (flags & V_SAVE)) {
				(void) VOP_BWRITE(bp);
				break;
			}

			if (bp->b_flags & B_LOCKED) {
				panic("vinvalbuf: bp @ 0x%x is locked!", bp);
				break;
			} else {
				SET(bp->b_flags, B_INVAL);
			}
			brelse(bp);
		}
	}
	if (!(flags & V_SAVEMETA) &&
	    (vp->v_dirtyblkhd.lh_first || vp->v_cleanblkhd.lh_first))
		panic("vinvalbuf: flush failed");
	return (0);
}

/*
 * Create a vnode for a block device.
 * Used for root filesystem, argdev, and swap areas.
 * Also used for memory file system special devices.
 */
int
bdevvp(dev, vpp)
	dev_t dev;
	struct vnode **vpp;
{
	register struct vnode *vp;
	struct vnode *nvp;
	int error;

	if (dev == NODEV) {
		*vpp = NULLVP;
		return (ENODEV);
	}
	error = getnewvnode(VT_NON, (struct mount *)0, spec_vnodeop_p, &nvp);
	if (error) {
		*vpp = NULLVP;
		return (error);
	}
	vp = nvp;
	vp->v_type = VBLK;
	if (nvp = checkalias(vp, dev, (struct mount *)0)) {
		vput(vp);
		vp = nvp;
	}
	*vpp = vp;
	return (0);
}

/*
 * Check to see if the new vnode represents a special device
 * for which we already have a vnode (either because of
 * bdevvp() or because of a different vnode representing
 * the same block device). If such an alias exists, deallocate
 * the existing contents and return the aliased vnode. The
 * caller is responsible for filling it with its new contents.
 */
struct vnode *
checkalias(nvp, nvp_rdev, mp)
	register struct vnode *nvp;
	dev_t nvp_rdev;
	struct mount *mp;
{
	struct proc *p = current_proc();	/* XXX */
	struct vnode *vp;
	struct vnode **vpp;
	struct specinfo *specinfop;

	if (nvp->v_type != VBLK && nvp->v_type != VCHR)
		return (NULLVP);

	MALLOC_ZONE(specinfop, struct specinfo *, sizeof(struct specinfo),
			M_SPECINFO, M_WAITOK);
	vpp = &speclisth[SPECHASH(nvp_rdev)];
loop:
	simple_lock(&spechash_slock);
	for (vp = *vpp; vp; vp = vp->v_specnext) {
		if (nvp_rdev != vp->v_rdev || nvp->v_type != vp->v_type)
			continue;
		/*
		 * Alias, but not in use, so flush it out.
		 */
		simple_lock(&vp->v_interlock);
		if (vp->v_usecount == 0) {
			simple_unlock(&spechash_slock);
			vgonel(vp, p);
			goto loop;
		}
		if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, p)) {
			simple_unlock(&spechash_slock);
			goto loop;
		}
		break;
	}
	if (vp == NULL || vp->v_tag != VT_NON) {
		nvp->v_specinfo = specinfop;
		specinfop = 0;	/* buffer used */
		bzero(nvp->v_specinfo, sizeof(struct specinfo));
		nvp->v_rdev = nvp_rdev;
		nvp->v_hashchain = vpp;
		nvp->v_specnext = *vpp;
		nvp->v_specflags = 0;
		simple_unlock(&spechash_slock);
		*vpp = nvp;
		if (vp != NULLVP) {
			nvp->v_flag |= VALIASED;
			vp->v_flag |= VALIASED;
			vput(vp);
		}
		/* Since buffer is used just return */
		return (NULLVP);
	}
	simple_unlock(&spechash_slock);
	VOP_UNLOCK(vp, 0, p);
	simple_lock(&vp->v_interlock);
	vclean(vp, 0, p);
	vp->v_op = nvp->v_op;
	vp->v_tag = nvp->v_tag;
	nvp->v_type = VNON;
	insmntque(vp, mp);
	if (specinfop)
		FREE_ZONE((void *)specinfop, sizeof(struct specinfo), M_SPECINFO);
	return (vp);
}

/*
 * Get a reference on a particular vnode and lock it if requested.
 * If the vnode was on the inactive list, remove it from the list.
 * If the vnode was on the free list, remove it from the list and
 * move it to inactive list as needed.
 * The vnode lock bit is set if the vnode is being eliminated in
 * vgone. The process is awakened when the transition is completed,
 * and an error returned to indicate that the vnode is no longer
 * usable (possibly having been changed to a new file system type).
 */
int
vget(vp, flags, p)
	struct vnode *vp;
	int flags;
	struct proc *p;
{
	int error = 0;
	u_long vpid;

	vpid = vp->v_id;    // save off the original v_id

retry:

	/*
	 * If the vnode is in the process of being cleaned out for
	 * another use, we wait for the cleaning to finish and then
	 * return failure. Cleaning is determined by checking that
	 * the VXLOCK flag is set.
	 */
	if ((flags & LK_INTERLOCK) == 0)
		simple_lock(&vp->v_interlock);
	if ((vp->v_flag & VXLOCK) || (vp->v_flag & VORECLAIM)) {
		vp->v_flag |= VXWANT;
		simple_unlock(&vp->v_interlock);
		(void)tsleep((caddr_t)vp, PINOD, "vget", 0);
		return (ENOENT);
	}

	/* 
	 * vnode is being terminated.
	 * wait for vnode_pager_no_senders() to clear VTERMINATE
	 */
	if (ISSET(vp->v_flag, VTERMINATE)) {
		SET(vp->v_flag, VTERMWANT);
		simple_unlock(&vp->v_interlock);
		(void)tsleep((caddr_t)&vp->v_ubcinfo, PINOD, "vget1", 0);
		return (ENOENT);
	}

	/*
	 * if the vnode is being initialized,
	 * wait for it to finish initialization
	 */
	if (ISSET(vp->v_flag,  VUINIT)) {
		SET(vp->v_flag, VUWANT);
		simple_unlock(&vp->v_interlock);
		(void) tsleep((caddr_t)vp, PINOD, "vget2", 0);
		goto retry;
	}

	simple_lock(&vnode_free_list_slock);
	if (VONLIST(vp)) {
		if (vp->v_usecount == 0)
			VREMFREE("vget", vp);
		 else if (ISSET((vp)->v_flag, VUINACTIVE))
			VREMINACTIVE("vget", vp);
	}
	simple_unlock(&vnode_free_list_slock);

	if (++vp->v_usecount <= 0)
		panic("vget: v_usecount");                     

	/*
	 * Recover named reference as needed
	 */
	if (UBCISVALID(vp) && !UBCINFOMISSING(vp) && !ubc_issetflags(vp, UI_HASOBJREF)) {
		simple_unlock(&vp->v_interlock);
		if (ubc_getobject(vp, UBC_HOLDOBJECT) == MEMORY_OBJECT_CONTROL_NULL) {
			error = ENOENT;
			goto errout;
		}
		simple_lock(&vp->v_interlock);
	}

	if (flags & LK_TYPE_MASK) {
		if (error = vn_lock(vp, flags | LK_INTERLOCK, p))
			goto errout;
		if (vpid != vp->v_id) {    // make sure it's still the same vnode
		    vput(vp);
		    return ENOENT;
		}
		return (0);
	}

	if ((flags & LK_INTERLOCK) == 0)
		simple_unlock(&vp->v_interlock);

	if (vpid != vp->v_id) {            // make sure it's still the same vnode
	    vrele(vp);
	    return ENOENT;
	}

	return (0);

errout:
	simple_lock(&vp->v_interlock);

	/*
	 * we may have blocked. Re-evaluate the state
	 */
	simple_lock(&vnode_free_list_slock);
	if (VONLIST(vp)) {
		if (vp->v_usecount == 0)
			VREMFREE("vget", vp);
		 else if (ISSET((vp)->v_flag, VUINACTIVE))
			VREMINACTIVE("vget", vp);
	}
	simple_unlock(&vnode_free_list_slock);

	/*
	 * If the vnode was not active in the first place
	 * must not call vrele() as VOP_INACTIVE() is not
	 * required.
	 * So inlined part of vrele() here.
	 */
	if (--vp->v_usecount == 1) {
		if (UBCINFOEXISTS(vp)) {
			vinactive(vp);
			simple_unlock(&vp->v_interlock);
			return (error);
		}
	}
	if (vp->v_usecount > 0) {
		simple_unlock(&vp->v_interlock);
		return (error);
	}
	if (vp->v_usecount < 0)
		panic("vget: negative usecount (%d)", vp->v_usecount);
	vfree(vp);
	simple_unlock(&vp->v_interlock);
	return (error);
}

/*
 * Get a pager reference on the particular vnode.
 *
 * This is called from ubc_info_init() and it is asumed that
 * the vnode is not on the free list.
 * It is also assumed that the vnode is neither being recycled
 * by vgonel nor being terminated by vnode_pager_vrele().
 *
 * The vnode interlock is NOT held by the caller.
 */
__private_extern__ int
vnode_pager_vget(vp)
	struct vnode *vp;
{
	simple_lock(&vp->v_interlock);

	UBCINFOCHECK("vnode_pager_vget", vp);

	if (ISSET(vp->v_flag, (VXLOCK|VORECLAIM|VTERMINATE)))
		panic("%s: dying vnode", "vnode_pager_vget");

	simple_lock(&vnode_free_list_slock);
	/* The vnode should not be on free list */
	if (VONLIST(vp)) {     
		if (vp->v_usecount == 0)
			panic("%s: still on list", "vnode_pager_vget");
		else if (ISSET((vp)->v_flag, VUINACTIVE))
			VREMINACTIVE("vnode_pager_vget", vp);
	}

	/* The vnode should not be on the inactive list here */
	simple_unlock(&vnode_free_list_slock);

	/* After all those checks, now do the real work :-) */
	if (++vp->v_usecount <= 0)
		panic("vnode_pager_vget: v_usecount");                     
	simple_unlock(&vp->v_interlock);

	return (0);
}

/*
 * Stubs to use when there is no locking to be done on the underlying object.
 * A minimal shared lock is necessary to ensure that the underlying object
 * is not revoked while an operation is in progress. So, an active shared
 * count is maintained in an auxillary vnode lock structure.
 */
int
vop_nolock(ap)
	struct vop_lock_args /* {
		struct vnode *a_vp;
		int a_flags;
		struct proc *a_p;
	} */ *ap;
{
#ifdef notyet
	/*
	 * This code cannot be used until all the non-locking filesystems
	 * (notably NFS) are converted to properly lock and release nodes.
	 * Also, certain vnode operations change the locking state within
	 * the operation (create, mknod, remove, link, rename, mkdir, rmdir,
	 * and symlink). Ideally these operations should not change the
	 * lock state, but should be changed to let the caller of the
	 * function unlock them. Otherwise all intermediate vnode layers
	 * (such as union, umapfs, etc) must catch these functions to do
	 * the necessary locking at their layer. Note that the inactive
	 * and lookup operations also change their lock state, but this 
	 * cannot be avoided, so these two operations will always need
	 * to be handled in intermediate layers.
	 */
	struct vnode *vp = ap->a_vp;
	int vnflags, flags = ap->a_flags;

	if (vp->v_vnlock == NULL) {
		if ((flags & LK_TYPE_MASK) == LK_DRAIN)
			return (0);
		MALLOC(vp->v_vnlock, struct lock__bsd__ *,
				sizeof(struct lock__bsd__), M_TEMP, M_WAITOK);
		lockinit(vp->v_vnlock, PVFS, "vnlock", 0, 0);
	}
	switch (flags & LK_TYPE_MASK) {
	case LK_DRAIN:
		vnflags = LK_DRAIN;
		break;
	case LK_EXCLUSIVE:
	case LK_SHARED:
		vnflags = LK_SHARED;
		break;
	case LK_UPGRADE:
	case LK_EXCLUPGRADE:
	case LK_DOWNGRADE:
		return (0);
	case LK_RELEASE:
	default:
		panic("vop_nolock: bad operation %d", flags & LK_TYPE_MASK);
	}
	if (flags & LK_INTERLOCK)
		vnflags |= LK_INTERLOCK;
	return(lockmgr(vp->v_vnlock, vnflags, &vp->v_interlock, ap->a_p));
#else /* for now */
	/*
	 * Since we are not using the lock manager, we must clear
	 * the interlock here.
	 */
	if (ap->a_flags & LK_INTERLOCK)
		simple_unlock(&ap->a_vp->v_interlock);
	return (0);
#endif
}

/*
 * Decrement the active use count.
 */
int
vop_nounlock(ap)
	struct vop_unlock_args /* {
		struct vnode *a_vp;
		int a_flags;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	if (vp->v_vnlock == NULL)
		return (0);
	return (lockmgr(vp->v_vnlock, LK_RELEASE, NULL, ap->a_p));
}

/*
 * Return whether or not the node is in use.
 */
int
vop_noislocked(ap)
	struct vop_islocked_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	if (vp->v_vnlock == NULL)
		return (0);
	return (lockstatus(vp->v_vnlock));
}

/*
 * Vnode reference.
 */
void
vref(vp)
	struct vnode *vp;
{

	simple_lock(&vp->v_interlock);
	if (vp->v_usecount <= 0)
		panic("vref used where vget required");

	/* If on the inactive list, remove it from there */
	simple_lock(&vnode_free_list_slock);
	if (ISSET((vp)->v_flag, VUINACTIVE))
		VREMINACTIVE("vref", vp);
	simple_unlock(&vnode_free_list_slock);

	if (++vp->v_usecount <= 0)
		panic("vref v_usecount");                     
	simple_unlock(&vp->v_interlock);
}

static void
clean_up_name_parent_ptrs(struct vnode *vp)
{
    if (VNAME(vp) || VPARENT(vp)) {
	char *tmp1;
	struct vnode *tmp2;

	// do it this way so we don't block before clearing 
	// these fields.
	tmp1 = VNAME(vp);
	tmp2 = VPARENT(vp);
	VNAME(vp) = NULL;
	VPARENT(vp) = NULL;
	    
	if (tmp1) {
	    remove_name(tmp1);
	}
	    
	if (tmp2) {
	    vrele(tmp2);
	}
    }
}


/*
 * put the vnode on appropriate free list.
 * called with v_interlock held.
 */
static void
vfree(vp)
	struct vnode *vp;
{
	funnel_t *curflock;
	extern int disable_funnel;

	if ((curflock = thread_funnel_get()) != kernel_flock &&
	    !(disable_funnel && curflock != THR_FUNNEL_NULL))
		panic("Entering vfree() without kernel funnel");

	/*
	 * if the vnode is not obtained by calling getnewvnode() we
	 * are not responsible for the cleanup. Just return.
	 */
	if (!(vp->v_flag & VSTANDARD)) {
		return;
	}

	if (vp->v_usecount != 0)
		panic("vfree: v_usecount");

	/* insert at tail of LRU list or at head if VAGE is set */
	simple_lock(&vnode_free_list_slock);

	// make sure the name & parent pointers get cleared out
//	clean_up_name_parent_ptrs(vp);

	if (VONLIST(vp))
		 panic("%s: vnode still on list", "vfree");

	if (vp->v_flag & VAGE) {
		TAILQ_INSERT_HEAD(&vnode_free_list, vp, v_freelist);
		vp->v_flag &= ~VAGE;
	} else
		TAILQ_INSERT_TAIL(&vnode_free_list, vp, v_freelist);
	freevnodes++;
	simple_unlock(&vnode_free_list_slock);
	return;
}

/*
 * put the vnode on the inactive list.
 * called with v_interlock held
 */
static void
vinactive(vp)
	struct vnode *vp;
{
	funnel_t *curflock;
	extern int disable_funnel;

	if ((curflock = thread_funnel_get()) != kernel_flock &&
	    !(disable_funnel && curflock != THR_FUNNEL_NULL))
		panic("Entering vinactive() without kernel funnel");

	if (!UBCINFOEXISTS(vp))
		panic("vinactive: not a UBC vnode");

	if (vp->v_usecount != 1)
		panic("vinactive: v_usecount");

	simple_lock(&vnode_free_list_slock);

	if (VONLIST(vp))
		 panic("%s: vnode still on list", "vinactive");
	VINACTIVECHECK("vinactive", vp, 0);

	TAILQ_INSERT_TAIL(&vnode_inactive_list, vp, v_freelist);
	SET(vp->v_flag, VUINACTIVE);
	CLR(vp->v_flag, (VNOCACHE_DATA | VRAOFF));

	inactivevnodes++;
	simple_unlock(&vnode_free_list_slock);
	return;
}


/*
 * vput(), just unlock and vrele()
 */
void
vput(vp)
	struct vnode *vp;
{
	struct proc *p = current_proc();	/* XXX */

	simple_lock(&vp->v_interlock);
	if (--vp->v_usecount == 1) {
		if (UBCINFOEXISTS(vp)) {
			vinactive(vp);
			simple_unlock(&vp->v_interlock);
			VOP_UNLOCK(vp, 0, p);
			return;
		}
	}
	if (vp->v_usecount > 0) {
		simple_unlock(&vp->v_interlock);
		VOP_UNLOCK(vp, 0, p);
		return;
	}
#if DIAGNOSTIC
	if (vp->v_usecount < 0 || vp->v_writecount != 0) {
		vprint("vput: bad ref count", vp);
		panic("vput: v_usecount = %d, v_writecount = %d",
			vp->v_usecount, vp->v_writecount);
	}
#endif
	simple_lock(&vnode_free_list_slock);
	if (ISSET((vp)->v_flag, VUINACTIVE))
		VREMINACTIVE("vref", vp);
	simple_unlock(&vnode_free_list_slock);

	simple_unlock(&vp->v_interlock);
	VOP_INACTIVE(vp, p);
	/*
	 * The interlock is not held and
	 * VOP_INCATIVE releases the vnode lock.
	 * We could block and the vnode might get reactivated
	 * Can not just call vfree without checking the state
	 */
	simple_lock(&vp->v_interlock);
	if (!VONLIST(vp)) {
		if (vp->v_usecount == 0) 
			vfree(vp);
		else if ((vp->v_usecount == 1) && UBCINFOEXISTS(vp))
			vinactive(vp);
	}
	simple_unlock(&vp->v_interlock);
}

/*
 * Vnode release.
 * If count drops to zero, call inactive routine and return to freelist.
 */
void
vrele(vp)
	struct vnode *vp;
{
	struct proc *p = current_proc();	/* XXX */
	funnel_t *curflock;
	extern int disable_funnel;

	if ((curflock = thread_funnel_get()) != kernel_flock &&
	    !(disable_funnel && curflock != THR_FUNNEL_NULL))
		panic("Entering vrele() without kernel funnel");

	simple_lock(&vp->v_interlock);
	if (--vp->v_usecount == 1) {
		if (UBCINFOEXISTS(vp)) {
			if ((vp->v_flag & VXLOCK) == 0)
				vinactive(vp);
			simple_unlock(&vp->v_interlock);
			return;
		}
	}
	if (vp->v_usecount > 0) {
		simple_unlock(&vp->v_interlock);
		return;
	}
#if DIAGNOSTIC
	if (vp->v_usecount < 0 || vp->v_writecount != 0) {
		vprint("vrele: bad ref count", vp);
		panic("vrele: ref cnt");
	}
#endif

	if ((vp->v_flag & VXLOCK) || (vp->v_flag & VORECLAIM)) {
		/* vnode is being cleaned, just return */
		vfree(vp);
		simple_unlock(&vp->v_interlock);
		return;
	}

	if (vn_lock(vp, LK_EXCLUSIVE | LK_INTERLOCK, p) == 0) {
		VOP_INACTIVE(vp, p);
		/*
		 * vn_lock releases the interlock and
		 * VOP_INCATIVE releases the vnode lock.
		 * We could block and the vnode might get reactivated
		 * Can not just call vfree without checking the state
		 */
		simple_lock(&vp->v_interlock);
		if (!VONLIST(vp)) {
			if (vp->v_usecount == 0) 
				vfree(vp);
			else if ((vp->v_usecount == 1) && UBCINFOEXISTS(vp))
				vinactive(vp);
		}
		simple_unlock(&vp->v_interlock);
	}
#if 0
	else {
		vfree(vp);
		simple_unlock(&vp->v_interlock);
		kprintf("vrele: vn_lock() failed for vp = 0x%08x\n", vp);
	}
#endif
}

void
vagevp(vp)
	struct vnode *vp;
{
	simple_lock(&vp->v_interlock);
	vp->v_flag |= VAGE;
	simple_unlock(&vp->v_interlock);
	return;
}

/*
 * Page or buffer structure gets a reference.
 */
void
vhold(vp)
	register struct vnode *vp;
{

	simple_lock(&vp->v_interlock);
	vp->v_holdcnt++;
	simple_unlock(&vp->v_interlock);
}

/*
 * Page or buffer structure frees a reference.
 */
void
holdrele(vp)
	register struct vnode *vp;
{

	simple_lock(&vp->v_interlock);
	if (vp->v_holdcnt <= 0)
		panic("holdrele: holdcnt");
	vp->v_holdcnt--;
	simple_unlock(&vp->v_interlock);
}

/*
 * Remove any vnodes in the vnode table belonging to mount point mp.
 *
 * If MNT_NOFORCE is specified, there should not be any active ones,
 * return error if any are found (nb: this is a user error, not a
 * system error). If MNT_FORCE is specified, detach any active vnodes
 * that are found.
 */
#if DIAGNOSTIC
int busyprt = 0;	/* print out busy vnodes */
#if 0
struct ctldebug debug1 = { "busyprt", &busyprt };
#endif /* 0 */
#endif

int
vflush(mp, skipvp, flags)
	struct mount *mp;
	struct vnode *skipvp;
	int flags;
{
	struct proc *p = current_proc();
	struct vnode *vp, *nvp;
	int busy = 0;

	simple_lock(&mntvnode_slock);
loop:
	for (vp = mp->mnt_vnodelist.lh_first; vp; vp = nvp) {
		if (vp->v_mount != mp)
			goto loop;
		nvp = vp->v_mntvnodes.le_next;
		/*
		 * Skip over a selected vnode.
		 */
		if (vp == skipvp)
			continue;

		simple_lock(&vp->v_interlock);
		/*
		 * Skip over a vnodes marked VSYSTEM or VNOFLUSH.
		 */
		if ((flags & SKIPSYSTEM) && ((vp->v_flag & VSYSTEM) || (vp->v_flag & VNOFLUSH))) {
			simple_unlock(&vp->v_interlock);
			continue;
		}
		/*
		 * Skip over a vnodes marked VSWAP.
		 */
		if ((flags & SKIPSWAP) && (vp->v_flag & VSWAP)) {
			simple_unlock(&vp->v_interlock);
			continue;
		}
		/*
		 * If WRITECLOSE is set, only flush out regular file
		 * vnodes open for writing.
		 */
		if ((flags & WRITECLOSE) &&
		    (vp->v_writecount == 0 || vp->v_type != VREG)) {
			simple_unlock(&vp->v_interlock);
			continue;
		}
		/*
		 * With v_usecount == 0, all we need to do is clear
		 * out the vnode data structures and we are done.
		 */
		if (vp->v_usecount == 0) {
			simple_unlock(&mntvnode_slock);
			vgonel(vp, p);
			simple_lock(&mntvnode_slock);
			continue;
		}
		/*
		 * If FORCECLOSE is set, forcibly close the vnode.
		 * For block or character devices, revert to an
		 * anonymous device. For all other files, just kill them.
		 */
		if (flags & FORCECLOSE) {
			simple_unlock(&mntvnode_slock);
			if (vp->v_type != VBLK && vp->v_type != VCHR) {
				vgonel(vp, p);
			} else {
				vclean(vp, 0, p);
				vp->v_op = spec_vnodeop_p;
				insmntque(vp, (struct mount *)0);
			}
			simple_lock(&mntvnode_slock);
			continue;
		}
#if DIAGNOSTIC
		if (busyprt)
			vprint("vflush: busy vnode", vp);
#endif
		simple_unlock(&vp->v_interlock);
		busy++;
	}
	simple_unlock(&mntvnode_slock);
	if (busy && ((flags & FORCECLOSE)==0))
		return (EBUSY);
	return (0);
}

/*
 * Disassociate the underlying file system from a vnode.
 * The vnode interlock is held on entry.
 */
static void
vclean(vp, flags, p)
	struct vnode *vp;
	int flags;
	struct proc *p;
{
	int active;
	int didhold;

	/*
	 * if the vnode is not obtained by calling getnewvnode() we
	 * are not responsible for the cleanup. Just return.
	 */
	if (!(vp->v_flag & VSTANDARD)) {
		simple_unlock(&vp->v_interlock);
		return;
	}

	/*
	 * Check to see if the vnode is in use.
	 * If so we have to reference it before we clean it out
	 * so that its count cannot fall to zero and generate a
	 * race against ourselves to recycle it.
	 */
	if (active = vp->v_usecount) {
		/*
		 * active vnode can not be on the free list.
		 * we are about to take an extra reference on this vnode
		 * do the queue management as needed
		 * Not doing so can cause "still on list" or
		 * "vnreclaim: v_usecount" panic if VOP_LOCK() blocks.
		 */
		simple_lock(&vnode_free_list_slock);
		if (ISSET((vp)->v_flag, VUINACTIVE))
			VREMINACTIVE("vclean", vp);
		simple_unlock(&vnode_free_list_slock);

		if (++vp->v_usecount <= 0)
			panic("vclean: v_usecount");
	}

	/*
	 * Prevent the vnode from being recycled or
	 * brought into use while we clean it out.
	 */
	if (vp->v_flag & VXLOCK)
		panic("vclean: deadlock");
	vp->v_flag |= VXLOCK;

	/*
	 * Even if the count is zero, the VOP_INACTIVE routine may still
	 * have the object locked while it cleans it out. The VOP_LOCK
	 * ensures that the VOP_INACTIVE routine is done with its work.
	 * For active vnodes, it ensures that no other activity can
	 * occur while the underlying object is being cleaned out.
	 */
	VOP_LOCK(vp, LK_DRAIN | LK_INTERLOCK, p);

	/*
	 * While blocked in VOP_LOCK() someone could have dropped
	 * reference[s] and we could land on the inactive list.
	 * if this vnode is on the inactive list 
	 * take it off the list.
	 */
	simple_lock(&vnode_free_list_slock);
	if (ISSET((vp)->v_flag, VUINACTIVE))
		VREMINACTIVE("vclean", vp);
	simple_unlock(&vnode_free_list_slock);

	/* Clean the pages in VM. */
	if (active && (flags & DOCLOSE))
		VOP_CLOSE(vp, IO_NDELAY, NOCRED, p);

	/* Clean the pages in VM. */
	didhold = ubc_hold(vp);
	if ((active) && (didhold))
		(void)ubc_clean(vp, 0); /* do not invalidate */

	/*
	 * Clean out any buffers associated with the vnode.
	 */
	if (flags & DOCLOSE) {
		if (vp->v_tag == VT_NFS)
			nfs_vinvalbuf(vp, V_SAVE, NOCRED, p, 0);
		else
			vinvalbuf(vp, V_SAVE, NOCRED, p, 0, 0);
	}

	if (active)
		VOP_INACTIVE(vp, p);
	else
		VOP_UNLOCK(vp, 0, p);

	/* Destroy ubc named reference */
	if (didhold) {
		ubc_rele(vp);
		ubc_destroy_named(vp);
	}
	/*
	 * Make sure vp isn't on the inactive list.
	 */
	simple_lock(&vnode_free_list_slock);
	if (ISSET((vp)->v_flag, VUINACTIVE)) {
		VREMINACTIVE("vclean", vp);
	}
	simple_unlock(&vnode_free_list_slock);

	/*
	 * Reclaim the vnode.
	 */
	if (VOP_RECLAIM(vp, p))
		panic("vclean: cannot reclaim");
	
	// make sure the name & parent ptrs get cleaned out!
	clean_up_name_parent_ptrs(vp);

	cache_purge(vp);
	if (vp->v_vnlock) {
		struct lock__bsd__ *tmp = vp->v_vnlock;
		if ((tmp->lk_flags & LK_DRAINED) == 0)
			vprint("vclean: lock not drained", vp);
		vp->v_vnlock = NULL;
		FREE(tmp, M_TEMP);
	}

	/* It's dead, Jim! */
	vp->v_op = dead_vnodeop_p;
	vp->v_tag = VT_NON;

	insmntque(vp, (struct mount *)0);

	/*
	 * Done with purge, notify sleepers of the grim news.
	 */
	vp->v_flag &= ~VXLOCK;
	if (vp->v_flag & VXWANT) {
		vp->v_flag &= ~VXWANT;
		wakeup((caddr_t)vp);
	}

	if (active)
		vrele(vp);
}

/*
 * Eliminate all activity associated with  the requested vnode
 * and with all vnodes aliased to the requested vnode.
 */
int
vop_revoke(ap)
	struct vop_revoke_args /* {
		struct vnode *a_vp;
		int a_flags;
	} */ *ap;
{
	struct vnode *vp, *vq;
	struct proc *p = current_proc();

#if DIAGNOSTIC
	if ((ap->a_flags & REVOKEALL) == 0)
		panic("vop_revoke");
#endif

	vp = ap->a_vp;
	simple_lock(&vp->v_interlock);

	if (vp->v_flag & VALIASED) {
		/*
		 * If a vgone (or vclean) is already in progress,
		 * wait until it is done and return.
		 */
		if (vp->v_flag & VXLOCK) {
			while (vp->v_flag & VXLOCK) {
				vp->v_flag |= VXWANT;
				simple_unlock(&vp->v_interlock);
				(void)tsleep((caddr_t)vp, PINOD, "vop_revokeall", 0);
			}
			return (0);
		}
		/*
		 * Ensure that vp will not be vgone'd while we
		 * are eliminating its aliases.
		 */
		vp->v_flag |= VXLOCK;
		simple_unlock(&vp->v_interlock);
		while (vp->v_flag & VALIASED) {
			simple_lock(&spechash_slock);
			for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
				if (vq->v_rdev != vp->v_rdev ||
				    vq->v_type != vp->v_type || vp == vq)
					continue;
				simple_unlock(&spechash_slock);
				vgone(vq);
				break;
			}
			if (vq == NULLVP)
				simple_unlock(&spechash_slock);
		}
		/*
		 * Remove the lock so that vgone below will
		 * really eliminate the vnode after which time
		 * vgone will awaken any sleepers.
		 */
		simple_lock(&vp->v_interlock);
		vp->v_flag &= ~VXLOCK;
	}
	vgonel(vp, p);
	return (0);
}

/*
 * Recycle an unused vnode to the front of the free list.
 * Release the passed interlock if the vnode will be recycled.
 */
int
vrecycle(vp, inter_lkp, p)
	struct vnode *vp;
	struct slock *inter_lkp;
	struct proc *p;
{

	simple_lock(&vp->v_interlock);
	if (vp->v_usecount == 0) {
		if (inter_lkp)
			simple_unlock(inter_lkp);
		vgonel(vp, p);
		return (1);
	}
	simple_unlock(&vp->v_interlock);
	return (0);
}

/*
 * Eliminate all activity associated with a vnode
 * in preparation for reuse.
 */
void
vgone(vp)
	struct vnode *vp;
{
	struct proc *p = current_proc();

	simple_lock(&vp->v_interlock);
	vgonel(vp, p);
}

/*
 * vgone, with the vp interlock held.
 */
void
vgonel(vp, p)
	struct vnode *vp;
	struct proc *p;
{
	struct vnode *vq;
	struct vnode *vx;

	/*
	 * if the vnode is not obtained by calling getnewvnode() we
	 * are not responsible for the cleanup. Just return.
	 */
	if (!(vp->v_flag & VSTANDARD)) {
		simple_unlock(&vp->v_interlock);
		return;
	}

	/*
	 * If a vgone (or vclean) is already in progress,
	 * wait until it is done and return.
	 */
	if (vp->v_flag & VXLOCK) {
		while (vp->v_flag & VXLOCK) {
			vp->v_flag |= VXWANT;
			simple_unlock(&vp->v_interlock);
			(void)tsleep((caddr_t)vp, PINOD, "vgone", 0);
		}
		return;
	}
	/*
	 * Clean out the filesystem specific data.
	 */
	vclean(vp, DOCLOSE, p);
	/*
	 * Delete from old mount point vnode list, if on one.
	 */
	if (vp->v_mount != NULL)
		insmntque(vp, (struct mount *)0);
	/*
	 * If special device, remove it from special device alias list
	 * if it is on one.
	 */
	if ((vp->v_type == VBLK || vp->v_type == VCHR) && vp->v_specinfo != 0) {
		simple_lock(&spechash_slock);
		if (*vp->v_hashchain == vp) {
			*vp->v_hashchain = vp->v_specnext;
		} else {
			for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
				if (vq->v_specnext != vp)
					continue;
				vq->v_specnext = vp->v_specnext;
				break;
			}
			if (vq == NULL)
				panic("missing bdev");
		}
		if (vp->v_flag & VALIASED) {
			vx = NULL;
			for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
				if (vq->v_rdev != vp->v_rdev ||
				    vq->v_type != vp->v_type)
					continue;
				if (vx)
					break;
				vx = vq;
			}
			if (vx == NULL)
				panic("missing alias");
			if (vq == NULL)
				vx->v_flag &= ~VALIASED;
			vp->v_flag &= ~VALIASED;
		}
		simple_unlock(&spechash_slock);
		{
		struct specinfo *tmp = vp->v_specinfo;
		vp->v_specinfo = NULL;
		FREE_ZONE((void *)tmp, sizeof(struct specinfo), M_SPECINFO);
		}
	}
	/*
	 * If it is on the freelist and not already at the head,
	 * move it to the head of the list. The test of the back
	 * pointer and the reference count of zero is because
	 * it will be removed from the free list by getnewvnode,
	 * but will not have its reference count incremented until
	 * after calling vgone. If the reference count were
	 * incremented first, vgone would (incorrectly) try to
	 * close the previous instance of the underlying object.
	 * So, the back pointer is explicitly set to `0xdeadb' in
	 * getnewvnode after removing it from the freelist to ensure
	 * that we do not try to move it here.
	 */
	if (vp->v_usecount == 0 && (vp->v_flag & VUINACTIVE) == 0) {
		simple_lock(&vnode_free_list_slock);
		if ((vp->v_freelist.tqe_prev != (struct vnode **)0xdeadb) &&
		    vnode_free_list.tqh_first != vp) {
			TAILQ_REMOVE(&vnode_free_list, vp, v_freelist);
			TAILQ_INSERT_HEAD(&vnode_free_list, vp, v_freelist);
		}
		simple_unlock(&vnode_free_list_slock);
	}
	vp->v_type = VBAD;
}

/*
 * Lookup a vnode by device number.
 */
int
vfinddev(dev, type, vpp)
	dev_t dev;
	enum vtype type;
	struct vnode **vpp;
{
	struct vnode *vp;
	int rc = 0;

	simple_lock(&spechash_slock);
	for (vp = speclisth[SPECHASH(dev)]; vp; vp = vp->v_specnext) {
		if (dev != vp->v_rdev || type != vp->v_type)
			continue;
		*vpp = vp;
		rc = 1;
		break;
	}
	simple_unlock(&spechash_slock);
	return (rc);
}

/*
 * Calculate the total number of references to a special device.
 */
int
vcount(vp)
	struct vnode *vp;
{
	struct vnode *vq, *vnext;
	int count;

loop:
	if ((vp->v_flag & VALIASED) == 0)
		return (vp->v_usecount);
	simple_lock(&spechash_slock);
	for (count = 0, vq = *vp->v_hashchain; vq; vq = vnext) {
		vnext = vq->v_specnext;
		if (vq->v_rdev != vp->v_rdev || vq->v_type != vp->v_type)
			continue;
		/*
		 * Alias, but not in use, so flush it out.
		 */
		if (vq->v_usecount == 0 && vq != vp) {
			simple_unlock(&spechash_slock);
			vgone(vq);
			goto loop;
		}
		count += vq->v_usecount;
	}
	simple_unlock(&spechash_slock);
	return (count);
}

int	prtactive = 0;		/* 1 => print out reclaim of active vnodes */

/*
 * Print out a description of a vnode.
 */
static char *typename[] =
   { "VNON", "VREG", "VDIR", "VBLK", "VCHR", "VLNK", "VSOCK", "VFIFO", "VBAD" };

void
vprint(label, vp)
	char *label;
	register struct vnode *vp;
{
	char buf[64];

	if (label != NULL)
		printf("%s: ", label);
	printf("type %s, usecount %d, writecount %d, refcount %d,",
		typename[vp->v_type], vp->v_usecount, vp->v_writecount,
		vp->v_holdcnt);
	buf[0] = '\0';
	if (vp->v_flag & VROOT)
		strcat(buf, "|VROOT");
	if (vp->v_flag & VTEXT)
		strcat(buf, "|VTEXT");
	if (vp->v_flag & VSYSTEM)
		strcat(buf, "|VSYSTEM");
	if (vp->v_flag & VNOFLUSH)
		strcat(buf, "|VNOFLUSH");
	if (vp->v_flag & VXLOCK)
		strcat(buf, "|VXLOCK");
	if (vp->v_flag & VXWANT)
		strcat(buf, "|VXWANT");
	if (vp->v_flag & VBWAIT)
		strcat(buf, "|VBWAIT");
	if (vp->v_flag & VALIASED)
		strcat(buf, "|VALIASED");
	if (buf[0] != '\0')
		printf(" flags (%s)", &buf[1]);
	if (vp->v_data == NULL) {
		printf("\n");
	} else {
		printf("\n\t");
		VOP_PRINT(vp);
	}
}

#ifdef DEBUG
/*
 * List all of the locked vnodes in the system.
 * Called when debugging the kernel.
 */
void
printlockedvnodes()
{
	struct proc *p = current_proc();
	struct mount *mp, *nmp;
	struct vnode *vp;

	printf("Locked vnodes\n");
	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
		for (vp = mp->mnt_vnodelist.lh_first;
		     vp != NULL;
		     vp = vp->v_mntvnodes.le_next) {
			if (VOP_ISLOCKED(vp))
				vprint((char *)0, vp);
		}
		simple_lock(&mountlist_slock);
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);
}
#endif

static int
build_path(struct vnode *vp, char *buff, int buflen, int *outlen)
{
    char *end, *str;
    int   i, len, ret=0, counter=0;

    end = &buff[buflen-1];
    *--end = '\0';

    while(vp && VPARENT(vp) != vp) {
	// the maximum depth of a file system hierarchy is MAXPATHLEN/2
	// (with single-char names separated by slashes).  we panic if
	// we've ever looped more than that.
	if (counter++ > MAXPATHLEN/2) {
	    panic("build_path: vnode parent chain is too long! vp 0x%x\n", vp);
	}
	str = VNAME(vp);
	if (VNAME(vp) == NULL) {
	    if (VPARENT(vp) != NULL) {
		ret = EINVAL;
	    }
	    break;
	}
	
	// count how long the string is
	for(len=0; *str; str++, len++)
	    /* nothing */;

	// check that there's enough space
	if ((end - buff) < len) {
	    ret = ENOSPC;
	    break;
	}

	// copy it backwards
	for(; len > 0; len--) {
	    *--end = *--str;
	}

	// put in the path separator
	*--end = '/';

	// walk up the chain.  
	vp = VPARENT(vp);

	// check if we're crossing a mount point and
	// switch the vp if we are.
	if (vp && (vp->v_flag & VROOT)) {
	    vp = vp->v_mount->mnt_vnodecovered;
	}
    }

    // slide it down to the beginning of the buffer
    memmove(buff, end, &buff[buflen] - end);
    
    *outlen = &buff[buflen] - end;
 
    return ret;
}

__private_extern__ int
vn_getpath(struct vnode *vp, char *pathbuf, int *len)
{
    return build_path(vp, pathbuf, *len, len);
}



/*
 * Top level filesystem related information gathering.
 */
int
vfs_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	struct vfsconf *vfsp;
	int *username;
	u_int usernamelen;
	int error;

	/*
	 * The VFS_NUMMNTOPS shouldn't be at name[0] since
	 * is a VFS generic variable. So now we must check
	 * namelen so we don't end up covering any UFS
	 * variables (sinc UFS vfc_typenum is 1).
	 *
	 * It should have been:
	 *    name[0]:  VFS_GENERIC
	 *    name[1]:  VFS_NUMMNTOPS
	 */
	if (namelen == 1 && name[0] == VFS_NUMMNTOPS) {
		extern unsigned int vfs_nummntops;
		return (sysctl_rdint(oldp, oldlenp, newp, vfs_nummntops));
	}

	/* all sysctl names at this level are at least name and field */
	if (namelen < 2)
		return (EISDIR);		/* overloaded */
	if (name[0] != VFS_GENERIC) {
		for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
			if (vfsp->vfc_typenum == name[0])
				break;
		if (vfsp == NULL)
			return (EOPNOTSUPP);
		return ((*vfsp->vfc_vfsops->vfs_sysctl)(&name[1], namelen - 1,
		    oldp, oldlenp, newp, newlen, p));
	}
	switch (name[1]) {
	case VFS_MAXTYPENUM:
		return (sysctl_rdint(oldp, oldlenp, newp, maxvfsconf));
	case VFS_CONF:
		if (namelen < 3)
			return (ENOTDIR);	/* overloaded */
		for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
			if (vfsp->vfc_typenum == name[2])
				break;
		if (vfsp == NULL)
			return (EOPNOTSUPP);
		return (sysctl_rdstruct(oldp, oldlenp, newp, vfsp,
		    sizeof(struct vfsconf)));
	}
	/*
	 * We need to get back into the general MIB, so we need to re-prepend
	 * CTL_VFS to our name and try userland_sysctl().
	 */
	usernamelen = namelen + 1;
	MALLOC(username, int *, usernamelen * sizeof(*username),
	    M_TEMP, M_WAITOK);
	bcopy(name, username + 1, namelen * sizeof(*name));
	username[0] = CTL_VFS;
	error = userland_sysctl(p, username, usernamelen, oldp, oldlenp, 1,
	    newp, newlen, oldlenp);
	FREE(username, M_TEMP);
	return (error);
}

int kinfo_vdebug = 1;
#define KINFO_VNODESLOP	10
/*
 * Dump vnode list (via sysctl).
 * Copyout address of vnode followed by vnode.
 */
/* ARGSUSED */
int
sysctl_vnode(where, sizep, p)
	char *where;
	size_t *sizep;
	struct proc *p;
{
	struct mount *mp, *nmp;
	struct vnode *nvp, *vp;
	char *bp = where, *savebp;
	char *ewhere;
	int error;

#define VPTRSZ	sizeof (struct vnode *)
#define VNODESZ	sizeof (struct vnode)
	if (where == NULL) {
		*sizep = (numvnodes + KINFO_VNODESLOP) * (VPTRSZ + VNODESZ);
		return (0);
	}
	ewhere = where + *sizep;
		
	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
		savebp = bp;
again:
		simple_lock(&mntvnode_slock);
		for (vp = mp->mnt_vnodelist.lh_first;
		     vp != NULL;
		     vp = nvp) {
			/*
			 * Check that the vp is still associated with
			 * this filesystem.  RACE: could have been
			 * recycled onto the same filesystem.
			 */
			if (vp->v_mount != mp) {
				simple_unlock(&mntvnode_slock);
				if (kinfo_vdebug)
					printf("kinfo: vp changed\n");
				bp = savebp;
				goto again;
			}
			nvp = vp->v_mntvnodes.le_next;
			if (bp + VPTRSZ + VNODESZ > ewhere) {
				simple_unlock(&mntvnode_slock);
				vfs_unbusy(mp, p);
				*sizep = bp - where;
				return (ENOMEM);
			}
			simple_unlock(&mntvnode_slock);
			if ((error = copyout((caddr_t)&vp, bp, VPTRSZ)) ||
			    (error = copyout((caddr_t)vp, bp + VPTRSZ, VNODESZ))) {
				vfs_unbusy(mp, p);
				return (error);
			}
			bp += VPTRSZ + VNODESZ;
			simple_lock(&mntvnode_slock);
		}
		simple_unlock(&mntvnode_slock);
		simple_lock(&mountlist_slock);
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);

	*sizep = bp - where;
	return (0);
}

/*
 * Check to see if a filesystem is mounted on a block device.
 */
int
vfs_mountedon(vp)
	struct vnode *vp;
{
	struct vnode *vq;
	int error = 0;

	if (vp->v_specflags & SI_MOUNTEDON)
		return (EBUSY);
	if (vp->v_flag & VALIASED) {
		simple_lock(&spechash_slock);
		for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
			if (vq->v_rdev != vp->v_rdev ||
			    vq->v_type != vp->v_type)
				continue;
			if (vq->v_specflags & SI_MOUNTEDON) {
				error = EBUSY;
				break;
			}
		}
		simple_unlock(&spechash_slock);
	}
	return (error);
}

/*
 * Unmount all filesystems. The list is traversed in reverse order
 * of mounting to avoid dependencies.
 */
__private_extern__ void
vfs_unmountall()
{
	struct mount *mp, *nmp;
	struct proc *p = current_proc();

	/*
	 * Since this only runs when rebooting, it is not interlocked.
	 */
	for (mp = mountlist.cqh_last; mp != (void *)&mountlist; mp = nmp) {
		nmp = mp->mnt_list.cqe_prev;
		(void) dounmount(mp, MNT_FORCE, p);
	}
}

/*
 * Build hash lists of net addresses and hang them off the mount point.
 * Called by vfs_export() to set up the lists of export addresses.
 */
static int
vfs_hang_addrlist(mp, nep, argp)
	struct mount *mp;
	struct netexport *nep;
	struct export_args *argp;
{
	register struct netcred *np;
	register struct radix_node_head *rnh;
	register int i;
	struct radix_node *rn;
	struct sockaddr *saddr, *smask = 0;
	struct domain *dom;
	int error;

	if (argp->ex_addrlen == 0) {
		if (mp->mnt_flag & MNT_DEFEXPORTED)
			return (EPERM);
		np = &nep->ne_defexported;
		np->netc_exflags = argp->ex_flags;
		np->netc_anon = argp->ex_anon;
		np->netc_anon.cr_ref = 1;
		mp->mnt_flag |= MNT_DEFEXPORTED;
		return (0);
	}
	i = sizeof(struct netcred) + argp->ex_addrlen + argp->ex_masklen;
	MALLOC(np, struct netcred *, i, M_NETADDR, M_WAITOK);
	bzero((caddr_t)np, i);
	saddr = (struct sockaddr *)(np + 1);
	if (error = copyin(argp->ex_addr, (caddr_t)saddr, argp->ex_addrlen))
		goto out;
	if (saddr->sa_len > argp->ex_addrlen)
		saddr->sa_len = argp->ex_addrlen;
	if (argp->ex_masklen) {
		smask = (struct sockaddr *)((caddr_t)saddr + argp->ex_addrlen);
		error = copyin(argp->ex_addr, (caddr_t)smask, argp->ex_masklen);
		if (error)
			goto out;
		if (smask->sa_len > argp->ex_masklen)
			smask->sa_len = argp->ex_masklen;
	}
	i = saddr->sa_family;
	if ((rnh = nep->ne_rtable[i]) == 0) {
		/*
		 * Seems silly to initialize every AF when most are not
		 * used, do so on demand here
		 */
		for (dom = domains; dom; dom = dom->dom_next)
			if (dom->dom_family == i && dom->dom_rtattach) {
				dom->dom_rtattach((void **)&nep->ne_rtable[i],
					dom->dom_rtoffset);
				break;
			}
		if ((rnh = nep->ne_rtable[i]) == 0) {
			error = ENOBUFS;
			goto out;
		}
	}
	rn = (*rnh->rnh_addaddr)((caddr_t)saddr, (caddr_t)smask, rnh,
		np->netc_rnodes);
	if (rn == 0) {
		/*
		 * One of the reasons that rnh_addaddr may fail is that
		 * the entry already exists. To check for this case, we
		 * look up the entry to see if it is there. If so, we
		 * do not need to make a new entry but do return success.
		 */
		_FREE(np, M_NETADDR);
		rn = (*rnh->rnh_matchaddr)((caddr_t)saddr, rnh);
		if (rn != 0 && (rn->rn_flags & RNF_ROOT) == 0 &&
		    ((struct netcred *)rn)->netc_exflags == argp->ex_flags &&
		    !bcmp((caddr_t)&((struct netcred *)rn)->netc_anon,
			    (caddr_t)&argp->ex_anon, sizeof(struct ucred)))
			return (0);
		return (EPERM);
	}
	np->netc_exflags = argp->ex_flags;
	np->netc_anon = argp->ex_anon;
	np->netc_anon.cr_ref = 1;
	return (0);
out:
	_FREE(np, M_NETADDR);
	return (error);
}

/* ARGSUSED */
static int
vfs_free_netcred(rn, w)
	struct radix_node *rn;
	caddr_t w;
{
	register struct radix_node_head *rnh = (struct radix_node_head *)w;

	(*rnh->rnh_deladdr)(rn->rn_key, rn->rn_mask, rnh);
	_FREE((caddr_t)rn, M_NETADDR);
	return (0);
}

/*
 * Free the net address hash lists that are hanging off the mount points.
 */
static void
vfs_free_addrlist(nep)
	struct netexport *nep;
{
	register int i;
	register struct radix_node_head *rnh;

	for (i = 0; i <= AF_MAX; i++)
		if (rnh = nep->ne_rtable[i]) {
			(*rnh->rnh_walktree)(rnh, vfs_free_netcred,
			    (caddr_t)rnh);
			_FREE((caddr_t)rnh, M_RTABLE);
			nep->ne_rtable[i] = 0;
		}
}

int
vfs_export(mp, nep, argp)
	struct mount *mp;
	struct netexport *nep;
	struct export_args *argp;
{
	int error;

	if (argp->ex_flags & MNT_DELEXPORT) {
		vfs_free_addrlist(nep);
		mp->mnt_flag &= ~(MNT_EXPORTED | MNT_DEFEXPORTED);
	}
	if (argp->ex_flags & MNT_EXPORTED) {
		if (error = vfs_hang_addrlist(mp, nep, argp))
			return (error);
		mp->mnt_flag |= MNT_EXPORTED;
	}
	return (0);
}

struct netcred *
vfs_export_lookup(mp, nep, nam)
	register struct mount *mp;
	struct netexport *nep;
	struct mbuf *nam;
{
	register struct netcred *np;
	register struct radix_node_head *rnh;
	struct sockaddr *saddr;

	np = NULL;
	if (mp->mnt_flag & MNT_EXPORTED) {
		/*
		 * Lookup in the export list first.
		 */
		if (nam != NULL) {
			saddr = mtod(nam, struct sockaddr *);
			rnh = nep->ne_rtable[saddr->sa_family];
			if (rnh != NULL) {
				np = (struct netcred *)
					(*rnh->rnh_matchaddr)((caddr_t)saddr,
							      rnh);
				if (np && np->netc_rnodes->rn_flags & RNF_ROOT)
					np = NULL;
			}
		}
		/*
		 * If no address match, use the default if it exists.
		 */
		if (np == NULL && mp->mnt_flag & MNT_DEFEXPORTED)
			np = &nep->ne_defexported;
	}
	return (np);
}

/*
 * try to reclaim vnodes from the memory 
 * object cache
 */
static int
vm_object_cache_reclaim(int count)
{
	int cnt;
	void vnode_pager_release_from_cache(int *);

	/* attempt to reclaim vnodes from VM object cache */
	cnt = count;
	vnode_pager_release_from_cache(&cnt);
	return(cnt);
}

/*
 * Release memory object reference held by inactive vnodes
 * and then try to reclaim some vnodes from the memory 
 * object cache
 */
static int
vnreclaim(int count)
{
	int i, loopcnt;
	struct vnode *vp;
	int err;
	struct proc *p;

	i = 0;
	loopcnt = 0;

	/* Try to release "count" vnodes from the inactive list */
restart:
	if (++loopcnt > inactivevnodes) {
		/*
		 * I did my best trying to reclaim the vnodes.
		 * Do not try any more as that would only lead to 
		 * long latencies. Also in the worst case 
		 * this can get totally CPU bound.
		 * Just fall though and attempt a reclaim of VM
		 * object cache
		 */
		goto out;
	}

	simple_lock(&vnode_free_list_slock);
	for (vp = TAILQ_FIRST(&vnode_inactive_list);
			(vp != NULLVP) && (i < count);
			vp = TAILQ_NEXT(vp, v_freelist)) {
		
		if (!simple_lock_try(&vp->v_interlock))
			continue;

		if (vp->v_usecount != 1)
			panic("vnreclaim: v_usecount");

		if(!UBCINFOEXISTS(vp)) {
			if (vp->v_type == VBAD) {
				VREMINACTIVE("vnreclaim", vp);
				simple_unlock(&vp->v_interlock);
				continue;
			} else
				panic("non UBC vnode on inactive list");
				/* Should not reach here */
		}

		/* If vnode is already being reclaimed, wait */
		if ((vp->v_flag & VXLOCK) || (vp->v_flag & VORECLAIM)) {
			vp->v_flag |= VXWANT;
			simple_unlock(&vp->v_interlock);
			simple_unlock(&vnode_free_list_slock);
			(void)tsleep((caddr_t)vp, PINOD, "vocr", 0);
			goto restart;
		}

		/*
		 * if the vnode is being initialized,
		 * skip over it
		 */
		if (ISSET(vp->v_flag,  VUINIT)) {
			SET(vp->v_flag, VUWANT);
			simple_unlock(&vp->v_interlock);
			continue;
		}

		VREMINACTIVE("vnreclaim", vp);
		simple_unlock(&vnode_free_list_slock);

		if (ubc_issetflags(vp, UI_WASMAPPED)) {
			/*
			 * We should not reclaim as it is likely
			 * to be in use. Let it die a natural death.
			 * Release the UBC reference if one exists
			 * and put it back at the tail.
			 */
			simple_unlock(&vp->v_interlock);
			if (ubc_release_named(vp)) {
				if (UBCINFOEXISTS(vp)) {
					simple_lock(&vp->v_interlock);
					if (vp->v_usecount == 1 && !VONLIST(vp))
						vinactive(vp);
					simple_unlock(&vp->v_interlock);
				}
			} else {
			    simple_lock(&vp->v_interlock);
				vinactive(vp);
				simple_unlock(&vp->v_interlock);
			}
		} else {
			int didhold;

			VORECLAIM_ENABLE(vp);

			/*
			 * scrub the dirty pages and invalidate the buffers
			 */
			p = current_proc();
			err = vn_lock(vp, LK_EXCLUSIVE|LK_INTERLOCK, p); 
			if (err) {
				/* cannot reclaim */
				simple_lock(&vp->v_interlock);
				vinactive(vp);
				VORECLAIM_DISABLE(vp);
				i++;
				simple_unlock(&vp->v_interlock);
				goto restart;
			}

			/* keep the vnode alive so we can kill it */
			simple_lock(&vp->v_interlock);
			if(vp->v_usecount != 1)
				panic("VOCR: usecount race");
			vp->v_usecount++;
			simple_unlock(&vp->v_interlock);

			/* clean up the state in VM without invalidating */
			didhold = ubc_hold(vp);
			if (didhold)
				(void)ubc_clean(vp, 0);

			/* flush and invalidate buffers associated with the vnode */
			if (vp->v_tag == VT_NFS)
				nfs_vinvalbuf(vp, V_SAVE, NOCRED, p, 0);
			else
				vinvalbuf(vp, V_SAVE, NOCRED, p, 0, 0);

			/*
			 * Note: for the v_usecount == 2 case, VOP_INACTIVE
			 * has not yet been called.  Call it now while vp is
			 * still locked, it will also release the lock.
			 */
			if (vp->v_usecount == 2)
				VOP_INACTIVE(vp, p);
			else
				VOP_UNLOCK(vp, 0, p);

			if (didhold)
				ubc_rele(vp);

			/*
			 * destroy the ubc named reference.
			 * If we can't because it is held for I/Os
			 * in progress, just put it back on the inactive
			 * list and move on.  Otherwise, the paging reference
			 * is toast (and so is this vnode?).
			 */
			if (ubc_destroy_named(vp)) {
			    i++;
			}
			simple_lock(&vp->v_interlock);
			VORECLAIM_DISABLE(vp);
			simple_unlock(&vp->v_interlock);
			vrele(vp);  /* release extra use we added here */
		}
		/* inactive list lock was released, must restart */
		goto restart;
	}
	simple_unlock(&vnode_free_list_slock);

	vnode_reclaim_tried += i;
out:
	i = vm_object_cache_reclaim(count);
	vnode_objects_reclaimed += i;

	return(i);
}

/*  
 * This routine is called from vnode_pager_no_senders()
 * which in turn can be called with vnode locked by vnode_uncache()
 * But it could also get called as a result of vm_object_cache_trim().
 * In that case lock state is unknown.
 * AGE the vnode so that it gets recycled quickly.
 * Check lock status to decide whether to call vput() or vrele().
 */
__private_extern__ void
vnode_pager_vrele(struct vnode *vp)
{

	boolean_t 	funnel_state;
	int isvnreclaim = 1;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	/* Mark the vnode to be recycled */
	vagevp(vp);

	simple_lock(&vp->v_interlock);
	/*
	 * If a vgone (or vclean) is already in progress,
	 * Do not bother with the ubc_info cleanup.
	 * Let the vclean deal with it.
	 */
	if (vp->v_flag & VXLOCK) {
		CLR(vp->v_flag, VTERMINATE);
		if (ISSET(vp->v_flag, VTERMWANT)) {
			CLR(vp->v_flag, VTERMWANT);
			wakeup((caddr_t)&vp->v_ubcinfo);
		}
		simple_unlock(&vp->v_interlock);
		vrele(vp);
		(void) thread_funnel_set(kernel_flock, funnel_state);
		return;
	}

	/* It's dead, Jim! */
	if (!ISSET(vp->v_flag, VORECLAIM)) {
		/*
		 * called as a result of eviction of the memory
		 * object from the memory object cache
		 */
		isvnreclaim = 0;

		/* So serialize vnode operations */
		VORECLAIM_ENABLE(vp);
	}
	if (!ISSET(vp->v_flag, VTERMINATE))
		SET(vp->v_flag, VTERMINATE);

	cache_purge(vp);

	if (UBCINFOEXISTS(vp)) {
		struct ubc_info *uip = vp->v_ubcinfo;

		if (ubc_issetflags(vp, UI_WASMAPPED))
			SET(vp->v_flag, VWASMAPPED);

		vp->v_ubcinfo = UBC_NOINFO;  /* catch bad accesses */
		simple_unlock(&vp->v_interlock);
		ubc_info_deallocate(uip);
	} else {
		if ((vp->v_type == VBAD) && ((vp)->v_ubcinfo != UBC_INFO_NULL) 
			&& ((vp)->v_ubcinfo != UBC_NOINFO)) {
			struct ubc_info *uip = vp->v_ubcinfo;

			vp->v_ubcinfo = UBC_NOINFO;  /* catch bad accesses */
			simple_unlock(&vp->v_interlock);
			ubc_info_deallocate(uip);
		} else {
			simple_unlock(&vp->v_interlock);
		}
	}

	CLR(vp->v_flag, VTERMINATE);

	if (vp->v_type != VBAD){
		vgone(vp);	/* revoke the vnode */
		vrele(vp);	/* and drop the reference */
	} else
		vrele(vp);

	if (ISSET(vp->v_flag, VTERMWANT)) {
		CLR(vp->v_flag, VTERMWANT);
		wakeup((caddr_t)&vp->v_ubcinfo);
	}
	if (!isvnreclaim)
		VORECLAIM_DISABLE(vp);
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return;
}


#if DIAGNOSTIC
int walk_vnodes_debug=0;

void
walk_allvnodes()
{
	struct mount *mp, *nmp;
	struct vnode *vp;
	int cnt = 0;

	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		for (vp = mp->mnt_vnodelist.lh_first;
		     vp != NULL;
		     vp = vp->v_mntvnodes.le_next) {
			if (vp->v_usecount < 0){
				if(walk_vnodes_debug) {
					printf("vp is %x\n",vp);
				}
			}
		}
		nmp = mp->mnt_list.cqe_next;
	}
	for (cnt = 0, vp = vnode_free_list.tqh_first;
		vp != NULLVP; cnt++, vp = vp->v_freelist.tqe_next) {
		if ((vp->v_usecount < 0) && walk_vnodes_debug) {
			if(walk_vnodes_debug) {
				printf("vp is %x\n",vp);
			}
		}
	}
	printf("%d - free\n", cnt);

	for (cnt = 0, vp = vnode_inactive_list.tqh_first;
		vp != NULLVP; cnt++, vp = vp->v_freelist.tqe_next) {
		if ((vp->v_usecount < 0) && walk_vnodes_debug) {
			if(walk_vnodes_debug) {
				printf("vp is %x\n",vp);
			}
		}
	}
	printf("%d - inactive\n", cnt);
}
#endif /* DIAGNOSTIC */


struct x_constraints {
        u_int32_t x_maxreadcnt;
        u_int32_t x_maxsegreadsize;
        u_int32_t x_maxsegwritesize;
};


void
vfs_io_attributes(vp, flags, iosize, vectors)
	struct vnode	*vp;
	int	flags;	/* B_READ or B_WRITE */
	int	*iosize;
	int	*vectors;
{
	struct mount *mp;

	/* start with "reasonable" defaults */
	*iosize = MAXPHYS;
	*vectors = 32;

	mp = vp->v_mount;
	if (mp != NULL) {
		switch (flags) {
		case B_READ:
		        if (mp->mnt_kern_flag & MNTK_IO_XINFO)
			        *iosize = ((struct x_constraints *)(mp->mnt_xinfo_ptr))->x_maxreadcnt;
			else
			        *iosize = mp->mnt_maxreadcnt;
			*vectors = mp->mnt_segreadcnt;
			break;
		case B_WRITE:
			*iosize = mp->mnt_maxwritecnt;
			*vectors = mp->mnt_segwritecnt;
			break;
		default:
			break;
		}
		if (*iosize == 0)
		        *iosize = MAXPHYS;
		if (*vectors == 0)
		        *vectors = 32;
	}
	return;
}

__private_extern__
void
vfs_io_maxsegsize(vp, flags, maxsegsize)
	struct vnode	*vp;
	int	flags;	/* B_READ or B_WRITE */
	int	*maxsegsize;
{
	struct mount *mp;

	/* start with "reasonable" default */
	*maxsegsize = MAXPHYS;

	mp = vp->v_mount;
	if (mp != NULL) {
		switch (flags) {
		case B_READ:
		        if (mp->mnt_kern_flag & MNTK_IO_XINFO)
			        *maxsegsize = ((struct x_constraints *)(mp->mnt_xinfo_ptr))->x_maxsegreadsize;
			else
			        /*
				 * if the extended info doesn't exist
				 * then use the maxread I/O size as the 
				 * max segment size... this is the previous behavior
				 */
			        *maxsegsize = mp->mnt_maxreadcnt;
			break;
		case B_WRITE:
		        if (mp->mnt_kern_flag & MNTK_IO_XINFO)
			        *maxsegsize = ((struct x_constraints *)(mp->mnt_xinfo_ptr))->x_maxsegwritesize;
			else
			        /*
				 * if the extended info doesn't exist
				 * then use the maxwrite I/O size as the 
				 * max segment size... this is the previous behavior
				 */
			        *maxsegsize = mp->mnt_maxwritecnt;
			break;
		default:
			break;
		}
		if (*maxsegsize == 0)
		        *maxsegsize = MAXPHYS;
	}
}


#include <sys/disk.h>


int
vfs_init_io_attributes(devvp, mp)
	struct vnode *devvp;
	struct mount *mp;
{
	int error;
	off_t readblockcnt;
	off_t writeblockcnt;
	off_t readmaxcnt;
	off_t writemaxcnt;
	off_t readsegcnt;
	off_t writesegcnt;
	off_t readsegsize;
	off_t writesegsize;
	u_long blksize;

	u_int64_t temp;

	struct proc *p = current_proc();
	struct  ucred *cred = p->p_ucred;

	int isvirtual = 0;
	/*
	 * determine if this mount point exists on the same device as the root
	 * partition... if so, then it comes under the hard throttle control
	 */
	int        thisunit = -1;
	static int rootunit = -1;
	extern struct vnode *rootvp;

	if (rootunit == -1) {
	        if (VOP_IOCTL(rootvp, DKIOCGETBSDUNIT, (caddr_t)&rootunit, 0, cred, p))
		        rootunit = -1; 
		else if (rootvp == devvp)
		        mp->mnt_kern_flag |= MNTK_ROOTDEV;
	}
	if (devvp != rootvp && rootunit != -1) {
	        if (VOP_IOCTL(devvp, DKIOCGETBSDUNIT, (caddr_t)&thisunit, 0, cred, p) == 0) {
		        if (thisunit == rootunit)
			        mp->mnt_kern_flag |= MNTK_ROOTDEV;
		}
	}
	if (VOP_IOCTL(devvp, DKIOCGETISVIRTUAL, (caddr_t)&isvirtual, 0, cred, p) == 0) {
	        if (isvirtual)
		        mp->mnt_kern_flag |= MNTK_VIRTUALDEV;
	}

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXBLOCKCOUNTREAD,
				(caddr_t)&readblockcnt, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXBLOCKCOUNTWRITE,
				(caddr_t)&writeblockcnt, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXBYTECOUNTREAD,
				(caddr_t)&readmaxcnt, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXBYTECOUNTWRITE,
				(caddr_t)&writemaxcnt, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXSEGMENTCOUNTREAD,
				(caddr_t)&readsegcnt, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXSEGMENTCOUNTWRITE,
				(caddr_t)&writesegcnt, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXSEGMENTBYTECOUNTREAD,
				(caddr_t)&readsegsize, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETMAXSEGMENTBYTECOUNTWRITE,
				(caddr_t)&writesegsize, 0, cred, p)))
		return (error);

	if ((error = VOP_IOCTL(devvp, DKIOCGETBLOCKSIZE,
				(caddr_t)&blksize, 0, cred, p)))
		return (error);


        if ( !(mp->mnt_kern_flag & MNTK_IO_XINFO)) {
		MALLOC(mp->mnt_xinfo_ptr, void *, sizeof(struct x_constraints), M_TEMP, M_WAITOK);
	        mp->mnt_kern_flag |= MNTK_IO_XINFO;
	}

	if (readmaxcnt)
	        temp = (readmaxcnt > UINT32_MAX) ? UINT32_MAX : readmaxcnt;
	else {
	        if (readblockcnt) {
		        temp = readblockcnt * blksize;
			temp = (temp > UINT32_MAX) ? UINT32_MAX : temp;
		} else
		        temp = MAXPHYS;
	}
	((struct x_constraints *)(mp->mnt_xinfo_ptr))->x_maxreadcnt = (u_int32_t)temp;

	if (writemaxcnt)
	        temp = (writemaxcnt > UINT32_MAX) ? UINT32_MAX : writemaxcnt;
	else {
	        if (writeblockcnt) {
		        temp = writeblockcnt * blksize;
			temp = (temp > UINT32_MAX) ? UINT32_MAX : temp;
		} else
		        temp = MAXPHYS;
	}
	mp->mnt_maxwritecnt = (u_int32_t)temp;

	if (readsegcnt) {
	        temp = (readsegcnt > UINT16_MAX) ? UINT16_MAX : readsegcnt;
		mp->mnt_segreadcnt = (u_int16_t)temp;
	}
	if (writesegcnt) {
	        temp = (writesegcnt > UINT16_MAX) ? UINT16_MAX : writesegcnt;
		mp->mnt_segwritecnt = (u_int16_t)temp;
	}
	if (readsegsize)
	        temp = (readsegsize > UINT32_MAX) ? UINT32_MAX : readsegsize;
	else
	        temp = mp->mnt_maxreadcnt;
	((struct x_constraints *)(mp->mnt_xinfo_ptr))->x_maxsegreadsize = (u_int32_t)temp;

	if (writesegsize)
	        temp = (writesegsize > UINT32_MAX) ? UINT32_MAX : writesegsize;
	else
	        temp = mp->mnt_maxwritecnt;
	((struct x_constraints *)(mp->mnt_xinfo_ptr))->x_maxsegwritesize = (u_int32_t)temp;

	return (error);
}

static struct klist fs_klist;

void
vfs_event_init(void)
{

	klist_init(&fs_klist);
}

void
vfs_event_signal(fsid_t *fsid, u_int32_t event, intptr_t data)
{

	KNOTE(&fs_klist, event);
}

/*
 * return the number of mounted filesystems.
 */
static int
sysctl_vfs_getvfscnt(void)
{
	struct mount *mp;
	int ret = 0;

	simple_lock(&mountlist_slock);
	CIRCLEQ_FOREACH(mp, &mountlist, mnt_list)
	    ret++;
	simple_unlock(&mountlist_slock);
	return (ret);
}

/*
 * fill in the array of fsid_t's up to a max of 'count', the actual
 * number filled in will be set in '*actual'.  If there are more fsid_t's
 * than room in fsidlst then ENOMEM will be returned and '*actual' will
 * have the actual count.
 * having *actual filled out even in the error case is depended upon.
 */
static int
sysctl_vfs_getvfslist(fsid_t *fsidlst, int count, int *actual)
{
	struct mount *mp;

	*actual = 0;
	simple_lock(&mountlist_slock);
	CIRCLEQ_FOREACH(mp, &mountlist, mnt_list) {
		(*actual)++;
		if (*actual <= count)
			fsidlst[(*actual) - 1] = mp->mnt_stat.f_fsid;
	}
	simple_unlock(&mountlist_slock);
	return (*actual <= count ? 0 : ENOMEM);
}

static int
sysctl_vfs_vfslist SYSCTL_HANDLER_ARGS
{
	int actual, error;
	size_t space;
	fsid_t *fsidlst;

	/* This is a readonly node. */
	if (req->newptr != NULL)
		return (EPERM);

	/* they are querying us so just return the space required. */
	if (req->oldptr == NULL) {
		req->oldidx = sysctl_vfs_getvfscnt() * sizeof(fsid_t);
		return 0;
	}
again:
	/*
	 * Retrieve an accurate count of the amount of space required to copy
	 * out all the fsids in the system.
	 */
	space = req->oldlen;
	req->oldlen = sysctl_vfs_getvfscnt() * sizeof(fsid_t);

	/* they didn't give us enough space. */
	if (space < req->oldlen)
		return (ENOMEM);

	MALLOC(fsidlst, fsid_t *, req->oldlen, M_TEMP, M_WAITOK);
	error = sysctl_vfs_getvfslist(fsidlst, req->oldlen / sizeof(fsid_t),
	    &actual);
	/*
	 * If we get back ENOMEM, then another mount has been added while we
	 * slept in malloc above.  If this is the case then try again.
	 */
	if (error == ENOMEM) {
		FREE(fsidlst, M_TEMP);
		req->oldlen = space;
		goto again;
	}
	if (error == 0) {
		error = SYSCTL_OUT(req, fsidlst, actual * sizeof(fsid_t));
	}
	FREE(fsidlst, M_TEMP);
	return (error);
}

/*
 * Do a sysctl by fsid.
 */
static int
sysctl_vfs_ctlbyfsid SYSCTL_HANDLER_ARGS
{
	struct vfsidctl vc;
	struct mount *mp;
	struct statfs *sp;
	struct proc *p;
	int *name;
	int error, flags, namelen;

	name = arg1;
	namelen = arg2;
	p = req->p;

	error = SYSCTL_IN(req, &vc, sizeof(vc));
	if (error)
		return (error);
	if (vc.vc_vers != VFS_CTL_VERS1)
		return (EINVAL);
	mp = vfs_getvfs(&vc.vc_fsid);
	if (mp == NULL)
		return (ENOENT);
	/* reset so that the fs specific code can fetch it. */
	req->newidx = 0;
	/*
	 * Note if this is a VFS_CTL then we pass the actual sysctl req
	 * in for "oldp" so that the lower layer can DTRT and use the
	 * SYSCTL_IN/OUT routines.
	 */
	if (mp->mnt_op->vfs_sysctl != NULL) {
		error = mp->mnt_op->vfs_sysctl(name, namelen,
		    req, NULL, NULL, 0, req->p);
		if (error != EOPNOTSUPP)
			return (error);
	}
	switch (name[0]) {
	case VFS_CTL_UMOUNT:
		VCTLTOREQ(&vc, req);
		error = SYSCTL_IN(req, &flags, sizeof(flags));
		if (error)
			break;
		error = safedounmount(mp, flags, p);
		break;
	case VFS_CTL_STATFS:
		VCTLTOREQ(&vc, req);
		error = SYSCTL_IN(req, &flags, sizeof(flags));
		if (error)
			break;
		sp = &mp->mnt_stat;
		if (((flags & MNT_NOWAIT) == 0 || (flags & MNT_WAIT)) &&
		    (error = VFS_STATFS(mp, sp, p)))
			return (error);
		sp->f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
		error = SYSCTL_OUT(req, sp, sizeof(*sp));
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (error);
}

static int	filt_fsattach(struct knote *kn);
static void	filt_fsdetach(struct knote *kn);
static int	filt_fsevent(struct knote *kn, long hint);

struct filterops fs_filtops =
	{ 0, filt_fsattach, filt_fsdetach, filt_fsevent };

static int
filt_fsattach(struct knote *kn)
{

	kn->kn_flags |= EV_CLEAR;
	KNOTE_ATTACH(&fs_klist, kn);
	return (0);
}

static void
filt_fsdetach(struct knote *kn)
{

	KNOTE_DETACH(&fs_klist, kn);
}

static int
filt_fsevent(struct knote *kn, long hint)
{

	kn->kn_fflags |= hint;
	return (kn->kn_fflags != 0);
}

static int
sysctl_vfs_noremotehang SYSCTL_HANDLER_ARGS
{
	int out, error;
	pid_t pid;
	size_t space;
	struct proc *p;

	/* We need a pid. */
	if (req->newptr == NULL)
		return (EINVAL);

	error = SYSCTL_IN(req, &pid, sizeof(pid));
	if (error)
		return (error);

	p = pfind(pid < 0 ? -pid : pid);
	if (p == NULL)
		return (ESRCH);

	/*
	 * Fetching the value is ok, but we only fetch if the old
	 * pointer is given.
	 */
	if (req->oldptr != NULL) {
		out = !((p->p_flag & P_NOREMOTEHANG) == 0);
		error = SYSCTL_OUT(req, &out, sizeof(out));
		return (error);
	}

	/* cansignal offers us enough security. */
	if (p != req->p && suser(req->p->p_ucred, &req->p->p_acflag) != 0)
		return (EPERM);

	if (pid < 0)
		p->p_flag &= ~P_NOREMOTEHANG;
	else
		p->p_flag |= P_NOREMOTEHANG;

	return (0);
}
/* the vfs.generic. branch. */
SYSCTL_NODE(_vfs, VFS_GENERIC, generic, CTLFLAG_RW, 0, "vfs generic hinge");
/* retreive a list of mounted filesystem fsid_t */
SYSCTL_PROC(_vfs_generic, OID_AUTO, vfsidlist, CTLFLAG_RD,
    0, 0, sysctl_vfs_vfslist, "S,fsid", "List of mounted filesystem ids");
/* perform operations on filesystem via fsid_t */
SYSCTL_NODE(_vfs_generic, OID_AUTO, ctlbyfsid, CTLFLAG_RW,
    sysctl_vfs_ctlbyfsid, "ctlbyfsid");
SYSCTL_PROC(_vfs_generic, OID_AUTO, noremotehang, CTLFLAG_RW,
    0, 0, sysctl_vfs_noremotehang, "I", "noremotehang");

