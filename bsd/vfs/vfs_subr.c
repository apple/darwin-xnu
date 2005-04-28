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
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/time.h>
#include <sys/lock.h>
#include <sys/vnode_internal.h>
#include <sys/stat.h>
#include <sys/namei.h>
#include <sys/ucred.h>
#include <sys/buf_internal.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/ubc_internal.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/filedesc.h>
#include <sys/event.h>
#include <sys/kdebug.h>
#include <sys/kauth.h>
#include <sys/user.h>
#include <miscfs/fifofs/fifo.h>

#include <string.h>
#include <machine/spl.h>


#include <kern/assert.h>

#include <miscfs/specfs/specdev.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>

extern lck_grp_t *vnode_lck_grp;
extern lck_attr_t *vnode_lck_attr;


extern lck_mtx_t * mnt_list_mtx_lock;

enum vtype iftovt_tab[16] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};
int	vttoif_tab[9] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK,
	S_IFSOCK, S_IFIFO, S_IFMT,
};

extern int ubc_isinuse_locked(vnode_t, int, int);
extern kern_return_t adjust_vm_object_cache(vm_size_t oval, vm_size_t nval);

static void vnode_list_add(vnode_t);
static void vnode_list_remove(vnode_t);

static errno_t vnode_drain(vnode_t);
static void vgone(vnode_t);
static void vclean(vnode_t vp, int flag, proc_t p);
static void vnode_reclaim_internal(vnode_t, int, int);

static void vnode_dropiocount (vnode_t, int);
static errno_t vnode_getiocount(vnode_t vp, int locked, int vid, int vflags);
static int vget_internal(vnode_t, int, int);

static vnode_t checkalias(vnode_t vp, dev_t nvp_rdev);
static int  vnode_reload(vnode_t);
static int  vnode_isinuse_locked(vnode_t, int, int);

static void insmntque(vnode_t vp, mount_t mp);
mount_t mount_list_lookupby_fsid(fsid_t *, int, int);
static int mount_getvfscnt(void);
static int mount_fillfsids(fsid_t *, int );
static void vnode_iterate_setup(mount_t);
static int vnode_umount_preflight(mount_t, vnode_t, int);
static int vnode_iterate_prepare(mount_t);
static int vnode_iterate_reloadq(mount_t);
static void vnode_iterate_clear(mount_t);

TAILQ_HEAD(freelst, vnode) vnode_free_list;	/* vnode free list */
TAILQ_HEAD(inactivelst, vnode) vnode_inactive_list;	/* vnode inactive list */
struct mntlist mountlist;			/* mounted filesystem list */
static int nummounts = 0;

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

/*
 * Have to declare first two locks as actual data even if !MACH_SLOCKS, since
 * a pointers to them get passed around.
 */
void * mntvnode_slock;
void * mntid_slock;
void * spechash_slock;

/*
 * vnodetarget is the amount of vnodes we expect to get back 
 * from the the inactive vnode list and VM object cache.
 * As vnreclaim() is a mainly cpu bound operation for faster 
 * processers this number could be higher.
 * Having this number too high introduces longer delays in 
 * the execution of new_vnode().
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
vntblinit(void)
{
	TAILQ_INIT(&vnode_free_list);
	TAILQ_INIT(&vnode_inactive_list);
	TAILQ_INIT(&mountlist);

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


/* the timeout is in 10 msecs */
int
vnode_waitforwrites(vnode_t vp, int output_target, int slpflag, int slptimeout, char *msg) {
        int error = 0;
	struct timespec ts;

	KERNEL_DEBUG(0x3010280 | DBG_FUNC_START, (int)vp, output_target, vp->v_numoutput, 0, 0);

	if (vp->v_numoutput > output_target) {

	        slpflag &= ~PDROP;

	        vnode_lock(vp);

		while ((vp->v_numoutput > output_target) && error == 0) {
		        if (output_target)
			        vp->v_flag |= VTHROTTLED;
			else
			        vp->v_flag |= VBWAIT;
			ts.tv_sec = (slptimeout/100);
			ts.tv_nsec = (slptimeout % 1000)  * 10 * NSEC_PER_USEC * 1000 ;
			error = msleep((caddr_t)&vp->v_numoutput, &vp->v_lock, (slpflag | (PRIBIO + 1)), msg, &ts);
		}
		vnode_unlock(vp);
	}
	KERNEL_DEBUG(0x3010280 | DBG_FUNC_END, (int)vp, output_target, vp->v_numoutput, error, 0);

	return error;
}


void
vnode_startwrite(vnode_t vp) {

        OSAddAtomic(1, &vp->v_numoutput);
}


void
vnode_writedone(vnode_t vp)
{
	if (vp) {
	        int need_wakeup = 0;
	  
	        OSAddAtomic(-1, &vp->v_numoutput);

		vnode_lock(vp);

		if (vp->v_numoutput < 0)
			panic("vnode_writedone: numoutput < 0");

		if ((vp->v_flag & VTHROTTLED) && (vp->v_numoutput < (VNODE_ASYNC_THROTTLE / 3))) {
			vp->v_flag &= ~VTHROTTLED;
			need_wakeup = 1;
		}
		if ((vp->v_flag & VBWAIT) && (vp->v_numoutput == 0)) {
		        vp->v_flag &= ~VBWAIT;
			need_wakeup = 1;
		}
		vnode_unlock(vp);
		
		if (need_wakeup)
		        wakeup((caddr_t)&vp->v_numoutput);
	}
}



int
vnode_hasdirtyblks(vnode_t vp)
{
        struct cl_writebehind *wbp;

	/*
	 * Not taking the buf_mtxp as there is little
	 * point doing it. Even if the lock is taken the
	 * state can change right after that. If their 
	 * needs to be a synchronization, it must be driven
	 * by the caller
	 */ 
        if (vp->v_dirtyblkhd.lh_first)
	        return (1);
	
	if (!UBCINFOEXISTS(vp))
	        return (0);

	wbp = vp->v_ubcinfo->cl_wbehind;

	if (wbp && (wbp->cl_number || wbp->cl_scmap))
	        return (1);

	return (0);
}

int
vnode_hascleanblks(vnode_t vp)
{
	/*
	 * Not taking the buf_mtxp as there is little
	 * point doing it. Even if the lock is taken the
	 * state can change right after that. If their 
	 * needs to be a synchronization, it must be driven
	 * by the caller
	 */ 
        if (vp->v_cleanblkhd.lh_first)
	        return (1);
	return (0);
}

void
vnode_iterate_setup(mount_t mp)
{
	while (mp->mnt_lflag & MNT_LITER) {
		mp->mnt_lflag |= MNT_LITERWAIT;
		msleep((caddr_t)mp, &mp->mnt_mlock, PVFS, "vnode_iterate_setup", 0);	
	}

	mp->mnt_lflag |= MNT_LITER;

}

static int
vnode_umount_preflight(mount_t mp, vnode_t skipvp, int flags)
{
	vnode_t vp;

	TAILQ_FOREACH(vp, &mp->mnt_vnodelist, v_mntvnodes) {
	        if (vp->v_type == VDIR)
		        continue;
		if (vp == skipvp)
			continue;
		if ((flags & SKIPSYSTEM) && ((vp->v_flag & VSYSTEM) ||
            (vp->v_flag & VNOFLUSH)))
			continue;
		if ((flags & SKIPSWAP) && (vp->v_flag & VSWAP))
			continue;
		if ((flags & WRITECLOSE) &&
            (vp->v_writecount == 0 || vp->v_type != VREG)) 
			continue;
		/* Look for busy vnode */
        if (((vp->v_usecount != 0) &&
            ((vp->v_usecount - vp->v_kusecount) != 0))) 
			return(1);
		}
	
	return(0);
}

/* 
 * This routine prepares iteration by moving all the vnodes to worker queue
 * called with mount lock held
 */
int
vnode_iterate_prepare(mount_t mp)
{
	vnode_t vp;

	if (TAILQ_EMPTY(&mp->mnt_vnodelist)) {
		/* nothing to do */
		return (0);
	} 

	vp = TAILQ_FIRST(&mp->mnt_vnodelist);
	vp->v_mntvnodes.tqe_prev = &(mp->mnt_workerqueue.tqh_first);
	mp->mnt_workerqueue.tqh_first = mp->mnt_vnodelist.tqh_first;
	mp->mnt_workerqueue.tqh_last = mp->mnt_vnodelist.tqh_last;

	TAILQ_INIT(&mp->mnt_vnodelist);
	if (mp->mnt_newvnodes.tqh_first != NULL)
		panic("vnode_iterate_prepare: newvnode when entering vnode");
	TAILQ_INIT(&mp->mnt_newvnodes);

	return (1);
}


/* called with mount lock held */
int 
vnode_iterate_reloadq(mount_t mp)
{
	int moved = 0;

	/* add the remaining entries in workerq to the end of mount vnode list */
	if (!TAILQ_EMPTY(&mp->mnt_workerqueue)) {
		struct vnode * mvp;
		mvp = TAILQ_LAST(&mp->mnt_vnodelist, vnodelst);
		
		/* Joining the workerque entities to mount vnode list */
		if (mvp)
			mvp->v_mntvnodes.tqe_next = mp->mnt_workerqueue.tqh_first;
		else
			mp->mnt_vnodelist.tqh_first = mp->mnt_workerqueue.tqh_first;
		mp->mnt_workerqueue.tqh_first->v_mntvnodes.tqe_prev = mp->mnt_vnodelist.tqh_last;
		mp->mnt_vnodelist.tqh_last = mp->mnt_workerqueue.tqh_last;
		TAILQ_INIT(&mp->mnt_workerqueue);
	}

	/* add the newvnodes to the head of mount vnode list */
	if (!TAILQ_EMPTY(&mp->mnt_newvnodes)) {
		struct vnode * nlvp;
		nlvp = TAILQ_LAST(&mp->mnt_newvnodes, vnodelst);
		
		mp->mnt_newvnodes.tqh_first->v_mntvnodes.tqe_prev = &mp->mnt_vnodelist.tqh_first;
		nlvp->v_mntvnodes.tqe_next = mp->mnt_vnodelist.tqh_first;
		if(mp->mnt_vnodelist.tqh_first) 
			mp->mnt_vnodelist.tqh_first->v_mntvnodes.tqe_prev = &nlvp->v_mntvnodes.tqe_next;
		else
			mp->mnt_vnodelist.tqh_last = mp->mnt_newvnodes.tqh_last;
		mp->mnt_vnodelist.tqh_first = mp->mnt_newvnodes.tqh_first;
		TAILQ_INIT(&mp->mnt_newvnodes);
		moved = 1;
	}

	return(moved);
}


void
vnode_iterate_clear(mount_t mp)
{
	mp->mnt_lflag &= ~MNT_LITER;
	if (mp->mnt_lflag & MNT_LITERWAIT) {
		mp->mnt_lflag &= ~MNT_LITERWAIT;
		wakeup(mp);
	}
}


int
vnode_iterate(mp, flags, callout, arg)
	mount_t mp;
	int flags;
	int (*callout)(struct vnode *, void *);
	void * arg;
{
	struct vnode *vp;
	int vid, retval;
	int ret = 0;

	mount_lock(mp);

	vnode_iterate_setup(mp);

	/* it is returns 0 then there is nothing to do */
	retval = vnode_iterate_prepare(mp);

	if (retval == 0)  {
		vnode_iterate_clear(mp);
		mount_unlock(mp);
		return(ret);
	}
	
	/* iterate over all the vnodes */
	while (!TAILQ_EMPTY(&mp->mnt_workerqueue)) {
		vp = TAILQ_FIRST(&mp->mnt_workerqueue);
		TAILQ_REMOVE(&mp->mnt_workerqueue, vp, v_mntvnodes);
		TAILQ_INSERT_TAIL(&mp->mnt_vnodelist, vp, v_mntvnodes);
		vid = vp->v_id;
		if ((vp->v_data == NULL) || (vp->v_type == VNON) || (vp->v_mount != mp)) {
			continue;
		}
		mount_unlock(mp);

		if ( vget_internal(vp, vid, (flags | VNODE_NODEAD| VNODE_WITHID | VNODE_NOSUSPEND))) {
			mount_lock(mp);
			continue;	
		}
		if (flags & VNODE_RELOAD) {
		        /*
			 * we're reloading the filesystem
			 * cast out any inactive vnodes...
			 */
		        if (vnode_reload(vp)) {
			        /* vnode will be recycled on the refcount drop */
			        vnode_put(vp);
				mount_lock(mp);
			    	continue;
			}
		}

		retval = callout(vp, arg);

		switch (retval) {
		  case VNODE_RETURNED:
		  case VNODE_RETURNED_DONE:
			  vnode_put(vp);
			  if (retval == VNODE_RETURNED_DONE) {
				mount_lock(mp);
				ret = 0;
				goto out;
			  }
			  break;

		  case VNODE_CLAIMED_DONE:
				mount_lock(mp);
				ret = 0;
				goto out;
		  case VNODE_CLAIMED:
		  default:
				break;
		}
		mount_lock(mp);
	}

out:
	(void)vnode_iterate_reloadq(mp);
	vnode_iterate_clear(mp);
	mount_unlock(mp);
	return (ret);
}

void
mount_lock_renames(mount_t mp)
{
	lck_mtx_lock(&mp->mnt_renamelock);
}

void
mount_unlock_renames(mount_t mp)
{
	lck_mtx_unlock(&mp->mnt_renamelock);
}

void
mount_lock(mount_t mp)
{
	lck_mtx_lock(&mp->mnt_mlock);
}

void
mount_unlock(mount_t mp)
{
	lck_mtx_unlock(&mp->mnt_mlock);
}


void
mount_ref(mount_t mp, int locked)
{
        if ( !locked)
	        mount_lock(mp);
	
	mp->mnt_count++;

        if ( !locked)
	        mount_unlock(mp);
}


void
mount_drop(mount_t mp, int locked)
{
        if ( !locked)
	        mount_lock(mp);
	
	mp->mnt_count--;

	if (mp->mnt_count == 0 && (mp->mnt_lflag & MNT_LDRAIN))
	        wakeup(&mp->mnt_lflag);

        if ( !locked)
	        mount_unlock(mp);
}


int
mount_iterref(mount_t mp, int locked)
{
	int retval = 0;

	if (!locked)
		mount_list_lock();
	if (mp->mnt_iterref < 0) {
		retval = 1;
	} else {
		mp->mnt_iterref++;
	}
	if (!locked)
		mount_list_unlock();
	return(retval);
}

int
mount_isdrained(mount_t mp, int locked)
{
	int retval;

	if (!locked)
		mount_list_lock();
	if (mp->mnt_iterref < 0)
		retval = 1;
	else
		retval = 0;	
	if (!locked)
		mount_list_unlock();
	return(retval);
}

void
mount_iterdrop(mount_t mp)
{
	mount_list_lock();
	mp->mnt_iterref--;
	wakeup(&mp->mnt_iterref);
	mount_list_unlock();
}

void
mount_iterdrain(mount_t mp)
{
	mount_list_lock();
	while (mp->mnt_iterref)
		msleep((caddr_t)&mp->mnt_iterref, mnt_list_mtx_lock, PVFS, "mount_iterdrain", 0 );
	/* mount iterations drained */
	mp->mnt_iterref = -1;
	mount_list_unlock();
}
void
mount_iterreset(mount_t mp)
{
	mount_list_lock();
	if (mp->mnt_iterref == -1)
		mp->mnt_iterref = 0;
	mount_list_unlock();
}

/* always called with  mount lock held */
int 
mount_refdrain(mount_t mp)
{
	if (mp->mnt_lflag & MNT_LDRAIN)
		panic("already in drain");
	mp->mnt_lflag |= MNT_LDRAIN;

	while (mp->mnt_count)
		msleep((caddr_t)&mp->mnt_lflag, &mp->mnt_mlock, PVFS, "mount_drain", 0 );

	if (mp->mnt_vnodelist.tqh_first != NULL)
		 panic("mount_refdrain: dangling vnode"); 

	mp->mnt_lflag &= ~MNT_LDRAIN;

	return(0);
}


/*
 * Mark a mount point as busy. Used to synchronize access and to delay
 * unmounting.
 */
int
vfs_busy(mount_t mp, int flags)
{

restart:
	if (mp->mnt_lflag & MNT_LDEAD)
		return(ENOENT);

	if (mp->mnt_lflag & MNT_LUNMOUNT) {
		if (flags & LK_NOWAIT)
			return (ENOENT);

		mount_lock(mp);

		if (mp->mnt_lflag & MNT_LDEAD) {
		        mount_unlock(mp);
		        return(ENOENT);
		}
		if (mp->mnt_lflag & MNT_LUNMOUNT) {
		        mp->mnt_lflag |= MNT_LWAIT;
			/*
			 * Since all busy locks are shared except the exclusive
			 * lock granted when unmounting, the only place that a
			 * wakeup needs to be done is at the release of the
			 * exclusive lock at the end of dounmount.
			 */
			msleep((caddr_t)mp, &mp->mnt_mlock, (PVFS | PDROP), "vfsbusy", 0 );
			return (ENOENT);
		}
		mount_unlock(mp);
	}

	lck_rw_lock_shared(&mp->mnt_rwlock);

	/* 
	 * until we are granted the rwlock, it's possible for the mount point to
	 * change state, so reevaluate before granting the vfs_busy
	 */
	if (mp->mnt_lflag & (MNT_LDEAD | MNT_LUNMOUNT)) {
		lck_rw_done(&mp->mnt_rwlock);
		goto restart;
	}
	return (0);
}

/*
 * Free a busy filesystem.
 */

void
vfs_unbusy(mount_t mp)
{
	lck_rw_done(&mp->mnt_rwlock);
}



static void
vfs_rootmountfailed(mount_t mp) {

	mount_list_lock();
	mp->mnt_vtable->vfc_refcount--;
	mount_list_unlock();

	vfs_unbusy(mp);

	mount_lock_destroy(mp);

	FREE_ZONE(mp, sizeof(struct mount), M_MOUNT);
}

/*
 * Lookup a filesystem type, and if found allocate and initialize
 * a mount structure for it.
 *
 * Devname is usually updated by mount(8) after booting.
 */
static mount_t
vfs_rootmountalloc_internal(struct vfstable *vfsp, const char *devname)
{
	mount_t	mp;

	mp = _MALLOC_ZONE((u_long)sizeof(struct mount), M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));

	/* Initialize the default IO constraints */
	mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
	mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;
	mp->mnt_maxsegreadsize = mp->mnt_maxreadcnt;
	mp->mnt_maxsegwritesize = mp->mnt_maxwritecnt;
	mp->mnt_devblocksize = DEV_BSIZE;

	mount_lock_init(mp);
	(void)vfs_busy(mp, LK_NOWAIT);

	TAILQ_INIT(&mp->mnt_vnodelist);
	TAILQ_INIT(&mp->mnt_workerqueue);
	TAILQ_INIT(&mp->mnt_newvnodes);

	mp->mnt_vtable = vfsp;
	mp->mnt_op = vfsp->vfc_vfsops;
	mp->mnt_flag = MNT_RDONLY | MNT_ROOTFS;
	mp->mnt_vnodecovered = NULLVP;
	//mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;

	mount_list_lock();
	vfsp->vfc_refcount++;
	mount_list_unlock();

	strncpy(mp->mnt_vfsstat.f_fstypename, vfsp->vfc_name, MFSTYPENAMELEN);
	mp->mnt_vfsstat.f_mntonname[0] = '/';
	(void) copystr((char *)devname, mp->mnt_vfsstat.f_mntfromname, MAXPATHLEN - 1, 0);

	return (mp);
}

errno_t
vfs_rootmountalloc(const char *fstypename, const char *devname, mount_t *mpp)
{
        struct vfstable *vfsp;

	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
	        if (!strcmp(vfsp->vfc_name, fstypename))
		        break;
        if (vfsp == NULL)
	        return (ENODEV);

	*mpp = vfs_rootmountalloc_internal(vfsp, devname);

	if (*mpp)
	        return (0);

	return (ENOMEM);
}


/*
 * Find an appropriate filesystem to use for the root. If a filesystem
 * has not been preselected, walk through the list of known filesystems
 * trying those that have mountroot routines, and try them until one
 * works or we have tried them all.
 */
extern int (*mountroot)(void);

int
vfs_mountroot()
{
	struct vfstable *vfsp;
	struct vfs_context context;
	int	error;
	mount_t mp;

	if (mountroot != NULL) {
	        /*
		 * used for netboot which follows a different set of rules
		 */
	        error = (*mountroot)();
		return (error);
	}
	if ((error = bdevvp(rootdev, &rootvp))) {
	        printf("vfs_mountroot: can't setup bdevvp\n");
		return (error);
	}
	context.vc_proc = current_proc();
	context.vc_ucred = kauth_cred_get();

	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next) {
		if (vfsp->vfc_mountroot == NULL)
			continue;

		mp = vfs_rootmountalloc_internal(vfsp, "root_device");
		mp->mnt_devvp = rootvp;

		if ((error = (*vfsp->vfc_mountroot)(mp, rootvp, &context)) == 0) {
		        mp->mnt_devvp->v_specflags |= SI_MOUNTEDON;

		        vfs_unbusy(mp);

			mount_list_add(mp);

			/*
			 *   cache the IO attributes for the underlying physical media...
			 *   an error return indicates the underlying driver doesn't
			 *   support all the queries necessary... however, reasonable
			 *   defaults will have been set, so no reason to bail or care
			 */
			vfs_init_io_attributes(rootvp, mp);
			/*
			 * get rid of iocount reference returned
			 * by bdevvp... it will have also taken
			 * a usecount reference which we want to keep
			 */
			vnode_put(rootvp);

			return (0);
		}
		vfs_rootmountfailed(mp);
		
		if (error != EINVAL)
			printf("%s_mountroot failed: %d\n", vfsp->vfc_name, error);
	}
	return (ENODEV);
}

/*
 * Lookup a mount point by filesystem identifier.
 */
extern mount_t vfs_getvfs_locked(fsid_t *);

struct mount *
vfs_getvfs(fsid)
	fsid_t *fsid;
{
	return (mount_list_lookupby_fsid(fsid, 0, 0));
}

struct mount *
vfs_getvfs_locked(fsid)
	fsid_t *fsid;
{
	return(mount_list_lookupby_fsid(fsid, 1, 0));
}

struct mount *
vfs_getvfs_by_mntonname(u_char *path)
{
	mount_t retmp = (mount_t)0;
	mount_t mp;

	mount_list_lock();
	TAILQ_FOREACH(mp, &mountlist, mnt_list) {
		if (!strcmp(mp->mnt_vfsstat.f_mntonname, path)) {
			retmp = mp;
			goto out;
		}
	}
out:
	mount_list_unlock();
	return (retmp);
}

/* generation number for creation of new fsids */
u_short mntid_gen = 0;
/*
 * Get a new unique fsid
 */
void
vfs_getnewfsid(mp)
	struct mount *mp;
{

	fsid_t tfsid;
	int mtype;
	mount_t nmp;

	mount_list_lock();

	/* generate a new fsid */
	mtype = mp->mnt_vtable->vfc_typenum;
	if (++mntid_gen == 0)
		mntid_gen++;
	tfsid.val[0] = makedev(nblkdev + mtype, mntid_gen);
	tfsid.val[1] = mtype;

	TAILQ_FOREACH(nmp, &mountlist, mnt_list) {
		while (vfs_getvfs_locked(&tfsid)) {
			if (++mntid_gen == 0)
				mntid_gen++;
			tfsid.val[0] = makedev(nblkdev + mtype, mntid_gen);
		}
	}
	mp->mnt_vfsstat.f_fsid.val[0] = tfsid.val[0];
	mp->mnt_vfsstat.f_fsid.val[1] = tfsid.val[1];
	mount_list_unlock();
}

/*
 * Routines having to do with the management of the vnode table.
 */
extern int (**dead_vnodeop_p)(void *);
long numvnodes, freevnodes;
long inactivevnodes;


/*
 * Move a vnode from one mount queue to another.
 */
static void
insmntque(vnode_t vp, mount_t mp)
{
	mount_t lmp;
	/*
	 * Delete from old mount point vnode list, if on one.
	 */
	if ( (lmp = vp->v_mount) != NULL) {
		if ((vp->v_lflag & VNAMED_MOUNT) == 0)
			panic("insmntque: vp not in mount vnode list");
		vp->v_lflag &= ~VNAMED_MOUNT;

		mount_lock(lmp);

		mount_drop(lmp, 1);

		if (vp->v_mntvnodes.tqe_next == NULL) {
			if (TAILQ_LAST(&lmp->mnt_vnodelist, vnodelst) == vp)
				TAILQ_REMOVE(&lmp->mnt_vnodelist, vp, v_mntvnodes);
			else if (TAILQ_LAST(&lmp->mnt_newvnodes, vnodelst) == vp)
				TAILQ_REMOVE(&lmp->mnt_newvnodes, vp, v_mntvnodes);
			else if (TAILQ_LAST(&lmp->mnt_workerqueue, vnodelst) == vp)
				TAILQ_REMOVE(&lmp->mnt_workerqueue, vp, v_mntvnodes);
		 } else {
			vp->v_mntvnodes.tqe_next->v_mntvnodes.tqe_prev = vp->v_mntvnodes.tqe_prev;
			*vp->v_mntvnodes.tqe_prev = vp->v_mntvnodes.tqe_next;
		}	
		vp->v_mntvnodes.tqe_next = 0;
		vp->v_mntvnodes.tqe_prev = 0;
		mount_unlock(lmp);
		return;
	}

	/*
	 * Insert into list of vnodes for the new mount point, if available.
	 */
	if ((vp->v_mount = mp) != NULL) {
		mount_lock(mp);
		if ((vp->v_mntvnodes.tqe_next != 0) && (vp->v_mntvnodes.tqe_prev != 0))
			panic("vp already in mount list");
		if (mp->mnt_lflag & MNT_LITER)
			TAILQ_INSERT_HEAD(&mp->mnt_newvnodes, vp, v_mntvnodes);
		else
			TAILQ_INSERT_HEAD(&mp->mnt_vnodelist, vp, v_mntvnodes);
		if (vp->v_lflag & VNAMED_MOUNT)
			panic("insmntque: vp already in mount vnode list");
		if ((vp->v_freelist.tqe_prev != (struct vnode **)0xdeadb))
		        panic("insmntque: vp on the free list\n");
		vp->v_lflag |= VNAMED_MOUNT;
		mount_ref(mp, 1);
		mount_unlock(mp);
	}
}


/*
 * Create a vnode for a block device.
 * Used for root filesystem, argdev, and swap areas.
 * Also used for memory file system special devices.
 */
int
bdevvp(dev_t dev, vnode_t *vpp)
{
	vnode_t	nvp;
	int	error;
	struct vnode_fsparam vfsp;
	struct vfs_context context;

	if (dev == NODEV) {
		*vpp = NULLVP;
		return (ENODEV);
	}

	context.vc_proc = current_proc();
	context.vc_ucred = FSCRED;

	vfsp.vnfs_mp = (struct mount *)0;
	vfsp.vnfs_vtype = VBLK;
	vfsp.vnfs_str = "bdevvp";
	vfsp.vnfs_dvp = 0;
	vfsp.vnfs_fsnode = 0;
	vfsp.vnfs_cnp = 0;
	vfsp.vnfs_vops = spec_vnodeop_p;
	vfsp.vnfs_rdev = dev;
	vfsp.vnfs_filesize = 0;

	vfsp.vnfs_flags = VNFS_NOCACHE | VNFS_CANTCACHE;

	vfsp.vnfs_marksystem = 0;
	vfsp.vnfs_markroot = 0;

	if ( (error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &nvp)) ) {
		*vpp = NULLVP;
		return (error);
	}
	if ( (error = vnode_ref(nvp)) ) {
		panic("bdevvp failed: vnode_ref");
		return (error);
	}
	if ( (error = VNOP_FSYNC(nvp, MNT_WAIT, &context)) ) {
		panic("bdevvp failed: fsync");
		return (error);
	}
	if ( (error = buf_invalidateblks(nvp, BUF_WRITE_DATA, 0, 0)) ) {
		panic("bdevvp failed: invalidateblks");
		return (error);
	}
	if ( (error = VNOP_OPEN(nvp, FREAD, &context)) ) {
		panic("bdevvp failed: open");
		return (error);
	}
	*vpp = nvp;

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
static vnode_t
checkalias(nvp, nvp_rdev)
	register struct vnode *nvp;
	dev_t nvp_rdev;
{
	struct vnode *vp;
	struct vnode **vpp;
	int vid = 0;

	vpp = &speclisth[SPECHASH(nvp_rdev)];
loop:
	SPECHASH_LOCK();

	for (vp = *vpp; vp; vp = vp->v_specnext) {
		if (nvp_rdev == vp->v_rdev && nvp->v_type == vp->v_type) {
		        vid = vp->v_id;
			break;
		}
	}
	SPECHASH_UNLOCK();

	if (vp) {
	        if (vnode_getwithvid(vp,vid)) {
		        goto loop;
		}
		/*
		 * Termination state is checked in vnode_getwithvid
		 */
		vnode_lock(vp);

		/*
		 * Alias, but not in use, so flush it out.
		 */
		if ((vp->v_iocount == 1) && (vp->v_usecount == 0)) {
		        vnode_reclaim_internal(vp, 1, 0);
			vnode_unlock(vp);
			vnode_put(vp);
			goto loop;
		}
	}
	if (vp == NULL || vp->v_tag != VT_NON) {
	        MALLOC_ZONE(nvp->v_specinfo, struct specinfo *, sizeof(struct specinfo),
			    M_SPECINFO, M_WAITOK);
		bzero(nvp->v_specinfo, sizeof(struct specinfo));
		nvp->v_rdev = nvp_rdev;
		nvp->v_specflags = 0;
		nvp->v_speclastr = -1;

		SPECHASH_LOCK();
		nvp->v_hashchain = vpp;
		nvp->v_specnext = *vpp;
		*vpp = nvp;
		SPECHASH_UNLOCK();

		if (vp != NULLVP) {
			nvp->v_flag |= VALIASED;
			vp->v_flag |= VALIASED;
			vnode_unlock(vp);
			vnode_put(vp);
		}
		return (NULLVP);
	}
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
static int
vget_internal(vnode_t vp, int vid, int vflags)
{
	int error = 0;
	u_long vpid;

	vnode_lock(vp);

	if (vflags & VNODE_WITHID)
		vpid = vid;
	else
		vpid = vp->v_id;    // save off the original v_id

	if ((vflags & VNODE_WRITEABLE) && (vp->v_writecount == 0))
	        /*
		 * vnode to be returned only if it has writers opened 
		 */
	        error = EINVAL;
	else
	        error = vnode_getiocount(vp, 1, vpid, vflags);

	vnode_unlock(vp);

	return (error);
}

int
vnode_ref(vnode_t vp)
{

        return (vnode_ref_ext(vp, 0));
}

int
vnode_ref_ext(vnode_t vp, int fmode)
{
	int	error = 0;

	vnode_lock(vp);

	/*
	 * once all the current call sites have been fixed to insure they have
	 * taken an iocount, we can toughen this assert up and insist that the
	 * iocount is non-zero... a non-zero usecount doesn't insure correctness
	 */
	if (vp->v_iocount <= 0 && vp->v_usecount <= 0) 
		panic("vnode_ref_ext: vp %x has no valid reference %d, %d", vp, vp->v_iocount, vp->v_usecount);

	/*
	 * if you are the owner of drain/termination, can acquire usecount
	 */
	if ((vp->v_lflag & (VL_DRAIN | VL_TERMINATE | VL_DEAD))) {
	        if (vp->v_owner != current_thread()) {
		        error = ENOENT;
			goto out;
		}
	}
	vp->v_usecount++;

	if (fmode & FWRITE) {
	        if (++vp->v_writecount <= 0)
		        panic("vnode_ref_ext: v_writecount");
	}
	if (fmode & O_EVTONLY) {
	        if (++vp->v_kusecount <= 0)
		        panic("vnode_ref_ext: v_kusecount");
	}
out:
	vnode_unlock(vp);

	return (error);
}


/*
 * put the vnode on appropriate free list.
 * called with vnode LOCKED
 */
static void
vnode_list_add(vnode_t vp)
{

	/*
	 * if it is already on a list or non zero references return 
	 */
	if (VONLIST(vp) || (vp->v_usecount != 0) || (vp->v_iocount != 0))
		return;
	vnode_list_lock();

	/*
	 * insert at tail of LRU list or at head if VAGE or VL_DEAD is set
	 */
	if ((vp->v_flag & VAGE) || (vp->v_lflag & VL_DEAD)) {
	        TAILQ_INSERT_HEAD(&vnode_free_list, vp, v_freelist);
		vp->v_flag &= ~VAGE;
	} else {
	        TAILQ_INSERT_TAIL(&vnode_free_list, vp, v_freelist);
	}
	freevnodes++;

	vnode_list_unlock();
}

/*
 * remove the vnode from appropriate free list.
 */
static void
vnode_list_remove(vnode_t vp)
{
        /*
	 * we want to avoid taking the list lock
	 * in the case where we're not on the free
	 * list... this will be true for most
	 * directories and any currently in use files
	 *
	 * we're guaranteed that we can't go from
	 * the not-on-list state to the on-list 
	 * state since we hold the vnode lock...
	 * all calls to vnode_list_add are done
	 * under the vnode lock... so we can
	 * check for that condition (the prevelant one)
	 * without taking the list lock
	 */
	if (VONLIST(vp)) {
	        vnode_list_lock();
		/*
		 * however, we're not guaranteed that
		 * we won't go from the on-list state
		 * to the non-on-list state until we
		 * hold the vnode_list_lock... this 
		 * is due to new_vnode removing vnodes
		 * from the free list uder the list_lock
		 * w/o the vnode lock... so we need to
		 * check again whether we're currently
		 * on the free list
		 */
		if (VONLIST(vp)) {
		        VREMFREE("vnode_list_remove", vp);
			VLISTNONE(vp);
		}
		vnode_list_unlock();
	}
}


void
vnode_rele(vnode_t vp)
{
        vnode_rele_internal(vp, 0, 0, 0);
}


void
vnode_rele_ext(vnode_t vp, int fmode, int dont_reenter)
{
        vnode_rele_internal(vp, fmode, dont_reenter, 0);
}


void
vnode_rele_internal(vnode_t vp, int fmode, int dont_reenter, int locked)
{
	struct vfs_context context;

	if ( !locked)
	        vnode_lock(vp);

	if (--vp->v_usecount < 0)
		panic("vnode_rele_ext: vp %x usecount -ve : %d", vp,  vp->v_usecount);

	if (fmode & FWRITE) {
	        if (--vp->v_writecount < 0)
		        panic("vnode_rele_ext: vp %x writecount -ve : %d", vp,  vp->v_writecount);
	}
	if (fmode & O_EVTONLY) {
	        if (--vp->v_kusecount < 0)
		        panic("vnode_rele_ext: vp %x kusecount -ve : %d", vp,  vp->v_kusecount);
	}
	if ((vp->v_iocount > 0) || (vp->v_usecount > 0)) {
	        /*
		 * vnode is still busy... if we're the last
		 * usecount, mark for a future call to VNOP_INACTIVE
		 * when the iocount finally drops to 0
		 */
	        if (vp->v_usecount == 0) {
	                vp->v_lflag |= VL_NEEDINACTIVE;
			vp->v_flag  &= ~(VNOCACHE_DATA | VRAOFF);
		}
		if ( !locked)
		        vnode_unlock(vp);
		return;
	}
	vp->v_flag  &= ~(VNOCACHE_DATA | VRAOFF);

	if ( (vp->v_lflag & (VL_TERMINATE | VL_DEAD)) || dont_reenter) {
	        /*
		 * vnode is being cleaned, or
		 * we've requested that we don't reenter
		 * the filesystem on this release... in
		 * this case, we'll mark the vnode aged
		 * if it's been marked for termination
		 */
	        if (dont_reenter) {
		        if ( !(vp->v_lflag & (VL_TERMINATE | VL_DEAD | VL_MARKTERM)) )
			        vp->v_lflag |= VL_NEEDINACTIVE;
		        vp->v_flag |= VAGE;
		}
	        vnode_list_add(vp);
		if ( !locked)
		        vnode_unlock(vp);
		return;
	}
	/*
	 * at this point both the iocount and usecount
	 * are zero
	 * pick up an iocount so that we can call
	 * VNOP_INACTIVE with the vnode lock unheld
	 */
	vp->v_iocount++;
#ifdef JOE_DEBUG
	record_vp(vp, 1);
#endif
        vp->v_lflag &= ~VL_NEEDINACTIVE;
	vnode_unlock(vp);

	context.vc_proc = current_proc();
	context.vc_ucred = kauth_cred_get();
	VNOP_INACTIVE(vp, &context);

	vnode_lock(vp);
	/*
	 * because we dropped the vnode lock to call VNOP_INACTIVE
	 * the state of the vnode may have changed... we may have
	 * picked up an iocount, usecount or the MARKTERM may have
	 * been set... we need to reevaluate the reference counts
	 * to determine if we can call vnode_reclaim_internal at
	 * this point... if the reference counts are up, we'll pick
	 * up the MARKTERM state when they get subsequently dropped
	 */
	if ( (vp->v_iocount == 1) && (vp->v_usecount == 0) &&
	     ((vp->v_lflag & (VL_MARKTERM | VL_TERMINATE | VL_DEAD)) == VL_MARKTERM)) {
	        struct  uthread *ut;

	        ut = get_bsdthread_info(current_thread());
		
		if (ut->uu_defer_reclaims) {
		        vp->v_defer_reclaimlist = ut->uu_vreclaims;
				ut->uu_vreclaims = vp;
		        goto defer_reclaim;
		}
	        vnode_reclaim_internal(vp, 1, 0);
	}
	vnode_dropiocount(vp, 1);
	vnode_list_add(vp);
defer_reclaim:
	if ( !locked)
	        vnode_unlock(vp);
	return;
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
	struct vnode *vp;
	int busy = 0;
	int reclaimed = 0;
	int vid, retval;

	mount_lock(mp);
	vnode_iterate_setup(mp);
	/*
	 * On regular unmounts(not forced) do a
	 * quick check for vnodes to be in use. This
	 * preserves the caching of vnodes. automounter
	 * tries unmounting every so often to see whether
	 * it is still busy or not.
	 */
	if ((flags & FORCECLOSE)==0) {
		if (vnode_umount_preflight(mp, skipvp, flags)) {
			vnode_iterate_clear(mp);
			mount_unlock(mp);
			return(EBUSY);
		}
	}
loop:
	/* it is returns 0 then there is nothing to do */
	retval = vnode_iterate_prepare(mp);

	if (retval == 0)  {
		vnode_iterate_clear(mp);
		mount_unlock(mp);
		return(retval);
	}

    /* iterate over all the vnodes */
    while (!TAILQ_EMPTY(&mp->mnt_workerqueue)) {
        vp = TAILQ_FIRST(&mp->mnt_workerqueue);
        TAILQ_REMOVE(&mp->mnt_workerqueue, vp, v_mntvnodes);
        TAILQ_INSERT_TAIL(&mp->mnt_vnodelist, vp, v_mntvnodes);
        if ( (vp->v_mount != mp) || (vp == skipvp)) {
            continue;
        }
        vid = vp->v_id;
        mount_unlock(mp);
		vnode_lock(vp);

		if ((vp->v_id != vid) || ((vp->v_lflag & (VL_DEAD | VL_TERMINATE)))) {
				vnode_unlock(vp);
				mount_lock(mp);
				continue;
		}

		/*
		 * If requested, skip over vnodes marked VSYSTEM.
		 * Skip over all vnodes marked VNOFLUSH.
                 */
		if ((flags & SKIPSYSTEM) && ((vp->v_flag & VSYSTEM) ||
		    (vp->v_flag & VNOFLUSH))) {
			vnode_unlock(vp);
			mount_lock(mp);
			continue;
		}
		/*
		 * If requested, skip over vnodes marked VSWAP.
		 */
		if ((flags & SKIPSWAP) && (vp->v_flag & VSWAP)) {
			vnode_unlock(vp);
			mount_lock(mp);
			continue;
		}
		/*
		 * If requested, skip over vnodes marked VSWAP.
		 */
		if ((flags & SKIPROOT) && (vp->v_flag & VROOT)) {
			vnode_unlock(vp);
			mount_lock(mp);
			continue;
		}
		/*
		 * If WRITECLOSE is set, only flush out regular file
		 * vnodes open for writing.
		 */
		if ((flags & WRITECLOSE) &&
		    (vp->v_writecount == 0 || vp->v_type != VREG)) {
			vnode_unlock(vp);
			mount_lock(mp);
			continue;
		}
		/*
		 * If the real usecount is 0, all we need to do is clear
		 * out the vnode data structures and we are done.
		 */
		if (((vp->v_usecount == 0) ||
		    ((vp->v_usecount - vp->v_kusecount) == 0))) {
		        vp->v_iocount++;	/* so that drain waits for * other iocounts */
#ifdef JOE_DEBUG
			record_vp(vp, 1);
#endif
			vnode_reclaim_internal(vp, 1, 0);
			vnode_dropiocount(vp, 1);
			vnode_list_add(vp);

			vnode_unlock(vp);
			reclaimed++;
			mount_lock(mp);
			continue;
		}
		/*
		 * If FORCECLOSE is set, forcibly close the vnode.
		 * For block or character devices, revert to an
		 * anonymous device. For all other files, just kill them.
		 */
		if (flags & FORCECLOSE) {
			if (vp->v_type != VBLK && vp->v_type != VCHR) {
				vp->v_iocount++;	/* so that drain waits * for other iocounts */
#ifdef JOE_DEBUG
				record_vp(vp, 1);
#endif
				vnode_reclaim_internal(vp, 1, 0);
				vnode_dropiocount(vp, 1);
				vnode_list_add(vp);
				vnode_unlock(vp);
			} else {
				vclean(vp, 0, p);
				vp->v_mount = 0;	/*override any dead_mountp */
				vp->v_lflag &= ~VL_DEAD;
				vp->v_op = spec_vnodeop_p;
				insmntque(vp, (struct mount *)0);
				vnode_unlock(vp);
			}
			mount_lock(mp);
			continue;
		}
#if DIAGNOSTIC
		if (busyprt)
			vprint("vflush: busy vnode", vp);
#endif
		vnode_unlock(vp);
		mount_lock(mp);
		busy++;
	}

	/* At this point the worker queue is completed */
	if (busy && ((flags & FORCECLOSE)==0) && reclaimed) {
		busy = 0;
		reclaimed = 0;
		(void)vnode_iterate_reloadq(mp);
		/* returned with mount lock held */
		goto loop;
	}

	/* if new vnodes were created in between retry the reclaim */
 	if ( vnode_iterate_reloadq(mp) != 0) {
		if (!(busy && ((flags & FORCECLOSE)==0)))
			goto loop;
	}
	vnode_iterate_clear(mp);
	mount_unlock(mp);

	if (busy && ((flags & FORCECLOSE)==0))
		return (EBUSY);
	return (0);
}

int num_recycledvnodes=0;
/*
 * Disassociate the underlying file system from a vnode.
 * The vnode lock is held on entry.
 */
static void
vclean(vnode_t vp, int flags, proc_t p)
{
	struct vfs_context context;
	int active;
	int need_inactive;
	int already_terminating;
	kauth_cred_t ucred = NULL;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	/*
	 * Check to see if the vnode is in use.
	 * If so we have to reference it before we clean it out
	 * so that its count cannot fall to zero and generate a
	 * race against ourselves to recycle it.
	 */
	active = vp->v_usecount;

	/*
	 * just in case we missed sending a needed
	 * VNOP_INACTIVE, we'll do it now
	 */
	need_inactive = (vp->v_lflag & VL_NEEDINACTIVE);

	vp->v_lflag &= ~VL_NEEDINACTIVE;

	/*
	 * Prevent the vnode from being recycled or
	 * brought into use while we clean it out.
	 */
	already_terminating = (vp->v_lflag & VL_TERMINATE);

	vp->v_lflag |= VL_TERMINATE;

	/*
	 * remove the vnode from any mount list
	 * it might be on...
	 */
	insmntque(vp, (struct mount *)0);

	ucred = vp->v_cred;
	vp->v_cred = NULL;

	vnode_unlock(vp);

	if (ucred)
	        kauth_cred_rele(ucred);

	OSAddAtomic(1, &num_recycledvnodes);
	/*
	 * purge from the name cache as early as possible...
	 */
	cache_purge(vp);

	if (active && (flags & DOCLOSE))
		VNOP_CLOSE(vp, IO_NDELAY, &context);

	/*
	 * Clean out any buffers associated with the vnode.
	 */
	if (flags & DOCLOSE) {
#if NFSCLIENT
		if (vp->v_tag == VT_NFS)
			nfs_vinvalbuf(vp, V_SAVE, NOCRED, p, 0);
		else
#endif
		{
		        VNOP_FSYNC(vp, MNT_WAIT, &context);
			buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0);
		}
		if (UBCINFOEXISTS(vp))
		        /*
			 * Clean the pages in VM.
			 */
		        (void)ubc_sync_range(vp, (off_t)0, ubc_getsize(vp), UBC_PUSHALL);
	}
	if (UBCINFOEXISTS(vp))
	        cluster_release(vp->v_ubcinfo);

	if (active || need_inactive) 
		VNOP_INACTIVE(vp, &context);

	/* Destroy ubc named reference */
	ubc_destroy_named(vp);

	/*
	 * Reclaim the vnode.
	 */
	if (VNOP_RECLAIM(vp, &context))
		panic("vclean: cannot reclaim");
	
	// make sure the name & parent ptrs get cleaned out!
	vnode_update_identity(vp, NULLVP, NULL, 0, 0, VNODE_UPDATE_PARENT | VNODE_UPDATE_NAME);

	vnode_lock(vp);

	vp->v_mount = dead_mountp;
	vp->v_op = dead_vnodeop_p;
	vp->v_tag = VT_NON;
	vp->v_data = NULL;

	vp->v_lflag |= VL_DEAD;

	if (already_terminating == 0) {
	        vp->v_lflag &= ~VL_TERMINATE;
		/*
		 * Done with purge, notify sleepers of the grim news.
		 */
		if (vp->v_lflag & VL_TERMWANT) {
		        vp->v_lflag &= ~VL_TERMWANT;
			wakeup(&vp->v_lflag);
		}
	}
}

/*
 * Eliminate all activity associated with  the requested vnode
 * and with all vnodes aliased to the requested vnode.
 */
int
vn_revoke(vnode_t vp, int flags, __unused vfs_context_t a_context)
{
	struct vnode *vq;
	int vid;

#if DIAGNOSTIC
	if ((flags & REVOKEALL) == 0)
		panic("vnop_revoke");
#endif

	if (vp->v_flag & VALIASED) {
		/*
		 * If a vgone (or vclean) is already in progress,
		 * wait until it is done and return.
		 */
		vnode_lock(vp);
		if (vp->v_lflag & VL_TERMINATE) {
			vnode_unlock(vp);
			return(ENOENT);
		}
		vnode_unlock(vp);
		/*
		 * Ensure that vp will not be vgone'd while we
		 * are eliminating its aliases.
		 */
		SPECHASH_LOCK();
		while (vp->v_flag & VALIASED) {
			for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
				if (vq->v_rdev != vp->v_rdev ||
				    vq->v_type != vp->v_type || vp == vq)
					continue;
				vid = vq->v_id;
				SPECHASH_UNLOCK();
				if (vnode_getwithvid(vq,vid)){
					SPECHASH_LOCK();	
					break;
				}
				vnode_reclaim_internal(vq, 0, 0);
				vnode_put(vq);
				SPECHASH_LOCK();
				break;
			}
		}
		SPECHASH_UNLOCK();
	}
	vnode_reclaim_internal(vp, 0, 0);

	return (0);
}

/*
 * Recycle an unused vnode to the front of the free list.
 * Release the passed interlock if the vnode will be recycled.
 */
int
vnode_recycle(vp)
	struct vnode *vp;
{
	vnode_lock(vp);

	if (vp->v_iocount || vp->v_usecount) {
		vp->v_lflag |= VL_MARKTERM;
		vnode_unlock(vp);
		return(0);
	} 
	vnode_reclaim_internal(vp, 1, 0);
	vnode_unlock(vp);

	return (1);
}

static int
vnode_reload(vnode_t vp)
{
	vnode_lock(vp);

	if ((vp->v_iocount > 1) || vp->v_usecount) {
		vnode_unlock(vp);
		return(0);
	} 
	if (vp->v_iocount <= 0)
		panic("vnode_reload with no iocount %d", vp->v_iocount);

	/* mark for release when iocount is dopped */
	vp->v_lflag |= VL_MARKTERM;
	vnode_unlock(vp);

	return (1);
}


static void
vgone(vnode_t vp)
{
	struct vnode *vq;
	struct vnode *vx;

	/*
	 * Clean out the filesystem specific data.
	 * vclean also takes care of removing the
	 * vnode from any mount list it might be on
	 */
	vclean(vp, DOCLOSE, current_proc());

	/*
	 * If special device, remove it from special device alias list
	 * if it is on one.
	 */
	if ((vp->v_type == VBLK || vp->v_type == VCHR) && vp->v_specinfo != 0) {
			SPECHASH_LOCK();
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
			SPECHASH_UNLOCK();
			{
			struct specinfo *tmp = vp->v_specinfo;
			vp->v_specinfo = NULL;
			FREE_ZONE((void *)tmp, sizeof(struct specinfo), M_SPECINFO);
			}
	}
}

/*
 * Lookup a vnode by device number.
 */
int
check_mountedon(dev_t dev, enum vtype type, int  *errorp)
{
	vnode_t	vp;
	int rc = 0;
	int vid;

loop:
	SPECHASH_LOCK();
	for (vp = speclisth[SPECHASH(dev)]; vp; vp = vp->v_specnext) {
		if (dev != vp->v_rdev || type != vp->v_type)
			continue;
		vid = vp->v_id;
		SPECHASH_UNLOCK();
		if (vnode_getwithvid(vp,vid))
			goto loop;
		vnode_lock(vp);
		if ((vp->v_usecount > 0) || (vp->v_iocount > 1)) {
			vnode_unlock(vp);
			if ((*errorp = vfs_mountedon(vp)) != 0)
				rc = 1;
		} else
			vnode_unlock(vp);
		vnode_put(vp);
		return(rc);
	}
	SPECHASH_UNLOCK();
	return (0);
}

/*
 * Calculate the total number of references to a special device.
 */
int
vcount(vnode_t vp)
{
	vnode_t vq, vnext;
	int count;
	int vid;

loop:
	if ((vp->v_flag & VALIASED) == 0)
	        return (vp->v_usecount - vp->v_kusecount);

	SPECHASH_LOCK();
	for (count = 0, vq = *vp->v_hashchain; vq; vq = vnext) {
		vnext = vq->v_specnext;
		if (vq->v_rdev != vp->v_rdev || vq->v_type != vp->v_type)
			continue;
		vid = vq->v_id;
		SPECHASH_UNLOCK();

		if (vnode_getwithvid(vq, vid)) {
			goto loop;
		}
		/*
		 * Alias, but not in use, so flush it out.
		 */
		vnode_lock(vq);
		if ((vq->v_usecount == 0) && (vq->v_iocount == 1)  && vq != vp) {
			vnode_reclaim_internal(vq, 1, 0);
			vnode_unlock(vq);
			vnode_put(vq);
			goto loop;
		}
		count += (vq->v_usecount - vq->v_kusecount);
		vnode_unlock(vq);
		vnode_put(vq);	

		SPECHASH_LOCK();
	}
	SPECHASH_UNLOCK();

	return (count);
}

int	prtactive = 0;		/* 1 => print out reclaim of active vnodes */

/*
 * Print out a description of a vnode.
 */
static char *typename[] =
   { "VNON", "VREG", "VDIR", "VBLK", "VCHR", "VLNK", "VSOCK", "VFIFO", "VBAD" };

void
vprint(const char *label, struct vnode *vp)
{
	char sbuf[64];

	if (label != NULL)
		printf("%s: ", label);
	printf("type %s, usecount %d, writecount %d",
	       typename[vp->v_type], vp->v_usecount, vp->v_writecount);
	sbuf[0] = '\0';
	if (vp->v_flag & VROOT)
		strcat(sbuf, "|VROOT");
	if (vp->v_flag & VTEXT)
		strcat(sbuf, "|VTEXT");
	if (vp->v_flag & VSYSTEM)
		strcat(sbuf, "|VSYSTEM");
	if (vp->v_flag & VNOFLUSH)
		strcat(sbuf, "|VNOFLUSH");
	if (vp->v_flag & VBWAIT)
		strcat(sbuf, "|VBWAIT");
	if (vp->v_flag & VALIASED)
		strcat(sbuf, "|VALIASED");
	if (sbuf[0] != '\0')
		printf(" flags (%s)", &sbuf[1]);
}


int
vn_getpath(struct vnode *vp, char *pathbuf, int *len)
{
    return build_path(vp, pathbuf, *len, len);
}


static char *extension_table=NULL;
static int   nexts;
static int   max_ext_width;

static int
extension_cmp(void *a, void *b)
{
    return (strlen((char *)a) - strlen((char *)b));
}


//
// This is the api LaunchServices uses to inform the kernel
// the list of package extensions to ignore.
//
// Internally we keep the list sorted by the length of the
// the extension (from longest to shortest).  We sort the
// list of extensions so that we can speed up our searches
// when comparing file names -- we only compare extensions
// that could possibly fit into the file name, not all of
// them (i.e. a short 8 character name can't have an 8
// character extension).
//
__private_extern__ int
set_package_extensions_table(void *data, int nentries, int maxwidth)
{
    char *new_exts, *ptr;
    int error, i, len;
    
    if (nentries <= 0 || nentries > 1024 || maxwidth <= 0 || maxwidth > 255) {
	return EINVAL;
    }

    MALLOC(new_exts, char *, nentries * maxwidth, M_TEMP, M_WAITOK);
    
    error = copyin(CAST_USER_ADDR_T(data), new_exts, nentries * maxwidth);
    if (error) {
	FREE(new_exts, M_TEMP);
	return error;
    }

    if (extension_table) {
	FREE(extension_table, M_TEMP);
    }
    extension_table = new_exts;
    nexts           = nentries;
    max_ext_width   = maxwidth;

    qsort(extension_table, nexts, maxwidth, extension_cmp);

    return 0;
}


__private_extern__ int
is_package_name(char *name, int len)
{
    int i, extlen;
    char *ptr, *name_ext;
    
    if (len <= 3) {
	return 0;
    }

    name_ext = NULL;
    for(ptr=name; *ptr != '\0'; ptr++) {
	if (*ptr == '.') {
	    name_ext = ptr;
	}
    }

    // if there is no "." extension, it can't match
    if (name_ext == NULL) {
	return 0;
    }

    // advance over the "."
    name_ext++;

    // now iterate over all the extensions to see if any match
    ptr = &extension_table[0];
    for(i=0; i < nexts; i++, ptr+=max_ext_width) {
	extlen = strlen(ptr);
	if (strncasecmp(name_ext, ptr, extlen) == 0 && name_ext[extlen] == '\0') {
	    // aha, a match!
	    return 1;
	}
    }

    // if we get here, no extension matched
    return 0;
}

int
vn_path_package_check(__unused vnode_t vp, char *path, int pathlen, int *component)
{
    char *ptr, *end;
    int comp=0;
    
    *component = -1;
    if (*path != '/') {
	return EINVAL;
    }

    end = path + 1;
    while(end < path + pathlen && *end != '\0') {
	while(end < path + pathlen && *end == '/' && *end != '\0') {
	    end++;
	}

	ptr = end;

	while(end < path + pathlen && *end != '/' && *end != '\0') {
	    end++;
	}

	if (end > path + pathlen) {
	    // hmm, string wasn't null terminated 
	    return EINVAL;
	}

	*end = '\0';
	if (is_package_name(ptr, end - ptr)) {
	    *component = comp;
	    break;
	}

	end++;
	comp++;
    }

    return 0;
}


/*
 * Top level filesystem related information gathering.
 */
extern unsigned int vfs_nummntops;

int
vfs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
           user_addr_t newp, size_t newlen, struct proc *p)
{
	struct vfstable *vfsp;
	int *username;
	u_int usernamelen;
	int error;
	struct vfsconf *vfsc;

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
		return (sysctl_rdint(oldp, oldlenp, newp, vfs_nummntops));
	}

	/* all sysctl names at this level are at least name and field */
	if (namelen < 2)
		return (EISDIR);		/* overloaded */
	if (name[0] != VFS_GENERIC) {
	        struct vfs_context context;

		for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
			if (vfsp->vfc_typenum == name[0])
				break;
		if (vfsp == NULL)
			return (ENOTSUP);
		context.vc_proc = p;
		context.vc_ucred = kauth_cred_get();

		return ((*vfsp->vfc_vfsops->vfs_sysctl)(&name[1], namelen - 1,
		            oldp, oldlenp, newp, newlen, &context));
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
			return (ENOTSUP);
		vfsc = (struct vfsconf *)vfsp;
		if (proc_is64bit(p)) {
		    struct user_vfsconf  usr_vfsc;
		    usr_vfsc.vfc_vfsops = CAST_USER_ADDR_T(vfsc->vfc_vfsops);
	        bcopy(vfsc->vfc_name, usr_vfsc.vfc_name, sizeof(usr_vfsc.vfc_name));
		    usr_vfsc.vfc_typenum = vfsc->vfc_typenum;
		    usr_vfsc.vfc_refcount = vfsc->vfc_refcount;
		    usr_vfsc.vfc_flags = vfsc->vfc_flags;
		    usr_vfsc.vfc_mountroot = CAST_USER_ADDR_T(vfsc->vfc_mountroot);
		    usr_vfsc.vfc_next = CAST_USER_ADDR_T(vfsc->vfc_next);
            return (sysctl_rdstruct(oldp, oldlenp, newp, &usr_vfsc,
                                    sizeof(usr_vfsc)));
		}
		else {
            return (sysctl_rdstruct(oldp, oldlenp, newp, vfsc,
                                    sizeof(struct vfsconf)));
		}
		
	case VFS_SET_PACKAGE_EXTS:
	        return set_package_extensions_table((void *)name[1], name[2], name[3]);
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
	error = userland_sysctl(p, username, usernamelen, oldp, 
	                        oldlenp, 1, newp, newlen, oldlenp);
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
sysctl_vnode(__unused user_addr_t where, __unused size_t *sizep)
{
#if 0
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
		
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
		savebp = bp;
again:
		TAILQ_FOREACH(vp, &mp->mnt_vnodelist, v_mntvnodes) {
			/*
			 * Check that the vp is still associated with
			 * this filesystem.  RACE: could have been
			 * recycled onto the same filesystem.
			 */
			if (vp->v_mount != mp) {
				if (kinfo_vdebug)
					printf("kinfo: vp changed\n");
				bp = savebp;
				goto again;
			}
			if (bp + VPTRSZ + VNODESZ > ewhere) {
				vfs_unbusy(mp);
				*sizep = bp - where;
				return (ENOMEM);
			}
			if ((error = copyout((caddr_t)&vp, bp, VPTRSZ)) ||
			    (error = copyout((caddr_t)vp, bp + VPTRSZ, VNODESZ))) {
				vfs_unbusy(mp);
				return (error);
			}
			bp += VPTRSZ + VNODESZ;
		}
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp);
	}

	*sizep = bp - where;
	return (0);
#else
	return(EINVAL);
#endif
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

	SPECHASH_LOCK();
	if (vp->v_specflags & SI_MOUNTEDON) {
		error = EBUSY;
		goto out;
	}
	if (vp->v_flag & VALIASED) {
		for (vq = *vp->v_hashchain; vq; vq = vq->v_specnext) {
			if (vq->v_rdev != vp->v_rdev ||
			    vq->v_type != vp->v_type)
				continue;
			if (vq->v_specflags & SI_MOUNTEDON) {
				error = EBUSY;
				break;
			}
		}
	}
out:
	SPECHASH_UNLOCK();
	return (error);
}

/*
 * Unmount all filesystems. The list is traversed in reverse order
 * of mounting to avoid dependencies.
 */
__private_extern__ void
vfs_unmountall()
{
	struct mount *mp;
	struct proc *p = current_proc();
	int error;

	/*
	 * Since this only runs when rebooting, it is not interlocked.
	 */
	mount_list_lock();
	while(!TAILQ_EMPTY(&mountlist)) {
		mp = TAILQ_LAST(&mountlist, mntlist);
		mount_list_unlock();
		error = dounmount(mp, MNT_FORCE, p);
		if (error) {
			mount_list_lock();
			TAILQ_REMOVE(&mountlist, mp, mnt_list);
			printf("unmount of %s failed (", mp->mnt_vfsstat.f_mntonname);
			if (error == EBUSY)
				printf("BUSY)\n");
			else
				printf("%d)\n", error);
			continue;
		}
		mount_list_lock();
	}
	mount_list_unlock();
}


/*  
 * This routine is called from vnode_pager_no_senders()
 * which in turn can be called with vnode locked by vnode_uncache()
 * But it could also get called as a result of vm_object_cache_trim().
 * In that case lock state is unknown.
 * AGE the vnode so that it gets recycled quickly.
 */
__private_extern__ void
vnode_pager_vrele(struct vnode *vp)
{
	vnode_lock(vp);

	if (!ISSET(vp->v_lflag, VL_TERMINATE))
		panic("vnode_pager_vrele: vp not in termination");
	vp->v_lflag &= ~VNAMED_UBC;

	if (UBCINFOEXISTS(vp)) {
		struct ubc_info *uip = vp->v_ubcinfo;

		if (ISSET(uip->ui_flags, UI_WASMAPPED))
			SET(vp->v_flag, VWASMAPPED);
		vp->v_ubcinfo = UBC_INFO_NULL;

		ubc_info_deallocate(uip);
	} else {
		panic("NO ubcinfo in vnode_pager_vrele");
	}
	vnode_unlock(vp);

	wakeup(&vp->v_lflag);
}


#include <sys/disk.h>

errno_t
vfs_init_io_attributes(vnode_t devvp, mount_t mp)
{
	int	error;
	off_t	readblockcnt;
	off_t	writeblockcnt;
	off_t	readmaxcnt;
	off_t	writemaxcnt;
	off_t	readsegcnt;
	off_t	writesegcnt;
	off_t	readsegsize;
	off_t	writesegsize;
	u_long 	blksize;
	u_int64_t temp;
	struct vfs_context context;

	proc_t	p = current_proc();

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	int isvirtual = 0;
	/*
	 * determine if this mount point exists on the same device as the root
	 * partition... if so, then it comes under the hard throttle control
	 */
	int        thisunit = -1;
	static int rootunit = -1;

	if (rootunit == -1) {
	        if (VNOP_IOCTL(rootvp, DKIOCGETBSDUNIT, (caddr_t)&rootunit, 0, &context))
		        rootunit = -1; 
		else if (rootvp == devvp)
		        mp->mnt_kern_flag |= MNTK_ROOTDEV;
	}
	if (devvp != rootvp && rootunit != -1) {
	        if (VNOP_IOCTL(devvp, DKIOCGETBSDUNIT, (caddr_t)&thisunit, 0, &context) == 0) {
		        if (thisunit == rootunit)
			        mp->mnt_kern_flag |= MNTK_ROOTDEV;
		}
	}
	/*
	 * force the spec device to re-cache
	 * the underlying block size in case
	 * the filesystem overrode the initial value
	 */
	set_fsblocksize(devvp);


	if ((error = VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE,
				(caddr_t)&blksize, 0, &context)))
		return (error);

	mp->mnt_devblocksize = blksize;

	if (VNOP_IOCTL(devvp, DKIOCISVIRTUAL, (caddr_t)&isvirtual, 0, &context) == 0) {
	        if (isvirtual)
		        mp->mnt_kern_flag |= MNTK_VIRTUALDEV;
	}

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXBLOCKCOUNTREAD,
				(caddr_t)&readblockcnt, 0, &context)))
		return (error);

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXBLOCKCOUNTWRITE,
				(caddr_t)&writeblockcnt, 0, &context)))
		return (error);

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXBYTECOUNTREAD,
				(caddr_t)&readmaxcnt, 0, &context)))
		return (error);

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXBYTECOUNTWRITE,
				(caddr_t)&writemaxcnt, 0, &context)))
		return (error);

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXSEGMENTCOUNTREAD,
				(caddr_t)&readsegcnt, 0, &context)))
		return (error);

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXSEGMENTCOUNTWRITE,
				(caddr_t)&writesegcnt, 0, &context)))
		return (error);

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXSEGMENTBYTECOUNTREAD,
				(caddr_t)&readsegsize, 0, &context)))
		return (error);

	if ((error = VNOP_IOCTL(devvp, DKIOCGETMAXSEGMENTBYTECOUNTWRITE,
				(caddr_t)&writesegsize, 0, &context)))
		return (error);

	if (readmaxcnt)
	        temp = (readmaxcnt > UINT32_MAX) ? UINT32_MAX : readmaxcnt;
	else {
	        if (readblockcnt) {
		        temp = readblockcnt * blksize;
			temp = (temp > UINT32_MAX) ? UINT32_MAX : temp;
		} else
		        temp = MAXPHYS;
	}
	mp->mnt_maxreadcnt = (u_int32_t)temp;

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
	mp->mnt_maxsegreadsize = (u_int32_t)temp;

	if (writesegsize)
	        temp = (writesegsize > UINT32_MAX) ? UINT32_MAX : writesegsize;
	else
	        temp = mp->mnt_maxwritecnt;
	mp->mnt_maxsegwritesize = (u_int32_t)temp;

	return (error);
}

static struct klist fs_klist;

void
vfs_event_init(void)
{

	klist_init(&fs_klist);
}

void
vfs_event_signal(__unused fsid_t *fsid, u_int32_t event, __unused intptr_t data)
{

	KNOTE(&fs_klist, event);
}

/*
 * return the number of mounted filesystems.
 */
static int
sysctl_vfs_getvfscnt(void)
{
	return(mount_getvfscnt());
}


static int
mount_getvfscnt(void)
{
	int ret;

	mount_list_lock();
	ret = nummounts;
	mount_list_unlock();
	return (ret);

}



static int
mount_fillfsids(fsid_t *fsidlst, int count)
{
	struct mount *mp;
	int actual=0;

	actual = 0;
	mount_list_lock();
	TAILQ_FOREACH(mp, &mountlist, mnt_list) {
		if (actual <= count) {
			fsidlst[actual] = mp->mnt_vfsstat.f_fsid;
			actual++;
		}
	}
	mount_list_unlock();
	return (actual);

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
	mount_list_lock();
	TAILQ_FOREACH(mp, &mountlist, mnt_list) {
		(*actual)++;
		if (*actual <= count)
			fsidlst[(*actual) - 1] = mp->mnt_vfsstat.f_fsid;
	}
	mount_list_unlock();
	return (*actual <= count ? 0 : ENOMEM);
}

static int
sysctl_vfs_vfslist SYSCTL_HANDLER_ARGS
{
	int actual, error;
	size_t space;
	fsid_t *fsidlst;

	/* This is a readonly node. */
	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	/* they are querying us so just return the space required. */
	if (req->oldptr == USER_ADDR_NULL) {
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
	struct user_vfsidctl user_vc;
	struct mount *mp;
	struct vfsstatfs *sp;
	struct proc *p;
	int *name;
	int error, flags, namelen;
	struct vfs_context context;
	boolean_t is_64_bit;

	name = arg1;
	namelen = arg2;
	p = req->p;
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	is_64_bit = proc_is64bit(p);

	if (is_64_bit) {
		error = SYSCTL_IN(req, &user_vc, sizeof(user_vc));
		if (error)
			return (error);
		if (user_vc.vc_vers != VFS_CTL_VERS1)
			return (EINVAL);
		mp = mount_list_lookupby_fsid(&user_vc.vc_fsid, 0, 0);
	} 
	else {
		error = SYSCTL_IN(req, &vc, sizeof(vc));
		if (error)
			return (error);
		if (vc.vc_vers != VFS_CTL_VERS1)
			return (EINVAL);
		mp = mount_list_lookupby_fsid(&vc.vc_fsid, 0, 0);
	}
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
		if (is_64_bit) {
			if (vfs_64bitready(mp)) {
				error = mp->mnt_op->vfs_sysctl(name, namelen,
				    CAST_USER_ADDR_T(req),
				    NULL, USER_ADDR_NULL, 0, 
				    &context);
			}
			else {
				error = ENOTSUP;
			}
		}
		else {
			error = mp->mnt_op->vfs_sysctl(name, namelen,
			    CAST_USER_ADDR_T(req),
			    NULL, USER_ADDR_NULL, 0, 
			    &context);
		}
		if (error != ENOTSUP)
			return (error);
	}
	switch (name[0]) {
	case VFS_CTL_UMOUNT:
		req->newidx = 0;
		if (is_64_bit) {
			req->newptr = user_vc.vc_ptr;
			req->newlen = (size_t)user_vc.vc_len;
		}
		else {
			req->newptr = CAST_USER_ADDR_T(vc.vc_ptr);
			req->newlen = vc.vc_len;
		}
		error = SYSCTL_IN(req, &flags, sizeof(flags));
		if (error)
			break;
		error = safedounmount(mp, flags, p);
		break;
	case VFS_CTL_STATFS:
		req->newidx = 0;
		if (is_64_bit) {
			req->newptr = user_vc.vc_ptr;
			req->newlen = (size_t)user_vc.vc_len;
		}
		else {
			req->newptr = CAST_USER_ADDR_T(vc.vc_ptr);
			req->newlen = vc.vc_len;
		}
		error = SYSCTL_IN(req, &flags, sizeof(flags));
		if (error)
			break;
		sp = &mp->mnt_vfsstat;
		if (((flags & MNT_NOWAIT) == 0 || (flags & MNT_WAIT)) &&
		    (error = vfs_update_vfsstat(mp, &context)))
			return (error);
		if (is_64_bit) {
			struct user_statfs sfs;
			bzero(&sfs, sizeof(sfs));
			sfs.f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
			sfs.f_type = mp->mnt_vtable->vfc_typenum;
			sfs.f_bsize = (user_long_t)sp->f_bsize;
			sfs.f_iosize = (user_long_t)sp->f_iosize;
			sfs.f_blocks = (user_long_t)sp->f_blocks;
			sfs.f_bfree = (user_long_t)sp->f_bfree;
			sfs.f_bavail = (user_long_t)sp->f_bavail;
			sfs.f_files = (user_long_t)sp->f_files;
			sfs.f_ffree = (user_long_t)sp->f_ffree;
			sfs.f_fsid = sp->f_fsid;
			sfs.f_owner = sp->f_owner;
    
			strncpy(&sfs.f_fstypename, &sp->f_fstypename, MFSNAMELEN-1);
			strncpy(&sfs.f_mntonname, &sp->f_mntonname, MNAMELEN-1);
			strncpy(&sfs.f_mntfromname, &sp->f_mntfromname, MNAMELEN-1);
            
			error = SYSCTL_OUT(req, &sfs, sizeof(sfs));
		}
		else {
			struct statfs sfs;
			bzero(&sfs, sizeof(struct statfs));
			sfs.f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
			sfs.f_type = mp->mnt_vtable->vfc_typenum;

			/*
			 * It's possible for there to be more than 2^^31 blocks in the filesystem, so we
			 * have to fudge the numbers here in that case.   We inflate the blocksize in order
			 * to reflect the filesystem size as best we can.
			 */
			if (sp->f_blocks > LONG_MAX) {
				int		shift;

				/*
				 * Work out how far we have to shift the block count down to make it fit.
				 * Note that it's possible to have to shift so far that the resulting
				 * blocksize would be unreportably large.  At that point, we will clip
				 * any values that don't fit.
				 *
				 * For safety's sake, we also ensure that f_iosize is never reported as
				 * being smaller than f_bsize.
				 */
				for (shift = 0; shift < 32; shift++) {
					if ((sp->f_blocks >> shift) <= LONG_MAX)
						break;
					if ((sp->f_bsize << (shift + 1)) > LONG_MAX)
						break;
				}
#define __SHIFT_OR_CLIP(x, s)	((((x) >> (s)) > LONG_MAX) ? LONG_MAX : ((x) >> (s)))
				sfs.f_blocks = (long)__SHIFT_OR_CLIP(sp->f_blocks, shift);
				sfs.f_bfree = (long)__SHIFT_OR_CLIP(sp->f_bfree, shift);
				sfs.f_bavail = (long)__SHIFT_OR_CLIP(sp->f_bavail, shift);
#undef __SHIFT_OR_CLIP
				sfs.f_bsize = (long)(sp->f_bsize << shift);
				sfs.f_iosize = lmax(sp->f_iosize, sp->f_bsize);
			} else {
				sfs.f_bsize = (long)sp->f_bsize;
				sfs.f_iosize = (long)sp->f_iosize;
				sfs.f_blocks = (long)sp->f_blocks;
				sfs.f_bfree = (long)sp->f_bfree;
				sfs.f_bavail = (long)sp->f_bavail;
			}
			sfs.f_files = (long)sp->f_files;
			sfs.f_ffree = (long)sp->f_ffree;
			sfs.f_fsid = sp->f_fsid;
			sfs.f_owner = sp->f_owner;
    
			strncpy(&sfs.f_fstypename, &sp->f_fstypename, MFSNAMELEN-1);
			strncpy(&sfs.f_mntonname, &sp->f_mntonname, MNAMELEN-1);
			strncpy(&sfs.f_mntfromname, &sp->f_mntfromname, MNAMELEN-1);
            
			error = SYSCTL_OUT(req, &sfs, sizeof(sfs));
		}
		break;
	default:
		return (ENOTSUP);
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
	if (req->newptr == USER_ADDR_NULL)
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
	if (req->oldptr != USER_ADDR_NULL) {
		out = !((p->p_flag & P_NOREMOTEHANG) == 0);
		error = SYSCTL_OUT(req, &out, sizeof(out));
		return (error);
	}

	/* XXX req->p->p_ucred -> kauth_cred_get() ??? */
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
	
	
int num_reusedvnodes=0;

static int
new_vnode(vnode_t *vpp)
{
	vnode_t	vp;
	int retries = 0;				/* retry incase of tablefull */
	int vpid;
	struct timespec ts;

retry:
	vnode_list_lock();

	if ( !TAILQ_EMPTY(&vnode_free_list)) {
	        /*
		 * Pick the first vp for possible reuse
		 */
	        vp = TAILQ_FIRST(&vnode_free_list);

		if (vp->v_lflag & VL_DEAD)
		        goto steal_this_vp;
	} else
	        vp = NULL;

	/*
	 * we're either empty, or the next guy on the
	 * list is a valid vnode... if we're under the
	 * limit, we'll create a new vnode
	 */
	if (numvnodes < desiredvnodes) {
		numvnodes++;
		vnode_list_unlock();
		MALLOC_ZONE(vp, struct vnode *, sizeof *vp, M_VNODE, M_WAITOK);
		bzero((char *)vp, sizeof *vp);
		VLISTNONE(vp);		/* avoid double queue removal */
		lck_mtx_init(&vp->v_lock, vnode_lck_grp, vnode_lck_attr);

		nanouptime(&ts);
		vp->v_id = ts.tv_nsec;
		vp->v_flag = VSTANDARD;

		goto done;
	}
	if (vp == NULL) {
	        /*
		 * we've reached the system imposed maximum number of vnodes
		 * but there isn't a single one available
		 * wait a bit and then retry... if we can't get a vnode
		 * after 100 retries, than log a complaint
		 */
		if (++retries <= 100) {
			vnode_list_unlock();
			IOSleep(1);
			goto retry;
		}
			
		vnode_list_unlock();
		tablefull("vnode");
		log(LOG_EMERG, "%d desired, %d numvnodes, "
			"%d free, %d inactive\n",
			desiredvnodes, numvnodes, freevnodes, inactivevnodes);
		*vpp = 0;
		return (ENFILE);
	}
steal_this_vp:
	vpid = vp->v_id;

	VREMFREE("new_vnode", vp);
	VLISTNONE(vp);

	vnode_list_unlock();
	vnode_lock(vp);

	/* 
	 * We could wait for the vnode_lock after removing the vp from the freelist
	 * and the vid is bumped only at the very end of reclaim. So it is  possible
	 * that we are looking at a vnode that is being terminated. If so skip it.
	 */ 
	if ((vpid != vp->v_id) || (vp->v_usecount != 0) || (vp->v_iocount != 0) || 
			VONLIST(vp) || (vp->v_lflag & VL_TERMINATE)) {
		/*
		 * we lost the race between dropping the list lock
		 * and picking up the vnode_lock... someone else
		 * used this vnode and it is now in a new state
		 * so we need to go back and try again
		 */
		vnode_unlock(vp);
		goto retry;
	}
	if ( (vp->v_lflag & (VL_NEEDINACTIVE | VL_MARKTERM)) == VL_NEEDINACTIVE ) {
	        /*
		 * we did a vnode_rele_ext that asked for
		 * us not to reenter the filesystem during
		 * the release even though VL_NEEDINACTIVE was
		 * set... we'll do it here by doing a
		 * vnode_get/vnode_put
		 *
		 * pick up an iocount so that we can call
		 * vnode_put and drive the VNOP_INACTIVE...
		 * vnode_put will either leave us off 
		 * the freelist if a new ref comes in,
		 * or put us back on the end of the freelist
		 * or recycle us if we were marked for termination...
		 * so we'll just go grab a new candidate
		 */
	        vp->v_iocount++;
#ifdef JOE_DEBUG
		record_vp(vp, 1);
#endif
		vnode_put_locked(vp);
		vnode_unlock(vp);
		goto retry;
	}
	OSAddAtomic(1, &num_reusedvnodes);

	/* Checks for anyone racing us for recycle */ 
	if (vp->v_type != VBAD) {
		if (vp->v_lflag & VL_DEAD)
			panic("new_vnode: the vnode is VL_DEAD but not VBAD");

		(void)vnode_reclaim_internal(vp, 1, 1);

		if ((VONLIST(vp)))
		        panic("new_vnode: vp on list ");
		if (vp->v_usecount || vp->v_iocount || vp->v_kusecount ||
		    (vp->v_lflag & (VNAMED_UBC | VNAMED_MOUNT | VNAMED_FSHASH)))
		        panic("new_vnode: free vnode still referenced\n");
		if ((vp->v_mntvnodes.tqe_prev != 0) && (vp->v_mntvnodes.tqe_next != 0))
		        panic("new_vnode: vnode seems to be on mount list ");
		if ( !LIST_EMPTY(&vp->v_nclinks) || !LIST_EMPTY(&vp->v_ncchildren))
		        panic("new_vnode: vnode still hooked into the name cache");
	}
	if (vp->v_unsafefs) {
	        lck_mtx_destroy(&vp->v_unsafefs->fsnodelock, vnode_lck_grp);
		FREE_ZONE((void *)vp->v_unsafefs, sizeof(struct unsafe_fsnode), M_UNSAFEFS);
		vp->v_unsafefs = (struct unsafe_fsnode *)NULL;
	}
	vp->v_lflag = 0;
	vp->v_writecount = 0;
        vp->v_references = 0;
	vp->v_iterblkflags = 0;
	vp->v_flag = VSTANDARD;
	/* vbad vnodes can point to dead_mountp */
	vp->v_mount = 0;
	vp->v_defer_reclaimlist = (vnode_t)0;

	vnode_unlock(vp);
done:
	*vpp = vp;

	return (0);
}

void
vnode_lock(vnode_t vp)
{
	lck_mtx_lock(&vp->v_lock);
}

void
vnode_unlock(vnode_t vp)
{
	lck_mtx_unlock(&vp->v_lock);
}



int
vnode_get(struct vnode *vp)
{
        vnode_lock(vp);

	if ( (vp->v_iocount == 0) && (vp->v_lflag & (VL_TERMINATE | VL_DEAD)) ) {
	        vnode_unlock(vp);
		return(ENOENT);	
	}
	vp->v_iocount++;
#ifdef JOE_DEBUG
	record_vp(vp, 1);
#endif
	vnode_unlock(vp);

	return(0);	
}

int
vnode_getwithvid(vnode_t vp, int vid)
{
        return(vget_internal(vp, vid, ( VNODE_NODEAD| VNODE_WITHID)));
}

int
vnode_getwithref(vnode_t vp)
{
        return(vget_internal(vp, 0, 0));
}


int
vnode_put(vnode_t vp)
{
        int retval;

	vnode_lock(vp);
	retval = vnode_put_locked(vp);
	vnode_unlock(vp);

	return(retval);
}

int
vnode_put_locked(vnode_t vp)
{
	struct vfs_context context;

retry:
	if (vp->v_iocount < 1) 
		panic("vnode_put(%x): iocount < 1", vp);

	if ((vp->v_usecount > 0) || (vp->v_iocount > 1))  {
		vnode_dropiocount(vp, 1);
		return(0);
	}
	if ((vp->v_lflag & (VL_MARKTERM | VL_TERMINATE | VL_DEAD | VL_NEEDINACTIVE)) == VL_NEEDINACTIVE) {

	        vp->v_lflag &= ~VL_NEEDINACTIVE;
	        vnode_unlock(vp);

		context.vc_proc = current_proc();
		context.vc_ucred = kauth_cred_get();
		VNOP_INACTIVE(vp, &context);

		vnode_lock(vp);
		/*
		 * because we had to drop the vnode lock before calling
		 * VNOP_INACTIVE, the state of this vnode may have changed...
		 * we may pick up both VL_MARTERM and either
		 * an iocount or a usecount while in the VNOP_INACTIVE call
		 * we don't want to call vnode_reclaim_internal on a vnode
		 * that has active references on it... so loop back around
		 * and reevaluate the state
		 */
		goto retry;
	}
        vp->v_lflag &= ~VL_NEEDINACTIVE;

	if ((vp->v_lflag & (VL_MARKTERM | VL_TERMINATE | VL_DEAD)) == VL_MARKTERM)
	        vnode_reclaim_internal(vp, 1, 0);

	vnode_dropiocount(vp, 1);
	vnode_list_add(vp);

	return(0);
}

/* is vnode_t in use by others?  */
int 
vnode_isinuse(vnode_t vp, int refcnt)
{
	return(vnode_isinuse_locked(vp, refcnt, 0));
}


static int 
vnode_isinuse_locked(vnode_t vp, int refcnt, int locked)
{
	int retval = 0;

	if (!locked)
		vnode_lock(vp);
	if ((vp->v_type != VREG) && (vp->v_usecount >  refcnt)) {
		retval = 1;
		goto out;
	}
	if (vp->v_type == VREG)  {
		retval = ubc_isinuse_locked(vp, refcnt, 1);
	}
		
out:
	if (!locked)
		vnode_unlock(vp);
	return(retval);
}


/* resume vnode_t */
errno_t 
vnode_resume(vnode_t vp)
{

	vnode_lock(vp);

	if (vp->v_owner == current_thread()) {
	        vp->v_lflag &= ~VL_SUSPENDED;
		vp->v_owner = 0;
		vnode_unlock(vp);
		wakeup(&vp->v_iocount);
	} else
	        vnode_unlock(vp);

	return(0);
}

static errno_t 
vnode_drain(vnode_t vp)
{
	
	if (vp->v_lflag & VL_DRAIN) {
		panic("vnode_drain: recursuve drain");
		return(ENOENT);
	}
	vp->v_lflag |= VL_DRAIN;
	vp->v_owner = current_thread();

	while (vp->v_iocount > 1)
		msleep(&vp->v_iocount, &vp->v_lock, PVFS, "vnode_drain", 0);
	return(0);
}


/*
 * if the number of recent references via vnode_getwithvid or vnode_getwithref
 * exceeds this threshhold, than 'UN-AGE' the vnode by removing it from
 * the LRU list if it's currently on it... once the iocount and usecount both drop
 * to 0, it will get put back on the end of the list, effectively making it younger
 * this allows us to keep actively referenced vnodes in the list without having
 * to constantly remove and add to the list each time a vnode w/o a usecount is
 * referenced which costs us taking and dropping a global lock twice.
 */
#define UNAGE_THRESHHOLD	10

errno_t
vnode_getiocount(vnode_t vp, int locked, int vid, int vflags)
{
	int nodead = vflags & VNODE_NODEAD;
	int nosusp = vflags & VNODE_NOSUSPEND;

	if (!locked)
		vnode_lock(vp);

	for (;;) {
		/*
		 * if it is a dead vnode with deadfs
		 */
		if (nodead && (vp->v_lflag & VL_DEAD) && ((vp->v_type == VBAD) || (vp->v_data == 0))) {
			if (!locked)
				vnode_unlock(vp);
			return(ENOENT);
		}
		/*
		 * will return VL_DEAD ones
		 */
		if ((vp->v_lflag & (VL_SUSPENDED | VL_DRAIN | VL_TERMINATE)) == 0 ) {
			break;
		}
		/*
		 * if suspended vnodes are to be failed
		 */
		if (nosusp && (vp->v_lflag & VL_SUSPENDED)) {
			if (!locked)
				vnode_unlock(vp);
			return(ENOENT);
		}
		/*
		 * if you are the owner of drain/suspend/termination , can acquire iocount
		 * check for VL_TERMINATE; it does not set owner
		 */
		if ((vp->v_lflag & (VL_DRAIN | VL_SUSPENDED | VL_TERMINATE)) &&
		    (vp->v_owner == current_thread())) {
		        break;
		}
		if (vp->v_lflag & VL_TERMINATE) {
			vp->v_lflag |= VL_TERMWANT;

			msleep(&vp->v_lflag,   &vp->v_lock, PVFS, "vnode getiocount", 0);
		} else
			msleep(&vp->v_iocount, &vp->v_lock, PVFS, "vnode_getiocount", 0);
	}
	if (vid != vp->v_id) {
		if (!locked)
			vnode_unlock(vp);
		return(ENOENT);
	}
	if (++vp->v_references >= UNAGE_THRESHHOLD) {
	        vp->v_references = 0;
		vnode_list_remove(vp);
	}
	vp->v_iocount++;
#ifdef JOE_DEBUG
	record_vp(vp, 1);
#endif
	if (!locked)
	        vnode_unlock(vp);
	return(0);	
}

static void
vnode_dropiocount (vnode_t vp, int locked)
{
	if (!locked)
		vnode_lock(vp);
	if (vp->v_iocount < 1)
		panic("vnode_dropiocount(%x): v_iocount < 1", vp);

	vp->v_iocount--;
#ifdef JOE_DEBUG
	record_vp(vp, -1);
#endif
	if ((vp->v_lflag & (VL_DRAIN | VL_SUSPENDED)) && (vp->v_iocount <= 1))
		wakeup(&vp->v_iocount);

	if (!locked)
		vnode_unlock(vp);
}


void
vnode_reclaim(struct vnode * vp)
{
	vnode_reclaim_internal(vp, 0, 0);
}

__private_extern__
void
vnode_reclaim_internal(struct vnode * vp, int locked, int reuse)
{
	int isfifo = 0;

	if (!locked)
		vnode_lock(vp);

	if (vp->v_lflag & VL_TERMINATE) {
		panic("vnode reclaim in progress");
	}
	vp->v_lflag |= VL_TERMINATE;

	if (vnode_drain(vp)) {
		panic("vnode drain failed");
		vnode_unlock(vp);
		return;
	}
	isfifo = (vp->v_type == VFIFO);

	if (vp->v_type != VBAD)
		vgone(vp);		/* clean and reclaim the vnode */

	/*
	 * give the vnode a new identity so
	 * that vnode_getwithvid will fail
	 * on any stale cache accesses
	 */
	vp->v_id++;
	if (isfifo) {
		struct fifoinfo * fip;

		fip = vp->v_fifoinfo;
		vp->v_fifoinfo = NULL;
		FREE(fip, M_TEMP);
	}

	vp->v_type = VBAD;

	if (vp->v_data)
		panic("vnode_reclaim_internal: cleaned vnode isn't");
	if (vp->v_numoutput)
		panic("vnode_reclaim_internal: Clean vnode has pending I/O's");
	if (UBCINFOEXISTS(vp))
		panic("vnode_reclaim_internal: ubcinfo not cleaned");
	if (vp->v_parent)
	        panic("vnode_reclaim_internal: vparent not removed");
	if (vp->v_name)
	        panic("vnode_reclaim_internal: vname not removed");

	vp->v_socket = 0;

	vp->v_lflag &= ~VL_TERMINATE;
	vp->v_lflag &= ~VL_DRAIN;
	vp->v_owner = 0;

	if (vp->v_lflag & VL_TERMWANT) {
		vp->v_lflag &= ~VL_TERMWANT;
		wakeup(&vp->v_lflag);
	}
	if (!reuse && vp->v_usecount == 0)
	        vnode_list_add(vp);
	if (!locked)
	        vnode_unlock(vp);
}

/* USAGE:
 * The following api creates a vnode and associates all the parameter specified in vnode_fsparam
 * structure and returns a vnode handle with a reference. device aliasing is handled here so checkalias
 * is obsoleted by this.
 *  vnode_create(int flavor, size_t size, void * param,  vnode_t  *vp)
 */
int  
vnode_create(int flavor, size_t size, void *data, vnode_t *vpp)
{
	int error;
	int insert = 1;
	vnode_t vp;
	vnode_t nvp;
	vnode_t dvp;
	struct componentname *cnp;
	struct vnode_fsparam *param = (struct vnode_fsparam *)data;
	
	if (flavor == VNCREATE_FLAVOR && (size == VCREATESIZE) && param) {
		if ( (error = new_vnode(&vp)) ) {
			return(error);
		} else {
			dvp = param->vnfs_dvp;
			cnp = param->vnfs_cnp;

			vp->v_op = param->vnfs_vops;
			vp->v_type = param->vnfs_vtype;
			vp->v_data = param->vnfs_fsnode;
			vp->v_iocount = 1;

			if (param->vnfs_markroot)
				vp->v_flag |= VROOT;
			if (param->vnfs_marksystem)
				vp->v_flag |= VSYSTEM;
			else if (vp->v_type == VREG) {
				/*
				 * only non SYSTEM vp
				 */
				error = ubc_info_init_withsize(vp, param->vnfs_filesize);
				if (error) {
#ifdef JOE_DEBUG
				        record_vp(vp, 1);
#endif
					vp->v_mount = 0;
					vp->v_op = dead_vnodeop_p;
					vp->v_tag = VT_NON;
					vp->v_data = NULL;
					vp->v_type = VBAD;
					vp->v_lflag |= VL_DEAD;

					vnode_put(vp);
					return(error);
				}
			}
#ifdef JOE_DEBUG
			record_vp(vp, 1);
#endif
			if (vp->v_type == VCHR || vp->v_type == VBLK) {
                
				if ( (nvp = checkalias(vp, param->vnfs_rdev)) ) {
				        /*
					 * if checkalias returns a vnode, it will be locked
					 *
					 * first get rid of the unneeded vnode we acquired
					 */
					vp->v_data = NULL;
					vp->v_op = spec_vnodeop_p;
					vp->v_type = VBAD;
					vp->v_lflag = VL_DEAD;
					vp->v_data = NULL; 
					vp->v_tag = VT_NON;
					vnode_put(vp);

					/*
					 * switch to aliased vnode and finish
					 * preparing it
					 */
					vp = nvp;

					vclean(vp, 0, current_proc());
					vp->v_op = param->vnfs_vops;
					vp->v_type = param->vnfs_vtype;
					vp->v_data = param->vnfs_fsnode;
					vp->v_lflag = 0;
					vp->v_mount = NULL;
					insmntque(vp, param->vnfs_mp);
					insert = 0;
					vnode_unlock(vp);
				}
			}

			if (vp->v_type == VFIFO) {
				struct fifoinfo *fip;

				MALLOC(fip, struct fifoinfo *,
					sizeof(*fip), M_TEMP, M_WAITOK);
				bzero(fip, sizeof(struct fifoinfo ));
				vp->v_fifoinfo = fip;
			}
			/* The file systems usually pass the address of the location where
			 * where there store  the vnode pointer. When we add the vnode in mount
			 * point and name cache they are discoverable. So the file system node
			 * will have the connection to vnode setup by then
			 */
			*vpp = vp;

			if (param->vnfs_mp) {
					if (param->vnfs_mp->mnt_kern_flag & MNTK_LOCK_LOCAL)
						vp->v_flag |= VLOCKLOCAL;
			        if (insert) {
				        /*
					 * enter in mount vnode list
					 */
				        insmntque(vp, param->vnfs_mp);
				}
#ifdef INTERIM_FSNODE_LOCK	
				if (param->vnfs_mp->mnt_vtable->vfc_threadsafe == 0) {
				        MALLOC_ZONE(vp->v_unsafefs, struct unsafe_fsnode *,
						    sizeof(struct unsafe_fsnode), M_UNSAFEFS, M_WAITOK);
					vp->v_unsafefs->fsnode_count = 0;
					vp->v_unsafefs->fsnodeowner  = (void *)NULL;
					lck_mtx_init(&vp->v_unsafefs->fsnodelock, vnode_lck_grp, vnode_lck_attr);
				}
#endif /* INTERIM_FSNODE_LOCK */
			}
			if (dvp && vnode_ref(dvp) == 0) {
				vp->v_parent = dvp;
			}
			if (cnp) {
				if (dvp && ((param->vnfs_flags & (VNFS_NOCACHE | VNFS_CANTCACHE)) == 0)) {
					/*
					 * enter into name cache
					 * we've got the info to enter it into the name cache now
					 */
					cache_enter(dvp, vp, cnp);
				}
				vp->v_name = vfs_addname(cnp->cn_nameptr, cnp->cn_namelen, cnp->cn_hash, 0);
			}
			if ((param->vnfs_flags & VNFS_CANTCACHE) == 0) {
			        /*
				 * this vnode is being created as cacheable in the name cache
				 * this allows us to re-enter it in the cache
				 */
			        vp->v_flag |= VNCACHEABLE;
			}
			if ((vp->v_flag & VSYSTEM) && (vp->v_type != VREG))
			        panic("incorrect vnode setup");

			return(0);
		}
	}
	return (EINVAL);
}

int
vnode_addfsref(vnode_t vp)
{
	vnode_lock(vp);
	if (vp->v_lflag & VNAMED_FSHASH)
		panic("add_fsref: vp already has named reference");
	if ((vp->v_freelist.tqe_prev != (struct vnode **)0xdeadb))
	        panic("addfsref: vp on the free list\n");
	vp->v_lflag |= VNAMED_FSHASH;
	vnode_unlock(vp);
	return(0);

}
int
vnode_removefsref(vnode_t vp)
{
	vnode_lock(vp);
	if ((vp->v_lflag & VNAMED_FSHASH) == 0)
		panic("remove_fsref: no named reference");
	vp->v_lflag &= ~VNAMED_FSHASH;
	vnode_unlock(vp);
	return(0);

}


int
vfs_iterate(__unused int flags, int (*callout)(mount_t, void *), void *arg)
{
	mount_t	mp;
	int ret = 0;
	fsid_t * fsid_list;
	int count, actualcount,  i;
	void * allocmem;

	count = mount_getvfscnt();
	count += 10;

	fsid_list = (fsid_t *)kalloc(count * sizeof(fsid_t));
	allocmem = (void *)fsid_list;

	actualcount = mount_fillfsids(fsid_list, count);

	for (i=0; i< actualcount; i++) {

		/* obtain the mount point with iteration reference */
		mp = mount_list_lookupby_fsid(&fsid_list[i], 0, 1);

		if(mp == (struct mount *)0)
			continue;
		mount_lock(mp);
		if (mp->mnt_lflag & (MNT_LDEAD | MNT_LUNMOUNT)) {
			mount_unlock(mp);
			mount_iterdrop(mp);
			continue;
		
		}
		mount_unlock(mp);

		/* iterate over all the vnodes */
		ret = callout(mp, arg);

		mount_iterdrop(mp);

		switch (ret) {
		case VFS_RETURNED:
		case VFS_RETURNED_DONE:
			if (ret == VFS_RETURNED_DONE) {
				ret = 0;
				goto out;
			}
			break;

		case VFS_CLAIMED_DONE:
			ret = 0;
			goto out;
		case VFS_CLAIMED:
		default:
			break;
		}
		ret = 0;
	}

out:
	kfree(allocmem, (count * sizeof(fsid_t)));
	return (ret);
}

/*
 * Update the vfsstatfs structure in the mountpoint.
 */
int
vfs_update_vfsstat(mount_t mp, vfs_context_t ctx)
{
	struct vfs_attr	va;
	int		error;

	/*
	 * Request the attributes we want to propagate into
	 * the per-mount vfsstat structure.
	 */
	VFSATTR_INIT(&va);
	VFSATTR_WANTED(&va, f_iosize);
	VFSATTR_WANTED(&va, f_blocks);
	VFSATTR_WANTED(&va, f_bfree);
	VFSATTR_WANTED(&va, f_bavail);
	VFSATTR_WANTED(&va, f_bused);
	VFSATTR_WANTED(&va, f_files);
	VFSATTR_WANTED(&va, f_ffree);
	VFSATTR_WANTED(&va, f_bsize);
	VFSATTR_WANTED(&va, f_fssubtype);
	if ((error = vfs_getattr(mp, &va, ctx)) != 0) {
		KAUTH_DEBUG("STAT - filesystem returned error %d", error);
		return(error);
	}

	/*
	 * Unpack into the per-mount structure.
	 *
	 * We only overwrite these fields, which are likely to change:
	 *	f_blocks
	 *	f_bfree
	 *	f_bavail
	 *	f_bused
	 *	f_files
	 *	f_ffree
	 *
	 * And these which are not, but which the FS has no other way
	 * of providing to us:
	 *	f_bsize
	 *	f_iosize
	 *	f_fssubtype
	 *
	 */
	if (VFSATTR_IS_SUPPORTED(&va, f_bsize)) {
		mp->mnt_vfsstat.f_bsize = va.f_bsize;
	} else {
		mp->mnt_vfsstat.f_bsize = mp->mnt_devblocksize;	/* default from the device block size */
	}
	if (VFSATTR_IS_SUPPORTED(&va, f_iosize)) {
		mp->mnt_vfsstat.f_iosize = va.f_iosize;
	} else {
		mp->mnt_vfsstat.f_iosize = 1024 * 1024;		/* 1MB sensible I/O size */
	}
	if (VFSATTR_IS_SUPPORTED(&va, f_blocks))
		mp->mnt_vfsstat.f_blocks = va.f_blocks;
	if (VFSATTR_IS_SUPPORTED(&va, f_bfree))
		mp->mnt_vfsstat.f_bfree = va.f_bfree;
	if (VFSATTR_IS_SUPPORTED(&va, f_bavail))
		mp->mnt_vfsstat.f_bavail = va.f_bavail;
	if (VFSATTR_IS_SUPPORTED(&va, f_bused))
		mp->mnt_vfsstat.f_bused = va.f_bused;
	if (VFSATTR_IS_SUPPORTED(&va, f_files))
		mp->mnt_vfsstat.f_files = va.f_files;
	if (VFSATTR_IS_SUPPORTED(&va, f_ffree))
		mp->mnt_vfsstat.f_ffree = va.f_ffree;

	/* this is unlikely to change, but has to be queried for */
	if (VFSATTR_IS_SUPPORTED(&va, f_fssubtype))
		mp->mnt_vfsstat.f_fssubtype = va.f_fssubtype;

	return(0);
}

void 
mount_list_add(mount_t mp)
{
	mount_list_lock();
	TAILQ_INSERT_TAIL(&mountlist, mp, mnt_list);	
	nummounts++;
	mount_list_unlock();
}

void
mount_list_remove(mount_t mp)
{
	mount_list_lock();
	TAILQ_REMOVE(&mountlist, mp, mnt_list);
	nummounts--;
	mp->mnt_list.tqe_next = 0;
	mp->mnt_list.tqe_prev = 0;
	mount_list_unlock();
}

mount_t
mount_lookupby_volfsid(int volfs_id, int withref)
{
	mount_t cur_mount = (mount_t)0;
	mount_t mp ;

	mount_list_lock();
	TAILQ_FOREACH(mp, &mountlist, mnt_list) { 
		if (validfsnode(mp) && mp->mnt_vfsstat.f_fsid.val[0] == volfs_id) {
            cur_mount = mp;
			if (withref) {
				if (mount_iterref(cur_mount, 1))  {
					cur_mount = (mount_t)0;
					mount_list_unlock();
					goto out;
				}
			}
            break;
          }
	}
	mount_list_unlock();
	if (withref && (cur_mount != (mount_t)0)) {
		mp = cur_mount;
		if (vfs_busy(mp, LK_NOWAIT) != 0) {
			cur_mount = (mount_t)0;
        } 
		mount_iterdrop(mp);
	}
out:
	return(cur_mount);
}


mount_t 
mount_list_lookupby_fsid(fsid, locked, withref)
	fsid_t *fsid;
	int locked;
	int withref;
{
	mount_t retmp = (mount_t)0;
	mount_t mp;

	if (!locked)
		mount_list_lock();
	TAILQ_FOREACH(mp, &mountlist, mnt_list) 
		if (mp->mnt_vfsstat.f_fsid.val[0] == fsid->val[0] &&
		    mp->mnt_vfsstat.f_fsid.val[1] == fsid->val[1]) {
			retmp = mp;
			if (withref) {
				if (mount_iterref(retmp, 1)) 
					retmp = (mount_t)0;
			}
			goto out;
		}
out:
	if (!locked)
		mount_list_unlock();
	return (retmp);
}

errno_t
vnode_lookup(const char *path, int flags, vnode_t *vpp, vfs_context_t context)
{
	struct nameidata nd;
	int error;
	struct vfs_context context2;
	vfs_context_t ctx = context;
	u_long ndflags = 0;

	if (context == NULL) {		/* XXX technically an error */
		context2.vc_proc = current_proc();
		context2.vc_ucred = kauth_cred_get();
		ctx = &context2;
	}

	if (flags & VNODE_LOOKUP_NOFOLLOW)
		ndflags = NOFOLLOW;
	else
		ndflags = FOLLOW;

	if (flags & VNODE_LOOKUP_NOCROSSMOUNT)
		ndflags |= NOCROSSMOUNT;
	if (flags & VNODE_LOOKUP_DOWHITEOUT)
		ndflags |= DOWHITEOUT;

	/* XXX AUDITVNPATH1 needed ? */
	NDINIT(&nd, LOOKUP, ndflags, UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);

	if ((error = namei(&nd)))
		return (error);
	*vpp = nd.ni_vp;
	nameidone(&nd);
	
	return (0);
}

errno_t
vnode_open(const char *path, int fmode, int cmode, int flags, vnode_t *vpp, vfs_context_t context)
{
	struct nameidata nd;
	int error;
	struct vfs_context context2;
	vfs_context_t ctx = context;
	u_long ndflags = 0;

	if (context == NULL) {		/* XXX technically an error */
		context2.vc_proc = current_proc();
		context2.vc_ucred = kauth_cred_get();
		ctx = &context2;
	}

	if (flags & VNODE_LOOKUP_NOFOLLOW)
		ndflags = NOFOLLOW;
	else
		ndflags = FOLLOW;

	if (flags & VNODE_LOOKUP_NOCROSSMOUNT)
		ndflags |= NOCROSSMOUNT;
	if (flags & VNODE_LOOKUP_DOWHITEOUT)
		ndflags |= DOWHITEOUT;
	
	/* XXX AUDITVNPATH1 needed ? */
	NDINIT(&nd, LOOKUP, ndflags, UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);

	if ((error = vn_open(&nd, fmode, cmode)))
		*vpp = NULL;
	else
		*vpp = nd.ni_vp;
	
	return (error);
}

errno_t
vnode_close(vnode_t vp, int flags, vfs_context_t context)
{
	kauth_cred_t cred;
	struct proc *p;
	int error;

	if (context) {
		p = context->vc_proc;
		cred = context->vc_ucred;
	} else {
		p = current_proc();
		cred = kauth_cred_get();
	}
	
	error = vn_close(vp, flags, cred, p);
	vnode_put(vp);
	return (error);
}

errno_t
vnode_size(vnode_t vp, off_t *sizep, vfs_context_t ctx)
{
	struct vnode_attr	va;
	int			error;

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_data_size);
	error = vnode_getattr(vp, &va, ctx);
	if (!error)
		*sizep = va.va_data_size;
	return(error);
}

errno_t
vnode_setsize(vnode_t vp, off_t size, int ioflag, vfs_context_t ctx)
{
	struct vnode_attr	va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_data_size, size);
	va.va_vaflags = ioflag & 0xffff;
	return(vnode_setattr(vp, &va, ctx));
}

errno_t
vn_create(vnode_t dvp, vnode_t *vpp, struct componentname *cnp, struct vnode_attr *vap, int flags, vfs_context_t ctx)
{
	kauth_acl_t oacl, nacl;
	int initial_acl;
	errno_t	error;
	vnode_t vp = (vnode_t)0;

	error = 0;
	oacl = nacl = NULL;
	initial_acl = 0;

	KAUTH_DEBUG("%p    CREATE - '%s'", dvp, cnp->cn_nameptr);

	/*
	 * Handle ACL inheritance.
	 */
	if (!(flags & VN_CREATE_NOINHERIT) && vfs_extendedsecurity(dvp->v_mount)) {
		/* save the original filesec */
		if (VATTR_IS_ACTIVE(vap, va_acl)) {
			initial_acl = 1;
			oacl = vap->va_acl;
		}

		vap->va_acl = NULL;
		if ((error = kauth_acl_inherit(dvp,
			 oacl,
			 &nacl,
			 vap->va_type == VDIR,
			 ctx)) != 0) {
			KAUTH_DEBUG("%p    CREATE - error %d processing inheritance", dvp, error);
			return(error);
		}

		/*
		 * If the generated ACL is NULL, then we can save ourselves some effort
		 * by clearing the active bit.
		 */
		if (nacl == NULL) {
			VATTR_CLEAR_ACTIVE(vap, va_acl);
		} else {
			VATTR_SET(vap, va_acl, nacl);
		}
	}
	
	/*
	 * Check and default new attributes.
	 * This will set va_uid, va_gid, va_mode and va_create_time at least, if the caller
	 * hasn't supplied them.
	 */
	if ((error = vnode_authattr_new(dvp, vap, flags & VN_CREATE_NOAUTH, ctx)) != 0) {
		KAUTH_DEBUG("%p    CREATE - error %d handing/defaulting attributes", dvp, error);
		goto out;
	}

		
	/*
	 * Create the requested node.
	 */
	switch(vap->va_type) {
	case VREG:
		error = VNOP_CREATE(dvp, vpp, cnp, vap, ctx);
		break;
	case VDIR:
		error = VNOP_MKDIR(dvp, vpp, cnp, vap, ctx);
		break;
	case VSOCK:
	case VFIFO:
	case VBLK:
	case VCHR:
		error = VNOP_MKNOD(dvp, vpp, cnp, vap, ctx);
		break;
	default:
		panic("vnode_create: unknown vtype %d", vap->va_type);
	}
	if (error != 0) {
		KAUTH_DEBUG("%p    CREATE - error %d returned by filesystem", dvp, error);
		goto out;
	}

	vp = *vpp;
	/*
	 * If some of the requested attributes weren't handled by the VNOP,
	 * use our fallback code.
	 */
	if (!VATTR_ALL_SUPPORTED(vap) && *vpp) {
		KAUTH_DEBUG("     CREATE - doing fallback with ACL %p", vap->va_acl);
		error = vnode_setattr_fallback(*vpp, vap, ctx);
	}
	if ((error != 0 ) && (vp != (vnode_t)0)) {
		*vpp = (vnode_t) 0;
		vnode_put(vp);
	}

out:
	/*
	 * If the caller supplied a filesec in vap, it has been replaced
	 * now by the post-inheritance copy.  We need to put the original back
	 * and free the inherited product.
	 */
	if (initial_acl) {
		VATTR_SET(vap, va_acl, oacl);
	} else {
		VATTR_CLEAR_ACTIVE(vap, va_acl);
	}
	if (nacl != NULL)
		kauth_acl_free(nacl);

	return(error);
}

static kauth_scope_t	vnode_scope;
static int	vnode_authorize_callback(kauth_cred_t credential, __unused void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

typedef struct _vnode_authorize_context {
	vnode_t		vp;
	struct vnode_attr *vap;
	vnode_t		dvp;
	struct vnode_attr *dvap;
	vfs_context_t	ctx;
	int		flags;
	int		flags_valid;
#define _VAC_IS_OWNER		(1<<0)
#define _VAC_IN_GROUP		(1<<1)
#define _VAC_IS_DIR_OWNER	(1<<2)
#define _VAC_IN_DIR_GROUP	(1<<3)
} *vauth_ctx;

void
vnode_authorize_init(void)
{
	vnode_scope = kauth_register_scope(KAUTH_SCOPE_VNODE, vnode_authorize_callback, NULL);
}

/*
 * Authorize an operation on a vnode.
 *
 * This is KPI, but here because it needs vnode_scope.
 */
int
vnode_authorize(vnode_t vp, vnode_t dvp, kauth_action_t action, vfs_context_t context)
{
	int	error, result;

	/*
	 * We can't authorize against a dead vnode; allow all operations through so that
	 * the correct error can be returned.
	 */
	if (vp->v_type == VBAD)
		return(0);
	
	error = 0;
	result = kauth_authorize_action(vnode_scope, vfs_context_ucred(context), action,
		   (uintptr_t)context, (uintptr_t)vp, (uintptr_t)dvp, (uintptr_t)&error);
	if (result == EPERM)		/* traditional behaviour */
		result = EACCES;
	/* did the lower layers give a better error return? */
	if ((result != 0) && (error != 0))
		return(error);
	return(result);
}

/*
 * Test for vnode immutability.
 *
 * The 'append' flag is set when the authorization request is constrained
 * to operations which only request the right to append to a file.
 *
 * The 'ignore' flag is set when an operation modifying the immutability flags
 * is being authorized.  We check the system securelevel to determine which
 * immutability flags we can ignore.
 */
static int
vnode_immutable(struct vnode_attr *vap, int append, int ignore)
{
	int	mask;

	/* start with all bits precluding the operation */
	mask = IMMUTABLE | APPEND;

	/* if appending only, remove the append-only bits */
	if (append)
		mask &= ~APPEND;

	/* ignore only set when authorizing flags changes */
	if (ignore) {
		if (securelevel <= 0) {
			/* in insecure state, flags do not inhibit changes */
			mask = 0;
		} else {
			/* in secure state, user flags don't inhibit */
			mask &= ~(UF_IMMUTABLE | UF_APPEND);
		}
	}
	KAUTH_DEBUG("IMMUTABLE - file flags 0x%x mask 0x%x append = %d ignore = %d", vap->va_flags, mask, append, ignore);
	if ((vap->va_flags & mask) != 0)
		return(EPERM);
	return(0);
}

static int
vauth_node_owner(struct vnode_attr *vap, kauth_cred_t cred)
{
	int result;

	/* default assumption is not-owner */
	result = 0;

	/*
	 * If the filesystem has given us a UID, we treat this as authoritative.
	 */
	if (vap && VATTR_IS_SUPPORTED(vap, va_uid)) {
		result = (vap->va_uid == kauth_cred_getuid(cred)) ? 1 : 0;
	}
	/* we could test the owner UUID here if we had a policy for it */
	
	return(result);
}

static int
vauth_node_group(struct vnode_attr *vap, kauth_cred_t cred, int *ismember)
{
	int	error;
	int	result;

	error = 0;
	result = 0;

	/* the caller is expected to have asked the filesystem for a group at some point */
	if (vap && VATTR_IS_SUPPORTED(vap, va_gid)) {
		error = kauth_cred_ismember_gid(cred, vap->va_gid, &result);
	}
	/* we could test the group UUID here if we had a policy for it */

	if (!error)
		*ismember = result;
	return(error);
}

static int
vauth_file_owner(vauth_ctx vcp)
{
	int result;

	if (vcp->flags_valid & _VAC_IS_OWNER) {
		result = (vcp->flags & _VAC_IS_OWNER) ? 1 : 0;
	} else {
		result = vauth_node_owner(vcp->vap, vcp->ctx->vc_ucred);

		/* cache our result */
		vcp->flags_valid |= _VAC_IS_OWNER;
		if (result) {
			vcp->flags |= _VAC_IS_OWNER;
		} else {
			vcp->flags &= ~_VAC_IS_OWNER;
		}
	}
	return(result);
}

static int
vauth_file_ingroup(vauth_ctx vcp, int *ismember)
{
	int	error;

	if (vcp->flags_valid & _VAC_IN_GROUP) {
		*ismember = (vcp->flags & _VAC_IN_GROUP) ? 1 : 0;
		error = 0;
	} else {
		error = vauth_node_group(vcp->vap, vcp->ctx->vc_ucred, ismember);

		if (!error) {
			/* cache our result */
			vcp->flags_valid |= _VAC_IN_GROUP;
			if (*ismember) {
				vcp->flags |= _VAC_IN_GROUP;
			} else {
				vcp->flags &= ~_VAC_IN_GROUP;
			}
		}
		
	}
	return(error);
}

static int
vauth_dir_owner(vauth_ctx vcp)
{
	int result;

	if (vcp->flags_valid & _VAC_IS_DIR_OWNER) {
		result = (vcp->flags & _VAC_IS_DIR_OWNER) ? 1 : 0;
	} else {
		result = vauth_node_owner(vcp->dvap, vcp->ctx->vc_ucred);

		/* cache our result */
		vcp->flags_valid |= _VAC_IS_DIR_OWNER;
		if (result) {
			vcp->flags |= _VAC_IS_DIR_OWNER;
		} else {
			vcp->flags &= ~_VAC_IS_DIR_OWNER;
		}
	}
	return(result);
}

static int
vauth_dir_ingroup(vauth_ctx vcp, int *ismember)
{
	int	error;

	if (vcp->flags_valid & _VAC_IN_DIR_GROUP) {
		*ismember = (vcp->flags & _VAC_IN_DIR_GROUP) ? 1 : 0;
		error = 0;
	} else {
		error = vauth_node_group(vcp->dvap, vcp->ctx->vc_ucred, ismember);

		if (!error) {
			/* cache our result */
			vcp->flags_valid |= _VAC_IN_DIR_GROUP;
			if (*ismember) {
				vcp->flags |= _VAC_IN_DIR_GROUP;
			} else {
				vcp->flags &= ~_VAC_IN_DIR_GROUP;
			}
		}
	}
	return(error);
}

/*
 * Test the posix permissions in (vap) to determine whether (credential)
 * may perform (action)
 */
static int
vnode_authorize_posix(vauth_ctx vcp, int action, int on_dir)
{
	struct vnode_attr *vap;
	int needed, error, owner_ok, group_ok, world_ok, ismember;
#ifdef KAUTH_DEBUG_ENABLE
	const char *where;
# define _SETWHERE(c)	where = c;
#else
# define _SETWHERE(c)
#endif

	/* checking file or directory? */
	if (on_dir) {
		vap = vcp->dvap;
	} else {
		vap = vcp->vap;
	}
	
	error = 0;
	
	/*
	 * We want to do as little work here as possible.  So first we check
	 * which sets of permissions grant us the access we need, and avoid checking
	 * whether specific permissions grant access when more generic ones would.
	 */

	/* owner permissions */
	needed = 0;
	if (action & VREAD)
		needed |= S_IRUSR;
	if (action & VWRITE)
		needed |= S_IWUSR;
	if (action & VEXEC)
		needed |= S_IXUSR;
	owner_ok = (needed & vap->va_mode) == needed;

	/* group permissions */
	needed = 0;
	if (action & VREAD)
		needed |= S_IRGRP;
	if (action & VWRITE)
		needed |= S_IWGRP;
	if (action & VEXEC)
		needed |= S_IXGRP;
	group_ok = (needed & vap->va_mode) == needed;

	/* world permissions */
	needed = 0;
	if (action & VREAD)
		needed |= S_IROTH;
	if (action & VWRITE)
		needed |= S_IWOTH;
	if (action & VEXEC)
		needed |= S_IXOTH;
	world_ok = (needed & vap->va_mode) == needed;

	/* If granted/denied by all three, we're done */
	if (owner_ok && group_ok && world_ok) {
		_SETWHERE("all");
		goto out;
	}
	if (!owner_ok && !group_ok && !world_ok) {
		_SETWHERE("all");
		error = EACCES;
		goto out;
	}

	/* Check ownership (relatively cheap) */
	if ((on_dir && vauth_dir_owner(vcp)) ||
	    (!on_dir && vauth_file_owner(vcp))) {
		_SETWHERE("user");
		if (!owner_ok)
			error = EACCES;
		goto out;
	}

	/* Not owner; if group and world both grant it we're done */
	if (group_ok && world_ok) {
		_SETWHERE("group/world");
		goto out;
	}
	if (!group_ok && !world_ok) {
		_SETWHERE("group/world");
		error = EACCES;
		goto out;
	}

	/* Check group membership (most expensive) */
	ismember = 0;
	if (on_dir) {
		error = vauth_dir_ingroup(vcp, &ismember);
	} else {
		error = vauth_file_ingroup(vcp, &ismember);
	}
	if (error)
		goto out;
	if (ismember) {
		_SETWHERE("group");
		if (!group_ok)
			error = EACCES;
		goto out;
	}

	/* Not owner, not in group, use world result */
	_SETWHERE("world");
	if (!world_ok)
		error = EACCES;

	/* FALLTHROUGH */

out:
	KAUTH_DEBUG("%p    %s - posix %s permissions : need %s%s%s %x have %s%s%s%s%s%s%s%s%s UID = %d file = %d,%d",
	    vcp->vp, (error == 0) ? "ALLOWED" : "DENIED", where,
	    (action & VREAD)  ? "r" : "-",
	    (action & VWRITE) ? "w" : "-",
	    (action & VEXEC)  ? "x" : "-",
	    needed,
	    (vap->va_mode & S_IRUSR) ? "r" : "-",
	    (vap->va_mode & S_IWUSR) ? "w" : "-",
	    (vap->va_mode & S_IXUSR) ? "x" : "-",
	    (vap->va_mode & S_IRGRP) ? "r" : "-",
	    (vap->va_mode & S_IWGRP) ? "w" : "-",
	    (vap->va_mode & S_IXGRP) ? "x" : "-",
	    (vap->va_mode & S_IROTH) ? "r" : "-",
	    (vap->va_mode & S_IWOTH) ? "w" : "-",
	    (vap->va_mode & S_IXOTH) ? "x" : "-",
	    kauth_cred_getuid(vcp->ctx->vc_ucred),
	    on_dir ? vcp->dvap->va_uid : vcp->vap->va_uid,
	    on_dir ? vcp->dvap->va_gid : vcp->vap->va_gid);
	return(error);
}

/*
 * Authorize the deletion of the node vp from the directory dvp.
 *
 * We assume that:
 * - Neither the node nor the directory are immutable.
 * - The user is not the superuser.
 *
 * Deletion is not permitted if the directory is sticky and the caller is not owner of the
 * node or directory.
 *
 * If either the node grants DELETE, or the directory grants DELETE_CHILD, the node may be
 * deleted.  If neither denies the permission, and the caller has Posix write access to the
 * directory, then the node may be deleted.
 */
static int
vnode_authorize_delete(vauth_ctx vcp)
{
	struct vnode_attr	*vap = vcp->vap;
	struct vnode_attr	*dvap = vcp->dvap;
	kauth_cred_t		cred = vcp->ctx->vc_ucred;
	struct kauth_acl_eval	eval;
	int			error, delete_denied, delete_child_denied, ismember;

	/* check the ACL on the directory */
	delete_child_denied = 0;
	if (VATTR_IS_NOT(dvap, va_acl, NULL)) {
		eval.ae_requested = KAUTH_VNODE_DELETE_CHILD;
		eval.ae_acl = &dvap->va_acl->acl_ace[0];
		eval.ae_count = dvap->va_acl->acl_entrycount;
		eval.ae_options = 0;
		if (vauth_dir_owner(vcp))
			eval.ae_options |= KAUTH_AEVAL_IS_OWNER;
		if ((error = vauth_dir_ingroup(vcp, &ismember)) != 0)
			return(error);
		if (ismember)
			eval.ae_options |= KAUTH_AEVAL_IN_GROUP;
		eval.ae_exp_gall = KAUTH_VNODE_GENERIC_ALL_BITS;
		eval.ae_exp_gread = KAUTH_VNODE_GENERIC_READ_BITS;
		eval.ae_exp_gwrite = KAUTH_VNODE_GENERIC_WRITE_BITS;
		eval.ae_exp_gexec = KAUTH_VNODE_GENERIC_EXECUTE_BITS;

		error = kauth_acl_evaluate(cred, &eval);

		if (error != 0) {
			KAUTH_DEBUG("%p    ERROR during ACL processing - %d", vcp->vp, error);
			return(error);
		}
		if (eval.ae_result == KAUTH_RESULT_DENY)
			delete_child_denied = 1;
		if (eval.ae_result == KAUTH_RESULT_ALLOW) {
			KAUTH_DEBUG("%p    ALLOWED - granted by directory ACL", vcp->vp);
			return(0);
		}
	}

	/* check the ACL on the node */
	delete_denied = 0;
	if (VATTR_IS_NOT(vap, va_acl, NULL)) {
		eval.ae_requested = KAUTH_VNODE_DELETE;
		eval.ae_acl = &vap->va_acl->acl_ace[0];
		eval.ae_count = vap->va_acl->acl_entrycount;
		eval.ae_options = 0;
		if (vauth_file_owner(vcp))
			eval.ae_options |= KAUTH_AEVAL_IS_OWNER;
		if ((error = vauth_file_ingroup(vcp, &ismember)) != 0)
			return(error);
		if (ismember)
			eval.ae_options |= KAUTH_AEVAL_IN_GROUP;
		eval.ae_exp_gall = KAUTH_VNODE_GENERIC_ALL_BITS;
		eval.ae_exp_gread = KAUTH_VNODE_GENERIC_READ_BITS;
		eval.ae_exp_gwrite = KAUTH_VNODE_GENERIC_WRITE_BITS;
		eval.ae_exp_gexec = KAUTH_VNODE_GENERIC_EXECUTE_BITS;

		if ((error = kauth_acl_evaluate(cred, &eval)) != 0) {
			KAUTH_DEBUG("%p    ERROR during ACL processing - %d", vcp->vp, error);
			return(error);
		}
		if (eval.ae_result == KAUTH_RESULT_DENY)
			delete_denied = 1;
		if (eval.ae_result == KAUTH_RESULT_ALLOW) {
			KAUTH_DEBUG("%p    ALLOWED - granted by file ACL", vcp->vp);
			return(0);
		}
	}

	/* if denied by ACL on directory or node, return denial */
	if (delete_denied || delete_child_denied) {
		KAUTH_DEBUG("%p    ALLOWED - denied by ACL", vcp->vp);
		return(EACCES);
	}

	/* enforce sticky bit behaviour */
	if ((dvap->va_mode & S_ISTXT) && !vauth_file_owner(vcp) && !vauth_dir_owner(vcp)) {
		KAUTH_DEBUG("%p    DENIED - sticky bit rules (user %d  file %d  dir %d)",
		    vcp->vp, cred->cr_uid, vap->va_uid, dvap->va_uid);
		return(EACCES);
	}

	/* check the directory */
	if ((error = vnode_authorize_posix(vcp, VWRITE, 1 /* on_dir */)) != 0) {
		KAUTH_DEBUG("%p    ALLOWED - granted by posix permisssions", vcp->vp);
		return(error);
	}

	/* not denied, must be OK */
	return(0);
}
	

/*
 * Authorize an operation based on the node's attributes.
 */
static int
vnode_authorize_simple(vauth_ctx vcp, kauth_ace_rights_t acl_rights, kauth_ace_rights_t preauth_rights)
{
	struct vnode_attr	*vap = vcp->vap;
	kauth_cred_t		cred = vcp->ctx->vc_ucred;
	struct kauth_acl_eval	eval;
	int			error, ismember;
	mode_t			posix_action;

	/*
	 * If we are the file owner, we automatically have some rights.
	 *
	 * Do we need to expand this to support group ownership?
	 */
	if (vauth_file_owner(vcp))
		acl_rights &= ~(KAUTH_VNODE_WRITE_SECURITY);

	/*
	 * If we are checking both TAKE_OWNERSHIP and WRITE_SECURITY, we can
	 * mask the latter.  If TAKE_OWNERSHIP is requested the caller is about to
	 * change ownership to themselves, and WRITE_SECURITY is implicitly
	 * granted to the owner.  We need to do this because at this point
	 * WRITE_SECURITY may not be granted as the caller is not currently
	 * the owner.
	 */
	if ((acl_rights & KAUTH_VNODE_TAKE_OWNERSHIP) &&
	    (acl_rights & KAUTH_VNODE_WRITE_SECURITY))
		acl_rights &= ~KAUTH_VNODE_WRITE_SECURITY;
	
	if (acl_rights == 0) {
		KAUTH_DEBUG("%p    ALLOWED - implicit or no rights required", vcp->vp);
		return(0);
	}

	/* if we have an ACL, evaluate it */
	if (VATTR_IS_NOT(vap, va_acl, NULL)) {
		eval.ae_requested = acl_rights;
		eval.ae_acl = &vap->va_acl->acl_ace[0];
		eval.ae_count = vap->va_acl->acl_entrycount;
		eval.ae_options = 0;
		if (vauth_file_owner(vcp))
			eval.ae_options |= KAUTH_AEVAL_IS_OWNER;
		if ((error = vauth_file_ingroup(vcp, &ismember)) != 0)
			return(error);
		if (ismember)
			eval.ae_options |= KAUTH_AEVAL_IN_GROUP;
		eval.ae_exp_gall = KAUTH_VNODE_GENERIC_ALL_BITS;
		eval.ae_exp_gread = KAUTH_VNODE_GENERIC_READ_BITS;
		eval.ae_exp_gwrite = KAUTH_VNODE_GENERIC_WRITE_BITS;
		eval.ae_exp_gexec = KAUTH_VNODE_GENERIC_EXECUTE_BITS;
		
		if ((error = kauth_acl_evaluate(cred, &eval)) != 0) {
			KAUTH_DEBUG("%p    ERROR during ACL processing - %d", vcp->vp, error);
			return(error);
		}
		
		if (eval.ae_result == KAUTH_RESULT_DENY) {
			KAUTH_DEBUG("%p    DENIED - by ACL", vcp->vp);
			return(EACCES);			/* deny, deny, counter-allege */
		}
		if (eval.ae_result == KAUTH_RESULT_ALLOW) {
			KAUTH_DEBUG("%p    ALLOWED - all rights granted by ACL", vcp->vp);
			return(0);
		}
		/* fall through and evaluate residual rights */
	} else {
		/* no ACL, everything is residual */
		eval.ae_residual = acl_rights;
	}

	/*
	 * Grant residual rights that have been pre-authorized.
	 */
	eval.ae_residual &= ~preauth_rights;

	/*
	 * We grant WRITE_ATTRIBUTES to the owner if it hasn't been denied.
	 */
	if (vauth_file_owner(vcp))
		eval.ae_residual &= ~KAUTH_VNODE_WRITE_ATTRIBUTES;
	
	if (eval.ae_residual == 0) {
		KAUTH_DEBUG("%p    ALLOWED - rights already authorized", vcp->vp);
		return(0);
	}		
	
	/*
	 * Bail if we have residual rights that can't be granted by posix permissions,
	 * or aren't presumed granted at this point.
	 *
	 * XXX these can be collapsed for performance
	 */
	if (eval.ae_residual & KAUTH_VNODE_CHANGE_OWNER) {
		KAUTH_DEBUG("%p    DENIED - CHANGE_OWNER not permitted", vcp->vp);
		return(EACCES);
	}
	if (eval.ae_residual & KAUTH_VNODE_WRITE_SECURITY) {
		KAUTH_DEBUG("%p    DENIED - WRITE_SECURITY not permitted", vcp->vp);
		return(EACCES);
	}

#if DIAGNOSTIC
	if (eval.ae_residual & KAUTH_VNODE_DELETE)
		panic("vnode_authorize: can't be checking delete permission here");
#endif

	/*
	 * Compute the fallback posix permissions that will satisfy the remaining
	 * rights.
	 */
	posix_action = 0;
	if (eval.ae_residual & (KAUTH_VNODE_READ_DATA |
		KAUTH_VNODE_LIST_DIRECTORY |
		KAUTH_VNODE_READ_EXTATTRIBUTES))
		posix_action |= VREAD;
	if (eval.ae_residual & (KAUTH_VNODE_WRITE_DATA |
		KAUTH_VNODE_ADD_FILE |
		KAUTH_VNODE_ADD_SUBDIRECTORY |
		KAUTH_VNODE_DELETE_CHILD |
		KAUTH_VNODE_WRITE_ATTRIBUTES |
		KAUTH_VNODE_WRITE_EXTATTRIBUTES))
		posix_action |= VWRITE;
	if (eval.ae_residual & (KAUTH_VNODE_EXECUTE |
		KAUTH_VNODE_SEARCH))
		posix_action |= VEXEC;
	
	if (posix_action != 0) {
		return(vnode_authorize_posix(vcp, posix_action, 0 /* !on_dir */));
	} else {
		KAUTH_DEBUG("%p    ALLOWED - residual rights %s%s%s%s%s%s%s%s%s%s%s%s%s%s granted due to no posix mapping",
		    vcp->vp,
		    (eval.ae_residual & KAUTH_VNODE_READ_DATA)
		    ? vnode_isdir(vcp->vp) ? " LIST_DIRECTORY" : " READ_DATA" : "",
		    (eval.ae_residual & KAUTH_VNODE_WRITE_DATA)
		    ? vnode_isdir(vcp->vp) ? " ADD_FILE" : " WRITE_DATA" : "",
		    (eval.ae_residual & KAUTH_VNODE_EXECUTE)
		    ? vnode_isdir(vcp->vp) ? " SEARCH" : " EXECUTE" : "",
		    (eval.ae_residual & KAUTH_VNODE_DELETE)
		    ? " DELETE" : "",
		    (eval.ae_residual & KAUTH_VNODE_APPEND_DATA)
		    ? vnode_isdir(vcp->vp) ? " ADD_SUBDIRECTORY" : " APPEND_DATA" : "",
		    (eval.ae_residual & KAUTH_VNODE_DELETE_CHILD)
		    ? " DELETE_CHILD" : "",
		    (eval.ae_residual & KAUTH_VNODE_READ_ATTRIBUTES)
		    ? " READ_ATTRIBUTES" : "",
		    (eval.ae_residual & KAUTH_VNODE_WRITE_ATTRIBUTES)
		    ? " WRITE_ATTRIBUTES" : "",
		    (eval.ae_residual & KAUTH_VNODE_READ_EXTATTRIBUTES)
		    ? " READ_EXTATTRIBUTES" : "",
		    (eval.ae_residual & KAUTH_VNODE_WRITE_EXTATTRIBUTES)
		    ? " WRITE_EXTATTRIBUTES" : "",
		    (eval.ae_residual & KAUTH_VNODE_READ_SECURITY)
		    ? " READ_SECURITY" : "",
		    (eval.ae_residual & KAUTH_VNODE_WRITE_SECURITY)
		    ? " WRITE_SECURITY" : "",
		    (eval.ae_residual & KAUTH_VNODE_CHECKIMMUTABLE)
		    ? " CHECKIMMUTABLE" : "",
		    (eval.ae_residual & KAUTH_VNODE_CHANGE_OWNER)
		    ? " CHANGE_OWNER" : "");
	}

	/*
	 * Lack of required Posix permissions implies no reason to deny access.
	 */
	return(0);
}

/*
 * Check for file immutability.
 */
static int
vnode_authorize_checkimmutable(vnode_t vp, struct vnode_attr *vap, int rights, int ignore)
{
	mount_t mp;
	int error;
	int append;

	/*
	 * Perform immutability checks for operations that change data.
	 *
	 * Sockets, fifos and devices require special handling.
	 */
	switch(vp->v_type) {
	case VSOCK:
	case VFIFO:
	case VBLK:
	case VCHR:
		/*
		 * Writing to these nodes does not change the filesystem data,
		 * so forget that it's being tried.
		 */
		rights &= ~KAUTH_VNODE_WRITE_DATA;
		break;
	default:
		break;
	}

	error = 0;
	if (rights & KAUTH_VNODE_WRITE_RIGHTS) {
		
		/* check per-filesystem options if possible */
		mp = vnode_mount(vp);
		if (mp != NULL) {
	
			/* check for no-EA filesystems */
			if ((rights & KAUTH_VNODE_WRITE_EXTATTRIBUTES) &&
			    (vfs_flags(mp) & MNT_NOUSERXATTR)) {
				KAUTH_DEBUG("%p    DENIED - filesystem disallowed extended attributes", vp);
				error = EACCES;  /* User attributes disabled */
				goto out;
			}
		}

		/* check for file immutability */
		append = 0;
		if (vp->v_type == VDIR) {
			if ((rights & (KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_ADD_SUBDIRECTORY)) == rights)
				append = 1;
		} else {
			if ((rights & KAUTH_VNODE_APPEND_DATA) == rights)
				append = 1;
		}
		if ((error = vnode_immutable(vap, append, ignore)) != 0) {
			KAUTH_DEBUG("%p    DENIED - file is immutable", vp);
			goto out;
		}
	}
out:
	return(error);
}

/*
 * Handle authorization actions for filesystems that advertise that the server will
 * be enforcing.
 */
static int
vnode_authorize_opaque(vnode_t vp, int *resultp, kauth_action_t action, vfs_context_t ctx)
{
	int	error;

	/*
	 * If the vp is a device node, socket or FIFO it actually represents a local
	 * endpoint, so we need to handle it locally.
	 */
	switch(vp->v_type) {
	case VBLK:
	case VCHR:
	case VSOCK:
	case VFIFO:
		return(0);
	default:
		break;
	}

	/*
	 * In the advisory request case, if the filesystem doesn't think it's reliable
	 * we will attempt to formulate a result ourselves based on VNOP_GETATTR data.
	 */
	if ((action & KAUTH_VNODE_ACCESS) && !vfs_authopaqueaccess(vnode_mount(vp)))
		return(0);

	/*
	 * Let the filesystem have a say in the matter.  It's OK for it to not implemnent
	 * VNOP_ACCESS, as most will authorise inline with the actual request.
	 */
	if ((error = VNOP_ACCESS(vp, action, ctx)) != ENOTSUP) {
		*resultp = error;
		KAUTH_DEBUG("%p    DENIED - opaque filesystem VNOP_ACCESS denied access", vp);
		return(1);
	}
	
	/*
	 * Typically opaque filesystems do authorisation in-line, but exec is a special case.  In
	 * order to be reasonably sure that exec will be permitted, we try a bit harder here.
	 */
	if ((action & KAUTH_VNODE_EXECUTE) && vnode_isreg(vp)) {
		/* try a VNOP_OPEN for readonly access */
		if ((error = VNOP_OPEN(vp, FREAD, ctx)) != 0) {
			*resultp = error;
			KAUTH_DEBUG("%p    DENIED - EXECUTE denied because file could not be opened readonly", vp);
			return(1);
		}
		VNOP_CLOSE(vp, FREAD, ctx);
	}

	/*
	 * We don't have any reason to believe that the request has to be denied at this point,
	 * so go ahead and allow it.
	 */
	*resultp = 0;
	KAUTH_DEBUG("%p    ALLOWED - bypassing access check for non-local filesystem", vp);
	return(1);
}

static int
vnode_authorize_callback(__unused kauth_cred_t unused_cred, __unused void *idata, kauth_action_t action,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	struct _vnode_authorize_context auth_context;
	vauth_ctx		vcp;
	vfs_context_t		ctx;
	vnode_t			vp, dvp;
	kauth_cred_t		cred;
	kauth_ace_rights_t	rights;
	struct vnode_attr	va, dva;
	int			result;
	int			*errorp;
	int			noimmutable;

	vcp = &auth_context;
	ctx = vcp->ctx = (vfs_context_t)arg0;
	vp = vcp->vp = (vnode_t)arg1;
	dvp = vcp->dvp = (vnode_t)arg2;
	errorp = (int *)arg3;
	/* note that we authorize against the context, not the passed cred (the same thing anyway) */
	cred = ctx->vc_ucred;

	VATTR_INIT(&va);
	vcp->vap = &va;
	VATTR_INIT(&dva);
	vcp->dvap = &dva;

	vcp->flags = vcp->flags_valid = 0;

#if DIAGNOSTIC
	if ((ctx == NULL) || (vp == NULL) || (cred == NULL))
		panic("vnode_authorize: bad arguments (context %p  vp %p  cred %p)", ctx, vp, cred);
#endif

	KAUTH_DEBUG("%p  AUTH - %s %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s on %s '%s' (0x%x:%p/%p)",
	    vp, vfs_context_proc(ctx)->p_comm,
	    (action & KAUTH_VNODE_ACCESS)		? "access" : "auth",
	    (action & KAUTH_VNODE_READ_DATA)		? vnode_isdir(vp) ? " LIST_DIRECTORY" : " READ_DATA" : "",
	    (action & KAUTH_VNODE_WRITE_DATA)		? vnode_isdir(vp) ? " ADD_FILE" : " WRITE_DATA" : "",
	    (action & KAUTH_VNODE_EXECUTE)		? vnode_isdir(vp) ? " SEARCH" : " EXECUTE" : "",
	    (action & KAUTH_VNODE_DELETE)		? " DELETE" : "",
	    (action & KAUTH_VNODE_APPEND_DATA)		? vnode_isdir(vp) ? " ADD_SUBDIRECTORY" : " APPEND_DATA" : "",
	    (action & KAUTH_VNODE_DELETE_CHILD)		? " DELETE_CHILD" : "",
	    (action & KAUTH_VNODE_READ_ATTRIBUTES)	? " READ_ATTRIBUTES" : "",
	    (action & KAUTH_VNODE_WRITE_ATTRIBUTES)	? " WRITE_ATTRIBUTES" : "",
	    (action & KAUTH_VNODE_READ_EXTATTRIBUTES)	? " READ_EXTATTRIBUTES" : "",
	    (action & KAUTH_VNODE_WRITE_EXTATTRIBUTES)	? " WRITE_EXTATTRIBUTES" : "",
	    (action & KAUTH_VNODE_READ_SECURITY)	? " READ_SECURITY" : "",
	    (action & KAUTH_VNODE_WRITE_SECURITY)	? " WRITE_SECURITY" : "",
	    (action & KAUTH_VNODE_CHANGE_OWNER)		? " CHANGE_OWNER" : "",
	    (action & KAUTH_VNODE_NOIMMUTABLE)		? " (noimmutable)" : "",
	    vnode_isdir(vp) ? "directory" : "file",
	    vp->v_name ? vp->v_name : "<NULL>", action, vp, dvp);

	/*
	 * Extract the control bits from the action, everything else is
	 * requested rights.
	 */
	noimmutable = (action & KAUTH_VNODE_NOIMMUTABLE) ? 1 : 0;
	rights = action & ~(KAUTH_VNODE_ACCESS | KAUTH_VNODE_NOIMMUTABLE);
 
	if (rights & KAUTH_VNODE_DELETE) {
#if DIAGNOSTIC
		if (dvp == NULL)
			panic("vnode_authorize: KAUTH_VNODE_DELETE test requires a directory");
#endif
	} else {
		dvp = NULL;
	}
	
	/*
	 * Check for read-only filesystems.
	 */
	if ((rights & KAUTH_VNODE_WRITE_RIGHTS) &&
	    (vp->v_mount->mnt_flag & MNT_RDONLY) &&
	    ((vp->v_type == VREG) || (vp->v_type == VDIR) || 
	     (vp->v_type == VLNK) || (vp->v_type == VCPLX) || 
	     (rights & KAUTH_VNODE_DELETE) || (rights & KAUTH_VNODE_DELETE_CHILD))) {
		result = EROFS;
		goto out;
	}

	/*
	 * Check for noexec filesystems.
	 */
	if ((rights & KAUTH_VNODE_EXECUTE) && vnode_isreg(vp) && (vp->v_mount->mnt_flag & MNT_NOEXEC)) {
		result = EACCES;
		goto out;
	}

	/*
	 * Handle cases related to filesystems with non-local enforcement.
	 * This call can return 0, in which case we will fall through to perform a
	 * check based on VNOP_GETATTR data.  Otherwise it returns 1 and sets
	 * an appropriate result, at which point we can return immediately.
	 */
	if (vfs_authopaque(vp->v_mount) && vnode_authorize_opaque(vp, &result, action, ctx))
		goto out;

	/*
	 * Get vnode attributes and extended security information for the vnode
	 * and directory if required.
	 */
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_flags);
	VATTR_WANTED(&va, va_acl);
	if ((result = vnode_getattr(vp, &va, ctx)) != 0) {
		KAUTH_DEBUG("%p    ERROR - failed to get vnode attributes - %d", vp, result);
		goto out;
	}
	if (dvp) {
		VATTR_WANTED(&dva, va_mode);
		VATTR_WANTED(&dva, va_uid);
		VATTR_WANTED(&dva, va_gid);
		VATTR_WANTED(&dva, va_flags);
		VATTR_WANTED(&dva, va_acl);
		if ((result = vnode_getattr(dvp, &dva, ctx)) != 0) {
			KAUTH_DEBUG("%p    ERROR - failed to get directory vnode attributes - %d", vp, result);
			goto out;
		}
	}

	/*
	 * If the vnode is an extended attribute data vnode (eg. a resource fork), *_DATA becomes
	 * *_EXTATTRIBUTES.
	 */
	if (S_ISXATTR(va.va_mode)) {
		if (rights & KAUTH_VNODE_READ_DATA) {
			rights &= ~KAUTH_VNODE_READ_DATA;
			rights |= KAUTH_VNODE_READ_EXTATTRIBUTES;
		}
		if (rights & KAUTH_VNODE_WRITE_DATA) {
			rights &= ~KAUTH_VNODE_WRITE_DATA;
			rights |= KAUTH_VNODE_WRITE_EXTATTRIBUTES;
		}
	}
	
	/*
	 * Check for immutability.
	 *
	 * In the deletion case, parent directory immutability vetoes specific
	 * file rights.
	 */
	if ((result = vnode_authorize_checkimmutable(vp, &va, rights, noimmutable)) != 0)
		goto out;
	if ((rights & KAUTH_VNODE_DELETE) &&
	    ((result = vnode_authorize_checkimmutable(dvp, &dva, KAUTH_VNODE_DELETE_CHILD, 0)) != 0))
		goto out;

	/*
	 * Clear rights that have been authorized by reaching this point, bail if nothing left to
	 * check.
	 */
	rights &= ~(KAUTH_VNODE_LINKTARGET | KAUTH_VNODE_CHECKIMMUTABLE);
	if (rights == 0)
		goto out;

	/*
	 * If we're not the superuser, authorize based on file properties.
	 */
	if (!vfs_context_issuser(ctx)) {
		/* process delete rights */
		if ((rights & KAUTH_VNODE_DELETE) &&
		    ((result = vnode_authorize_delete(vcp)) != 0))
		    goto out;

		/* process remaining rights */
		if ((rights & ~KAUTH_VNODE_DELETE) &&
		    ((result = vnode_authorize_simple(vcp, rights, rights & KAUTH_VNODE_DELETE)) != 0))
			goto out;
	} else {

		/*
		 * Execute is only granted to root if one of the x bits is set.  This check only
		 * makes sense if the posix mode bits are actually supported.
		 */
		if ((rights & KAUTH_VNODE_EXECUTE) &&
		    (vp->v_type == VREG) &&
		    VATTR_IS_SUPPORTED(&va, va_mode) &&
		    !(va.va_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
			result = EPERM;
			KAUTH_DEBUG("%p    DENIED - root execute requires at least one x bit in 0x%x", vp, va.va_mode);
			goto out;
		}
		
		KAUTH_DEBUG("%p    ALLOWED - caller is superuser", vp);
	}

out:
	if (VATTR_IS_SUPPORTED(&va, va_acl) && (va.va_acl != NULL))
		kauth_acl_free(va.va_acl);
	if (VATTR_IS_SUPPORTED(&dva, va_acl) && (dva.va_acl != NULL))
		kauth_acl_free(dva.va_acl);
	if (result) {
		*errorp = result;
		KAUTH_DEBUG("%p    DENIED - auth denied", vp);
		return(KAUTH_RESULT_DENY);
	}

	/*
	 * Note that this implies that we will allow requests for no rights, as well as
	 * for rights that we do not recognise.  There should be none of these.
	 */
	KAUTH_DEBUG("%p    ALLOWED - auth granted", vp);
	return(KAUTH_RESULT_ALLOW);
}

/*
 * Check that the attribute information in vattr can be legally applied to
 * a new file by the context.
 */
int
vnode_authattr_new(vnode_t dvp, struct vnode_attr *vap, int noauth, vfs_context_t ctx)
{
	int		error;
	int		is_suser, ismember, defaulted_owner, defaulted_group, defaulted_mode;
	kauth_cred_t	cred;
	guid_t		changer;
	mount_t		dmp;

	error = 0;
	defaulted_owner = defaulted_group = defaulted_mode = 0;

	/*
	 * Require that the filesystem support extended security to apply any.
	 */
	if (!vfs_extendedsecurity(dvp->v_mount) &&
	    (VATTR_IS_ACTIVE(vap, va_acl) || VATTR_IS_ACTIVE(vap, va_uuuid) || VATTR_IS_ACTIVE(vap, va_guuid))) {
		error = EINVAL;
		goto out;
	}
	
	/*
	 * Default some fields.
	 */
	dmp = dvp->v_mount;

	/*
	 * If the filesystem is mounted IGNORE_OWNERSHIP and an explicit owner is set, that
	 * owner takes ownership of all new files.
	 */
	if ((dmp->mnt_flag & MNT_IGNORE_OWNERSHIP) && (dmp->mnt_fsowner != KAUTH_UID_NONE)) {
		VATTR_SET(vap, va_uid, dmp->mnt_fsowner);
		defaulted_owner = 1;
	} else {
		if (!VATTR_IS_ACTIVE(vap, va_uid)) {
			/* default owner is current user */
			VATTR_SET(vap, va_uid, kauth_cred_getuid(vfs_context_ucred(ctx)));
			defaulted_owner = 1;
		}
	}

	/*
	 * If the filesystem is mounted IGNORE_OWNERSHIP and an explicit grouo is set, that
	 * group takes ownership of all new files.
	 */
	if ((dmp->mnt_flag & MNT_IGNORE_OWNERSHIP) && (dmp->mnt_fsgroup != KAUTH_GID_NONE)) {
		VATTR_SET(vap, va_gid, dmp->mnt_fsgroup);
		defaulted_group = 1;
	} else {
		if (!VATTR_IS_ACTIVE(vap, va_gid)) {
			/* default group comes from parent object, fallback to current user */
			struct vnode_attr dva;
			VATTR_INIT(&dva);
			VATTR_WANTED(&dva, va_gid);
			if ((error = vnode_getattr(dvp, &dva, ctx)) != 0)
				goto out;
			if (VATTR_IS_SUPPORTED(&dva, va_gid)) {
				VATTR_SET(vap, va_gid, dva.va_gid);
			} else {
				VATTR_SET(vap, va_gid, kauth_cred_getgid(vfs_context_ucred(ctx)));
			}
			defaulted_group = 1;
		}
	}

	if (!VATTR_IS_ACTIVE(vap, va_flags))
		VATTR_SET(vap, va_flags, 0);
	
	/* default mode is everything, masked with current umask */
	if (!VATTR_IS_ACTIVE(vap, va_mode)) {
		VATTR_SET(vap, va_mode, ACCESSPERMS & ~vfs_context_proc(ctx)->p_fd->fd_cmask);
		KAUTH_DEBUG("ATTR - defaulting new file mode to %o from umask %o", vap->va_mode, vfs_context_proc(ctx)->p_fd->fd_cmask);
		defaulted_mode = 1;
	}
	/* set timestamps to now */
	if (!VATTR_IS_ACTIVE(vap, va_create_time)) {
		nanotime(&vap->va_create_time);
		VATTR_SET_ACTIVE(vap, va_create_time);
	}
	
	/*
	 * Check for attempts to set nonsensical fields.
	 */
	if (vap->va_active & ~VNODE_ATTR_NEWOBJ) {
		error = EINVAL;
		KAUTH_DEBUG("ATTR - ERROR - attempt to set unsupported new-file attributes %llx",
		    vap->va_active & ~VNODE_ATTR_NEWOBJ);
		goto out;
	}

	/*
	 * Quickly check for the applicability of any enforcement here.
	 * Tests below maintain the integrity of the local security model.
	 */
	if (vfs_authopaque(vnode_mount(dvp)))
	    goto out;

	/*
	 * We need to know if the caller is the superuser, or if the work is
	 * otherwise already authorised.
	 */
	cred = vfs_context_ucred(ctx);
	if (noauth) {
		/* doing work for the kernel */
		is_suser = 1;
	} else {
		is_suser = vfs_context_issuser(ctx);
	}


	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		if (is_suser) {
			if ((vap->va_flags & (UF_SETTABLE | SF_SETTABLE)) != vap->va_flags) {
				error = EPERM;
				KAUTH_DEBUG("  DENIED - superuser attempt to set illegal flag(s)");
				goto out;
			}
		} else {
			if ((vap->va_flags & UF_SETTABLE) != vap->va_flags) {
				error = EPERM;
				KAUTH_DEBUG("  DENIED - user attempt to set illegal flag(s)");
				goto out;
			}
		}
	}

	/* if not superuser, validate legality of new-item attributes */
	if (!is_suser) {
		if (!defaulted_mode && VATTR_IS_ACTIVE(vap, va_mode)) {
			/* setgid? */
			if (vap->va_mode & S_ISGID) {
				if ((error = kauth_cred_ismember_gid(cred, vap->va_gid, &ismember)) != 0) {
					KAUTH_DEBUG("ATTR - ERROR: got %d checking for membership in %d", error, vap->va_gid);
					goto out;
				}
				if (!ismember) {
					KAUTH_DEBUG("  DENIED - can't set SGID bit, not a member of %d", vap->va_gid);
					error = EPERM;
					goto out;
				}
			}

			/* setuid? */
			if ((vap->va_mode & S_ISUID) && (vap->va_uid != kauth_cred_getuid(cred))) {
				KAUTH_DEBUG("ATTR - ERROR: illegal attempt to set the setuid bit");
				error = EPERM;
				goto out;
			}
		}
		if (!defaulted_owner && (vap->va_uid != kauth_cred_getuid(cred))) {
			KAUTH_DEBUG("  DENIED - cannot create new item owned by %d", vap->va_uid);
			error = EPERM;
			goto out;
		}
		if (!defaulted_group) {
			if ((error = kauth_cred_ismember_gid(cred, vap->va_gid, &ismember)) != 0) {
				KAUTH_DEBUG("  ERROR - got %d checking for membership in %d", error, vap->va_gid);
				goto out;
			}
			if (!ismember) {
				KAUTH_DEBUG("  DENIED - cannot create new item with group %d - not a member", vap->va_gid);
				error = EPERM;
				goto out;
			}
		}

		/* initialising owner/group UUID */
		if (VATTR_IS_ACTIVE(vap, va_uuuid)) {
			if ((error = kauth_cred_getguid(cred, &changer)) != 0) {
				KAUTH_DEBUG("  ERROR - got %d trying to get caller UUID", error);
				/* XXX ENOENT here - no GUID - should perhaps become EPERM */
				goto out;
			}
			if (!kauth_guid_equal(&vap->va_uuuid, &changer)) {
				KAUTH_DEBUG("  ERROR - cannot create item with supplied owner UUID - not us");
				error = EPERM;
				goto out;
			}
		}
		if (VATTR_IS_ACTIVE(vap, va_guuid)) {
			if ((error = kauth_cred_ismember_guid(cred, &vap->va_guuid, &ismember)) != 0) {
				KAUTH_DEBUG("  ERROR - got %d trying to check group membership", error);
				goto out;
			}
			if (!ismember) {
				KAUTH_DEBUG("  ERROR - cannot create item with supplied group UUID - not a member");
				error = EPERM;
				goto out;
			}
		}
	}
out:	
	return(error);
}

/*
 * Check that the attribute information in vap can be legally written by the context.
 *
 * Call this when you're not sure about the vnode_attr; either its contents have come
 * from an unknown source, or when they are variable.
 *
 * Returns errno, or zero and sets *actionp to the KAUTH_VNODE_* actions that
 * must be authorized to be permitted to write the vattr.
 */
int
vnode_authattr(vnode_t vp, struct vnode_attr *vap, kauth_action_t *actionp, vfs_context_t ctx)
{
	struct vnode_attr ova;
	kauth_action_t	required_action;
	int		error, is_suser, ismember, chowner, chgroup;
	guid_t		changer;
	gid_t		group;
	uid_t		owner;
	mode_t		newmode;
	kauth_cred_t	cred;
	uint32_t	fdelta;

	VATTR_INIT(&ova);
	required_action = 0;
	error = 0;

	/*
	 * Quickly check for enforcement applicability.
	 */
	if (vfs_authopaque(vnode_mount(vp)))
		goto out;
	
	/*
	 * Check for attempts to set nonsensical fields.
	 */
	if (vap->va_active & VNODE_ATTR_RDONLY) {
		KAUTH_DEBUG("ATTR - ERROR: attempt to set readonly attribute(s)");
		error = EINVAL;
		goto out;
	}

	/*
	 * We need to know if the caller is the superuser.
	 */
	cred = vfs_context_ucred(ctx);
	is_suser = kauth_cred_issuser(cred);
	
	/*
	 * If any of the following are changing, we need information from the old file:
	 * va_uid
	 * va_gid
	 * va_mode
	 * va_uuuid
	 * va_guuid
	 */
	if (VATTR_IS_ACTIVE(vap, va_uid) ||
	    VATTR_IS_ACTIVE(vap, va_gid) ||
	    VATTR_IS_ACTIVE(vap, va_mode) ||
	    VATTR_IS_ACTIVE(vap, va_uuuid) ||
	    VATTR_IS_ACTIVE(vap, va_guuid)) {
		VATTR_WANTED(&ova, va_mode);
		VATTR_WANTED(&ova, va_uid);
		VATTR_WANTED(&ova, va_gid);
		VATTR_WANTED(&ova, va_uuuid);
		VATTR_WANTED(&ova, va_guuid);
		KAUTH_DEBUG("ATTR - security information changing, fetching existing attributes");
	}

	/*
	 * If timestamps are being changed, we need to know who the file is owned
	 * by.
	 */
	if (VATTR_IS_ACTIVE(vap, va_create_time) ||
	    VATTR_IS_ACTIVE(vap, va_change_time) ||
	    VATTR_IS_ACTIVE(vap, va_modify_time) ||
	    VATTR_IS_ACTIVE(vap, va_access_time) ||
	    VATTR_IS_ACTIVE(vap, va_backup_time)) {

		VATTR_WANTED(&ova, va_uid);
#if 0	/* enable this when we support UUIDs as official owners */
		VATTR_WANTED(&ova, va_uuuid);
#endif
		KAUTH_DEBUG("ATTR - timestamps changing, fetching uid and GUID");
	}
		
	/*
	 * If flags are being changed, we need the old flags.
	 */
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		KAUTH_DEBUG("ATTR - flags changing, fetching old flags");
		VATTR_WANTED(&ova, va_flags);
	}

	/*
	 * If the size is being set, make sure it's not a directory.
	 */
	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		/* size is meaningless on a directory, don't permit this */
		if (vnode_isdir(vp)) {
			KAUTH_DEBUG("ATTR - ERROR: size change requested on a directory");
			error = EISDIR;
			goto out;
		}
	}

	/*
	 * Get old data.
	 */
	KAUTH_DEBUG("ATTR - fetching old attributes %016llx", ova.va_active);
	if ((error = vnode_getattr(vp, &ova, ctx)) != 0) {
		KAUTH_DEBUG("  ERROR - got %d trying to get attributes", error);
		goto out;
	}

	/*
	 * Size changes require write access to the file data.
	 */
	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		/* if we can't get the size, or it's different, we need write access */
			KAUTH_DEBUG("ATTR - size change, requiring WRITE_DATA");
			required_action |= KAUTH_VNODE_WRITE_DATA;
	}

	/*
	 * Changing timestamps?
	 *
	 * Note that we are only called to authorize user-requested time changes;
	 * side-effect time changes are not authorized.  Authorisation is only
	 * required for existing files.
	 *
	 * Non-owners are not permitted to change the time on an existing
	 * file to anything other than the current time.
	 */
	if (VATTR_IS_ACTIVE(vap, va_create_time) ||
	    VATTR_IS_ACTIVE(vap, va_change_time) ||
	    VATTR_IS_ACTIVE(vap, va_modify_time) ||
	    VATTR_IS_ACTIVE(vap, va_access_time) ||
	    VATTR_IS_ACTIVE(vap, va_backup_time)) {
		/*
		 * The owner and root may set any timestamps they like,
		 * provided that the file is not immutable.  The owner still needs
		 * WRITE_ATTRIBUTES (implied by ownership but still deniable).
		 */
		if (is_suser || vauth_node_owner(&ova, cred)) {
			KAUTH_DEBUG("ATTR - root or owner changing timestamps");
			required_action |= KAUTH_VNODE_CHECKIMMUTABLE | KAUTH_VNODE_WRITE_ATTRIBUTES;
		} else {
			/* just setting the current time? */
			if (vap->va_vaflags & VA_UTIMES_NULL) {
				KAUTH_DEBUG("ATTR - non-root/owner changing timestamps, requiring WRITE_ATTRIBUTES");
				required_action |= KAUTH_VNODE_WRITE_ATTRIBUTES;
			} else {
				KAUTH_DEBUG("ATTR - ERROR: illegal timestamp modification attempted");
				error = EACCES;
				goto out;
			}
		}
	}

	/*
	 * Changing file mode?
	 */
	if (VATTR_IS_ACTIVE(vap, va_mode) && VATTR_IS_SUPPORTED(&ova, va_mode) && (ova.va_mode != vap->va_mode)) {
		KAUTH_DEBUG("ATTR - mode change from %06o to %06o", ova.va_mode, vap->va_mode);

		/*
		 * Mode changes always have the same basic auth requirements.
		 */
		if (is_suser) {
			KAUTH_DEBUG("ATTR - superuser mode change, requiring immutability check");
			required_action |= KAUTH_VNODE_CHECKIMMUTABLE;
		} else {
			/* need WRITE_SECURITY */
			KAUTH_DEBUG("ATTR - non-superuser mode change, requiring WRITE_SECURITY");
			required_action |= KAUTH_VNODE_WRITE_SECURITY;
		}

		/*
		 * Can't set the setgid bit if you're not in the group and not root.  Have to have
		 * existing group information in the case we're not setting it right now.
		 */
		if (vap->va_mode & S_ISGID) {
			required_action |= KAUTH_VNODE_CHECKIMMUTABLE;	/* always required */
			if (!is_suser) {
				if (VATTR_IS_ACTIVE(vap, va_gid)) {
					group = vap->va_gid;
				} else if (VATTR_IS_SUPPORTED(&ova, va_gid)) {
					group = ova.va_gid;
				} else {
					KAUTH_DEBUG("ATTR - ERROR: setgid but no gid available");
					error = EINVAL;
					goto out;
				}
				/*
				 * This might be too restrictive; WRITE_SECURITY might be implied by
				 * membership in this case, rather than being an additional requirement.
				 */
				if ((error = kauth_cred_ismember_gid(cred, group, &ismember)) != 0) {
					KAUTH_DEBUG("ATTR - ERROR: got %d checking for membership in %d", error, vap->va_gid);
					goto out;
				}
				if (!ismember) {
					KAUTH_DEBUG("  DENIED - can't set SGID bit, not a member of %d", group);
					error = EPERM;
					goto out;
				}
			}
		}

		/*
		 * Can't set the setuid bit unless you're root or the file's owner.
		 */
		if (vap->va_mode & S_ISUID) {
			required_action |= KAUTH_VNODE_CHECKIMMUTABLE;	/* always required */
			if (!is_suser) {
				if (VATTR_IS_ACTIVE(vap, va_uid)) {
					owner = vap->va_uid;
				} else if (VATTR_IS_SUPPORTED(&ova, va_uid)) {
					owner = ova.va_uid;
				} else {
					KAUTH_DEBUG("ATTR - ERROR: setuid but no uid available");
					error = EINVAL;
					goto out;
				}
				if (owner != kauth_cred_getuid(cred)) {
					/*
					 * We could allow this if WRITE_SECURITY is permitted, perhaps.
					 */
					KAUTH_DEBUG("ATTR - ERROR: illegal attempt to set the setuid bit");
					error = EPERM;
					goto out;
				}
			}
		}
	}
	    
	/*
	 * Validate/mask flags changes.  This checks that only the flags in
	 * the UF_SETTABLE mask are being set, and preserves the flags in
	 * the SF_SETTABLE case.
	 *
	 * Since flags changes may be made in conjunction with other changes,
	 * we will ask the auth code to ignore immutability in the case that
	 * the SF_* flags are not set and we are only manipulating the file flags.
	 * 
	 */
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		/* compute changing flags bits */
		if (VATTR_IS_SUPPORTED(&ova, va_flags)) {
			fdelta = vap->va_flags ^ ova.va_flags;
		} else {
			fdelta = vap->va_flags;
		}

		if (fdelta != 0) {
			KAUTH_DEBUG("ATTR - flags changing, requiring WRITE_SECURITY");
			required_action |= KAUTH_VNODE_WRITE_SECURITY;

			/* check that changing bits are legal */
			if (is_suser) {
				/*
				 * The immutability check will prevent us from clearing the SF_*
				 * flags unless the system securelevel permits it, so just check
				 * for legal flags here.
				 */
				if (fdelta & ~(UF_SETTABLE | SF_SETTABLE)) {
					error = EPERM;
					KAUTH_DEBUG("  DENIED - superuser attempt to set illegal flag(s)");
					goto out;
				}
			} else {
				if (fdelta & ~UF_SETTABLE) {
					error = EPERM;
					KAUTH_DEBUG("  DENIED - user attempt to set illegal flag(s)");
					goto out;
				}
			}
			/*
			 * If the caller has the ability to manipulate file flags,
			 * security is not reduced by ignoring them for this operation.
			 *
			 * A more complete test here would consider the 'after' states of the flags
			 * to determine whether it would permit the operation, but this becomes
			 * very complex.
			 *
			 * Ignoring immutability is conditional on securelevel; this does not bypass
			 * the SF_* flags if securelevel > 0.
			 */
			required_action |= KAUTH_VNODE_NOIMMUTABLE;
		}
	}

	/*
	 * Validate ownership information.
	 */
	chowner = 0;
	chgroup = 0;

	/*
	 * uid changing
	 * Note that if the filesystem didn't give us a UID, we expect that it doesn't
	 * support them in general, and will ignore it if/when we try to set it.
	 * We might want to clear the uid out of vap completely here.
	 */
	if (VATTR_IS_ACTIVE(vap, va_uid) && VATTR_IS_SUPPORTED(&ova, va_uid) && (vap->va_uid != ova.va_uid)) {
		if (!is_suser && (kauth_cred_getuid(cred) != vap->va_uid)) {
			KAUTH_DEBUG("  DENIED - non-superuser cannot change ownershipt to a third party");
			error = EPERM;
			goto out;
		}
		chowner = 1;
	}
	
	/*
	 * gid changing
	 * Note that if the filesystem didn't give us a GID, we expect that it doesn't
	 * support them in general, and will ignore it if/when we try to set it.
	 * We might want to clear the gid out of vap completely here.
	 */
	if (VATTR_IS_ACTIVE(vap, va_gid) && VATTR_IS_SUPPORTED(&ova, va_gid) && (vap->va_gid != ova.va_gid)) {
		if (!is_suser) {
			if ((error = kauth_cred_ismember_gid(cred, vap->va_gid, &ismember)) != 0) {
				KAUTH_DEBUG("  ERROR - got %d checking for membership in %d", error, vap->va_gid);
				goto out;
			}
			if (!ismember) {
				KAUTH_DEBUG("  DENIED - group change from %d to %d but not a member of target group",
				    ova.va_gid, vap->va_gid);
				error = EPERM;
				goto out;
			}
		}
		chgroup = 1;
	}

	/*
	 * Owner UUID being set or changed.
	 */
	if (VATTR_IS_ACTIVE(vap, va_uuuid)) {
		/* if the owner UUID is not actually changing ... */
		if (VATTR_IS_SUPPORTED(&ova, va_uuuid) && kauth_guid_equal(&vap->va_uuuid, &ova.va_uuuid))
			goto no_uuuid_change;
		
		/*
		 * The owner UUID cannot be set by a non-superuser to anything other than
		 * their own.
		 */
		if (!is_suser) {
			if ((error = kauth_cred_getguid(cred, &changer)) != 0) {
				KAUTH_DEBUG("  ERROR - got %d trying to get caller UUID", error);
				/* XXX ENOENT here - no UUID - should perhaps become EPERM */
				goto out;
			}
			if (!kauth_guid_equal(&vap->va_uuuid, &changer)) {
				KAUTH_DEBUG("  ERROR - cannot set supplied owner UUID - not us");
				error = EPERM;
				goto out;
			}
		}
		chowner = 1;
	}
no_uuuid_change:
	/*
	 * Group UUID being set or changed.
	 */
	if (VATTR_IS_ACTIVE(vap, va_guuid)) {
		/* if the group UUID is not actually changing ... */
		if (VATTR_IS_SUPPORTED(&ova, va_guuid) && kauth_guid_equal(&vap->va_guuid, &ova.va_guuid))
			goto no_guuid_change;

		/*
		 * The group UUID cannot be set by a non-superuser to anything other than
		 * one of which they are a member.
		 */
		if (!is_suser) {
			if ((error = kauth_cred_ismember_guid(cred, &vap->va_guuid, &ismember)) != 0) {
				KAUTH_DEBUG("  ERROR - got %d trying to check group membership", error);
				goto out;
			}
			if (!ismember) {
				KAUTH_DEBUG("  ERROR - cannot create item with supplied group UUID - not a member");
				error = EPERM;
				goto out;
			}
		}
		chgroup = 1;
	}
no_guuid_change:

	/*
	 * Compute authorisation for group/ownership changes.
	 */
	if (chowner || chgroup) {
		if (is_suser) {
			KAUTH_DEBUG("ATTR - superuser changing file owner/group, requiring immutability check");
			required_action |= KAUTH_VNODE_CHECKIMMUTABLE;
		} else {
			if (chowner) {
				KAUTH_DEBUG("ATTR - ownership change, requiring TAKE_OWNERSHIP");
				required_action |= KAUTH_VNODE_TAKE_OWNERSHIP;
			}
			if (chgroup && !chowner) {
				KAUTH_DEBUG("ATTR - group change, requiring WRITE_SECURITY");
				required_action |= KAUTH_VNODE_WRITE_SECURITY;
			}
			
			/* clear set-uid and set-gid bits as required by Posix */
			if (VATTR_IS_ACTIVE(vap, va_mode)) {
				newmode = vap->va_mode;
			} else if (VATTR_IS_SUPPORTED(&ova, va_mode)) {
				newmode = ova.va_mode;
			} else {
				KAUTH_DEBUG("CHOWN - trying to change owner but cannot get mode from filesystem to mask setugid bits");
				newmode = 0;
			}
			if (newmode & (S_ISUID | S_ISGID)) {
				VATTR_SET(vap, va_mode, newmode & ~(S_ISUID | S_ISGID));
				KAUTH_DEBUG("CHOWN - masking setugid bits from mode %o to %o", newmode, vap->va_mode);
			}
		}
	}

	/*
	 * Authorise changes in the ACL.
	 */
	if (VATTR_IS_ACTIVE(vap, va_acl)) {

		/* no existing ACL */
		if (!VATTR_IS_ACTIVE(&ova, va_acl) || (ova.va_acl == NULL)) {

			/* adding an ACL */
			if (vap->va_acl != NULL) {
				required_action |= KAUTH_VNODE_WRITE_SECURITY;
				KAUTH_DEBUG("CHMOD - adding ACL");
			}

			/* removing an existing ACL */
		} else if (vap->va_acl == NULL) {
			required_action |= KAUTH_VNODE_WRITE_SECURITY;
			KAUTH_DEBUG("CHMOD - removing ACL");

			/* updating an existing ACL */
		} else {
			if (vap->va_acl->acl_entrycount != ova.va_acl->acl_entrycount) {
				/* entry count changed, must be different */
				required_action |= KAUTH_VNODE_WRITE_SECURITY;
				KAUTH_DEBUG("CHMOD - adding/removing ACL entries");
			} else if (vap->va_acl->acl_entrycount > 0) {
				/* both ACLs have the same ACE count, said count is 1 or more, bitwise compare ACLs */
				if (!memcmp(&vap->va_acl->acl_ace[0], &ova.va_acl->acl_ace[0],
					sizeof(struct kauth_ace) * vap->va_acl->acl_entrycount)) {
					required_action |= KAUTH_VNODE_WRITE_SECURITY;
					KAUTH_DEBUG("CHMOD - changing ACL entries");
				}
			}
		}
	}

	/*
	 * Other attributes that require authorisation.
	 */
	if (VATTR_IS_ACTIVE(vap, va_encoding))
		required_action |= KAUTH_VNODE_WRITE_ATTRIBUTES;
	
out:
	if (VATTR_IS_SUPPORTED(&ova, va_acl) && (ova.va_acl != NULL))
		kauth_acl_free(ova.va_acl);
	if (error == 0)
		*actionp = required_action;
	return(error);
}


void
vfs_setlocklocal(mount_t mp)
{
	vnode_t vp;
	
	mount_lock(mp);
	mp->mnt_kern_flag |= MNTK_LOCK_LOCAL;

	/*
	 * We do not expect anyone to be using any vnodes at the
	 * time this routine is called. So no need for vnode locking 
	 */
	TAILQ_FOREACH(vp, &mp->mnt_vnodelist, v_mntvnodes) {
			vp->v_flag |= VLOCKLOCAL;
	}
	TAILQ_FOREACH(vp, &mp->mnt_workerqueue, v_mntvnodes) {
			vp->v_flag |= VLOCKLOCAL;
	}
	TAILQ_FOREACH(vp, &mp->mnt_newvnodes, v_mntvnodes) {
			vp->v_flag |= VLOCKLOCAL;
	}
	mount_unlock(mp);
}


#ifdef JOE_DEBUG

record_vp(vnode_t vp, int count) {
        struct uthread *ut;
        int  i;

	if ((vp->v_flag & VSYSTEM))
	        return;

	ut = get_bsdthread_info(current_thread());
        ut->uu_iocount += count;

	if (ut->uu_vpindex < 32) {
	        for (i = 0; i < ut->uu_vpindex; i++) {
		        if (ut->uu_vps[i] == vp)
			        return;
		}
		ut->uu_vps[ut->uu_vpindex] = vp;
		ut->uu_vpindex++;
	}
}
#endif
