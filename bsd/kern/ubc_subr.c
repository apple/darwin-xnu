/*
 * Copyright (c) 1999-2002 Apple Computer, Inc. All rights reserved.
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
/* 
 *	File:	ubc_subr.c
 *	Author:	Umesh Vaishampayan [umeshv@apple.com]
 *		05-Aug-1999	umeshv	Created.
 *
 *	Functions related to Unified Buffer cache.
 *
 * Caller of UBC functions MUST have a valid reference on the vnode.
 *
 */ 

#undef DIAGNOSTIC
#define DIAGNOSTIC 1

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/ubc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/ubc.h>
#include <sys/ucred.h>
#include <sys/proc.h>
#include <sys/buf.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>

#include <kern/zalloc.h>

#if DIAGNOSTIC
#if defined(assert)
#undef assert()
#endif
#define assert(cond)    \
    ((void) ((cond) ? 0 : panic("%s:%d (%s)", __FILE__, __LINE__, # cond)))
#else
#include <kern/assert.h>
#endif /* DIAGNOSTIC */

struct zone	*ubc_info_zone;

/* lock for changes to struct UBC */
static __inline__ void
ubc_lock(struct vnode *vp)
{
	/* For now, just use the v_interlock */
	simple_lock(&vp->v_interlock);
}

/* unlock */
static __inline__ void
ubc_unlock(struct vnode *vp)
{
	/* For now, just use the v_interlock */
	simple_unlock(&vp->v_interlock);
}

/*
 * Serialize the requests to the VM
 * Returns:
 *		0	-	Failure
 *		1	-	Sucessful in acquiring the lock
 *		2	-	Sucessful in acquiring the lock recursively
 *				do not call ubc_unbusy()
 *				[This is strange, but saves 4 bytes in struct ubc_info]
 */
static int
ubc_busy(struct vnode *vp)
{
	register struct ubc_info	*uip;

	if (!UBCINFOEXISTS(vp))
		return (0);

	uip = vp->v_ubcinfo;

	while (ISSET(uip->ui_flags, UI_BUSY)) {

		if (uip->ui_owner == (void *)current_thread())
			return (2);

		SET(uip->ui_flags, UI_WANTED);
		(void) tsleep((caddr_t)&vp->v_ubcinfo, PINOD, "ubcbusy", 0);

		if (!UBCINFOEXISTS(vp))
			return (0);
	}
	uip->ui_owner = (void *)current_thread();

	SET(uip->ui_flags, UI_BUSY);

	return (1);
}

static void
ubc_unbusy(struct vnode *vp)
{
	register struct ubc_info	*uip;

	if (!UBCINFOEXISTS(vp)) {
		wakeup((caddr_t)&vp->v_ubcinfo);
		return;
	}
	uip = vp->v_ubcinfo;
	CLR(uip->ui_flags, UI_BUSY);
	uip->ui_owner = (void *)NULL;

	if (ISSET(uip->ui_flags, UI_WANTED)) {
		CLR(uip->ui_flags, UI_WANTED);
		wakeup((caddr_t)&vp->v_ubcinfo);
	}
}

/*
 *	Initialization of the zone for Unified Buffer Cache.
 */
__private_extern__ void
ubc_init()
{
	int	i;

	i = (vm_size_t) sizeof (struct ubc_info);
	/* XXX  the number of elements should be tied in to maxvnodes */
	ubc_info_zone = zinit (i, 10000*i, 8192, "ubc_info zone");
	return;
}

/*
 *	Initialize a ubc_info structure for a vnode.
 */
int
ubc_info_init(struct vnode *vp)
{
	register struct ubc_info	*uip;
	void *  pager;
	struct vattr	vattr;
	struct proc *p = current_proc();
	int error = 0;
	kern_return_t kret;
	memory_object_control_t control;

	if (!UBCISVALID(vp))
		return (EINVAL);

	ubc_lock(vp);
	if (ISSET(vp->v_flag,  VUINIT)) {
		/*
		 * other thread is already doing this
		 * wait till done
		 */
		while (ISSET(vp->v_flag,  VUINIT)) {
			SET(vp->v_flag, VUWANT); /* XXX overloaded! */
			ubc_unlock(vp);
			(void) tsleep((caddr_t)vp, PINOD, "ubcinfo", 0);
			ubc_lock(vp);
		}
		ubc_unlock(vp);
		return (0);
	} else {
		SET(vp->v_flag, VUINIT);
	}

	uip = vp->v_ubcinfo;
	if ((uip == UBC_INFO_NULL) || (uip == UBC_NOINFO)) {
		ubc_unlock(vp);
		uip = (struct ubc_info *) zalloc(ubc_info_zone);
		uip->ui_pager = MEMORY_OBJECT_NULL;
		uip->ui_control = MEMORY_OBJECT_CONTROL_NULL;
		uip->ui_flags = UI_INITED;
		uip->ui_vnode = vp;
		uip->ui_ucred = NOCRED;
		uip->ui_refcount = 1;
		uip->ui_size = 0;
		uip->ui_mapped = 0;
		uip->ui_owner = (void *)NULL;
		ubc_lock(vp);
	}
#if DIAGNOSTIC
	else
		Debugger("ubc_info_init: already");
#endif /* DIAGNOSTIC */
	
	assert(uip->ui_flags != UI_NONE);
	assert(uip->ui_vnode == vp);

#if 0
	if(ISSET(uip->ui_flags, UI_HASPAGER))
		goto done;
#endif /* 0 */

	/* now set this ubc_info in the vnode */
	vp->v_ubcinfo = uip;
	SET(uip->ui_flags, UI_HASPAGER);
	ubc_unlock(vp);
	pager = (void *)vnode_pager_setup(vp, uip->ui_pager);
	assert(pager);
	ubc_setpager(vp, pager);

	/*
	 * Note: We can not use VOP_GETATTR() to get accurate
	 * value of ui_size. Thanks to NFS.
	 * nfs_getattr() can call vinvalbuf() and in this case
	 * ubc_info is not set up to deal with that.
	 * So use bogus size.
	 */

	/*
	 * create a vnode - vm_object association
	 * memory_object_create_named() creates a "named" reference on the
	 * memory object we hold this reference as long as the vnode is
	 * "alive."  Since memory_object_create_named() took its own reference
	 * on the vnode pager we passed it, we can drop the reference
	 * vnode_pager_setup() returned here.
	 */
	kret = memory_object_create_named(pager,
		(memory_object_size_t)uip->ui_size, &control);
	vnode_pager_deallocate(pager); 
	if (kret != KERN_SUCCESS)
		panic("ubc_info_init: memory_object_create_named returned %d", kret);

	assert(control);
	uip->ui_control = control;	/* cache the value of the mo control */
	SET(uip->ui_flags, UI_HASOBJREF);	/* with a named reference */
	/* create a pager reference on the vnode */
	error = vnode_pager_vget(vp);
	if (error)
		panic("ubc_info_init: vnode_pager_vget error = %d", error);

	/* initialize the size */
	error = VOP_GETATTR(vp, &vattr, p->p_ucred, p);

	ubc_lock(vp);
	uip->ui_size = (error ? 0: vattr.va_size);

done:
	CLR(vp->v_flag, VUINIT);
	if (ISSET(vp->v_flag, VUWANT)) {
		CLR(vp->v_flag, VUWANT);
		ubc_unlock(vp);
		wakeup((caddr_t)vp);
	} else 
		ubc_unlock(vp);

	return (error);
}

/* Free the ubc_info */
static void
ubc_info_free(struct ubc_info *uip)
{
	struct ucred *credp;
	
	credp = uip->ui_ucred;
	if (credp != NOCRED) {
		uip->ui_ucred = NOCRED;
		crfree(credp);
	}

	if (uip->ui_control != MEMORY_OBJECT_CONTROL_NULL)
		memory_object_control_deallocate(uip->ui_control);

	zfree(ubc_info_zone, (vm_offset_t)uip);
	return;
}

void
ubc_info_deallocate(struct ubc_info *uip)
{

	assert(uip->ui_refcount > 0);

    if (uip->ui_refcount-- == 1) {
		struct vnode *vp;

		vp = uip->ui_vnode;
		if (ISSET(uip->ui_flags, UI_WANTED)) {
			CLR(uip->ui_flags, UI_WANTED);
			wakeup((caddr_t)&vp->v_ubcinfo);
		}

		ubc_info_free(uip);
	}
}

/*
 * Communicate with VM the size change of the file
 * returns 1 on success, 0 on failure
 */
int
ubc_setsize(struct vnode *vp, off_t nsize)
{
	off_t osize;	/* ui_size before change */
	off_t lastpg, olastpgend, lastoff;
	struct ubc_info *uip;
	memory_object_control_t control;
	kern_return_t kret;

	assert(nsize >= (off_t)0);

	if (UBCINVALID(vp))
		return (0);

	if (!UBCINFOEXISTS(vp))
		return (0);

	uip = vp->v_ubcinfo;
	osize = uip->ui_size;	/* call ubc_getsize() ??? */
	/* Update the size before flushing the VM */
	uip->ui_size = nsize;

	if (nsize >= osize)	/* Nothing more to do */
		return (1);		/* return success */

	/*
	 * When the file shrinks, invalidate the pages beyond the
	 * new size. Also get rid of garbage beyond nsize on the
	 * last page. The ui_size already has the nsize. This
	 * insures that the pageout would not write beyond the new
	 * end of the file.
	 */

	lastpg = trunc_page_64(nsize);
	olastpgend = round_page_64(osize);
	control = uip->ui_control;
	assert(control);
	lastoff = (nsize & PAGE_MASK_64);

	/*
	 * If length is multiple of page size, we should not flush
	 * invalidating is sufficient
	 */
	 if (!lastoff) {
        /* invalidate last page and old contents beyond nsize */
        kret = memory_object_lock_request(control,
                    (memory_object_offset_t)lastpg,
                    (memory_object_size_t)(olastpgend - lastpg),
                    MEMORY_OBJECT_RETURN_NONE, MEMORY_OBJECT_DATA_FLUSH,
                    VM_PROT_NO_CHANGE);
        if (kret != KERN_SUCCESS)
            printf("ubc_setsize: invalidate failed (error = %d)\n", kret);

		return ((kret == KERN_SUCCESS) ? 1 : 0);
	 }

	/* flush the last page */
	kret = memory_object_lock_request(control,
				(memory_object_offset_t)lastpg,
				PAGE_SIZE_64,
				MEMORY_OBJECT_RETURN_DIRTY, FALSE,
				VM_PROT_NO_CHANGE);

	if (kret == KERN_SUCCESS) {
		/* invalidate last page and old contents beyond nsize */
		kret = memory_object_lock_request(control,
					(memory_object_offset_t)lastpg,
					(memory_object_size_t)(olastpgend - lastpg),
					MEMORY_OBJECT_RETURN_NONE, MEMORY_OBJECT_DATA_FLUSH,
					VM_PROT_NO_CHANGE);
		if (kret != KERN_SUCCESS)
			printf("ubc_setsize: invalidate failed (error = %d)\n", kret);
	} else
		printf("ubc_setsize: flush failed (error = %d)\n", kret);

	return ((kret == KERN_SUCCESS) ? 1 : 0);
}

/*
 * Get the size of the file
 */
off_t
ubc_getsize(struct vnode *vp)
{
	return (vp->v_ubcinfo->ui_size);
}

/*
 * Caller indicate that the object corresponding to the vnode 
 * can not be cached in object cache. Make it so.
 * returns 1 on success, 0 on failure
 */
int
ubc_uncache(struct vnode *vp)
{
	kern_return_t kret;
	struct ubc_info *uip;
	int    recursed;
	memory_object_control_t control;
	memory_object_perf_info_data_t   perf;

	if (!UBCINFOEXISTS(vp))
		return (0);

	if ((recursed = ubc_busy(vp)) == 0)
		return (0);

	uip = vp->v_ubcinfo;

	assert(uip != UBC_INFO_NULL);

	/*
	 * AGE it so that vfree() can make sure that it
	 * would get recycled soon after the last reference is gone
	 * This will insure that .nfs turds would not linger
	 */
	vagevp(vp);

	/* set the "do not cache" bit */
	SET(uip->ui_flags, UI_DONTCACHE);

	control = uip->ui_control;
	assert(control);

	perf.cluster_size = PAGE_SIZE; /* XXX use real cluster_size. */
	perf.may_cache = FALSE;
	kret = memory_object_change_attributes(control,
				MEMORY_OBJECT_PERFORMANCE_INFO,
				(memory_object_info_t) &perf,
				MEMORY_OBJECT_PERF_INFO_COUNT);

	if (kret != KERN_SUCCESS) {
		printf("ubc_uncache: memory_object_change_attributes_named "
			"kret = %d", kret);
		if (recursed == 1)
			ubc_unbusy(vp);
		return (0);
	}

	ubc_release_named(vp);

	if (recursed == 1)
		ubc_unbusy(vp);
	return (1);
}

/*
 * call ubc_clean() and ubc_uncache() on all the vnodes
 * for this mount point.
 * returns 1 on success, 0 on failure
 */
__private_extern__ int
ubc_umount(struct mount *mp)
{
	struct proc *p = current_proc();
	struct vnode *vp, *nvp;
	int ret = 1;

loop:
	simple_lock(&mntvnode_slock);
	for (vp = mp->mnt_vnodelist.lh_first; vp; vp = nvp) {
		if (vp->v_mount != mp) {
			simple_unlock(&mntvnode_slock);
			goto loop;
		}
		nvp = vp->v_mntvnodes.le_next;
		simple_unlock(&mntvnode_slock);
		if (UBCINFOEXISTS(vp)) {

			/*
			 * Must get a valid reference on the vnode
			 * before callig UBC functions
			 */
			if (vget(vp, 0, p)) {
				ret = 0;
				simple_lock(&mntvnode_slock);
				continue; /* move on to the next vnode */
			}
			ret &= ubc_clean(vp, 0); /* do not invalidate */
			ret &= ubc_uncache(vp);
			vrele(vp);
		}
		simple_lock(&mntvnode_slock);
	}
	simple_unlock(&mntvnode_slock);
	return (ret);
}

/*
 * Call ubc_unmount() for all filesystems.
 * The list is traversed in reverse order
 * of mounting to avoid dependencies.
 */
__private_extern__ void
ubc_unmountall()
{
	struct mount *mp, *nmp;

	/*
	 * Since this only runs when rebooting, it is not interlocked.
	 */
	for (mp = mountlist.cqh_last; mp != (void *)&mountlist; mp = nmp) {
		nmp = mp->mnt_list.cqe_prev;
		(void) ubc_umount(mp);
	}
}

/* Get the credentials */
struct ucred *
ubc_getcred(struct vnode *vp)
{
	struct ubc_info *uip;

	uip = vp->v_ubcinfo;

	if (UBCINVALID(vp))
		return (NOCRED);

	return (uip->ui_ucred);
}

/*
 * Set the credentials
 * existing credentials are not changed
 * returns 1 on success and 0 on failure
 */
int
ubc_setcred(struct vnode *vp, struct proc *p)
{
	struct ubc_info *uip;
	struct ucred *credp;

	uip = vp->v_ubcinfo;

	if (UBCINVALID(vp))
		return (0); 

	credp = uip->ui_ucred;
	if (credp == NOCRED) {
		crhold(p->p_ucred);
		uip->ui_ucred = p->p_ucred;
	} 

	return (1);
}

/* Get the pager */
__private_extern__ memory_object_t
ubc_getpager(struct vnode *vp)
{
	struct ubc_info *uip;

	uip = vp->v_ubcinfo;

	if (UBCINVALID(vp))
		return (0);

	return (uip->ui_pager);
}

/*
 * Get the memory object associated with this vnode
 * If the vnode was reactivated, memory object would not exist.
 * Unless "do not rectivate" was specified, look it up using the pager.
 * If hold was requested create an object reference of one does not
 * exist already.
 */

memory_object_control_t
ubc_getobject(struct vnode *vp, int flags)
{
	struct ubc_info *uip;
	int    recursed;
	memory_object_control_t control;

	if (UBCINVALID(vp))
		return (0);

	if (flags & UBC_FOR_PAGEOUT)
	        return(vp->v_ubcinfo->ui_control);

	if ((recursed = ubc_busy(vp)) == 0)
		return (0);

	uip = vp->v_ubcinfo;
	control = uip->ui_control;

	if ((flags & UBC_HOLDOBJECT) && (!ISSET(uip->ui_flags, UI_HASOBJREF))) {

		/*
		 * Take a temporary reference on the ubc info so that it won't go
		 * away during our recovery attempt.
		 */
		ubc_lock(vp);
		uip->ui_refcount++;
		ubc_unlock(vp);
		if (memory_object_recover_named(control, TRUE) == KERN_SUCCESS) {
			SET(uip->ui_flags, UI_HASOBJREF);
		} else {
			control = MEMORY_OBJECT_CONTROL_NULL;
		}
		if (recursed == 1)
			ubc_unbusy(vp);
		ubc_info_deallocate(uip);

	} else {
		if (recursed == 1)
			ubc_unbusy(vp);
	}

	return (control);
}

/* Set the pager */
int
ubc_setpager(struct vnode *vp, memory_object_t pager)
{
	struct ubc_info *uip;

	uip = vp->v_ubcinfo;

	if (UBCINVALID(vp))
		return (0);

	uip->ui_pager = pager;
	return (1);
}

int 
ubc_setflags(struct vnode * vp, int  flags)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp))
		return (0);

	uip = vp->v_ubcinfo;

	SET(uip->ui_flags, flags);

	return (1);	
} 

int 
ubc_clearflags(struct vnode * vp, int  flags)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp))
		return (0);

	uip = vp->v_ubcinfo;

	CLR(uip->ui_flags, flags);

	return (1);	
} 


int 
ubc_issetflags(struct vnode * vp, int  flags)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp))
		return (0);

	uip = vp->v_ubcinfo;

	return (ISSET(uip->ui_flags, flags));
} 

off_t
ubc_blktooff(struct vnode *vp, daddr_t blkno)
{
	off_t file_offset;
	int error;

    if (UBCINVALID(vp))
        return ((off_t)-1);

	error = VOP_BLKTOOFF(vp, blkno, &file_offset);
	if (error)
		file_offset = -1;

	return (file_offset);
}

daddr_t
ubc_offtoblk(struct vnode *vp, off_t offset)
{
	daddr_t blkno;
	int error = 0;

    if (UBCINVALID(vp)) { 
        return ((daddr_t)-1);
    }   

	error = VOP_OFFTOBLK(vp, offset, &blkno);
	if (error)
		blkno = -1;

	return (blkno);
}

/*
 * Cause the file data in VM to be pushed out to the storage
 * it also causes all currently valid pages to be released
 * returns 1 on success, 0 on failure
 */
int
ubc_clean(struct vnode *vp, int invalidate)
{
	off_t size;
	struct ubc_info *uip;
	memory_object_control_t control;
	kern_return_t kret;
	int flags = 0;

	if (UBCINVALID(vp))
		return (0);

	if (!UBCINFOEXISTS(vp))
		return (0);

	/*
	 * if invalidate was requested, write dirty data and then discard
	 * the resident pages
	 */
	if (invalidate)
		flags = (MEMORY_OBJECT_DATA_FLUSH | MEMORY_OBJECT_DATA_NO_CHANGE);

	uip = vp->v_ubcinfo;
	size = uip->ui_size;	/* call ubc_getsize() ??? */

	control = uip->ui_control;
	assert(control);

	vp->v_flag &= ~VHASDIRTY;
	vp->v_clen = 0;

	/* Write the dirty data in the file and discard cached pages */
	kret = memory_object_lock_request(control,
				(memory_object_offset_t)0,
				(memory_object_size_t)round_page_64(size),
				MEMORY_OBJECT_RETURN_ALL, flags,
				VM_PROT_NO_CHANGE);

	if (kret != KERN_SUCCESS)
		printf("ubc_clean: clean failed (error = %d)\n", kret);

	return ((kret == KERN_SUCCESS) ? 1 : 0);
}

/*
 * Cause the file data in VM to be pushed out to the storage
 * currently valid pages are NOT invalidated
 * returns 1 on success, 0 on failure
 */
int
ubc_pushdirty(struct vnode *vp)
{
	off_t size;
	struct ubc_info *uip;
	memory_object_control_t control;
	kern_return_t kret;

	if (UBCINVALID(vp))
		return (0);

	if (!UBCINFOEXISTS(vp))
		return (0);

	uip = vp->v_ubcinfo;
	size = uip->ui_size;	/* call ubc_getsize() ??? */

	control = uip->ui_control;
	assert(control);

	vp->v_flag &= ~VHASDIRTY;
	vp->v_clen = 0;

	/* Write the dirty data in the file and discard cached pages */
	kret = memory_object_lock_request(control,
				(memory_object_offset_t)0,
				(memory_object_size_t)round_page_64(size),
				MEMORY_OBJECT_RETURN_DIRTY, FALSE,
				VM_PROT_NO_CHANGE);

	if (kret != KERN_SUCCESS)
		printf("ubc_pushdirty: flush failed (error = %d)\n", kret);

	return ((kret == KERN_SUCCESS) ? 1 : 0);
}

/*
 * Cause the file data in VM to be pushed out to the storage
 * currently valid pages are NOT invalidated
 * returns 1 on success, 0 on failure
 */
int
ubc_pushdirty_range(struct vnode *vp, off_t offset, off_t size)
{
	struct ubc_info *uip;
	memory_object_control_t control;
	kern_return_t kret;

	if (UBCINVALID(vp))
		return (0);

	if (!UBCINFOEXISTS(vp))
		return (0);

	uip = vp->v_ubcinfo;

	control = uip->ui_control;
	assert(control);

	/* Write any dirty pages in the requested range of the file: */
	kret = memory_object_lock_request(control,
				(memory_object_offset_t)offset,
				(memory_object_size_t)round_page_64(size),
				MEMORY_OBJECT_RETURN_DIRTY, FALSE,
				VM_PROT_NO_CHANGE);

	if (kret != KERN_SUCCESS)
		printf("ubc_pushdirty_range: flush failed (error = %d)\n", kret);

	return ((kret == KERN_SUCCESS) ? 1 : 0);
}

/*
 * Make sure the vm object does not vanish 
 * returns 1 if the hold count was incremented
 * returns 0 if the hold count was not incremented
 * This return value should be used to balance 
 * ubc_hold() and ubc_rele().
 */
int
ubc_hold(struct vnode *vp)
{
	struct ubc_info *uip;
	int    recursed;
	memory_object_control_t object;

	if (UBCINVALID(vp))
		return (0);

	if ((recursed = ubc_busy(vp)) == 0) {
		/* must be invalid or dying vnode */
		assert(UBCINVALID(vp) ||
			((vp->v_flag & VXLOCK) || (vp->v_flag & VTERMINATE)));
		return (0);
	}

	uip = vp->v_ubcinfo;
	assert(uip->ui_control != MEMORY_OBJECT_CONTROL_NULL);

	ubc_lock(vp);
	uip->ui_refcount++;
	ubc_unlock(vp);

	if (!ISSET(uip->ui_flags, UI_HASOBJREF)) {
		if (memory_object_recover_named(uip->ui_control, TRUE)
			!= KERN_SUCCESS) {
			if (recursed == 1)
				ubc_unbusy(vp);
			ubc_info_deallocate(uip);
			return (0);
		}
		SET(uip->ui_flags, UI_HASOBJREF);
	}
	if (recursed == 1)
		ubc_unbusy(vp);

	assert(uip->ui_refcount > 0);

	return (1);
}

/*
 * Drop the holdcount.
 * release the reference on the vm object if the this is "uncached"
 * ubc_info.
 */
void
ubc_rele(struct vnode *vp)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp))
		return;

	if (!UBCINFOEXISTS(vp)) {
		/* nothing more to do for a dying vnode */
		if ((vp->v_flag & VXLOCK) || (vp->v_flag & VTERMINATE))
			return;
		panic("ubc_rele: can not");
	}

	uip = vp->v_ubcinfo;

	if (uip->ui_refcount == 1)
		panic("ubc_rele: ui_refcount");

	--uip->ui_refcount;

	if ((uip->ui_refcount == 1)
		&& ISSET(uip->ui_flags, UI_DONTCACHE))
		(void) ubc_release_named(vp);

	return;
}

/*
 * The vnode is mapped explicitly, mark it so.
 */
__private_extern__ void
ubc_map(struct vnode *vp)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp))
		return;

	if (!UBCINFOEXISTS(vp))
		return;

	ubc_lock(vp);
	uip = vp->v_ubcinfo;

	SET(uip->ui_flags, UI_WASMAPPED);
	uip->ui_mapped = 1;
	ubc_unlock(vp);

	return;
}

/*
 * Release the memory object reference on the vnode
 * only if it is not in use
 * Return 1 if the reference was released, 0 otherwise.
 */
int
ubc_release_named(struct vnode *vp)
{
	struct ubc_info *uip;
	int    recursed;
	memory_object_control_t control;
	kern_return_t kret = KERN_FAILURE;

	if (UBCINVALID(vp))
		return (0);

	if ((recursed = ubc_busy(vp)) == 0)
		return (0);
	uip = vp->v_ubcinfo;

	/* can not release held or mapped vnodes */
	if (ISSET(uip->ui_flags, UI_HASOBJREF) && 
		(uip->ui_refcount == 1) && !uip->ui_mapped) {
		control = uip->ui_control;
		assert(control);
		CLR(uip->ui_flags, UI_HASOBJREF);
		kret = memory_object_release_name(control,
				MEMORY_OBJECT_RESPECT_CACHE);
	}

	if (recursed == 1)
		ubc_unbusy(vp);
	return ((kret != KERN_SUCCESS) ? 0 : 1);
}

/*
 * This function used to called by extensions directly.  Some may
 * still exist with this behavior.  In those cases, we will do the
 * release as part of reclaiming or cleaning the vnode.  We don't
 * need anything explicit - so just stub this out until those callers
 * get cleaned up.
 */
int
ubc_release(
	struct vnode	*vp)
{
	return 0;
}

/*
 * destroy the named reference for a given vnode
 */
__private_extern__ int
ubc_destroy_named(
	struct vnode	*vp)
{
	memory_object_control_t control;
	struct proc *p;
	struct ubc_info *uip;
	kern_return_t kret;

	/*
	 * We may already have had the object terminated
	 * and the ubcinfo released as a side effect of
	 * some earlier processing.  If so, pretend we did
	 * it, because it probably was a result of our
	 * efforts.
	 */
	if (!UBCINFOEXISTS(vp))
		return (1);

	uip = vp->v_ubcinfo;

	/* can not destroy held vnodes */
	if (uip->ui_refcount > 1)
		return (0);

	/* 
	 * Terminate the memory object.
	 * memory_object_destroy() will result in
	 * vnode_pager_no_senders(). 
	 * That will release the pager reference
	 * and the vnode will move to the free list.
	 */
	control = ubc_getobject(vp, UBC_HOLDOBJECT);
	if (control != MEMORY_OBJECT_CONTROL_NULL) {

		if (ISSET(vp->v_flag, VTERMINATE))
			panic("ubc_destroy_named: already teminating");
		SET(vp->v_flag, VTERMINATE);

		kret = memory_object_destroy(control, 0);
		if (kret != KERN_SUCCESS)
			return (0);

		/* 
		 * memory_object_destroy() is asynchronous
		 * with respect to vnode_pager_no_senders().
		 * wait for vnode_pager_no_senders() to clear
		 * VTERMINATE
		 */
		while (ISSET(vp->v_flag, VTERMINATE)) {
			SET(vp->v_flag, VTERMWANT);
			(void)tsleep((caddr_t)&vp->v_ubcinfo,
						 PINOD, "ubc_destroy_named", 0);
		}
	}
	return (1);
}


/*
 * Invalidate a range in the memory object that backs this
 * vnode. The offset is truncated to the page boundary and the
 * size is adjusted to include the last page in the range.
 */
int
ubc_invalidate(struct vnode *vp, off_t offset, size_t size)
{
	struct ubc_info *uip;
	memory_object_control_t control;
	kern_return_t kret;
	off_t toff;
	size_t tsize;

	if (UBCINVALID(vp))
		return (0);

	if (!UBCINFOEXISTS(vp))
		return (0);

	toff = trunc_page_64(offset);
	tsize = (size_t)(round_page_64(offset+size) - toff);
	uip = vp->v_ubcinfo;
	control = uip->ui_control;
	assert(control);

	/* invalidate pages in the range requested */
	kret = memory_object_lock_request(control,
				(memory_object_offset_t)toff,
				(memory_object_size_t)tsize,
				MEMORY_OBJECT_RETURN_NONE,
				(MEMORY_OBJECT_DATA_NO_CHANGE| MEMORY_OBJECT_DATA_FLUSH),
				VM_PROT_NO_CHANGE);
	if (kret != KERN_SUCCESS)
		printf("ubc_invalidate: invalidate failed (error = %d)\n", kret);

	return ((kret == KERN_SUCCESS) ? 1 : 0);
}

/*
 * Find out whether a vnode is in use by UBC
 * Returns 1 if file is in use by UBC, 0 if not
 */
int
ubc_isinuse(struct vnode *vp, int tookref)
{
	int busycount = tookref ? 2 : 1;

	if (!UBCINFOEXISTS(vp))
		return (0);

	if (tookref == 0) {
		printf("ubc_isinuse: called without a valid reference"
		    ": v_tag = %d\v", vp->v_tag);
		vprint("ubc_isinuse", vp);
		return (0);
	}

	if (vp->v_usecount > busycount)
		return (1);

	if ((vp->v_usecount == busycount)
		&& (vp->v_ubcinfo->ui_mapped == 1))
		return (1);
	else
		return (0);
}

/*
 * The backdoor routine to clear the ui_mapped.
 * MUST only be called by the VM
 *
 * Note that this routine is not called under funnel. There are numerous
 * things about the calling sequence that make this work on SMP.
 * Any code change in those paths can break this.
 *
 */
__private_extern__ void
ubc_unmap(struct vnode *vp)
{
	struct ubc_info *uip;
	boolean_t 	funnel_state;
 
	if (UBCINVALID(vp))
		return;

	if (!UBCINFOEXISTS(vp))
		return;

	ubc_lock(vp);
	uip = vp->v_ubcinfo;
	uip->ui_mapped = 0;
	if ((uip->ui_refcount > 1) || !ISSET(uip->ui_flags, UI_DONTCACHE)) {
		ubc_unlock(vp);
		return;
	}
	ubc_unlock(vp);

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	(void) ubc_release_named(vp);
	(void) thread_funnel_set(kernel_flock, funnel_state);
}

kern_return_t
ubc_page_op(
	struct vnode 	*vp,
	off_t		f_offset,
	int		ops,
	ppnum_t	*phys_entryp,
	int		*flagsp)
{
	memory_object_control_t		control;

	control = ubc_getobject(vp, UBC_FLAGS_NONE);
	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	return (memory_object_page_op(control,
				      (memory_object_offset_t)f_offset,
				      ops,
				      phys_entryp,
				      flagsp));
}
				      
kern_return_t
ubc_create_upl(
	struct vnode	*vp,
	off_t 			f_offset,
	long			bufsize,
	upl_t			*uplp,
	upl_page_info_t	**plp,
	int				uplflags)
{
	memory_object_control_t		control;
	int				count;
	int                             ubcflags;
	off_t				file_offset;
	kern_return_t			kr;
	
	if (bufsize & 0xfff)
		return KERN_INVALID_ARGUMENT;

	if (uplflags & UPL_FOR_PAGEOUT) {
		uplflags &= ~UPL_FOR_PAGEOUT;
	        ubcflags  =  UBC_FOR_PAGEOUT;
	} else
	        ubcflags = UBC_FLAGS_NONE;

	control = ubc_getobject(vp, ubcflags);
	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	uplflags |= (UPL_NO_SYNC|UPL_CLEAN_IN_PLACE|UPL_SET_INTERNAL);
	count = 0;
	kr = memory_object_upl_request(control, f_offset, bufsize,
								   uplp, NULL, &count, uplflags);
	if (plp != NULL)
			*plp = UPL_GET_INTERNAL_PAGE_LIST(*uplp);
	return kr;
}
				      

kern_return_t
ubc_upl_map(
	upl_t		upl,
	vm_offset_t	*dst_addr)
{
	return (vm_upl_map(kernel_map, upl, dst_addr));
}


kern_return_t
ubc_upl_unmap(
	upl_t	upl)
{
	return(vm_upl_unmap(kernel_map, upl));
}

kern_return_t
ubc_upl_commit(
	upl_t 			upl)
{
	upl_page_info_t	*pl;
	kern_return_t 	kr;

	pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	kr = upl_commit(upl, pl, MAX_UPL_TRANSFER);
	upl_deallocate(upl);
	return kr;
}


kern_return_t
ubc_upl_commit_range(
	upl_t 			upl,
	vm_offset_t		offset,
	vm_size_t		size,
	int				flags)
{
	upl_page_info_t	*pl;
	boolean_t		empty;
	kern_return_t 	kr;

	if (flags & UPL_COMMIT_FREE_ON_EMPTY)
		flags |= UPL_COMMIT_NOTIFY_EMPTY;

	pl = UPL_GET_INTERNAL_PAGE_LIST(upl);

	kr = upl_commit_range(upl, offset, size, flags,
						  pl, MAX_UPL_TRANSFER, &empty);

	if((flags & UPL_COMMIT_FREE_ON_EMPTY) && empty)
		upl_deallocate(upl);

	return kr;
}
	
kern_return_t
ubc_upl_abort_range(
	upl_t			upl,
	vm_offset_t		offset,
	vm_size_t		size,
	int				abort_flags)
{
	kern_return_t 	kr;
	boolean_t		empty = FALSE;

	if (abort_flags & UPL_ABORT_FREE_ON_EMPTY)
		abort_flags |= UPL_ABORT_NOTIFY_EMPTY;

	kr = upl_abort_range(upl, offset, size, abort_flags, &empty);

	if((abort_flags & UPL_ABORT_FREE_ON_EMPTY) && empty)
		upl_deallocate(upl);

	return kr;
}

kern_return_t
ubc_upl_abort(
	upl_t			upl,
	int				abort_type)
{
	kern_return_t	kr;

	kr = upl_abort(upl, abort_type);
	upl_deallocate(upl);
	return kr;
}

upl_page_info_t *
ubc_upl_pageinfo(
	upl_t			upl)
{	       
	return (UPL_GET_INTERNAL_PAGE_LIST(upl));
}
