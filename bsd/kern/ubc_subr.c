/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
/* 
 *	File:	ubc_subr.c
 *	Author:	Umesh Vaishampayan [umeshv@apple.com]
 *		05-Aug-1999	umeshv	Created.
 *
 *	Functions related to Unified Buffer cache.
 *
 */ 

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
    if (!(cond)) panic("%s:%d (%s)", __FILE__, __LINE__, # cond)
#else
#include <kern/assert.h>
#endif /* DIAGNOSTIC */

struct zone	*ubc_info_zone;

#if DIAGNOSTIC
#define USHOULDNOT(fun)	panic("%s: should not", (fun));
#else
#define USHOULDNOT(fun)
#endif /* DIAGNOSTIC */


static void *_ubc_getobject(struct vnode *, int);
static void ubc_lock(struct vnode *);
static void ubc_unlock(struct vnode *);

static void
ubc_getobjref(struct vnode *vp)
{
	register struct ubc_info	*uip;
	void *pager_cport;
	void *object;

	uip = vp->v_ubcinfo;

	if (pager_cport = (void *)vnode_pager_lookup(vp, uip->ui_pager))
		object = (void *)vm_object_lookup(pager_cport);

	if (object != uip->ui_object) {
#if 0
		Debugger("ubc_getobjref: object changed");
#endif /* 0 */
		uip->ui_object = object;
	}

	if (uip->ui_object == NULL)
		panic("ubc_getobjref: lost object");
}

/*
 *	Initialization of the zone for Unified Buffer Cache.
 */
void
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
	void * 	pager_cport;

	assert(vp);
	assert(UBCISVALID(vp));

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
		bzero(uip, sizeof(struct ubc_info));
		ubc_lock(vp);
		SET(uip->ui_flags, UI_INITED);
		uip->ui_vnode = vp;
		uip->ui_ucred = NOCRED;
	}
	
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

	/*
	 * Can not use VOP_GETATTR() to get accurate value
	 * of ui_size. Thanks to NFS.
	 * nfs_getattr() can call vinvalbuf() and in this case
	 * ubc_info is not set up to deal with that.
	 * So use bogus size.
	 */

	/* create a vm_object association */
	kret = vm_object_create_nomap(pager, (vm_object_offset_t)uip->ui_size);
	if (kret != KERN_SUCCESS)
		panic("ubc_info_init: vm_object_create_nomap returned %d", kret);

	/* _ubc_getobject() gets a reference on the memory object */
	if (_ubc_getobject(vp, 0) == NULL)
		panic("ubc_info_init: lost vmobject : uip = 0X%08x", uip);

	/*
	 * vm_object_allocate() called from vm_object_create_nomap()
	 * created the object with a refcount of 1
	 * need to drop the reference gained by vm_object_lookup()
	 */
	vm_object_deallocate(uip->ui_object);

	/* create a pager reference on the vnode */
	error = vget(vp, LK_INTERLOCK, p);
	if (error)
		panic("ubc_info_init: vget error = %d", error);

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

	return(error);
}

/* Free the ubc_info */
void
ubc_info_free(struct vnode *vp)
{
	register struct ubc_info	*uip;
	struct ucred *credp;
	
	assert(vp);

	uip = vp->v_ubcinfo;
	vp->v_ubcinfo = UBC_INFO_NULL;
	credp = uip->ui_ucred;
	if (credp != NOCRED) {
		uip->ui_ucred = NOCRED;
		crfree(credp);
	}
	zfree(ubc_info_zone, (vm_offset_t)uip);
	return;
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
	void *object;
	kern_return_t kret;
	int didhold;

#if DIAGNOSTIC
	assert(vp);
	assert(nsize >= (off_t)0);
#endif

	if (UBCINVALID(vp))
		return(0);

	if (!UBCINFOEXISTS(vp))
		return(0);

	uip = vp->v_ubcinfo;
	osize = uip->ui_size;	/* call ubc_getsize() ??? */
	/* Update the size before flushing the VM */
	uip->ui_size = nsize;

	if (nsize >= osize)	/* Nothing more to do */
		return(0);

	/*
	 * When the file shrinks, invalidate the pages beyond the
	 * new size. Also get rid of garbage beyond nsize on the
	 * last page. The ui_size already has the nsize. This
	 * insures that the pageout would not write beyond the new
	 * end of the file.
	 */

	didhold = ubc_hold(vp);
	lastpg = trunc_page_64(nsize);
	olastpgend = round_page_64(osize);
	object = _ubc_getobject(vp, UBC_NOREACTIVATE);
	assert(object);
	lastoff = (nsize & PAGE_MASK_64);

	/*
	 * If length is multiple of page size, we should not flush
	 * invalidating is sufficient
	 */
	 if (!lastoff) {
        /*
         * memory_object_lock_request() drops an object
         * reference. gain a reference before calling it
         */
        ubc_getobjref(vp);

        /* invalidate last page and old contents beyond nsize */
        kret = memory_object_lock_request(object,
                    (vm_object_offset_t)lastpg,
                    (memory_object_size_t)(olastpgend - lastpg),
                    MEMORY_OBJECT_RETURN_NONE,TRUE,
                    VM_PROT_NO_CHANGE,MACH_PORT_NULL);
        if (kret != KERN_SUCCESS)
            printf("ubc_setsize: invalidate failed (error = %d)\n", kret);

		if (didhold)
			ubc_rele(vp);
		return ((kret == KERN_SUCCESS) ? 1 : 0);
	 }

	/* 
	 * memory_object_lock_request() drops an object
	 * reference. gain a reference before calling it
	 */
	ubc_getobjref(vp);

	/* flush the last page */
	kret = memory_object_lock_request(object,
				(vm_object_offset_t)lastpg,
				PAGE_SIZE_64,
				MEMORY_OBJECT_RETURN_DIRTY,FALSE,
				VM_PROT_NO_CHANGE,MACH_PORT_NULL);

	if (kret == KERN_SUCCESS) {
		/* 
		 * memory_object_lock_request() drops an object
		 * reference. gain a reference before calling it
		 */
		ubc_getobjref(vp);

		/* invalidate last page and old contents beyond nsize */
		kret = memory_object_lock_request(object,
					(vm_object_offset_t)lastpg,
					(memory_object_size_t)(olastpgend - lastpg),
					MEMORY_OBJECT_RETURN_NONE,TRUE,
					VM_PROT_NO_CHANGE,MACH_PORT_NULL);
		if (kret != KERN_SUCCESS)
			printf("ubc_setsize: invalidate failed (error = %d)\n", kret);
	} else
		printf("ubc_setsize: flush failed (error = %d)\n", kret);

	if (didhold)
		ubc_rele(vp);
	return ((kret == KERN_SUCCESS) ? 1 : 0);
}

/*
 * Get the size of the file
 * For local file systems the size is locally cached. For NFS
 * there might be a network transaction for this.
 */
off_t
ubc_getsize(struct vnode *vp)
{
	/* XXX deal with NFS */
	return (vp->v_ubcinfo->ui_size);
}

/* lock for changes to struct UBC */
static void
ubc_lock(struct vnode *vp)
{
	/* For now, just use the v_interlock */
	simple_lock(&vp->v_interlock);
}

/* unlock */
static void
ubc_unlock(struct vnode *vp)
{
	/* For now, just use the v_interlock */
	simple_unlock(&vp->v_interlock);
}

/*
 * Caller indicate that the object corresponding to the vnode 
 * can not be cached in object cache. Make it so.
 * returns 1 on success, 0 on failure
 *
 * Caller of ubc_uncache() MUST have a valid reference on the vnode.
 */
int
ubc_uncache(struct vnode *vp)
{
	void *object;
	kern_return_t kret;
	struct ubc_info *uip;
	memory_object_perf_info_data_t   perf;
	int didhold;

	assert(vp);

	if (!UBCINFOEXISTS(vp))
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

	didhold = ubc_hold(vp);

	object = _ubc_getobject(vp, UBC_NOREACTIVATE);
	assert(object);

	/* 
	 * memory_object_change_attributes() drops an object
	 * reference. gain a reference before calling it
	 */
	ubc_getobjref(vp);

	perf.cluster_size = PAGE_SIZE; /* XXX use real cluster_size. */
	perf.may_cache = FALSE;
	kret = memory_object_change_attributes(object,
				MEMORY_OBJECT_PERFORMANCE_INFO,
				(memory_object_info_t) &perf,
				MEMORY_OBJECT_PERF_INFO_COUNT,
				MACH_PORT_NULL, 0);

	if (didhold)
		ubc_rele(vp);

	if (kret != KERN_SUCCESS) {
#if DIAGNOSTIC
		panic("ubc_uncache: memory_object_change_attributes "
			"kret = %d", kret);
#endif /* DIAGNOSTIC */
		return (0);
	}

	return (1);
}


/*
 * call ubc_clean() and ubc_uncache() on all the vnodes
 * for this mount point.
 * returns 1 on success, 0 on failure
 */
int
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
			ret &= ubc_clean(vp, 0); /* do not invalidate */
			ret &= ubc_uncache(vp);
			ubc_release(vp);
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
void
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

	assert(vp);

	uip = vp->v_ubcinfo;

	assert(uip);

	if (UBCINVALID(vp)) {
		return (NOCRED);
	}

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

	assert(vp);
	assert(p);

	uip = vp->v_ubcinfo;

	assert(uip);

	if (UBCINVALID(vp)) {
		USHOULDNOT("ubc_setcred");
		return (0); 
	}

	credp = uip->ui_ucred;
	if (credp == NOCRED) {
		crhold(p->p_ucred);
		uip->ui_ucred = p->p_ucred;
	} 

	return (1);
}

/* Get the pager */
void *
ubc_getpager(struct vnode *vp)
{
	struct ubc_info *uip;

	assert(vp);

	uip = vp->v_ubcinfo;

	assert(uip);

	if (UBCINVALID(vp)) {
		USHOULDNOT("ubc_getpager");
		return (0);
	}

	return (uip->ui_pager);
}

/*
 * Get the memory object associated with this vnode
 * If the vnode was reactivated, memory object would not exist.
 * Unless "do not rectivate" was specified, look it up using the pager.
 * The vm_object_lookup() would create a reference on the memory object.
 * If hold was requested create an object reference of one does not
 * exist already.
 */

static void *
_ubc_getobject(struct vnode *vp, int flags)
{
	struct ubc_info *uip;
	void *object;

	uip = vp->v_ubcinfo;
	object = uip->ui_object;

	if ((object == NULL) && ISSET(uip->ui_flags, UI_HASPAGER)
		&& !(flags & UBC_NOREACTIVATE)) {
		void *pager_cport; 

		if (ISSET(uip->ui_flags, UI_HASOBJREF))
			panic("ubc_getobject: lost object");

		if (pager_cport = (void *)vnode_pager_lookup(vp, uip->ui_pager)) {
			object = (void *)vm_object_lookup(pager_cport);
#if 0
			if ((uip->ui_object) && (uip->ui_object != object))
				Debugger("_ubc_getobject: object changed");
#endif /* 0 */

			uip->ui_object = object;
		}

		if (object != NULL)
			SET(uip->ui_flags, UI_HASOBJREF);
	}

	if ((flags & UBC_HOLDOBJECT)
		&& (object != NULL)) {
		if (!ISSET(uip->ui_flags, UI_HASOBJREF)) {
			ubc_getobjref(vp);
			SET(uip->ui_flags, UI_HASOBJREF);
		}
	}
	return (uip->ui_object);
}

void *
ubc_getobject(struct vnode *vp, int flags)
{
	struct ubc_info *uip;
	void *object;

	assert(vp);
	uip = vp->v_ubcinfo;
	assert(uip);

	if (UBCINVALID(vp)) {
		return (0);
	}

	object = _ubc_getobject(vp, flags);
	assert(object);

	if (!ISSET(uip->ui_flags, (UI_HASOBJREF|UI_WASMAPPED)) 
		&& !(uip->ui_holdcnt)) {
		if (!(flags & UBC_PAGINGOP))
		panic("ubc_getobject: lost reference");
	}
}

/* Set the pager */
int
ubc_setpager(struct vnode *vp, void *pager)
{
	struct ubc_info *uip;

	assert(vp);

	uip = vp->v_ubcinfo;

	assert(uip);

	if (UBCINVALID(vp)) {
		USHOULDNOT("ubc_setpager");
		return (0);
	}

	uip->ui_pager = pager;
	return (1);
}

int 
ubc_setflags(struct vnode * vp, int  flags)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp)) {
		USHOULDNOT("ubc_setflags");
		return (EINVAL);
	}

	assert(vp);

	uip = vp->v_ubcinfo;

	assert(uip);

	SET(uip->ui_flags, flags);

	return(0);	
} 

int 
ubc_clearflags(struct vnode * vp, int  flags)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp)) {
		USHOULDNOT("ubc_clearflags");
		return (EINVAL);
	}

	assert(vp);

	uip = vp->v_ubcinfo;

	assert(uip);

	CLR(uip->ui_flags, flags);

	return(0);	
} 


int 
ubc_issetflags(struct vnode * vp, int  flags)
{
	struct ubc_info *uip;

	if (UBCINVALID(vp)) {
		USHOULDNOT("ubc_issetflags");
		return (EINVAL);
	}

	assert(vp);

	uip = vp->v_ubcinfo;

	assert(uip);

	return(ISSET(uip->ui_flags, flags));
} 

off_t
ubc_blktooff(struct vnode *vp, daddr_t blkno)
{
	off_t file_offset;
	int error;

	assert(vp);
    if (UBCINVALID(vp)) { 
		USHOULDNOT("ubc_blktooff");
        return ((off_t)-1);
    }   

	error = VOP_BLKTOOFF(vp, blkno, &file_offset);
	if (error)
		file_offset = -1;

	return (file_offset);
}
daddr_t
ubc_offtoblk(struct vnode *vp, off_t offset)
{
	daddr_t blkno;
	int error=0;

	assert(vp);
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
	void *object;
	kern_return_t kret;
	int flags = 0;
	int didhold;

#if DIAGNOSTIC
	assert(vp);
#endif

	if (UBCINVALID(vp))
		return(0);

	if (!UBCINFOEXISTS(vp))
		return(0);

	/*
	 * if invalidate was requested, write dirty data and then discard
	 * the resident pages
	 */
	if (invalidate)
		flags = (MEMORY_OBJECT_DATA_FLUSH | MEMORY_OBJECT_DATA_NO_CHANGE);

	didhold = ubc_hold(vp);
	uip = vp->v_ubcinfo;
	size = uip->ui_size;	/* call ubc_getsize() ??? */

	object = _ubc_getobject(vp, UBC_NOREACTIVATE);
	assert(object);

	/* 
	 * memory_object_lock_request() drops an object
	 * reference. gain a reference before calling it
	 */
	ubc_getobjref(vp);

	vp->v_flag &= ~VHASDIRTY;
	vp->v_clen = 0;

	/* Write the dirty data in the file and discard cached pages */
	kret = memory_object_lock_request(object,
				(vm_object_offset_t)0,
				(memory_object_size_t)round_page_64(size),
				MEMORY_OBJECT_RETURN_ALL, flags,
				VM_PROT_NO_CHANGE,MACH_PORT_NULL);

	if (kret != KERN_SUCCESS) {
		printf("ubc_clean: clean failed (error = %d)\n", kret);
	}

	if (didhold)
		ubc_rele(vp);

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
	void *object;
	kern_return_t kret;
	int didhold;

#if DIAGNOSTIC
	assert(vp);
#endif

	if (UBCINVALID(vp))
		return(0);

	if (!UBCINFOEXISTS(vp))
		return(0);

	didhold = ubc_hold(vp);
	uip = vp->v_ubcinfo;
	size = uip->ui_size;	/* call ubc_getsize() ??? */

	object = _ubc_getobject(vp, UBC_NOREACTIVATE);
	assert(object);

	/* 
	 * memory_object_lock_request() drops an object
	 * reference. gain a reference before calling it
	 */
	ubc_getobjref(vp);

	vp->v_flag &= ~VHASDIRTY;
	vp->v_clen = 0;

	/* Write the dirty data in the file and discard cached pages */
	kret = memory_object_lock_request(object,
				(vm_object_offset_t)0,
				(memory_object_size_t)round_page_64(size),
				MEMORY_OBJECT_RETURN_DIRTY,FALSE,
				VM_PROT_NO_CHANGE,MACH_PORT_NULL);

	if (kret != KERN_SUCCESS) {
		printf("ubc_pushdirty: flush failed (error = %d)\n", kret);
	}

	if (didhold)
		ubc_rele(vp);

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
	void *object;

	if (UBCINVALID(vp))
		return (0);

	if (!UBCINFOEXISTS(vp)) {
		/* nothing more to do for a dying vnode */
		if  ((vp->v_flag & VXLOCK) || (vp->v_flag & VTERMINATE))
			return (0);
		vp->v_ubcinfo = UBC_INFO_NULL;
		ubc_info_init(vp);
	}
	uip = vp->v_ubcinfo;
	object = _ubc_getobject(vp, UBC_NOREACTIVATE);
	assert(object);

	if (uip->ui_holdcnt++ == 0)
			ubc_getobjref(vp);
	if (uip->ui_holdcnt < 0)
		panic("ubc_hold: ui_holdcnt");

	return (1);
}

/* relese the reference on the vm object */
void
ubc_rele(struct vnode *vp)
{
	struct ubc_info *uip;
	void *object;

	if (UBCINVALID(vp))
		return;

	if (!UBCINFOEXISTS(vp)) {
		/* nothing more to do for a dying vnode */
		if ((vp->v_flag & VXLOCK) || (vp->v_flag & VTERMINATE))
			return;
		panic("ubc_rele: can not");
	}

	uip = vp->v_ubcinfo;

	/* get the object before loosing to hold count */
	object = _ubc_getobject(vp, UBC_NOREACTIVATE);

	if (uip->ui_holdcnt == 0)
		panic("ubc_rele: ui_holdcnt");

	if (--uip->ui_holdcnt == 0) {
		/* If the object is already dead do nothing */
		if (object)
		vm_object_deallocate(object);
#if DIAGNOSTIC
		else
			printf("ubc_rele: null object for %x", vp);
#endif /* DIAGNOSTIC */
	}

	return;
}

/*
 * The vnode is mapped explicitly
 * Mark it so, and release the vm object reference gained in
 * ubc_info_init()
 */
void
ubc_map(struct vnode *vp)
{
	struct ubc_info *uip;
	void *object;
 
	ubc_lock(vp);
#if DIAGNOSTIC
	assert(vp);
#endif

	if (UBCINVALID(vp)) {
		ubc_unlock(vp);
		return;
	}

	if (!UBCINFOEXISTS(vp))
		panic("ubc_map: can not");

	uip = vp->v_ubcinfo;

	SET(uip->ui_flags, UI_WASMAPPED);
	uip->ui_mapped = 1;
	ubc_unlock(vp);

#if 1
	/*
	 * Do not release the ubc reference on the
	 * memory object right away. Let vnreclaim
	 * deal with that
	 */
#else
	/*
	 * Release the ubc reference. memory object cahe
	 * is responsible for caching this object now.
	 */
	if (ISSET(uip->ui_flags, UI_HASOBJREF)) {
		object = _ubc_getobject(vp, UBC_NOREACTIVATE);
		assert(object);
		CLR(uip->ui_flags, UI_HASOBJREF);
		vm_object_deallocate(object);
	}
#endif

	return;

}

/*
 * Release the memory object reference on the vnode
 * only if it is not in use
 * Return 1 if the reference was released, 0 otherwise.
 */
int
ubc_release(struct vnode *vp)
{
	struct ubc_info *uip;
	void *object;
#if DIAGNOSTIC
	assert(vp);
#endif

	if (UBCINVALID(vp))
		return (0);

	if (!UBCINFOEXISTS(vp))
		panic("ubc_release: can not");

	uip = vp->v_ubcinfo;

	/* can not release held vnodes */
	if (uip->ui_holdcnt)
		return (0);

	if (ISSET(uip->ui_flags, UI_HASOBJREF)) {
		object = _ubc_getobject(vp, UBC_NOREACTIVATE);
		assert(object);
		CLR(uip->ui_flags, UI_HASOBJREF);
		vm_object_deallocate(object);
		return (1);
	} else 
		return (0);
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
	void *object;
	kern_return_t kret;
	off_t toff;
	size_t tsize;
	int didhold;

#if DIAGNOSTIC
	assert(vp);
#endif

	if (UBCINVALID(vp))
		return;

	if (!UBCINFOEXISTS(vp))
		panic("ubc_invalidate: can not");

	didhold = ubc_hold(vp);
	toff = trunc_page_64(offset);
	tsize = (size_t)(round_page_64(offset+size) - toff);
	uip = vp->v_ubcinfo;
	object = _ubc_getobject(vp, UBC_NOREACTIVATE);
	assert(object);

	/* 
	 * memory_object_lock_request() drops an object
	 * reference. gain a reference before calling it
	 */
	ubc_getobjref(vp);

	/* invalidate pages in the range requested */
	kret = memory_object_lock_request(object,
				(vm_object_offset_t)toff,
				(memory_object_size_t)tsize,
				MEMORY_OBJECT_RETURN_NONE,
				(MEMORY_OBJECT_DATA_NO_CHANGE| MEMORY_OBJECT_DATA_FLUSH),
				VM_PROT_NO_CHANGE,MACH_PORT_NULL);
	if (kret != KERN_SUCCESS)
		printf("ubc_invalidate: invalidate failed (error = %d)\n", kret);

	if (didhold)
		ubc_rele(vp);

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
		return(0);

	if (vp->v_usecount > busycount)
		return (1);

	if ((vp->v_usecount == busycount)
		&& (vp->v_ubcinfo->ui_mapped == 1))
		return(1);
	else
		return(0);
}


/* -- UGLY HACK ALERT -- */
/*
 * The backdoor routine to clear the UI_WASMAPPED bit.
 * MUST only be called by the VM
 *
 * Note that this routine is not under funnel. There are numerous
 * thing about the calling sequence that make this work on SMP.
 * Any code change in those paths can break this.
 *
 * This will be replaced soon.
 */
void
ubc_unmap(struct vnode *vp)
{
	struct ubc_info *uip;
 
#if DIAGNOSTIC
	assert(vp);
#endif

	if (UBCINVALID(vp)) {
		return;
	}

	if (!UBCINFOEXISTS(vp))
		panic("ubc_unmap: can not");

	ubc_lock(vp);
	uip = vp->v_ubcinfo;

	uip->ui_mapped = 0;
	ubc_unlock(vp);

	return;
}

