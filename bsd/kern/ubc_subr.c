/*
 * Copyright (c) 1999-2004 Apple Computer, Inc. All rights reserved.
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
 * Caller of UBC functions MUST have a valid reference on the vnode.
 *
 */ 

#undef DIAGNOSTIC
#define DIAGNOSTIC 1

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mman.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/ubc_internal.h>
#include <sys/ucred.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/buf.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <mach/memory_object_control.h>
#include <mach/vm_map.h>
#include <mach/upl.h>

#include <kern/kern_types.h>
#include <kern/zalloc.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h> /* last */

#if DIAGNOSTIC
#if defined(assert)
#undef assert()
#endif
#define assert(cond)    \
    ((void) ((cond) ? 0 : panic("%s:%d (%s)", __FILE__, __LINE__, # cond)))
#else
#include <kern/assert.h>
#endif /* DIAGNOSTIC */

int ubc_info_init_internal(struct vnode *vp, int withfsize, off_t filesize);
int ubc_umcallback(vnode_t, void *);
int ubc_isinuse_locked(vnode_t, int, int);
int ubc_msync_internal(vnode_t, off_t, off_t, off_t *, int, int *);

struct zone	*ubc_info_zone;

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
	return(ubc_info_init_internal(vp, 0, 0));
}
int
ubc_info_init_withsize(struct vnode *vp, off_t filesize)
{
	return(ubc_info_init_internal(vp, 1, filesize));
}

int
ubc_info_init_internal(struct vnode *vp, int withfsize, off_t filesize)
{
	register struct ubc_info	*uip;
	void *  pager;
	struct proc *p = current_proc();
	int error = 0;
	kern_return_t kret;
	memory_object_control_t control;

	uip = vp->v_ubcinfo;

	if (uip == UBC_INFO_NULL) {

		uip = (struct ubc_info *) zalloc(ubc_info_zone);
		bzero((char *)uip, sizeof(struct ubc_info));

		uip->ui_vnode = vp;
		uip->ui_flags = UI_INITED;
		uip->ui_ucred = NOCRED;
	}
#if DIAGNOSTIC
	else
		Debugger("ubc_info_init: already");
#endif /* DIAGNOSTIC */
	
	assert(uip->ui_flags != UI_NONE);
	assert(uip->ui_vnode == vp);

	/* now set this ubc_info in the vnode */
	vp->v_ubcinfo = uip;

	pager = (void *)vnode_pager_setup(vp, uip->ui_pager);
	assert(pager);

	SET(uip->ui_flags, UI_HASPAGER);
	uip->ui_pager = pager;

	/*
	 * Note: We can not use VNOP_GETATTR() to get accurate
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
#if 0
	/* create a pager reference on the vnode */
	error = vnode_pager_vget(vp);
	if (error)
		panic("ubc_info_init: vnode_pager_vget error = %d", error);
#endif
	if (withfsize == 0) {
		struct vfs_context context;
		/* initialize the size */
		context.vc_proc = p;
		context.vc_ucred = kauth_cred_get();
		error = vnode_size(vp, &uip->ui_size, &context);
		if (error)
			uip->ui_size = 0;
	} else {
		uip->ui_size = filesize;
	}
	vp->v_lflag |= VNAMED_UBC;

	return (error);
}

/* Free the ubc_info */
static void
ubc_info_free(struct ubc_info *uip)
{
	kauth_cred_t credp;
	
	credp = uip->ui_ucred;
	if (credp != NOCRED) {
		uip->ui_ucred = NOCRED;
		kauth_cred_rele(credp);
	}

	if (uip->ui_control != MEMORY_OBJECT_CONTROL_NULL)
		memory_object_control_deallocate(uip->ui_control);
	
	cluster_release(uip);

	zfree(ubc_info_zone, (vm_offset_t)uip);
	return;
}

void
ubc_info_deallocate(struct ubc_info *uip)
{
        ubc_info_free(uip);
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

	if (nsize < (off_t)0)
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
		    (memory_object_size_t)(olastpgend - lastpg), NULL, NULL,
                    MEMORY_OBJECT_RETURN_NONE, MEMORY_OBJECT_DATA_FLUSH,
                    VM_PROT_NO_CHANGE);
        if (kret != KERN_SUCCESS)
            printf("ubc_setsize: invalidate failed (error = %d)\n", kret);

		return ((kret == KERN_SUCCESS) ? 1 : 0);
	 }

	/* flush the last page */
	kret = memory_object_lock_request(control,
				(memory_object_offset_t)lastpg,
			        PAGE_SIZE_64, NULL, NULL,
				MEMORY_OBJECT_RETURN_DIRTY, FALSE,
				VM_PROT_NO_CHANGE);

	if (kret == KERN_SUCCESS) {
		/* invalidate last page and old contents beyond nsize */
		kret = memory_object_lock_request(control,
					(memory_object_offset_t)lastpg,
				        (memory_object_size_t)(olastpgend - lastpg), NULL, NULL,
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
	/* people depend on the side effect of this working this way
	 * as they call this for directory 
	 */
	if (!UBCINFOEXISTS(vp))
		return ((off_t)0);
	return (vp->v_ubcinfo->ui_size);
}

/*
 * call ubc_sync_range(vp, 0, EOF, UBC_PUSHALL) on all the vnodes
 * for this mount point.
 * returns 1 on success, 0 on failure
 */

__private_extern__ int
ubc_umount(struct mount *mp)
{
	vnode_iterate(mp, 0, ubc_umcallback, 0);
	return(0);
}

static int
ubc_umcallback(vnode_t vp, __unused void * args)
{

	if (UBCINFOEXISTS(vp)) {

		cluster_push(vp, 0);

		(void) ubc_msync(vp, (off_t)0, ubc_getsize(vp), NULL, UBC_PUSHALL);
	}
	return (VNODE_RETURNED);
}



/* Get the credentials */
kauth_cred_t
ubc_getcred(struct vnode *vp)
{
        if (UBCINFOEXISTS(vp))
	        return (vp->v_ubcinfo->ui_ucred);

	return (NOCRED);
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
	kauth_cred_t credp;

        if ( !UBCINFOEXISTS(vp))
		return (0); 

	vnode_lock(vp);

	uip = vp->v_ubcinfo;
	credp = uip->ui_ucred;

	if (credp == NOCRED) {
		uip->ui_ucred = kauth_cred_proc_ref(p);
	} 
	vnode_unlock(vp);

	return (1);
}

/* Get the pager */
__private_extern__ memory_object_t
ubc_getpager(struct vnode *vp)
{
        if (UBCINFOEXISTS(vp))
	        return (vp->v_ubcinfo->ui_pager);

	return (0);
}

/*
 * Get the memory object associated with this vnode
 * If the vnode was reactivated, memory object would not exist.
 * Unless "do not rectivate" was specified, look it up using the pager.
 * If hold was requested create an object reference of one does not
 * exist already.
 */

memory_object_control_t
ubc_getobject(struct vnode *vp, __unused int flags)
{
        if (UBCINFOEXISTS(vp))
	        return((vp->v_ubcinfo->ui_control));

	return (0);
}


off_t
ubc_blktooff(vnode_t vp, daddr64_t blkno)
{
	off_t file_offset;
	int error;

	if (UBCINVALID(vp))
	        return ((off_t)-1);

	error = VNOP_BLKTOOFF(vp, blkno, &file_offset);
	if (error)
		file_offset = -1;

	return (file_offset);
}

daddr64_t
ubc_offtoblk(vnode_t vp, off_t offset)
{
	daddr64_t blkno;
	int error = 0;

	if (UBCINVALID(vp))
	        return ((daddr64_t)-1);

	error = VNOP_OFFTOBLK(vp, offset, &blkno);
	if (error)
		blkno = -1;

	return (blkno);
}

int
ubc_pages_resident(vnode_t vp)
{
	kern_return_t		kret;
	boolean_t			has_pages_resident;
	
	if ( !UBCINFOEXISTS(vp))
		return (0);
			
	kret = memory_object_pages_resident(vp->v_ubcinfo->ui_control, &has_pages_resident);
	
	if (kret != KERN_SUCCESS)
		return (0);
		
	if (has_pages_resident == TRUE)
		return (1);
		
	return (0);
}



/*
 * This interface will eventually be deprecated
 *
 * clean and/or invalidate  a range in the memory object that backs this
 * vnode. The start offset is truncated to the page boundary and the
 * size is adjusted to include the last page in the range.
 *
 * returns 1 for success,  0 for failure
 */
int
ubc_sync_range(vnode_t vp, off_t beg_off, off_t end_off, int flags)
{
        return (ubc_msync_internal(vp, beg_off, end_off, NULL, flags, NULL));
}


/*
 * clean and/or invalidate  a range in the memory object that backs this
 * vnode. The start offset is truncated to the page boundary and the
 * size is adjusted to include the last page in the range.
 * if a
 */
errno_t
ubc_msync(vnode_t vp, off_t beg_off, off_t end_off, off_t *resid_off, int flags)
{
        int retval;
	int io_errno = 0;
	
	if (resid_off)
	        *resid_off = beg_off;

        retval = ubc_msync_internal(vp, beg_off, end_off, resid_off, flags, &io_errno);

	if (retval == 0 && io_errno == 0)
	        return (EINVAL);
	return (io_errno);
}



/*
 * clean and/or invalidate  a range in the memory object that backs this
 * vnode. The start offset is truncated to the page boundary and the
 * size is adjusted to include the last page in the range.
 */
static int
ubc_msync_internal(vnode_t vp, off_t beg_off, off_t end_off, off_t *resid_off, int flags, int *io_errno)
{
	memory_object_size_t	tsize;
	kern_return_t		kret;
	int request_flags = 0;
	int flush_flags   = MEMORY_OBJECT_RETURN_NONE;
	
	if ( !UBCINFOEXISTS(vp))
	        return (0);
	if (end_off <= beg_off)
	        return (0);
	if ((flags & (UBC_INVALIDATE | UBC_PUSHDIRTY | UBC_PUSHALL)) == 0)
	        return (0);

	if (flags & UBC_INVALIDATE)
	        /*
		 * discard the resident pages
		 */
		request_flags = (MEMORY_OBJECT_DATA_FLUSH | MEMORY_OBJECT_DATA_NO_CHANGE);

	if (flags & UBC_SYNC)
	        /*
		 * wait for all the I/O to complete before returning
		 */
	        request_flags |= MEMORY_OBJECT_IO_SYNC;

	if (flags & UBC_PUSHDIRTY)
	        /*
		 * we only return the dirty pages in the range
		 */
	        flush_flags = MEMORY_OBJECT_RETURN_DIRTY;

	if (flags & UBC_PUSHALL)
	        /*
		 * then return all the interesting pages in the range (both dirty and precious)
		 * to the pager
		 */
	        flush_flags = MEMORY_OBJECT_RETURN_ALL;

	beg_off = trunc_page_64(beg_off);
	end_off = round_page_64(end_off);
	tsize   = (memory_object_size_t)end_off - beg_off;

	/* flush and/or invalidate pages in the range requested */
	kret = memory_object_lock_request(vp->v_ubcinfo->ui_control,
					  beg_off, tsize, resid_off, io_errno,
					  flush_flags, request_flags, VM_PROT_NO_CHANGE);
	
	return ((kret == KERN_SUCCESS) ? 1 : 0);
}


/*
 * The vnode is mapped explicitly, mark it so.
 */
__private_extern__ int
ubc_map(vnode_t vp, int flags)
{
	struct ubc_info *uip;
	int error = 0;
	int need_ref = 0;
	struct vfs_context context;

	if (vnode_getwithref(vp))
	        return (0);

	if (UBCINFOEXISTS(vp)) {
		context.vc_proc = current_proc();
		context.vc_ucred = kauth_cred_get();

		error = VNOP_MMAP(vp, flags, &context);

		if (error != EPERM)
		        error = 0;

		if (error == 0) {
		        vnode_lock(vp);
			
			uip = vp->v_ubcinfo;

			if ( !ISSET(uip->ui_flags, UI_ISMAPPED))
			        need_ref = 1;
			SET(uip->ui_flags, (UI_WASMAPPED | UI_ISMAPPED));

			vnode_unlock(vp);
			
			if (need_ref)
			        vnode_ref(vp);
		}
	}
	vnode_put(vp);

	return (error);
}

/*
 * destroy the named reference for a given vnode
 */
__private_extern__ int
ubc_destroy_named(struct vnode	*vp)
{
	memory_object_control_t control;
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

	/* 
	 * Terminate the memory object.
	 * memory_object_destroy() will result in
	 * vnode_pager_no_senders(). 
	 * That will release the pager reference
	 * and the vnode will move to the free list.
	 */
	control = ubc_getobject(vp, UBC_HOLDOBJECT);
	if (control != MEMORY_OBJECT_CONTROL_NULL) {

	  /*
	   * XXXXX - should we hold the vnode lock here?
	   */
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
		vnode_lock(vp);
		while (ISSET(vp->v_lflag, VNAMED_UBC)) {
			(void)msleep((caddr_t)&vp->v_lflag, &vp->v_lock,
						 PINOD, "ubc_destroy_named", 0);
		}
		vnode_unlock(vp);
	}
	return (1);
}


/*
 * Find out whether a vnode is in use by UBC
 * Returns 1 if file is in use by UBC, 0 if not
 */
int
ubc_isinuse(struct vnode *vp, int busycount)
{
	if ( !UBCINFOEXISTS(vp))
		return (0);
	return(ubc_isinuse_locked(vp, busycount, 0));
}


int
ubc_isinuse_locked(struct vnode *vp, int busycount, int locked)
{
	int retval = 0;


	if (!locked)
		vnode_lock(vp);

	if ((vp->v_usecount - vp->v_kusecount) > busycount)
		retval = 1;

	if (!locked)
		vnode_unlock(vp);
	return (retval);
}


/*
 * MUST only be called by the VM
 */
__private_extern__ void
ubc_unmap(struct vnode *vp)
{
	struct vfs_context context;
	struct ubc_info *uip;
	int	need_rele = 0;

	if (vnode_getwithref(vp))
	        return;

	if (UBCINFOEXISTS(vp)) {
		vnode_lock(vp);

		uip = vp->v_ubcinfo;
		if (ISSET(uip->ui_flags, UI_ISMAPPED)) {
		        CLR(uip->ui_flags, UI_ISMAPPED);
			need_rele = 1;
		}
		vnode_unlock(vp);
		
		if (need_rele) {
		        context.vc_proc = current_proc();
			context.vc_ucred = kauth_cred_get();
		        (void)VNOP_MNOMAP(vp, &context);

		        vnode_rele(vp);
		}
	}
	/*
	 * the drop of the vnode ref will cleanup
	 */
	vnode_put(vp);
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
				      
__private_extern__ kern_return_t
ubc_page_op_with_control(
	memory_object_control_t	 control,
	off_t		         f_offset,
	int		         ops,
	ppnum_t	                 *phys_entryp,
	int		         *flagsp)
{
	return (memory_object_page_op(control,
				      (memory_object_offset_t)f_offset,
				      ops,
				      phys_entryp,
				      flagsp));
}
				      
kern_return_t
ubc_range_op(
	struct vnode 	*vp,
	off_t		f_offset_beg,
	off_t		f_offset_end,
	int             ops,
	int             *range)
{
	memory_object_control_t		control;

	control = ubc_getobject(vp, UBC_FLAGS_NONE);
	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	return (memory_object_range_op(control,
				      (memory_object_offset_t)f_offset_beg,
				      (memory_object_offset_t)f_offset_end,
				      ops,
				      range));
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

	if (uplflags & UPL_WILL_BE_DUMPED) {
	        uplflags &= ~UPL_WILL_BE_DUMPED;
		uplflags |= (UPL_NO_SYNC|UPL_SET_INTERNAL);
	} else
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

/************* UBC APIS **************/

int 
UBCINFOMISSING(struct vnode * vp)
{
	return((vp) && ((vp)->v_type == VREG) && ((vp)->v_ubcinfo == UBC_INFO_NULL));
}

int 
UBCINFORECLAIMED(struct vnode * vp)
{
	return((vp) && ((vp)->v_type == VREG) && ((vp)->v_ubcinfo == UBC_INFO_NULL));
}


int 
UBCINFOEXISTS(struct vnode * vp)
{
        return((vp) && ((vp)->v_type == VREG) && ((vp)->v_ubcinfo != UBC_INFO_NULL));
}
int 
UBCISVALID(struct vnode * vp)
{
	return((vp) && ((vp)->v_type == VREG) && !((vp)->v_flag & VSYSTEM));
}
int 
UBCINVALID(struct vnode * vp)
{
	return(((vp) == NULL) || ((vp) && ((vp)->v_type != VREG))
		|| ((vp) && ((vp)->v_flag & VSYSTEM)));
}
int 
UBCINFOCHECK(const char * fun, struct vnode * vp)
{
	if ((vp) && ((vp)->v_type == VREG) &&
		((vp)->v_ubcinfo == UBC_INFO_NULL)) {
		panic("%s: lost ubc_info", (fun));
		return(1);
	} else
		return(0);
}

