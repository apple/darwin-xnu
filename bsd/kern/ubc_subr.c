/*
 * Copyright (c) 1999-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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
#include <sys/user.h>
#include <sys/codesign.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <mach/memory_object_control.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/upl.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/thread.h>
#include <vm/vm_kern.h>
#include <vm/vm_protos.h> /* last */

#include <libkern/crypto/sha1.h>

#include <security/mac_framework.h>

/* XXX These should be in a BSD accessible Mach header, but aren't. */
extern kern_return_t memory_object_pages_resident(memory_object_control_t,
							boolean_t *);
extern kern_return_t	memory_object_signed(memory_object_control_t control,
					     boolean_t is_signed);
extern void Debugger(const char *message);


/* XXX no one uses this interface! */
kern_return_t ubc_page_op_with_control(
	memory_object_control_t	 control,
	off_t		         f_offset,
	int		         ops,
	ppnum_t	                 *phys_entryp,
	int		         *flagsp);


#if DIAGNOSTIC
#if defined(assert)
#undef assert
#endif
#define assert(cond)    \
    ((void) ((cond) ? 0 : panic("Assert failed: %s", # cond)))
#else
#include <kern/assert.h>
#endif /* DIAGNOSTIC */

static int ubc_info_init_internal(struct vnode *vp, int withfsize, off_t filesize);
static int ubc_umcallback(vnode_t, void *);
static int ubc_msync_internal(vnode_t, off_t, off_t, off_t *, int, int *);
static void ubc_cs_free(struct ubc_info *uip);

struct zone	*ubc_info_zone;


/*
 * CODESIGNING
 * Routines to navigate code signing data structures in the kernel...
 */

extern int cs_debug;

static boolean_t
cs_valid_range(
	const void *start,
	const void *end,
	const void *lower_bound,
	const void *upper_bound)
{
	if (upper_bound < lower_bound ||
	    end < start) {
		return FALSE;
	}

	if (start < lower_bound ||
	    end > upper_bound) {
		return FALSE;
	}

	return TRUE;
}

/*
 * Magic numbers used by Code Signing
 */
enum {
	CSMAGIC_REQUIREMENT = 0xfade0c00,		/* single Requirement blob */
	CSMAGIC_REQUIREMENTS = 0xfade0c01,		/* Requirements vector (internal requirements) */
	CSMAGIC_CODEDIRECTORY = 0xfade0c02,		/* CodeDirectory blob */
	CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0, /* embedded form of signature data */
	CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02,	/* XXX */
	CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1, /* multi-arch collection of embedded signatures */
	
	CSSLOT_CODEDIRECTORY = 0,				/* slot index for CodeDirectory */
};

static const uint32_t supportsScatter = 0x20100;	// first version to support scatter option

/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
	uint32_t type;					/* type of entry */
	uint32_t offset;				/* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
	uint32_t magic;					/* magic number */
	uint32_t length;				/* total length of SuperBlob */
	uint32_t count;					/* number of index entries following */
	CS_BlobIndex index[];			/* (count) entries */
	/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

struct Scatter {
	uint32_t count;			// number of pages; zero for sentinel (only)
	uint32_t base;			// first page number
	uint64_t targetOffset;		// offset in target
	uint64_t spare;			// reserved
};

/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
	uint32_t magic;					/* magic number (CSMAGIC_CODEDIRECTORY) */
	uint32_t length;				/* total length of CodeDirectory blob */
	uint32_t version;				/* compatibility version */
	uint32_t flags;					/* setup and mode flags */
	uint32_t hashOffset;			/* offset of hash slot element at index zero */
	uint32_t identOffset;			/* offset of identifier string */
	uint32_t nSpecialSlots;			/* number of special hash slots */
	uint32_t nCodeSlots;			/* number of ordinary (code) hash slots */
	uint32_t codeLimit;				/* limit to main image signature range */
	uint8_t hashSize;				/* size of each hash in bytes */
	uint8_t hashType;				/* type of hash (cdHashType* constants) */
	uint8_t spare1;					/* unused (must be zero) */
	uint8_t	pageSize;				/* log2(page size in bytes); 0 => infinite */
	uint32_t spare2;				/* unused (must be zero) */
	/* Version 0x20100 */
	uint32_t scatterOffset;				/* offset of optional scatter vector */
	/* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;


/*
 * Locate the CodeDirectory from an embedded signature blob
 */
static const 
CS_CodeDirectory *findCodeDirectory(
	const CS_SuperBlob *embedded,
	char *lower_bound,
	char *upper_bound)
{
	const CS_CodeDirectory *cd = NULL;

	if (embedded &&
	    cs_valid_range(embedded, embedded + 1, lower_bound, upper_bound) &&
	    ntohl(embedded->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
		const CS_BlobIndex *limit;
		const CS_BlobIndex *p;

		limit = &embedded->index[ntohl(embedded->count)];
		if (!cs_valid_range(&embedded->index[0], limit,
				    lower_bound, upper_bound)) {
			return NULL;
		}
		for (p = embedded->index; p < limit; ++p) {
			if (ntohl(p->type) == CSSLOT_CODEDIRECTORY) {
				const unsigned char *base;

				base = (const unsigned char *)embedded;
				cd = (const CS_CodeDirectory *)(base + ntohl(p->offset));
				break;
			}
		}
	} else {
		/*
		 * Detached signatures come as a bare CS_CodeDirectory,
		 * without a blob.
		 */
		cd = (const CS_CodeDirectory *) embedded;
	}

	if (cd &&
	    cs_valid_range(cd, cd + 1, lower_bound, upper_bound) &&
	    cs_valid_range(cd, (const char *) cd + ntohl(cd->length),
			   lower_bound, upper_bound) &&
	    cs_valid_range(cd, (const char *) cd + ntohl(cd->hashOffset),
			   lower_bound, upper_bound) &&
	    cs_valid_range(cd, (const char *) cd +
			   ntohl(cd->hashOffset) +
			   (ntohl(cd->nCodeSlots) * SHA1_RESULTLEN),
			   lower_bound, upper_bound) &&
	    
	    ntohl(cd->magic) == CSMAGIC_CODEDIRECTORY) {
		return cd;
	}

	// not found or not a valid code directory
	return NULL;
}


/*
 * Locating a page hash
 */
static const unsigned char *
hashes(
	const CS_CodeDirectory *cd,
	unsigned page,
	char *lower_bound,
	char *upper_bound)
{
	const unsigned char *base, *top, *hash;
	uint32_t nCodeSlots = ntohl(cd->nCodeSlots);

	assert(cs_valid_range(cd, cd + 1, lower_bound, upper_bound));

	if((ntohl(cd->version) >= supportsScatter) && (ntohl(cd->scatterOffset))) {
		/* Get first scatter struct */
		const struct Scatter *scatter = (const struct Scatter*)
			((const char*)cd + ntohl(cd->scatterOffset));
		uint32_t hashindex=0, scount, sbase=0;
		/* iterate all scatter structs */
		do {
			if((const char*)scatter > (const char*)cd + ntohl(cd->length)) {
				if(cs_debug) {
					printf("CODE SIGNING: Scatter extends past Code Directory\n");
				}
				return NULL;
			}
			
			scount = ntohl(scatter->count);
			uint32_t new_base = ntohl(scatter->base);

			/* last scatter? */
			if (scount == 0) {
				return NULL;
			}
			
			if((hashindex > 0) && (new_base <= sbase)) {
				if(cs_debug) {
					printf("CODE SIGNING: unordered Scatter, prev base %d, cur base %d\n",
					sbase, new_base);
				}
				return NULL;	/* unordered scatter array */
			}
			sbase = new_base;

			/* this scatter beyond page we're looking for? */
			if (sbase > page) {
				return NULL;
			}
			
			if (sbase+scount >= page) {
				/* Found the scatter struct that is 
				 * referencing our page */

				/* base = address of first hash covered by scatter */
				base = (const unsigned char *)cd + ntohl(cd->hashOffset) + 
					hashindex * SHA1_RESULTLEN;
				/* top = address of first hash after this scatter */
				top = base + scount * SHA1_RESULTLEN;
				if (!cs_valid_range(base, top, lower_bound, 
						    upper_bound) ||
				    hashindex > nCodeSlots) {
					return NULL;
				}
				
				break;
			}
			
			/* this scatter struct is before the page we're looking 
			 * for. Iterate. */
			hashindex+=scount;
			scatter++;
		} while(1);
		
		hash = base + (page - sbase) * SHA1_RESULTLEN;
	} else {
		base = (const unsigned char *)cd + ntohl(cd->hashOffset);
		top = base + nCodeSlots * SHA1_RESULTLEN;
		if (!cs_valid_range(base, top, lower_bound, upper_bound) ||
		    page > nCodeSlots) {
			return NULL;
		}
		assert(page < nCodeSlots);

		hash = base + page * SHA1_RESULTLEN;
	}
	
	if (!cs_valid_range(hash, hash + SHA1_RESULTLEN,
			    lower_bound, upper_bound)) {
		hash = NULL;
	}

	return hash;
}
/*
 * CODESIGNING
 * End of routines to navigate code signing data structures in the kernel.
 */


/*
 * ubc_init
 * 
 * Initialization of the zone for Unified Buffer Cache.
 *
 * Parameters:	(void)
 *
 * Returns:	(void)
 *
 * Implicit returns:
 *		ubc_info_zone(global)	initialized for subsequent allocations
 */
__private_extern__ void
ubc_init(void)
{
	int	i;

	i = (vm_size_t) sizeof (struct ubc_info);

	ubc_info_zone = zinit (i, 10000*i, 8192, "ubc_info zone");

	zone_change(ubc_info_zone, Z_NOENCRYPT, TRUE);
}


/*
 * ubc_info_init
 *
 * Allocate and attach an empty ubc_info structure to a vnode
 *
 * Parameters:	vp			Pointer to the vnode
 *
 * Returns:	0			Success
 *	vnode_size:ENOMEM		Not enough space
 *	vnode_size:???			Other error from vnode_getattr
 *
 */
int
ubc_info_init(struct vnode *vp)
{
	return(ubc_info_init_internal(vp, 0, 0));
}


/*
 * ubc_info_init_withsize
 *
 * Allocate and attach a sized ubc_info structure to a vnode
 *
 * Parameters:	vp			Pointer to the vnode
 *		filesize		The size of the file
 *
 * Returns:	0			Success
 *	vnode_size:ENOMEM		Not enough space
 *	vnode_size:???			Other error from vnode_getattr
 */
int
ubc_info_init_withsize(struct vnode *vp, off_t filesize)
{
	return(ubc_info_init_internal(vp, 1, filesize));
}


/*
 * ubc_info_init_internal
 *
 * Allocate and attach a ubc_info structure to a vnode
 *
 * Parameters:	vp			Pointer to the vnode
 *		withfsize{0,1}		Zero if the size should be obtained
 *					from the vnode; otherwise, use filesize
 *		filesize		The size of the file, if withfsize == 1
 *
 * Returns:	0			Success
 *	vnode_size:ENOMEM		Not enough space
 *	vnode_size:???			Other error from vnode_getattr
 *
 * Notes:	We call a blocking zalloc(), and the zone was created as an
 *		expandable and collectable zone, so if no memory is available,
 *		it is possible for zalloc() to block indefinitely.  zalloc()
 *		may also panic if the zone of zones is exhausted, since it's
 *		NOT expandable.
 *
 *		We unconditionally call vnode_pager_setup(), even if this is
 *		a reuse of a ubc_info; in that case, we should probably assert
 *		that it does not already have a pager association, but do not.
 *
 *		Since memory_object_create_named() can only fail from receiving
 *		an invalid pager argument, the explicit check and panic is
 *		merely precautionary.
 */
static int
ubc_info_init_internal(vnode_t vp, int withfsize, off_t filesize)
{
	register struct ubc_info	*uip;
	void *  pager;
	int error = 0;
	kern_return_t kret;
	memory_object_control_t control;

	uip = vp->v_ubcinfo;

	/*
	 * If there is not already a ubc_info attached to the vnode, we
	 * attach one; otherwise, we will reuse the one that's there.
	 */
	if (uip == UBC_INFO_NULL) {

		uip = (struct ubc_info *) zalloc(ubc_info_zone);
		bzero((char *)uip, sizeof(struct ubc_info));

		uip->ui_vnode = vp;
		uip->ui_flags = UI_INITED;
		uip->ui_ucred = NOCRED;
	}
	assert(uip->ui_flags != UI_NONE);
	assert(uip->ui_vnode == vp);

	/* now set this ubc_info in the vnode */
	vp->v_ubcinfo = uip;

	/*
	 * Allocate a pager object for this vnode
	 *
	 * XXX The value of the pager parameter is currently ignored.
	 * XXX Presumably, this API changed to avoid the race between
	 * XXX setting the pager and the UI_HASPAGER flag.
	 */
	pager = (void *)vnode_pager_setup(vp, uip->ui_pager);
	assert(pager);

	/*
	 * Explicitly set the pager into the ubc_info, after setting the
	 * UI_HASPAGER flag.
	 */
	SET(uip->ui_flags, UI_HASPAGER);
	uip->ui_pager = pager;

	/*
	 * Note: We can not use VNOP_GETATTR() to get accurate
	 * value of ui_size because this may be an NFS vnode, and
	 * nfs_getattr() can call vinvalbuf(); if this happens,
	 * ubc_info is not set up to deal with that event.
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

	if (withfsize == 0) {
		/* initialize the size */
		error = vnode_size(vp, &uip->ui_size, vfs_context_current());
		if (error)
			uip->ui_size = 0;
	} else {
		uip->ui_size = filesize;
	}
	vp->v_lflag |= VNAMED_UBC;	/* vnode has a named ubc reference */

	return (error);
}


/*
 * ubc_info_free
 *
 * Free a ubc_info structure
 *
 * Parameters:	uip			A pointer to the ubc_info to free
 *
 * Returns:	(void)
 *
 * Notes:	If there is a credential that has subsequently been associated
 *		with the ubc_info via a call to ubc_setcred(), the reference
 *		to the credential is dropped.
 *
 *		It's actually impossible for a ubc_info.ui_control to take the
 *		value MEMORY_OBJECT_CONTROL_NULL.
 */
static void
ubc_info_free(struct ubc_info *uip)
{
	if (IS_VALID_CRED(uip->ui_ucred)) {
		kauth_cred_unref(&uip->ui_ucred);
	}

	if (uip->ui_control != MEMORY_OBJECT_CONTROL_NULL)
		memory_object_control_deallocate(uip->ui_control);
	
	cluster_release(uip);
	ubc_cs_free(uip);

	zfree(ubc_info_zone, uip);
	return;
}


void
ubc_info_deallocate(struct ubc_info *uip)
{
        ubc_info_free(uip);
}


/*
 * ubc_setsize
 *
 * Tell the  VM that the the size of the file represented by the vnode has
 * changed
 *
 * Parameters:	vp			The vp whose backing file size is
 *					being changed
 *		nsize			The new size of the backing file
 *
 * Returns:	1			Success
 *		0			Failure
 *
 * Notes:	This function will indicate failure if the new size that's
 *		being attempted to be set is negative.
 *
 *		This function will fail if there is no ubc_info currently
 *		associated with the vnode.
 *
 *		This function will indicate success it the new size is the
 *		same or larger than the old size (in this case, the remainder
 *		of the file will require modification or use of an existing upl
 *		to access successfully).
 *
 *		This function will fail if the new file size is smaller, and
 *		the memory region being invalidated was unable to actually be
 *		invalidated and/or the last page could not be flushed, if the
 *		new size is not aligned to a page boundary.  This is usually
 *		indicative of an I/O error.
 */
int
ubc_setsize(struct vnode *vp, off_t nsize)
{
	off_t osize;	/* ui_size before change */
	off_t lastpg, olastpgend, lastoff;
	struct ubc_info *uip;
	memory_object_control_t control;
	kern_return_t kret = KERN_SUCCESS;

	if (nsize < (off_t)0)
		return (0);

	if (!UBCINFOEXISTS(vp))
		return (0);

	uip = vp->v_ubcinfo;
	osize = uip->ui_size;
	/*
	 * Update the size before flushing the VM
	 */
	uip->ui_size = nsize;

	if (nsize >= osize) {	/* Nothing more to do */
		lock_vnode_and_post(vp, NOTE_EXTEND);
		return (1);		/* return success */
	}

	/*
	 * When the file shrinks, invalidate the pages beyond the
	 * new size. Also get rid of garbage beyond nsize on the
	 * last page. The ui_size already has the nsize, so any
	 * subsequent page-in will zero-fill the tail properly
	 */
	lastpg = trunc_page_64(nsize);
	olastpgend = round_page_64(osize);
	control = uip->ui_control;
	assert(control);
	lastoff = (nsize & PAGE_MASK_64);

	if (lastoff) {
	        upl_t		upl;
		upl_page_info_t	*pl;


	        /*
		 * new EOF ends up in the middle of a page
		 * zero the tail of this page if its currently
		 * present in the cache
		 */
	        kret = ubc_create_upl(vp, lastpg, PAGE_SIZE, &upl, &pl, UPL_SET_LITE);
		
		if (kret != KERN_SUCCESS)
		        panic("ubc_setsize: ubc_create_upl (error = %d)\n", kret);

		if (upl_valid_page(pl, 0))
		        cluster_zero(upl, (uint32_t)lastoff, PAGE_SIZE - (uint32_t)lastoff, NULL);

		ubc_upl_abort_range(upl, 0, PAGE_SIZE, UPL_ABORT_FREE_ON_EMPTY);

		lastpg += PAGE_SIZE_64;
	}
	if (olastpgend > lastpg) {
		int	flags;

		if (lastpg == 0)
			flags = MEMORY_OBJECT_DATA_FLUSH_ALL;
		else
			flags = MEMORY_OBJECT_DATA_FLUSH;
	        /*
		 * invalidate the pages beyond the new EOF page
		 *
		 */
	        kret = memory_object_lock_request(control,
						  (memory_object_offset_t)lastpg,
						  (memory_object_size_t)(olastpgend - lastpg), NULL, NULL,
						  MEMORY_OBJECT_RETURN_NONE, flags, VM_PROT_NO_CHANGE);
		if (kret != KERN_SUCCESS)
		        printf("ubc_setsize: invalidate failed (error = %d)\n", kret);
	}
	return ((kret == KERN_SUCCESS) ? 1 : 0);
}


/*
 * ubc_getsize
 *
 * Get the size of the file assocated with the specified vnode
 *
 * Parameters:	vp			The vnode whose size is of interest
 *
 * Returns:	0			There is no ubc_info associated with
 *					this vnode, or the size is zero
 *		!0			The size of the file
 *
 * Notes:	Using this routine, it is not possible for a caller to
 *		successfully distinguish between a vnode associate with a zero
 *		length file, and a vnode with no associated ubc_info.  The
 *		caller therefore needs to not care, or needs to ensure that
 *		they have previously successfully called ubc_info_init() or
 *		ubc_info_init_withsize().
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
 * ubc_umount
 *
 * Call ubc_sync_range(vp, 0, EOF, UBC_PUSHALL) on all the vnodes for this
 * mount point
 *
 * Parameters:	mp			The mount point
 *
 * Returns:	0			Success
 *
 * Notes:	There is no failure indication for this function.
 *
 *		This function is used in the unmount path; since it may block
 *		I/O indefinitely, it should not be used in the forced unmount
 *		path, since a device unavailability could also block that
 *		indefinitely.
 *
 *		Because there is no device ejection interlock on USB, FireWire,
 *		or similar devices, it's possible that an ejection that begins
 *		subsequent to the vnode_iterate() completing, either on one of
 *		those devices, or a network mount for which the server quits
 *		responding, etc., may cause the caller to block indefinitely.
 */
__private_extern__ int
ubc_umount(struct mount *mp)
{
	vnode_iterate(mp, 0, ubc_umcallback, 0);
	return(0);
}


/*
 * ubc_umcallback
 *
 * Used by ubc_umount() as an internal implementation detail; see ubc_umount()
 * and vnode_iterate() for details of implementation.
 */
static int
ubc_umcallback(vnode_t vp, __unused void * args)
{

	if (UBCINFOEXISTS(vp)) {

		(void) ubc_msync(vp, (off_t)0, ubc_getsize(vp), NULL, UBC_PUSHALL);
	}
	return (VNODE_RETURNED);
}


/*
 * ubc_getcred
 *
 * Get the credentials currently active for the ubc_info associated with the
 * vnode.
 *
 * Parameters:	vp			The vnode whose ubc_info credentials
 *					are to be retrieved
 *
 * Returns:	!NOCRED			The credentials
 *		NOCRED			If there is no ubc_info for the vnode,
 *					or if there is one, but it has not had
 *					any credentials associated with it via
 *					a call to ubc_setcred()
 */
kauth_cred_t
ubc_getcred(struct vnode *vp)
{
        if (UBCINFOEXISTS(vp))
	        return (vp->v_ubcinfo->ui_ucred);

	return (NOCRED);
}


/*
 * ubc_setthreadcred
 *
 * If they are not already set, set the credentials of the ubc_info structure
 * associated with the vnode to those of the supplied thread; otherwise leave
 * them alone.
 *
 * Parameters:	vp			The vnode whose ubc_info creds are to
 *					be set
 *		p			The process whose credentials are to
 *					be used, if not running on an assumed
 *					credential
 *		thread			The thread whose credentials are to
 *					be used
 *
 * Returns:	1			This vnode has no associated ubc_info
 *		0			Success
 *
 * Notes:	This function takes a proc parameter to account for bootstrap
 *		issues where a task or thread may call this routine, either
 *		before credentials have been initialized by bsd_init(), or if
 *		there is no BSD info asscoiate with a mach thread yet.  This
 *		is known to happen in both the initial swap and memory mapping
 *		calls.
 *
 *		This function is generally used only in the following cases:
 *
 *		o	a memory mapped file via the mmap() system call
 *		o	a memory mapped file via the deprecated map_fd() call
 *		o	a swap store backing file
 *		o	subsequent to a successful write via vn_write()
 *
 *		The information is then used by the NFS client in order to
 *		cons up a wire message in either the page-in or page-out path.
 *
 *		There are two potential problems with the use of this API:
 *
 *		o	Because the write path only set it on a successful
 *			write, there is a race window between setting the
 *			credential and its use to evict the pages to the
 *			remote file server
 *
 *		o	Because a page-in may occur prior to a write, the
 *			credential may not be set at this time, if the page-in
 *			is not the result of a mapping established via mmap()
 *			or map_fd().
 *
 *		In both these cases, this will be triggered from the paging
 *		path, which will instead use the credential of the current
 *		process, which in this case is either the dynamic_pager or
 *		the kernel task, both of which utilize "root" credentials.
 *
 *		This may potentially permit operations to occur which should
 *		be denied, or it may cause to be denied operations which
 *		should be permitted, depending on the configuration of the NFS
 *		server.
 */
int
ubc_setthreadcred(struct vnode *vp, proc_t p, thread_t thread)
{
	struct ubc_info *uip;
	kauth_cred_t credp;
	struct uthread  *uthread = get_bsdthread_info(thread);

	if (!UBCINFOEXISTS(vp))
		return (1); 

	vnode_lock(vp);

	uip = vp->v_ubcinfo;
	credp = uip->ui_ucred;

	if (!IS_VALID_CRED(credp)) {
		/* use per-thread cred, if assumed identity, else proc cred */
		if (uthread == NULL || (uthread->uu_flag & UT_SETUID) == 0) {
			uip->ui_ucred = kauth_cred_proc_ref(p);
		} else {
			uip->ui_ucred = uthread->uu_ucred;
			kauth_cred_ref(uip->ui_ucred);
		}
	} 
	vnode_unlock(vp);

	return (0);
}


/*
 * ubc_setcred
 *
 * If they are not already set, set the credentials of the ubc_info structure
 * associated with the vnode to those of the process; otherwise leave them
 * alone.
 *
 * Parameters:	vp			The vnode whose ubc_info creds are to
 *					be set
 *		p			The process whose credentials are to
 *					be used
 *
 * Returns:	0			This vnode has no associated ubc_info
 *		1			Success
 *
 * Notes:	The return values for this function are inverted from nearly
 *		all other uses in the kernel.
 *
 *		See also ubc_setthreadcred(), above.
 *
 *		This function is considered deprecated, and generally should
 *		not be used, as it is incompatible with per-thread credentials;
 *		it exists for legacy KPI reasons.
 *
 * DEPRECATION:	ubc_setcred() is being deprecated. Please use 
 *		ubc_setthreadcred() instead.
 */
int
ubc_setcred(struct vnode *vp, proc_t p)
{
	struct ubc_info *uip;
	kauth_cred_t credp;

	/* If there is no ubc_info, deny the operation */
	if ( !UBCINFOEXISTS(vp))
		return (0); 

	/*
	 * Check to see if there is already a credential reference in the
	 * ubc_info; if there is not, take one on the supplied credential.
	 */
	vnode_lock(vp);
	uip = vp->v_ubcinfo;
	credp = uip->ui_ucred;
	if (!IS_VALID_CRED(credp)) {
		uip->ui_ucred = kauth_cred_proc_ref(p);
	} 
	vnode_unlock(vp);

	return (1);
}

/*
 * ubc_getpager
 *
 * Get the pager associated with the ubc_info associated with the vnode.
 *
 * Parameters:	vp			The vnode to obtain the pager from
 *
 * Returns:	!VNODE_PAGER_NULL	The memory_object_t for the pager
 *		VNODE_PAGER_NULL	There is no ubc_info for this vnode
 *
 * Notes:	For each vnode that has a ubc_info associated with it, that
 *		ubc_info SHALL have a pager associated with it, so in the
 *		normal case, it's impossible to return VNODE_PAGER_NULL for
 *		a vnode with an associated ubc_info.
 */
__private_extern__ memory_object_t
ubc_getpager(struct vnode *vp)
{
        if (UBCINFOEXISTS(vp))
	        return (vp->v_ubcinfo->ui_pager);

	return (0);
}


/*
 * ubc_getobject
 *
 * Get the memory object control associated with the ubc_info associated with
 * the vnode
 *
 * Parameters:	vp			The vnode to obtain the memory object
 *					from
 *		flags			DEPRECATED
 *
 * Returns:	!MEMORY_OBJECT_CONTROL_NULL
 *		MEMORY_OBJECT_CONTROL_NULL
 *
 * Notes:	Historically, if the flags were not "do not reactivate", this
 *		function would look up the memory object using the pager if
 *		it did not exist (this could be the case if the vnode had
 *		been previously reactivated).  The flags would also permit a
 *		hold to be requested, which would have created an object
 *		reference, if one had not already existed.  This usage is
 *		deprecated, as it would permit a race between finding and
 *		taking the reference vs. a single reference being dropped in
 *		another thread.
 */
memory_object_control_t
ubc_getobject(struct vnode *vp, __unused int flags)
{
        if (UBCINFOEXISTS(vp))
	        return((vp->v_ubcinfo->ui_control));

	return (MEMORY_OBJECT_CONTROL_NULL);
}


/*
 * ubc_blktooff
 *
 * Convert a given block number to a memory backing object (file) offset for a
 * given vnode
 *
 * Parameters:	vp			The vnode in which the block is located
 *		blkno			The block number to convert
 *
 * Returns:	!-1			The offset into the backing object
 *		-1			There is no ubc_info associated with
 *					the vnode
 *		-1			An error occurred in the underlying VFS
 *					while translating the block to an
 *					offset; the most likely cause is that
 *					the caller specified a block past the
 *					end of the file, but this could also be
 *					any other error from VNOP_BLKTOOFF().
 *
 * Note:	Representing the error in band loses some information, but does
 *		not occlude a valid offset, since an off_t of -1 is normally
 *		used to represent EOF.  If we had a more reliable constant in
 *		our header files for it (i.e. explicitly cast to an off_t), we
 *		would use it here instead.
 */
off_t
ubc_blktooff(vnode_t vp, daddr64_t blkno)
{
	off_t file_offset = -1;
	int error;

	if (UBCINFOEXISTS(vp)) {
		error = VNOP_BLKTOOFF(vp, blkno, &file_offset);
		if (error)
			file_offset = -1;
	}

	return (file_offset);
}


/*
 * ubc_offtoblk
 *
 * Convert a given offset in a memory backing object into a block number for a
 * given vnode
 *
 * Parameters:	vp			The vnode in which the offset is
 *					located
 *		offset			The offset into the backing object
 *
 * Returns:	!-1			The returned block number
 *		-1			There is no ubc_info associated with
 *					the vnode
 *		-1			An error occurred in the underlying VFS
 *					while translating the block to an
 *					offset; the most likely cause is that
 *					the caller specified a block past the
 *					end of the file, but this could also be
 *					any other error from VNOP_OFFTOBLK().
 *
 * Note:	Representing the error in band loses some information, but does
 *		not occlude a valid block number, since block numbers exceed
 *		the valid range for offsets, due to their relative sizes.  If
 *		we had a more reliable constant than -1 in our header files
 *		for it (i.e. explicitly cast to an daddr64_t), we would use it
 *		here instead.
 */
daddr64_t
ubc_offtoblk(vnode_t vp, off_t offset)
{
	daddr64_t blkno = -1;
	int error = 0;

	if (UBCINFOEXISTS(vp)) {
		error = VNOP_OFFTOBLK(vp, offset, &blkno);
		if (error)
			blkno = -1;
	}

	return (blkno);
}


/*
 * ubc_pages_resident
 *
 * Determine whether or not a given vnode has pages resident via the memory
 * object control associated with the ubc_info associated with the vnode
 *
 * Parameters:	vp			The vnode we want to know about
 *
 * Returns:	1			Yes
 *		0			No
 */
int
ubc_pages_resident(vnode_t vp)
{
	kern_return_t		kret;
	boolean_t			has_pages_resident;
	
	if (!UBCINFOEXISTS(vp))
		return (0);
			
	/*
	 * The following call may fail if an invalid ui_control is specified,
	 * or if there is no VM object associated with the control object.  In
	 * either case, reacting to it as if there were no pages resident will
	 * result in correct behavior.
	 */
	kret = memory_object_pages_resident(vp->v_ubcinfo->ui_control, &has_pages_resident);
	
	if (kret != KERN_SUCCESS)
		return (0);
		
	if (has_pages_resident == TRUE)
		return (1);
		
	return (0);
}


/*
 * ubc_sync_range
 *
 * Clean and/or invalidate a range in the memory object that backs this vnode
 *
 * Parameters:	vp			The vnode whose associated ubc_info's
 *					associated memory object is to have a
 *					range invalidated within it
 *		beg_off			The start of the range, as an offset
 *		end_off			The end of the range, as an offset
 *		flags			See ubc_msync_internal()
 *
 * Returns:	1			Success
 *		0			Failure
 *
 * Notes:	see ubc_msync_internal() for more detailed information.
 *
 * DEPRECATED:	This interface is obsolete due to a failure to return error
 *		information needed in order to correct failures.  The currently
 *		recommended interface is ubc_msync().
 */
int
ubc_sync_range(vnode_t vp, off_t beg_off, off_t end_off, int flags)
{
        return (ubc_msync_internal(vp, beg_off, end_off, NULL, flags, NULL));
}


/*
 * ubc_msync
 *
 * Clean and/or invalidate a range in the memory object that backs this vnode
 *
 * Parameters:	vp			The vnode whose associated ubc_info's
 *					associated memory object is to have a
 *					range invalidated within it
 *		beg_off			The start of the range, as an offset
 *		end_off			The end of the range, as an offset
 *		resid_off		The address of an off_t supplied by the
 *					caller; may be set to NULL to ignore
 *		flags			See ubc_msync_internal()
 *
 * Returns:	0			Success
 *		!0			Failure; an errno is returned
 *
 * Implicit Returns:
 *		*resid_off, modified	If non-NULL, the  contents are ALWAYS
 *					modified; they are initialized to the
 *					beg_off, and in case of an I/O error,
 *					the difference between beg_off and the
 *					current value will reflect what was
 *					able to be written before the error
 *					occurred.  If no error is returned, the
 *					value of the resid_off is undefined; do
 *					NOT use it in place of end_off if you
 *					intend to increment from the end of the
 *					last call and call iteratively.
 *
 * Notes:	see ubc_msync_internal() for more detailed information.
 *
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
 * Clean and/or invalidate a range in the memory object that backs this vnode
 *
 * Parameters:	vp			The vnode whose associated ubc_info's
 *					associated memory object is to have a
 *					range invalidated within it
 *		beg_off			The start of the range, as an offset
 *		end_off			The end of the range, as an offset
 *		resid_off		The address of an off_t supplied by the
 *					caller; may be set to NULL to ignore
 *		flags			MUST contain at least one of the flags
 *					UBC_INVALIDATE, UBC_PUSHDIRTY, or
 *					UBC_PUSHALL; if UBC_PUSHDIRTY is used,
 *					UBC_SYNC may also be specified to cause
 *					this function to block until the
 *					operation is complete.  The behavior
 *					of UBC_SYNC is otherwise undefined.
 *		io_errno		The address of an int to contain the
 *					errno from a failed I/O operation, if
 *					one occurs; may be set to NULL to
 *					ignore
 *
 * Returns:	1			Success
 *		0			Failure
 *
 * Implicit Returns:
 *		*resid_off, modified	The contents of this offset MAY be
 *					modified; in case of an I/O error, the
 *					difference between beg_off and the
 *					current value will reflect what was
 *					able to be written before the error
 *					occurred.
 *		*io_errno, modified	The contents of this offset are set to
 *					an errno, if an error occurs; if the
 *					caller supplies an io_errno parameter,
 *					they should be careful to initialize it
 *					to 0 before calling this function to
 *					enable them to distinguish an error
 *					with a valid *resid_off from an invalid
 *					one, and to avoid potentially falsely
 *					reporting an error, depending on use.
 *
 * Notes:	If there is no ubc_info associated with the vnode supplied,
 *		this function immediately returns success.
 *
 *		If the value of end_off is less than or equal to beg_off, this
 *		function immediately returns success; that is, end_off is NOT
 *		inclusive.
 *
 *		IMPORTANT: one of the flags UBC_INVALIDATE, UBC_PUSHDIRTY, or
 *		UBC_PUSHALL MUST be specified; that is, it is NOT possible to
 *		attempt to block on in-progress I/O by calling this function
 *		with UBC_PUSHDIRTY, and then later call it with just UBC_SYNC
 *		in order to block pending on the I/O already in progress.
 *
 *		The start offset is truncated to the page boundary and the
 *		size is adjusted to include the last page in the range; that
 *		is, end_off on exactly a page boundary will not change if it
 *		is rounded, and the range of bytes written will be from the
 *		truncate beg_off to the rounded (end_off - 1).
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
	if ((flags & (UBC_INVALIDATE | UBC_PUSHDIRTY | UBC_PUSHALL)) == 0)
	        return (0);
	if (end_off <= beg_off)
	        return (1);

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
		 * then return all the interesting pages in the range (both
		 * dirty and precious) to the pager
		 */
	        flush_flags = MEMORY_OBJECT_RETURN_ALL;

	beg_off = trunc_page_64(beg_off);
	end_off = round_page_64(end_off);
	tsize   = (memory_object_size_t)end_off - beg_off;

	/* flush and/or invalidate pages in the range requested */
	kret = memory_object_lock_request(vp->v_ubcinfo->ui_control,
					  beg_off, tsize,
					  (memory_object_offset_t *)resid_off,
					  io_errno, flush_flags, request_flags,
					  VM_PROT_NO_CHANGE);
	
	return ((kret == KERN_SUCCESS) ? 1 : 0);
}


/*
 * ubc_msync_internal
 *
 * Explicitly map a vnode that has an associate ubc_info, and add a reference
 * to it for the ubc system, if there isn't one already, so it will not be
 * recycled while it's in use, and set flags on the ubc_info to indicate that
 * we have done this
 *
 * Parameters:	vp			The vnode to map
 *		flags			The mapping flags for the vnode; this
 *					will be a combination of one or more of
 *					PROT_READ, PROT_WRITE, and PROT_EXEC
 *
 * Returns:	0			Success
 *		EPERM			Permission was denied
 *
 * Notes:	An I/O reference on the vnode must already be held on entry
 *
 *		If there is no ubc_info associated with the vnode, this function
 *		will return success.
 *
 *		If a permission error occurs, this function will return
 *		failure; all other failures will cause this function to return
 *		success.
 *
 *		IMPORTANT: This is an internal use function, and its symbols
 *		are not exported, hence its error checking is not very robust.
 *		It is primarily used by:
 *
 *		o	mmap(), when mapping a file
 *		o	The deprecated map_fd() interface, when mapping a file
 *		o	When mapping a shared file (a shared library in the
 *			shared segment region)
 *		o	When loading a program image during the exec process
 *
 *		...all of these uses ignore the return code, and any fault that
 *		results later because of a failure is handled in the fix-up path
 *		of the fault handler.  The interface exists primarily as a
 *		performance hint.
 *
 *		Given that third party implementation of the type of interfaces
 *		that would use this function, such as alternative executable
 *		formats, etc., are unsupported, this function is not exported
 *		for general use.
 *
 *		The extra reference is held until the VM system unmaps the
 *		vnode from its own context to maintain a vnode reference in
 *		cases like open()/mmap()/close(), which leave the backing
 *		object referenced by a mapped memory region in a process
 *		address space.
 */
__private_extern__ int
ubc_map(vnode_t vp, int flags)
{
	struct ubc_info *uip;
	int error = 0;
	int need_ref = 0;
	int need_wakeup = 0;

	if (UBCINFOEXISTS(vp)) {

		vnode_lock(vp);
		uip = vp->v_ubcinfo;

		while (ISSET(uip->ui_flags, UI_MAPBUSY)) {
			SET(uip->ui_flags, UI_MAPWAITING);
			(void) msleep(&uip->ui_flags, &vp->v_lock,
				      PRIBIO, "ubc_map", NULL);
		}
		SET(uip->ui_flags, UI_MAPBUSY);
		vnode_unlock(vp);

		error = VNOP_MMAP(vp, flags, vfs_context_current());

		if (error != EPERM)
		        error = 0;

		vnode_lock_spin(vp);

		if (error == 0) {
			if ( !ISSET(uip->ui_flags, UI_ISMAPPED))
			        need_ref = 1;
			SET(uip->ui_flags, (UI_WASMAPPED | UI_ISMAPPED));
		}
		CLR(uip->ui_flags, UI_MAPBUSY);

		if (ISSET(uip->ui_flags, UI_MAPWAITING)) {
			CLR(uip->ui_flags, UI_MAPWAITING);
			need_wakeup = 1;
		}
		vnode_unlock(vp);

		if (need_wakeup)
			wakeup(&uip->ui_flags);

		if (need_ref)
			vnode_ref(vp);
	}
	return (error);
}


/*
 * ubc_destroy_named
 *
 * Destroy the named memory object associated with the ubc_info control object
 * associated with the designated vnode, if there is a ubc_info associated
 * with the vnode, and a control object is associated with it
 *
 * Parameters:	vp			The designated vnode
 *
 * Returns:	(void)
 *
 * Notes:	This function is called on vnode termination for all vnodes,
 *		and must therefore not assume that there is a ubc_info that is
 *		associated with the vnode, nor that there is a control object
 *		associated with the ubc_info.
 *
 *		If all the conditions necessary are present, this function
 *		calls memory_object_destory(), which will in turn end up
 *		calling ubc_unmap() to release any vnode references that were
 *		established via ubc_map().
 *
 *		IMPORTANT: This is an internal use function that is used
 *		exclusively by the internal use function vclean().
 */
__private_extern__ void
ubc_destroy_named(vnode_t vp)
{
	memory_object_control_t control;
	struct ubc_info *uip;
	kern_return_t kret;

	if (UBCINFOEXISTS(vp)) {
	        uip = vp->v_ubcinfo;

		/* Terminate the memory object  */
		control = ubc_getobject(vp, UBC_HOLDOBJECT);
		if (control != MEMORY_OBJECT_CONTROL_NULL) {
		        kret = memory_object_destroy(control, 0);
			if (kret != KERN_SUCCESS)
			        panic("ubc_destroy_named: memory_object_destroy failed");
		}
	}
}


/*
 * ubc_isinuse
 *
 * Determine whether or not a vnode is currently in use by ubc at a level in
 * excess of the requested busycount
 *
 * Parameters:	vp			The vnode to check
 *		busycount		The threshold busy count, used to bias
 *					the count usually already held by the
 *					caller to avoid races
 *
 * Returns:	1			The vnode is in use over the threshold
 *		0			The vnode is not in use over the
 *					threshold
 *
 * Notes:	Because the vnode is only held locked while actually asking
 *		the use count, this function only represents a snapshot of the
 *		current state of the vnode.  If more accurate information is
 *		required, an additional busycount should be held by the caller
 *		and a non-zero busycount used.
 *
 *		If there is no ubc_info associated with the vnode, this
 *		function will report that the vnode is not in use by ubc.
 */
int
ubc_isinuse(struct vnode *vp, int busycount)
{
	if ( !UBCINFOEXISTS(vp))
		return (0);
	return(ubc_isinuse_locked(vp, busycount, 0));
}


/*
 * ubc_isinuse_locked
 *
 * Determine whether or not a vnode is currently in use by ubc at a level in
 * excess of the requested busycount
 *
 * Parameters:	vp			The vnode to check
 *		busycount		The threshold busy count, used to bias
 *					the count usually already held by the
 *					caller to avoid races
 *		locked			True if the vnode is already locked by
 *					the caller
 *
 * Returns:	1			The vnode is in use over the threshold
 *		0			The vnode is not in use over the
 *					threshold
 *
 * Notes:	If the vnode is not locked on entry, it is locked while
 *		actually asking the use count.  If this is the case, this
 *		function only represents a snapshot of the current state of
 *		the vnode.  If more accurate information is required, the
 *		vnode lock should be held by the caller, otherwise an
 *		additional busycount should be held by the caller and a
 *		non-zero busycount used.
 *
 *		If there is no ubc_info associated with the vnode, this
 *		function will report that the vnode is not in use by ubc.
 */
int
ubc_isinuse_locked(struct vnode *vp, int busycount, int locked)
{
	int retval = 0;


	if (!locked)
		vnode_lock_spin(vp);

	if ((vp->v_usecount - vp->v_kusecount) > busycount)
		retval = 1;

	if (!locked)
		vnode_unlock(vp);
	return (retval);
}


/*
 * ubc_unmap
 *
 * Reverse the effects of a ubc_map() call for a given vnode
 *
 * Parameters:	vp			vnode to unmap from ubc
 *
 * Returns:	(void)
 *
 * Notes:	This is an internal use function used by vnode_pager_unmap().
 *		It will attempt to obtain a reference on the supplied vnode,
 *		and if it can do so, and there is an associated ubc_info, and
 *		the flags indicate that it was mapped via ubc_map(), then the
 *		flag is cleared, the mapping removed, and the reference taken
 *		by ubc_map() is released.
 *
 *		IMPORTANT: This MUST only be called by the VM
 *		to prevent race conditions.
 */
__private_extern__ void
ubc_unmap(struct vnode *vp)
{
	struct ubc_info *uip;
	int	need_rele = 0;
	int	need_wakeup = 0;

	if (vnode_getwithref(vp))
	        return;

	if (UBCINFOEXISTS(vp)) {
		vnode_lock(vp);
		uip = vp->v_ubcinfo;

		while (ISSET(uip->ui_flags, UI_MAPBUSY)) {
			SET(uip->ui_flags, UI_MAPWAITING);
			(void) msleep(&uip->ui_flags, &vp->v_lock,
				      PRIBIO, "ubc_unmap", NULL);
		}
		SET(uip->ui_flags, UI_MAPBUSY);

		if (ISSET(uip->ui_flags, UI_ISMAPPED)) {
		        CLR(uip->ui_flags, UI_ISMAPPED);
			need_rele = 1;
		}
		vnode_unlock(vp);
		
		if (need_rele) {
		        (void)VNOP_MNOMAP(vp, vfs_context_current());
		        vnode_rele(vp);
		}

		vnode_lock_spin(vp);

		CLR(uip->ui_flags, UI_MAPBUSY);
		if (ISSET(uip->ui_flags, UI_MAPWAITING)) {
			CLR(uip->ui_flags, UI_MAPWAITING);
			need_wakeup = 1;
		}
		vnode_unlock(vp);

		if (need_wakeup)
		        wakeup(&uip->ui_flags);

	}
	/*
	 * the drop of the vnode ref will cleanup
	 */
	vnode_put(vp);
}


/*
 * ubc_page_op
 *
 * Manipulate individual page state for a vnode with an associated ubc_info
 * with an associated memory object control.
 *
 * Parameters:	vp			The vnode backing the page
 *		f_offset		A file offset interior to the page
 *		ops			The operations to perform, as a bitmap
 *					(see below for more information)
 *		phys_entryp		The address of a ppnum_t; may be NULL
 *					to ignore
 *		flagsp			A pointer to an int to contain flags;
 *					may be NULL to ignore
 *
 * Returns:	KERN_SUCCESS		Success
 *		KERN_INVALID_ARGUMENT	If the memory object control has no VM
 *					object associated
 *		KERN_INVALID_OBJECT	If UPL_POP_PHYSICAL and the object is
 *					not physically contiguous
 *		KERN_INVALID_OBJECT	If !UPL_POP_PHYSICAL and the object is
 *					physically contiguous
 *		KERN_FAILURE		If the page cannot be looked up
 *
 * Implicit Returns:
 *		*phys_entryp (modified)	If phys_entryp is non-NULL and
 *					UPL_POP_PHYSICAL
 *		*flagsp (modified)	If flagsp is non-NULL and there was
 *					!UPL_POP_PHYSICAL and a KERN_SUCCESS
 *
 * Notes:	For object boundaries, it is considerably more efficient to
 *		ensure that f_offset is in fact on a page boundary, as this
 *		will avoid internal use of the hash table to identify the
 *		page, and would therefore skip a number of early optimizations.
 *		Since this is a page operation anyway, the caller should try
 *		to pass only a page aligned offset because of this.
 *
 *		*flagsp may be modified even if this function fails.  If it is
 *		modified, it will contain the condition of the page before the
 *		requested operation was attempted; these will only include the
 *		bitmap flags, and not the PL_POP_PHYSICAL, UPL_POP_DUMP,
 *		UPL_POP_SET, or UPL_POP_CLR bits.
 *
 *		The flags field may contain a specific operation, such as
 *		UPL_POP_PHYSICAL or UPL_POP_DUMP:
 *
 *		o	UPL_POP_PHYSICAL	Fail if not contiguous; if
 *						*phys_entryp and successful, set
 *						*phys_entryp
 *		o	UPL_POP_DUMP		Dump the specified page
 *
 *		Otherwise, it is treated as a bitmap of one or more page
 *		operations to perform on the final memory object; allowable
 *		bit values are:
 *
 *		o	UPL_POP_DIRTY		The page is dirty
 *		o	UPL_POP_PAGEOUT		The page is paged out
 *		o	UPL_POP_PRECIOUS	The page is precious
 *		o	UPL_POP_ABSENT		The page is absent
 *		o	UPL_POP_BUSY		The page is busy
 *
 *		If the page status is only being queried and not modified, then
 *		not other bits should be specified.  However, if it is being
 *		modified, exactly ONE of the following bits should be set:
 *
 *		o	UPL_POP_SET		Set the current bitmap bits
 *		o	UPL_POP_CLR		Clear the current bitmap bits
 *
 *		Thus to effect a combination of setting an clearing, it may be
 *		necessary to call this function twice.  If this is done, the
 *		set should be used before the clear, since clearing may trigger
 *		a wakeup on the destination page, and if the page is backed by
 *		an encrypted swap file, setting will trigger the decryption
 *		needed before the wakeup occurs.
 */
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


/*
 * ubc_range_op
 *
 * Manipulate page state for a range of memory for a vnode with an associated
 * ubc_info with an associated memory object control, when page level state is
 * not required to be returned from the call (i.e. there are no phys_entryp or
 * flagsp parameters to this call, and it takes a range which may contain
 * multiple pages, rather than an offset interior to a single page).
 *
 * Parameters:	vp			The vnode backing the page
 *		f_offset_beg		A file offset interior to the start page
 *		f_offset_end		A file offset interior to the end page
 *		ops			The operations to perform, as a bitmap
 *					(see below for more information)
 *		range			The address of an int; may be NULL to
 *					ignore
 *
 * Returns:	KERN_SUCCESS		Success
 *		KERN_INVALID_ARGUMENT	If the memory object control has no VM
 *					object associated
 *		KERN_INVALID_OBJECT	If the object is physically contiguous
 *
 * Implicit Returns:
 *		*range (modified)	If range is non-NULL, its contents will
 *					be modified to contain the number of
 *					bytes successfully operated upon.
 *
 * Notes:	IMPORTANT: This function cannot be used on a range that
 *		consists of physically contiguous pages.
 *
 *		For object boundaries, it is considerably more efficient to
 *		ensure that f_offset_beg and f_offset_end are in fact on page
 *		boundaries, as this will avoid internal use of the hash table
 *		to identify the page, and would therefore skip a number of
 *		early optimizations.  Since this is an operation on a set of
 *		pages anyway, the caller should try to pass only a page aligned
 *		offsets because of this.
 *
 *		*range will be modified only if this function succeeds.
 *
 *		The flags field MUST contain a specific operation; allowable
 *		values are:
 *
 *		o	UPL_ROP_ABSENT	Returns the extent of the range
 *					presented which is absent, starting
 *					with the start address presented
 *
 *		o	UPL_ROP_PRESENT	Returns the extent of the range
 *					presented which is present (resident),
 *					starting with the start address
 *					presented
 *		o	UPL_ROP_DUMP	Dump the pages which are found in the
 *					target object for the target range.
 *
 *		IMPORTANT: For UPL_ROP_ABSENT and UPL_ROP_PRESENT; if there are
 *		multiple regions in the range, only the first matching region
 *		is returned.
 */
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


/*
 * ubc_create_upl
 *
 * Given a vnode, cause the population of a portion of the vm_object; based on
 * the nature of the request, the pages returned may contain valid data, or
 * they may be uninitialized.
 *
 * Parameters:	vp			The vnode from which to create the upl
 *		f_offset		The start offset into the backing store
 *					represented by the vnode
 *		bufsize			The size of the upl to create
 *		uplp			Pointer to the upl_t to receive the
 *					created upl; MUST NOT be NULL
 *		plp			Pointer to receive the internal page
 *					list for the created upl; MAY be NULL
 *					to ignore
 *
 * Returns:	KERN_SUCCESS		The requested upl has been created
 *		KERN_INVALID_ARGUMENT	The bufsize argument is not an even
 *					multiple of the page size
 *		KERN_INVALID_ARGUMENT	There is no ubc_info associated with
 *					the vnode, or there is no memory object
 *					control associated with the ubc_info 
 *	memory_object_upl_request:KERN_INVALID_VALUE
 *					The supplied upl_flags argument is
 *					invalid
 * Implicit Returns:
 *		*uplp (modified)	
 *		*plp (modified)		If non-NULL, the value of *plp will be
 *					modified to point to the internal page
 *					list; this modification may occur even
 *					if this function is unsuccessful, in
 *					which case the contents may be invalid
 *
 * Note:	If successful, the returned *uplp MUST subsequently be freed
 *		via a call to ubc_upl_commit(), ubc_upl_commit_range(),
 *		ubc_upl_abort(), or ubc_upl_abort_range().
 */
kern_return_t
ubc_create_upl(
	struct vnode	*vp,
	off_t 		f_offset,
	int		bufsize,
	upl_t		*uplp,
	upl_page_info_t	**plp,
	int		uplflags)
{
	memory_object_control_t		control;
	kern_return_t			kr;

	if (plp != NULL)
		*plp = NULL;
	*uplp = NULL;
	
	if (bufsize & 0xfff)
		return KERN_INVALID_ARGUMENT;

	if (uplflags & (UPL_UBC_MSYNC | UPL_UBC_PAGEOUT | UPL_UBC_PAGEIN)) {

		if (uplflags & UPL_UBC_MSYNC) {
			uplflags &= UPL_RET_ONLY_DIRTY;

			uplflags |= UPL_COPYOUT_FROM | UPL_CLEAN_IN_PLACE |
				    UPL_SET_INTERNAL | UPL_SET_LITE;

		} else if (uplflags & UPL_UBC_PAGEOUT) {
			uplflags &= UPL_RET_ONLY_DIRTY;

			if (uplflags & UPL_RET_ONLY_DIRTY)
				uplflags |= UPL_NOBLOCK;

			uplflags |= UPL_FOR_PAGEOUT | UPL_CLEAN_IN_PLACE |
                                    UPL_COPYOUT_FROM | UPL_SET_INTERNAL | UPL_SET_LITE;
		} else {
			uplflags |= UPL_RET_ONLY_ABSENT | UPL_NOBLOCK |
				    UPL_NO_SYNC | UPL_CLEAN_IN_PLACE |
				    UPL_SET_INTERNAL | UPL_SET_LITE;
		}
	} else {
		uplflags &= ~UPL_FOR_PAGEOUT;

		if (uplflags & UPL_WILL_BE_DUMPED) {
			uplflags &= ~UPL_WILL_BE_DUMPED;
			uplflags |= (UPL_NO_SYNC|UPL_SET_INTERNAL);
		} else
			uplflags |= (UPL_NO_SYNC|UPL_CLEAN_IN_PLACE|UPL_SET_INTERNAL);
	}
	control = ubc_getobject(vp, UBC_FLAGS_NONE);
	if (control == MEMORY_OBJECT_CONTROL_NULL)
		return KERN_INVALID_ARGUMENT;

	kr = memory_object_upl_request(control, f_offset, bufsize, uplp, NULL, NULL, uplflags);
	if (kr == KERN_SUCCESS && plp != NULL)
		*plp = UPL_GET_INTERNAL_PAGE_LIST(*uplp);
	return kr;
}
		
					  		      
/*
 * ubc_upl_maxbufsize
 *
 * Return the maximum bufsize ubc_create_upl( ) will take.
 *
 * Parameters:	none
 *
 * Returns:	maximum size buffer (in bytes) ubc_create_upl( ) will take.
 */
upl_size_t 
ubc_upl_maxbufsize(
	void)
{
	return(MAX_UPL_SIZE * PAGE_SIZE);
}

/*
 * ubc_upl_map
 *
 * Map the page list assocated with the supplied upl into the kernel virtual
 * address space at the virtual address indicated by the dst_addr argument;
 * the entire upl is mapped
 *
 * Parameters:	upl			The upl to map
 *		dst_addr		The address at which to map the upl
 *
 * Returns:	KERN_SUCCESS		The upl has been mapped
 *		KERN_INVALID_ARGUMENT	The upl is UPL_NULL
 *		KERN_FAILURE		The upl is already mapped
 *	vm_map_enter:KERN_INVALID_ARGUMENT
 *					A failure code from vm_map_enter() due
 *					to an invalid argument
 */
kern_return_t
ubc_upl_map(
	upl_t		upl,
	vm_offset_t	*dst_addr)
{
	return (vm_upl_map(kernel_map, upl, dst_addr));
}


/*
 * ubc_upl_unmap
 *
 * Unmap the page list assocated with the supplied upl from the kernel virtual
 * address space; the entire upl is unmapped.
 *
 * Parameters:	upl			The upl to unmap
 *
 * Returns:	KERN_SUCCESS		The upl has been unmapped
 *		KERN_FAILURE		The upl is not currently mapped
 *		KERN_INVALID_ARGUMENT	If the upl is UPL_NULL
 */
kern_return_t
ubc_upl_unmap(
	upl_t	upl)
{
	return(vm_upl_unmap(kernel_map, upl));
}


/*
 * ubc_upl_commit
 *
 * Commit the contents of the upl to the backing store
 *
 * Parameters:	upl			The upl to commit
 *
 * Returns:	KERN_SUCCESS		The upl has been committed
 *		KERN_INVALID_ARGUMENT	The supplied upl was UPL_NULL
 *		KERN_FAILURE		The supplied upl does not represent
 *					device memory, and the offset plus the
 *					size would exceed the actual size of
 *					the upl
 *
 * Notes:	In practice, the only return value for this function should be
 *		KERN_SUCCESS, unless there has been data structure corruption;
 *		since the upl is deallocated regardless of success or failure,
 *		there's really nothing to do about this other than panic.
 *
 *		IMPORTANT: Use of this function should not be mixed with use of
 *		ubc_upl_commit_range(), due to the unconditional deallocation
 *		by this function.
 */
kern_return_t
ubc_upl_commit(
	upl_t 			upl)
{
	upl_page_info_t	*pl;
	kern_return_t 	kr;

	pl = UPL_GET_INTERNAL_PAGE_LIST(upl);
	kr = upl_commit(upl, pl, MAX_UPL_SIZE);
	upl_deallocate(upl);
	return kr;
}


/*
 * ubc_upl_commit
 *
 * Commit the contents of the specified range of the upl to the backing store
 *
 * Parameters:	upl			The upl to commit
 *		offset			The offset into the upl
 *		size			The size of the region to be committed,
 *					starting at the specified offset
 *		flags			commit type (see below)
 *
 * Returns:	KERN_SUCCESS		The range has been committed
 *		KERN_INVALID_ARGUMENT	The supplied upl was UPL_NULL
 *		KERN_FAILURE		The supplied upl does not represent
 *					device memory, and the offset plus the
 *					size would exceed the actual size of
 *					the upl
 *
 * Notes:	IMPORTANT: If the commit is successful, and the object is now
 *		empty, the upl will be deallocated.  Since the caller cannot
 *		check that this is the case, the UPL_COMMIT_FREE_ON_EMPTY flag
 *		should generally only be used when the offset is 0 and the size
 *		is equal to the upl size.
 *
 *		The flags argument is a bitmap of flags on the rage of pages in
 *		the upl to be committed; allowable flags are:
 *
 *		o	UPL_COMMIT_FREE_ON_EMPTY	Free the upl when it is
 *							both empty and has been
 *							successfully committed
 *		o	UPL_COMMIT_CLEAR_DIRTY		Clear each pages dirty
 *							bit; will prevent a
 *							later pageout
 *		o	UPL_COMMIT_SET_DIRTY		Set each pages dirty
 *							bit; will cause a later
 *							pageout
 *		o	UPL_COMMIT_INACTIVATE		Clear each pages
 *							reference bit; the page
 *							will not be accessed
 *		o	UPL_COMMIT_ALLOW_ACCESS		Unbusy each page; pages
 *							become busy when an
 *							IOMemoryDescriptor is
 *							mapped or redirected,
 *							and we have to wait for
 *							an IOKit driver
 *
 *		The flag UPL_COMMIT_NOTIFY_EMPTY is used internally, and should
 *		not be specified by the caller.
 *
 *		The UPL_COMMIT_CLEAR_DIRTY and UPL_COMMIT_SET_DIRTY flags are
 *		mutually exclusive, and should not be combined.
 */
kern_return_t
ubc_upl_commit_range(
	upl_t 			upl,
	upl_offset_t		offset,
	upl_size_t		size,
	int				flags)
{
	upl_page_info_t	*pl;
	boolean_t		empty;
	kern_return_t 	kr;

	if (flags & UPL_COMMIT_FREE_ON_EMPTY)
		flags |= UPL_COMMIT_NOTIFY_EMPTY;

	if (flags & UPL_COMMIT_KERNEL_ONLY_FLAGS) {
		return KERN_INVALID_ARGUMENT;
	}

	pl = UPL_GET_INTERNAL_PAGE_LIST(upl);

	kr = upl_commit_range(upl, offset, size, flags,
						  pl, MAX_UPL_SIZE, &empty);

	if((flags & UPL_COMMIT_FREE_ON_EMPTY) && empty)
		upl_deallocate(upl);

	return kr;
}


/*
 * ubc_upl_abort_range
 *
 * Abort the contents of the specified range of the specified upl
 *
 * Parameters:	upl			The upl to abort
 *		offset			The offset into the upl
 *		size			The size of the region to be aborted,
 *					starting at the specified offset
 *		abort_flags		abort type (see below)
 *
 * Returns:	KERN_SUCCESS		The range has been aborted
 *		KERN_INVALID_ARGUMENT	The supplied upl was UPL_NULL
 *		KERN_FAILURE		The supplied upl does not represent
 *					device memory, and the offset plus the
 *					size would exceed the actual size of
 *					the upl
 *
 * Notes:	IMPORTANT: If the abort is successful, and the object is now
 *		empty, the upl will be deallocated.  Since the caller cannot
 *		check that this is the case, the UPL_ABORT_FREE_ON_EMPTY flag
 *		should generally only be used when the offset is 0 and the size
 *		is equal to the upl size.
 *
 *		The abort_flags argument is a bitmap of flags on the range of
 *		pages in the upl to be aborted; allowable flags are:
 *
 *		o	UPL_ABORT_FREE_ON_EMPTY	Free the upl when it is both
 *						empty and has been successfully
 *						aborted
 *		o	UPL_ABORT_RESTART	The operation must be restarted
 *		o	UPL_ABORT_UNAVAILABLE	The pages are unavailable
 *		o	UPL_ABORT_ERROR		An I/O error occurred
 *		o	UPL_ABORT_DUMP_PAGES	Just free the pages
 *		o	UPL_ABORT_NOTIFY_EMPTY	RESERVED
 *		o	UPL_ABORT_ALLOW_ACCESS	RESERVED
 *
 *		The UPL_ABORT_NOTIFY_EMPTY is an internal use flag and should
 *		not be specified by the caller.  It is intended to fulfill the
 *		same role as UPL_COMMIT_NOTIFY_EMPTY does in the function
 *		ubc_upl_commit_range(), but is never referenced internally.
 *
 *		The UPL_ABORT_ALLOW_ACCESS is defined, but neither set nor
 *		referenced; do not use it.
 */
kern_return_t
ubc_upl_abort_range(
	upl_t			upl,
	upl_offset_t		offset,
	upl_size_t		size,
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


/*
 * ubc_upl_abort
 *
 * Abort the contents of the specified upl
 *
 * Parameters:	upl			The upl to abort
 *		abort_type		abort type (see below)
 *
 * Returns:	KERN_SUCCESS		The range has been aborted
 *		KERN_INVALID_ARGUMENT	The supplied upl was UPL_NULL
 *		KERN_FAILURE		The supplied upl does not represent
 *					device memory, and the offset plus the
 *					size would exceed the actual size of
 *					the upl
 *
 * Notes:	IMPORTANT: If the abort is successful, and the object is now
 *		empty, the upl will be deallocated.  Since the caller cannot
 *		check that this is the case, the UPL_ABORT_FREE_ON_EMPTY flag
 *		should generally only be used when the offset is 0 and the size
 *		is equal to the upl size.
 *
 *		The abort_type is a bitmap of flags on the range of
 *		pages in the upl to be aborted; allowable flags are:
 *
 *		o	UPL_ABORT_FREE_ON_EMPTY	Free the upl when it is both
 *						empty and has been successfully
 *						aborted
 *		o	UPL_ABORT_RESTART	The operation must be restarted
 *		o	UPL_ABORT_UNAVAILABLE	The pages are unavailable
 *		o	UPL_ABORT_ERROR		An I/O error occurred
 *		o	UPL_ABORT_DUMP_PAGES	Just free the pages
 *		o	UPL_ABORT_NOTIFY_EMPTY	RESERVED
 *		o	UPL_ABORT_ALLOW_ACCESS	RESERVED
 *
 *		The UPL_ABORT_NOTIFY_EMPTY is an internal use flag and should
 *		not be specified by the caller.  It is intended to fulfill the
 *		same role as UPL_COMMIT_NOTIFY_EMPTY does in the function
 *		ubc_upl_commit_range(), but is never referenced internally.
 *
 *		The UPL_ABORT_ALLOW_ACCESS is defined, but neither set nor
 *		referenced; do not use it.
 */
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


/*
 * ubc_upl_pageinfo
 *
 *  Retrieve the internal page list for the specified upl
 *
 * Parameters:	upl			The upl to obtain the page list from
 *
 * Returns:	!NULL			The (upl_page_info_t *) for the page
 *					list internal to the upl
 *		NULL			Error/no page list associated
 *
 * Notes:	IMPORTANT: The function is only valid on internal objects
 *		where the list request was made with the UPL_INTERNAL flag.
 *
 *		This function is a utility helper function, since some callers
 *		may not have direct access to the header defining the macro,
 *		due to abstraction layering constraints.
 */
upl_page_info_t *
ubc_upl_pageinfo(
	upl_t			upl)
{	       
	return (UPL_GET_INTERNAL_PAGE_LIST(upl));
}


int 
UBCINFOEXISTS(struct vnode * vp)
{
        return((vp) && ((vp)->v_type == VREG) && ((vp)->v_ubcinfo != UBC_INFO_NULL));
}


/*
 * CODE SIGNING
 */
#define CS_BLOB_PAGEABLE 0
static volatile SInt32 cs_blob_size = 0;
static volatile SInt32 cs_blob_count = 0;
static SInt32 cs_blob_size_peak = 0;
static UInt32 cs_blob_size_max = 0;
static SInt32 cs_blob_count_peak = 0;

int cs_validation = 1;

SYSCTL_INT(_vm, OID_AUTO, cs_validation, CTLFLAG_RW, &cs_validation, 0, "Do validate code signatures");
SYSCTL_INT(_vm, OID_AUTO, cs_blob_count, CTLFLAG_RD, &cs_blob_count, 0, "Current number of code signature blobs");
SYSCTL_INT(_vm, OID_AUTO, cs_blob_size, CTLFLAG_RD, &cs_blob_size, 0, "Current size of all code signature blobs");
SYSCTL_INT(_vm, OID_AUTO, cs_blob_count_peak, CTLFLAG_RD, &cs_blob_count_peak, 0, "Peak number of code signature blobs");
SYSCTL_INT(_vm, OID_AUTO, cs_blob_size_peak, CTLFLAG_RD, &cs_blob_size_peak, 0, "Peak size of code signature blobs");
SYSCTL_INT(_vm, OID_AUTO, cs_blob_size_max, CTLFLAG_RD, &cs_blob_size_max, 0, "Size of biggest code signature blob");

kern_return_t
ubc_cs_blob_allocate(
	vm_offset_t	*blob_addr_p,
	vm_size_t	*blob_size_p)
{
	kern_return_t	kr;

#if CS_BLOB_PAGEABLE
	*blob_size_p = round_page(*blob_size_p);
	kr = kmem_alloc(kernel_map, blob_addr_p, *blob_size_p);
#else	/* CS_BLOB_PAGEABLE */
	*blob_addr_p = (vm_offset_t) kalloc(*blob_size_p);
	if (*blob_addr_p == 0) {
		kr = KERN_NO_SPACE;
	} else {
		kr = KERN_SUCCESS;
	}
#endif	/* CS_BLOB_PAGEABLE */
	return kr;
}

void
ubc_cs_blob_deallocate(
	vm_offset_t	blob_addr,
	vm_size_t	blob_size)
{
#if CS_BLOB_PAGEABLE
	kmem_free(kernel_map, blob_addr, blob_size);
#else	/* CS_BLOB_PAGEABLE */
	kfree((void *) blob_addr, blob_size);
#endif	/* CS_BLOB_PAGEABLE */
}
	
int
ubc_cs_blob_add(
	struct vnode	*vp,
	cpu_type_t	cputype,
	off_t		base_offset,
	vm_address_t	addr,
	vm_size_t	size)
{
	kern_return_t		kr;
	struct ubc_info		*uip;
	struct cs_blob		*blob, *oblob;
	int			error;
	ipc_port_t		blob_handle;
	memory_object_size_t	blob_size;
	const CS_CodeDirectory *cd;
	off_t			blob_start_offset, blob_end_offset;
	SHA1_CTX		sha1ctxt;

	blob_handle = IPC_PORT_NULL;

	blob = (struct cs_blob *) kalloc(sizeof (struct cs_blob));
	if (blob == NULL) {
		return ENOMEM;
	}

#if CS_BLOB_PAGEABLE
	/* get a memory entry on the blob */
	blob_size = (memory_object_size_t) size;
	kr = mach_make_memory_entry_64(kernel_map,
				       &blob_size,
				       addr,
				       VM_PROT_READ,
				       &blob_handle,
				       IPC_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		error = ENOMEM;
		goto out;
	}
	if (memory_object_round_page(blob_size) !=
	    (memory_object_size_t) round_page(size)) {
		printf("ubc_cs_blob_add: size mismatch 0x%llx 0x%lx !?\n",
		       blob_size, (size_t)size);
		panic("XXX FBDP size mismatch 0x%llx 0x%lx\n", blob_size, (size_t)size);
		error = EINVAL;
		goto out;
	}
#else
	blob_size = (memory_object_size_t) size;
	blob_handle = IPC_PORT_NULL;
#endif

	/* fill in the new blob */
	blob->csb_cpu_type = cputype;
	blob->csb_base_offset = base_offset;
	blob->csb_mem_size = size;
	blob->csb_mem_offset = 0;
	blob->csb_mem_handle = blob_handle;
	blob->csb_mem_kaddr = addr;
	
	/*
	 * Validate the blob's contents
	 */
	cd = findCodeDirectory(
		(const CS_SuperBlob *) addr, 
		(char *) addr, 
		(char *) addr + blob->csb_mem_size);
	if (cd == NULL) {
		/* no code directory => useless blob ! */
		blob->csb_flags = 0;
		blob->csb_start_offset = 0;
		blob->csb_end_offset = 0;
	} else {
		unsigned char *sha1_base;
		int sha1_size;

		blob->csb_flags = ntohl(cd->flags) | CS_VALID;
		blob->csb_end_offset = round_page(ntohl(cd->codeLimit));
		if((ntohl(cd->version) >= supportsScatter) && (ntohl(cd->scatterOffset))) {
			const struct Scatter *scatter = (const struct Scatter*)
				((const char*)cd + ntohl(cd->scatterOffset));
			blob->csb_start_offset = ntohl(scatter->base) * PAGE_SIZE;
		} else {
			blob->csb_start_offset = (blob->csb_end_offset -
						  (ntohl(cd->nCodeSlots) * PAGE_SIZE));
		}
		/* compute the blob's SHA1 hash */
		sha1_base = (const unsigned char *) cd;
		sha1_size = ntohl(cd->length);
		SHA1Init(&sha1ctxt);
		SHA1Update(&sha1ctxt, sha1_base, sha1_size);
		SHA1Final(blob->csb_sha1, &sha1ctxt);
	}

	/* 
	 * Let policy module check whether the blob's signature is accepted.
	 */
#if CONFIG_MACF
	error = mac_vnode_check_signature(vp, blob->csb_sha1, (void*)addr, size);
	if (error) 
		goto out;
#endif	
	
	/*
	 * Validate the blob's coverage
	 */
	blob_start_offset = blob->csb_base_offset + blob->csb_start_offset;
	blob_end_offset = blob->csb_base_offset + blob->csb_end_offset;

	if (blob_start_offset >= blob_end_offset ||
	    blob_start_offset < 0 ||
	    blob_end_offset <= 0) {
		/* reject empty or backwards blob */
		error = EINVAL;
		goto out;
	}

	vnode_lock(vp);
	if (! UBCINFOEXISTS(vp)) {
		vnode_unlock(vp);
		error = ENOENT;
		goto out;
	}
	uip = vp->v_ubcinfo;

	/* check if this new blob overlaps with an existing blob */
	for (oblob = uip->cs_blobs;
	     oblob != NULL;
	     oblob = oblob->csb_next) {
		 off_t oblob_start_offset, oblob_end_offset;

		 oblob_start_offset = (oblob->csb_base_offset +
				       oblob->csb_start_offset);
		 oblob_end_offset = (oblob->csb_base_offset +
				     oblob->csb_end_offset);
		 if (blob_start_offset >= oblob_end_offset ||
		     blob_end_offset <= oblob_start_offset) {
			 /* no conflict with this existing blob */
		 } else {
			 /* conflict ! */
			 if (blob_start_offset == oblob_start_offset &&
			     blob_end_offset == oblob_end_offset &&
			     blob->csb_mem_size == oblob->csb_mem_size &&
			     blob->csb_flags == oblob->csb_flags &&
			     (blob->csb_cpu_type == CPU_TYPE_ANY ||
			      oblob->csb_cpu_type == CPU_TYPE_ANY ||
			      blob->csb_cpu_type == oblob->csb_cpu_type) &&
			     !bcmp(blob->csb_sha1,
				   oblob->csb_sha1,
				   SHA1_RESULTLEN)) {
				 /*
				  * We already have this blob:
				  * we'll return success but
				  * throw away the new blob.
				  */
				 if (oblob->csb_cpu_type == CPU_TYPE_ANY) {
					 /*
					  * The old blob matches this one
					  * but doesn't have any CPU type.
					  * Update it with whatever the caller
					  * provided this time.
					  */
					 oblob->csb_cpu_type = cputype;
				 }
				 vnode_unlock(vp);
				 error = EAGAIN;
				 goto out;
			 } else {
				 /* different blob: reject the new one */
				 vnode_unlock(vp);
				 error = EALREADY;
				 goto out;
			 }
		 }

	}


	/* mark this vnode's VM object as having "signed pages" */
	kr = memory_object_signed(uip->ui_control, TRUE);
	if (kr != KERN_SUCCESS) {
		vnode_unlock(vp);
		error = ENOENT;
		goto out;
	}

	/*
	 * Add this blob to the list of blobs for this vnode.
	 * We always add at the front of the list and we never remove a
	 * blob from the list, so ubc_cs_get_blobs() can return whatever
	 * the top of the list was and that list will remain valid
	 * while we validate a page, even after we release the vnode's lock.
	 */
	blob->csb_next = uip->cs_blobs;
	uip->cs_blobs = blob;

	OSAddAtomic(+1, &cs_blob_count);
	if (cs_blob_count > cs_blob_count_peak) {
		cs_blob_count_peak = cs_blob_count; /* XXX atomic ? */
	}
	OSAddAtomic((SInt32) +blob->csb_mem_size, &cs_blob_size);
	if ((SInt32) cs_blob_size > cs_blob_size_peak) {
		cs_blob_size_peak = (SInt32) cs_blob_size; /* XXX atomic ? */
	}
	if ((UInt32) blob->csb_mem_size > cs_blob_size_max) {
		cs_blob_size_max = (UInt32) blob->csb_mem_size;
	}

	if (cs_debug) {
		proc_t p;

		p = current_proc();
		printf("CODE SIGNING: proc %d(%s) "
		       "loaded %s signatures for file (%s) "
		       "range 0x%llx:0x%llx flags 0x%x\n",
		       p->p_pid, p->p_comm,
		       blob->csb_cpu_type == -1 ? "detached" : "embedded",
		       vnode_name(vp),
		       blob->csb_base_offset + blob->csb_start_offset,
		       blob->csb_base_offset + blob->csb_end_offset,
		       blob->csb_flags);
	}

	vnode_unlock(vp);

	error = 0;	/* success ! */

out:
	if (error) {
		/* we failed; release what we allocated */
		if (blob) {
			kfree(blob, sizeof (*blob));
			blob = NULL;
		}
		if (blob_handle != IPC_PORT_NULL) {
			mach_memory_entry_port_release(blob_handle);
			blob_handle = IPC_PORT_NULL;
		}
	}

	if (error == EAGAIN) {
		/*
		 * See above:  error is EAGAIN if we were asked 
		 * to add an existing blob again.  We cleaned the new
		 * blob and we want to return success.
		 */
		error = 0;
		/*
		 * Since we're not failing, consume the data we received.
		 */
		ubc_cs_blob_deallocate(addr, size);
	}

	return error;
}


struct cs_blob *
ubc_cs_blob_get(
	struct vnode	*vp,
	cpu_type_t	cputype,
	off_t		offset)
{
	struct ubc_info	*uip;
	struct cs_blob	*blob;
	off_t offset_in_blob;

	vnode_lock_spin(vp);

	if (! UBCINFOEXISTS(vp)) {
		blob = NULL;
		goto out;
	}

	uip = vp->v_ubcinfo;
	for (blob = uip->cs_blobs;
	     blob != NULL;
	     blob = blob->csb_next) {
		if (cputype != -1 && blob->csb_cpu_type == cputype) {
			break;
		}
		if (offset != -1) {
			offset_in_blob = offset - blob->csb_base_offset;
			if (offset_in_blob >= blob->csb_start_offset &&
			    offset_in_blob < blob->csb_end_offset) {
				/* our offset is covered by this blob */
				break;
			}
		}
	}

out:
	vnode_unlock(vp);

	return blob;
}

static void
ubc_cs_free(
	struct ubc_info	*uip)
{
	struct cs_blob	*blob, *next_blob;

	for (blob = uip->cs_blobs;
	     blob != NULL;
	     blob = next_blob) {
		next_blob = blob->csb_next;
		if (blob->csb_mem_kaddr != 0) {
			ubc_cs_blob_deallocate(blob->csb_mem_kaddr,
					       blob->csb_mem_size);
			blob->csb_mem_kaddr = 0;
		}
		if (blob->csb_mem_handle != IPC_PORT_NULL) {
			mach_memory_entry_port_release(blob->csb_mem_handle);
		}
		blob->csb_mem_handle = IPC_PORT_NULL;
		OSAddAtomic(-1, &cs_blob_count);
		OSAddAtomic((SInt32) -blob->csb_mem_size, &cs_blob_size);
		kfree(blob, sizeof (*blob));
	}
	uip->cs_blobs = NULL;
}

struct cs_blob *
ubc_get_cs_blobs(
	struct vnode	*vp)
{
	struct ubc_info	*uip;
	struct cs_blob	*blobs;

	/*
	 * No need to take the vnode lock here.  The caller must be holding
	 * a reference on the vnode (via a VM mapping or open file descriptor),
	 * so the vnode will not go away.  The ubc_info stays until the vnode
	 * goes away.  And we only modify "blobs" by adding to the head of the
	 * list.
	 * The ubc_info could go away entirely if the vnode gets reclaimed as
	 * part of a forced unmount.  In the case of a code-signature validation
	 * during a page fault, the "paging_in_progress" reference on the VM
	 * object guarantess that the vnode pager (and the ubc_info) won't go
	 * away during the fault.
	 * Other callers need to protect against vnode reclaim by holding the
	 * vnode lock, for example.
	 */

	if (! UBCINFOEXISTS(vp)) {
		blobs = NULL;
		goto out;
	}

	uip = vp->v_ubcinfo;
	blobs = uip->cs_blobs;

out:
	return blobs;
}

unsigned long cs_validate_page_no_hash = 0;
unsigned long cs_validate_page_bad_hash = 0;
boolean_t
cs_validate_page(
	void			*_blobs,
	memory_object_offset_t	page_offset,
	const void		*data,
	boolean_t		*tainted)
{
	SHA1_CTX		sha1ctxt;
	unsigned char		actual_hash[SHA1_RESULTLEN];
	unsigned char		expected_hash[SHA1_RESULTLEN];
	boolean_t		found_hash;
	struct cs_blob		*blobs, *blob;
	const CS_CodeDirectory	*cd;
	const CS_SuperBlob	*embedded;
	const unsigned char	*hash;
	boolean_t		validated;
	off_t			offset;	/* page offset in the file */
	size_t			size;
	off_t			codeLimit = 0;
	char			*lower_bound, *upper_bound;
	vm_offset_t		kaddr, blob_addr;
	vm_size_t		ksize;
	kern_return_t		kr;

	offset = page_offset;

	/* retrieve the expected hash */
	found_hash = FALSE;
	blobs = (struct cs_blob *) _blobs;

	for (blob = blobs;
	     blob != NULL;
	     blob = blob->csb_next) {
		offset = page_offset - blob->csb_base_offset;
		if (offset < blob->csb_start_offset ||
		    offset >= blob->csb_end_offset) {
			/* our page is not covered by this blob */
			continue;
		}

		/* map the blob in the kernel address space */
		kaddr = blob->csb_mem_kaddr;
		if (kaddr == 0) {
			ksize = (vm_size_t) (blob->csb_mem_size +
					     blob->csb_mem_offset);
			kr = vm_map(kernel_map,
				    &kaddr,
				    ksize,
				    0,
				    VM_FLAGS_ANYWHERE,
				    blob->csb_mem_handle,
				    0,
				    TRUE,
				    VM_PROT_READ,
				    VM_PROT_READ,
				    VM_INHERIT_NONE);
			if (kr != KERN_SUCCESS) {
				/* XXX FBDP what to do !? */
				printf("cs_validate_page: failed to map blob, "
				       "size=0x%lx kr=0x%x\n",
				       (size_t)blob->csb_mem_size, kr);
				break;
			}
		}
		blob_addr = kaddr + blob->csb_mem_offset;
		
		lower_bound = CAST_DOWN(char *, blob_addr);
		upper_bound = lower_bound + blob->csb_mem_size;

		embedded = (const CS_SuperBlob *) blob_addr;
		cd = findCodeDirectory(embedded, lower_bound, upper_bound);
		if (cd != NULL) {
			if (cd->pageSize != PAGE_SHIFT ||
			    cd->hashType != 0x1 ||
			    cd->hashSize != SHA1_RESULTLEN) {
				/* bogus blob ? */
				continue;
			}

			offset = page_offset - blob->csb_base_offset;
			if (offset < blob->csb_start_offset ||
			    offset >= blob->csb_end_offset) {
				/* our page is not covered by this blob */
				continue;
			}

			codeLimit = ntohl(cd->codeLimit);
			hash = hashes(cd, atop(offset),
				      lower_bound, upper_bound);
			if (hash != NULL) {
				bcopy(hash, expected_hash,
				      sizeof (expected_hash));
				found_hash = TRUE;
			}

			break;
		}
	}

	if (found_hash == FALSE) {
		/*
		 * We can't verify this page because there is no signature
		 * for it (yet).  It's possible that this part of the object
		 * is not signed, or that signatures for that part have not
		 * been loaded yet.
		 * Report that the page has not been validated and let the
		 * caller decide if it wants to accept it or not.
		 */
		cs_validate_page_no_hash++;
		if (cs_debug > 1) {
			printf("CODE SIGNING: cs_validate_page: "
			       "off 0x%llx: no hash to validate !?\n",
			       page_offset);
		}
		validated = FALSE;
		*tainted = FALSE;
	} else {

		size = PAGE_SIZE;
		const uint32_t *asha1, *esha1;
		if ((off_t)(offset + size) > codeLimit) {
			/* partial page at end of segment */
			assert(offset < codeLimit);
			size = (size_t) (codeLimit & PAGE_MASK);
		}
		/* compute the actual page's SHA1 hash */
		SHA1Init(&sha1ctxt);
		SHA1UpdateUsePhysicalAddress(&sha1ctxt, data, size);
		SHA1Final(actual_hash, &sha1ctxt);

		asha1 = (const uint32_t *) actual_hash;
		esha1 = (const uint32_t *) expected_hash;

		if (bcmp(expected_hash, actual_hash, SHA1_RESULTLEN) != 0) {
			if (cs_debug) {
				printf("CODE SIGNING: cs_validate_page: "
				       "off 0x%llx size 0x%lx: "
				       "actual [0x%x 0x%x 0x%x 0x%x 0x%x] != "
				       "expected [0x%x 0x%x 0x%x 0x%x 0x%x]\n",
				       page_offset, size,
				       asha1[0], asha1[1], asha1[2],
				       asha1[3], asha1[4],
				       esha1[0], esha1[1], esha1[2],
				       esha1[3], esha1[4]);
			}
			cs_validate_page_bad_hash++;
			*tainted = TRUE;
		} else {
			if (cs_debug > 1) {
				printf("CODE SIGNING: cs_validate_page: "
				       "off 0x%llx size 0x%lx: SHA1 OK\n",
				       page_offset, size);
			}
			*tainted = FALSE;
		}
		validated = TRUE;
	}
	
	return validated;
}

int
ubc_cs_getcdhash(
	vnode_t		vp,
	off_t		offset,
	unsigned char	*cdhash)
{
	struct cs_blob	*blobs, *blob;
	off_t		rel_offset;
	int		ret;

	vnode_lock(vp);

	blobs = ubc_get_cs_blobs(vp);
	for (blob = blobs;
	     blob != NULL;
	     blob = blob->csb_next) {
		/* compute offset relative to this blob */
		rel_offset = offset - blob->csb_base_offset;
		if (rel_offset >= blob->csb_start_offset &&
		    rel_offset < blob->csb_end_offset) {
			/* this blob does cover our "offset" ! */
			break;
		}
	}

	if (blob == NULL) {
		/* we didn't find a blob covering "offset" */
		ret = EBADEXEC; /* XXX any better error ? */
	} else {
		/* get the SHA1 hash of that blob */
		bcopy(blob->csb_sha1, cdhash, sizeof (blob->csb_sha1));
		ret = 0;
	}

	vnode_unlock(vp);

	return ret;
}
