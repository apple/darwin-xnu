/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 *	Copyright (c) 1990, 1996-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */
/*
 * posix_shm.c : Support for POSIX shared memory APIs
 *
 *	File:	posix_shm.c
 *	Author:	Ananthakrishna Ramesh
 *
 * HISTORY
 * 2-Sep-1999	A.Ramesh
 *	Created for MacOSX
 *
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/proc_info.h>
#include <sys/posix_shm.h>
#include <security/audit/audit.h>
#include <stdbool.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/kern_return.h>
#include <mach/memory_object_control.h>

#include <vm/vm_map.h>
#include <vm/vm_protos.h>

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_ops->fo_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data

/*
 * Used to construct the list of memory objects
 * assigned to a populated shared memory segment.
 */
typedef struct pshm_mobj {
	void                  *pshmo_memobject;
	memory_object_size_t  pshmo_size;
	SLIST_ENTRY(pshm_mobj) pshmo_next;
} pshm_mobj_t;

/*
 * This represents an existing Posix shared memory object.
 *
 * It comes into existence with a shm_open(...O_CREAT...)
 * call and goes away only after it has been shm_unlink()ed
 * and the last remaining shm_open() file reference is closed.
 *
 * To keep track of that lifetime, pshm_usecount is used as a reference
 * counter. It's incremented for every successful shm_open() and
 * one extra time for the shm_unlink() to release. Internally
 * you can temporarily use an additional reference whenever the
 * subsystem lock has to be dropped for other reasons.
 */
typedef struct internal_pshminfo {
	struct pshminfo pshm_hdr;
	SLIST_HEAD(pshm_mobjhead, pshm_mobj) pshm_mobjs;
	RB_ENTRY(internal_pshminfo) pshm_links;        /* links for red/black tree */
} pshm_info_t;
#define pshm_flags    pshm_hdr.pshm_flags
#define pshm_usecount pshm_hdr.pshm_usecount
#define pshm_length   pshm_hdr.pshm_length
#define pshm_mode     pshm_hdr.pshm_mode
#define pshm_uid      pshm_hdr.pshm_uid
#define pshm_gid      pshm_hdr.pshm_gid
#define pshm_label    pshm_hdr.pshm_label

/* Values for pshm_flags that are still used */
#define PSHM_ALLOCATED  0x004   /* backing storage is allocated */
#define PSHM_MAPPED     0x008   /* mapped at least once */
#define PSHM_INUSE      0x010   /* mapped at least once */
#define PSHM_REMOVED    0x020   /* no longer in the name cache due to shm_unlink() */
#define PSHM_ALLOCATING 0x100   /* storage is being allocated */

/*
 * These handle reference counting pshm_info_t structs using pshm_usecount.
 */
static int pshm_ref(pshm_info_t *pinfo);
static void pshm_deref(pshm_info_t *pinfo);
#define PSHM_MAXCOUNT UINT_MAX

/*
 * For every shm_open, we get a new one of these.
 * The only reason we don't just use pshm_info directly is that
 * you can query the mapped memory objects via proc_pidinfo to
 * query the mapped address. Note that even this is a hack. If
 * you mmap() the same fd multiple times, we only save/report
 * one address.
 */
typedef struct pshmnode {
	off_t       mapp_addr;
	pshm_info_t *pinfo;
} pshmnode_t;


/* compare function for the red black tree */
static int
pshm_compare(pshm_info_t *a, pshm_info_t *b)
{
	int cmp = strncmp(a->pshm_hdr.pshm_name, b->pshm_hdr.pshm_name, PSHMNAMLEN + 1);

	if (cmp < 0) {
		return -1;
	}
	if (cmp > 0) {
		return 1;
	}
	return 0;
}


/*
 * shared memory "paths" are stored in a red black tree for lookup
 */
u_long pshmnument;    /* count of entries allocated in the red black tree */
RB_HEAD(pshmhead, internal_pshminfo) pshm_head;
RB_PROTOTYPE(pshmhead, internal_pshminfo, pshm_links, pshm_compare)
RB_GENERATE(pshmhead, internal_pshminfo, pshm_links, pshm_compare)

/* lookup, add, remove functions */
static pshm_info_t *pshm_cache_search(pshm_info_t * look);
static void pshm_cache_add(pshm_info_t *entry);
static void pshm_cache_delete(pshm_info_t *entry);

static int pshm_closefile(struct fileglob *fg, vfs_context_t ctx);

static int pshm_access(pshm_info_t *pinfo, int mode, kauth_cred_t cred, proc_t p);
int pshm_cache_purge_all(proc_t p);

static int pshm_unlink_internal(pshm_info_t *pinfo);

static const struct fileops pshmops = {
	.fo_type     = DTYPE_PSXSHM,
	.fo_read     = fo_no_read,
	.fo_write    = fo_no_write,
	.fo_ioctl    = fo_no_ioctl,
	.fo_select   = fo_no_select,
	.fo_close    = pshm_closefile,
	.fo_drain    = fo_no_drain,
	.fo_kqfilter = fo_no_kqfilter,
};

/*
 * Everything here is protected by a single mutex.
 */
static lck_grp_t       *psx_shm_subsys_lck_grp;
static lck_grp_attr_t  *psx_shm_subsys_lck_grp_attr;
static lck_attr_t      *psx_shm_subsys_lck_attr;
static lck_mtx_t        psx_shm_subsys_mutex;

#define PSHM_SUBSYS_LOCK() lck_mtx_lock(& psx_shm_subsys_mutex)
#define PSHM_SUBSYS_UNLOCK() lck_mtx_unlock(& psx_shm_subsys_mutex)
#define PSHM_SUBSYS_ASSERT_HELD()  LCK_MTX_ASSERT(&psx_shm_subsys_mutex, LCK_MTX_ASSERT_OWNED)


__private_extern__ void
pshm_lock_init( void )
{
	psx_shm_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

	psx_shm_subsys_lck_grp =
	    lck_grp_alloc_init("posix shared memory", psx_shm_subsys_lck_grp_attr);

	psx_shm_subsys_lck_attr = lck_attr_alloc_init();
	lck_mtx_init(&psx_shm_subsys_mutex, psx_shm_subsys_lck_grp, psx_shm_subsys_lck_attr);
}

/*
 * Lookup an entry in the cache. Only the name is used from "look".
 */
static pshm_info_t *
pshm_cache_search(pshm_info_t *look)
{
	PSHM_SUBSYS_ASSERT_HELD();
	return RB_FIND(pshmhead, &pshm_head, look);
}

/*
 * Add a new entry to the cache.
 */
static void
pshm_cache_add(pshm_info_t *entry)
{
	pshm_info_t *conflict;

	PSHM_SUBSYS_ASSERT_HELD();
	conflict = RB_INSERT(pshmhead, &pshm_head, entry);
	if (conflict != NULL) {
		panic("pshm_cache_add() found %p", conflict);
	}
	pshmnument++;
}

/*
 * Remove the given entry from the red black tree.
 */
static void
pshm_cache_delete(pshm_info_t *entry)
{
	PSHM_SUBSYS_ASSERT_HELD();
	assert(!(entry->pshm_flags & PSHM_REMOVED));
	RB_REMOVE(pshmhead, &pshm_head, entry);
	pshmnument--;
}

/*
 * Initialize the red black tree.
 */
void
pshm_cache_init(void)
{
	RB_INIT(&pshm_head);
}

/*
 * Invalidate all entries and delete all objects associated with them
 * XXX - due to the reference counting, this only works if all userland
 * references to it via file descriptors are also closed already. Is this
 * known to be called after all user processes are killed?
 */
int
pshm_cache_purge_all(__unused proc_t proc)
{
	pshm_info_t *p;
	pshm_info_t *tmp;
	int error = 0;

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		return EPERM;
	}

	PSHM_SUBSYS_LOCK();
	RB_FOREACH_SAFE(p, pshmhead, &pshm_head, tmp) {
		error = pshm_unlink_internal(p);
		if (error) {  /* XXX: why give up on failure, should keep going */
			goto out;
		}
	}
	assert(pshmnument == 0);

out:
	PSHM_SUBSYS_UNLOCK();

	if (error) {
		printf("%s: Error %d removing posix shm cache: %ld remain!\n",
		    __func__, error, pshmnument);
	}
	return error;
}

/*
 * Utility to get the shared memory name from userspace and
 * populate a pshm_info_t with it. If there's a problem
 * reading the name or it's malformed, will return an error code.
 */
static int
pshm_get_name(pshm_info_t *pinfo, const user_addr_t user_addr)
{
	size_t bytes_copied = 0;
	int error;


	error = copyinstr(user_addr, &pinfo->pshm_hdr.pshm_name[0], PSHMNAMLEN + 1, &bytes_copied);
	if (error != 0) {
		return error;
	}
	assert(bytes_copied <= PSHMNAMLEN + 1);
	assert(pinfo->pshm_hdr.pshm_name[bytes_copied - 1] == 0);
	if (bytes_copied < 2) { /* 2: expect at least one character and terminating zero */
		return EINVAL;
	}
	AUDIT_ARG(text, &pinfo->pshm_hdr.pshm_name[0]);
	return 0;
}

/*
 * Process a shm_open() system call.
 */
int
shm_open(proc_t p, struct shm_open_args *uap, int32_t *retval)
{
	int             indx;
	int             error = 0;
	pshm_info_t     *pinfo = NULL;
	pshm_info_t     *new_pinfo = NULL;
	pshmnode_t      *new_pnode = NULL;
	struct fileproc *fp = NULL;
	int             fmode;
	int             cmode = uap->mode;
	bool            incache = false;
	bool            have_label = false;

	AUDIT_ARG(fflags, uap->oflag);
	AUDIT_ARG(mode, uap->mode);

	/*
	 * Allocate data structures we need. We parse the userspace name into
	 * a pshm_info_t, even when we don't need to O_CREAT.
	 */
	MALLOC(new_pinfo, pshm_info_t *, sizeof(pshm_info_t), M_SHM, M_WAITOK | M_ZERO);
	if (new_pinfo == NULL) {
		error = ENOSPC;
		goto bad;
	}

	/*
	 * Get and check the name.
	 */
	error = pshm_get_name(new_pinfo, uap->name);
	if (error != 0) {
		goto bad;
	}

	/*
	 * Attempt to allocate a new fp. If unsuccessful, the fp will be
	 * left unmodified (NULL).
	 */
	error = falloc(p, &fp, &indx, vfs_context_current());
	if (error) {
		goto bad;
	}

	cmode &= ALLPERMS;

	fmode = FFLAGS(uap->oflag);
	if ((fmode & (FREAD | FWRITE)) == 0) {
		error = EINVAL;
		goto bad;
	}

	/*
	 * Will need a new pnode for the file pointer
	 */
	MALLOC(new_pnode, pshmnode_t *, sizeof(pshmnode_t), M_SHM, M_WAITOK | M_ZERO);
	if (new_pnode == NULL) {
		error = ENOSPC;
		goto bad;
	}

	/*
	 * If creating a new segment, fill in its information.
	 * If we find a pre-exisitng one in cache lookup we'll just toss this one later.
	 */
	if (fmode & O_CREAT) {
		new_pinfo->pshm_usecount = 2; /* one each for: file pointer, shm_unlink */
		new_pinfo->pshm_length = 0;
		new_pinfo->pshm_mode = cmode;
		new_pinfo->pshm_uid = kauth_getuid();
		new_pinfo->pshm_gid = kauth_getgid();
		SLIST_INIT(&new_pinfo->pshm_mobjs);
#if CONFIG_MACF
		mac_posixshm_label_init(&new_pinfo->pshm_hdr);
		have_label = true;
		error = mac_posixshm_check_create(kauth_cred_get(), new_pinfo->pshm_hdr.pshm_name);
		if (error) {
			goto bad;
		}
#endif
	}

	/*
	 * Look up the named shared memory segment in the cache, possibly adding
	 * it for O_CREAT.
	 */
	PSHM_SUBSYS_LOCK();

	pinfo = pshm_cache_search(new_pinfo);
	if (pinfo != NULL) {
		incache = true;

		/* Get a new reference to go with the file pointer.*/
		error = pshm_ref(pinfo);
		if (error) {
			pinfo = NULL;      /* so cleanup code doesn't deref */
			goto bad_locked;
		}

		/* can't have pre-existing if O_EXCL */
		if ((fmode & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL)) {
			error = EEXIST;
			goto bad_locked;
		}

		/* O_TRUNC is only valid while length is not yet set */
		if ((fmode & O_TRUNC) &&
		    (pinfo->pshm_flags & (PSHM_ALLOCATING | PSHM_ALLOCATED))) {
			error = EINVAL;
			goto bad_locked;
		}
	} else {
		incache = false;

		/* if it wasn't found, must have O_CREAT */
		if (!(fmode & O_CREAT)) {
			error = ENOENT;
			goto bad_locked;
		}

		/* Add the new region to the cache. */
		pinfo = new_pinfo;
		pshm_cache_add(pinfo);
		new_pinfo = NULL;       /* so that it doesn't get free'd */
	}

	PSHM_SUBSYS_UNLOCK();

	/*
	 * Check we have permission to access any pre-existing segment
	 */
	if (incache) {
		if (fmode & O_CREAT) {
			AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid,
			    pinfo->pshm_gid, pinfo->pshm_mode);
		}
#if CONFIG_MACF
		if ((error = mac_posixshm_check_open(kauth_cred_get(), &pinfo->pshm_hdr, fmode))) {
			goto bad;
		}
#endif
		if ((error = pshm_access(pinfo, fmode, kauth_cred_get(), p))) {
			goto bad;
		}
	} else {
#if CONFIG_MACF
		mac_posixshm_label_associate(kauth_cred_get(), &pinfo->pshm_hdr, pinfo->pshm_hdr.pshm_name);
#endif
	}

	proc_fdlock(p);
	fp->f_flag = fmode & FMASK;
	fp->f_ops = &pshmops;
	new_pnode->pinfo = pinfo;
	fp->f_data = (caddr_t)new_pnode;
	*fdflags(p, indx) |= UF_EXCLOSE;
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = indx;
	error = 0;
	goto done;

bad_locked:
	PSHM_SUBSYS_UNLOCK();
bad:
	/*
	 * Drop any new reference to a pre-existing shared memory region.
	 */
	if (incache && pinfo != NULL) {
		PSHM_SUBSYS_LOCK();
		pshm_deref(pinfo);
		PSHM_SUBSYS_UNLOCK();
	}

	/*
	 * Delete any allocated unused data structures.
	 */
	if (new_pnode != NULL) {
		FREE(new_pnode, M_SHM);
	}

	if (fp != NULL) {
		fp_free(p, indx, fp);
	}

done:
	if (new_pinfo != NULL) {
#if CONFIG_MACF
		if (have_label) {
			mac_posixshm_label_destroy(&new_pinfo->pshm_hdr);
		}
#endif
		FREE(new_pinfo, M_SHM);
	}
	return error;
}


/*
 * The truncate call associates memory with shared memory region. It can
 * only be succesfully done with a non-zero length once per shared memory region.
 */
int
pshm_truncate(
	__unused proc_t       p,
	struct fileproc       *fp,
	__unused int          fd,
	off_t                 length,
	__unused int32_t      *retval)
{
	pshm_info_t           *pinfo;
	pshmnode_t            *pnode;
	kern_return_t         kret;
	mem_entry_name_port_t mem_object;
	mach_vm_size_t        total_size, alloc_size;
	memory_object_size_t  mosize;
	pshm_mobj_t           *pshmobj, *pshmobj_last;
	vm_map_t              user_map;
	int                   error;

	user_map = current_map();

	if (fp->f_type != DTYPE_PSXSHM) {
		return EINVAL;
	}

#if 0
	/*
	 * Can't enforce this yet, some third party tools don't
	 * specify O_RDWR like they ought to. See radar 48692182
	 */
	/* ftruncate() requires write permission */
	if (!(fp->f_flag & FWRITE)) {
		return EINVAL;
	}
#endif

	PSHM_SUBSYS_LOCK();
	if (((pnode = (pshmnode_t *)fp->f_data)) == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	if ((pinfo = pnode->pinfo) == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	/* We only allow one ftruncate() per lifetime of the shm object. */
	if (pinfo->pshm_flags & (PSHM_ALLOCATING | PSHM_ALLOCATED)) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

#if CONFIG_MACF
	error = mac_posixshm_check_truncate(kauth_cred_get(), &pinfo->pshm_hdr, length);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return error;
	}
#endif
	/*
	 * Grab an extra reference, so we can drop the lock while allocating and
	 * ensure the objects don't disappear.
	 */
	error = pshm_ref(pinfo);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return error;
	}

	/* set ALLOCATING, so another truncate can't start */
	pinfo->pshm_flags |= PSHM_ALLOCATING;
	total_size = vm_map_round_page(length, vm_map_page_mask(user_map));

	pshmobj_last = NULL;
	for (alloc_size = 0; alloc_size < total_size; alloc_size += mosize) {
		PSHM_SUBSYS_UNLOCK();

		/* get a memory object back some of the shared memory */
		mosize = MIN(total_size - alloc_size, ANON_MAX_SIZE);
		kret = mach_make_memory_entry_64(VM_MAP_NULL, &mosize, 0,
		    MAP_MEM_NAMED_CREATE | VM_PROT_DEFAULT, &mem_object, 0);

		if (kret != KERN_SUCCESS) {
			goto out;
		}

		/* get a list entry to track the memory object */
		MALLOC(pshmobj, pshm_mobj_t *, sizeof(pshm_mobj_t), M_SHM, M_WAITOK);
		if (pshmobj == NULL) {
			kret = KERN_NO_SPACE;
			mach_memory_entry_port_release(mem_object);
			mem_object = NULL;
			goto out;
		}

		PSHM_SUBSYS_LOCK();

		/* link in the new entry */
		pshmobj->pshmo_memobject = (void *)mem_object;
		pshmobj->pshmo_size = mosize;
		SLIST_NEXT(pshmobj, pshmo_next) = NULL;

		if (pshmobj_last == NULL) {
			SLIST_FIRST(&pinfo->pshm_mobjs) = pshmobj;
		} else {
			SLIST_INSERT_AFTER(pshmobj_last, pshmobj, pshmo_next);
		}
		pshmobj_last = pshmobj;
	}

	/* all done, change flags to ALLOCATED and return success */
	pinfo->pshm_flags |= PSHM_ALLOCATED;
	pinfo->pshm_flags &= ~(PSHM_ALLOCATING);
	pinfo->pshm_length = total_size;
	pshm_deref(pinfo);              /* drop the "allocating" reference */
	PSHM_SUBSYS_UNLOCK();
	return 0;

out:
	/* clean up any partially allocated objects */
	PSHM_SUBSYS_LOCK();
	while ((pshmobj = SLIST_FIRST(&pinfo->pshm_mobjs)) != NULL) {
		SLIST_REMOVE_HEAD(&pinfo->pshm_mobjs, pshmo_next);
		PSHM_SUBSYS_UNLOCK();
		mach_memory_entry_port_release(pshmobj->pshmo_memobject);
		FREE(pshmobj, M_SHM);
		PSHM_SUBSYS_LOCK();
	}
	pinfo->pshm_flags &= ~PSHM_ALLOCATING;
	pshm_deref(pinfo);              /* drop the "allocating" reference */
	PSHM_SUBSYS_UNLOCK();

	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return ENOMEM;
	case KERN_PROTECTION_FAILURE:
		return EACCES;
	default:
		return EINVAL;
	}
}

int
pshm_stat(pshmnode_t *pnode, void *ub, int isstat64)
{
	struct stat *sb = (struct stat *)0;     /* warning avoidance ; protected by isstat64 */
	struct stat64 * sb64 = (struct stat64 *)0;  /* warning avoidance ; protected by isstat64 */
	pshm_info_t *pinfo;
#if CONFIG_MACF
	int error;
#endif

	PSHM_SUBSYS_LOCK();
	if ((pinfo = pnode->pinfo) == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

#if CONFIG_MACF
	error = mac_posixshm_check_stat(kauth_cred_get(), &pinfo->pshm_hdr);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return error;
	}
#endif

	if (isstat64 != 0) {
		sb64 = (struct stat64 *)ub;
		bzero(sb64, sizeof(struct stat64));
		sb64->st_mode = pinfo->pshm_mode;
		sb64->st_uid = pinfo->pshm_uid;
		sb64->st_gid = pinfo->pshm_gid;
		sb64->st_size = pinfo->pshm_length;
	} else {
		sb = (struct stat *)ub;
		bzero(sb, sizeof(struct stat));
		sb->st_mode = pinfo->pshm_mode;
		sb->st_uid = pinfo->pshm_uid;
		sb->st_gid = pinfo->pshm_gid;
		sb->st_size = pinfo->pshm_length;
	}
	PSHM_SUBSYS_UNLOCK();

	return 0;
}

/*
 * Verify access to a shared memory region.
 */
static int
pshm_access(pshm_info_t *pinfo, int mode, kauth_cred_t cred, __unused proc_t p)
{
	int mode_req = ((mode & FREAD) ? S_IRUSR : 0) |
	    ((mode & FWRITE) ? S_IWUSR : 0);

	/* Otherwise, user id 0 always gets access. */
	if (!suser(cred, NULL)) {
		return 0;
	}

	return posix_cred_access(cred, pinfo->pshm_uid, pinfo->pshm_gid, pinfo->pshm_mode, mode_req);
}

int
pshm_mmap(
	__unused proc_t    p,
	struct mmap_args   *uap,
	user_addr_t        *retval,
	struct fileproc    *fp,
	off_t              pageoff)
{
	vm_map_offset_t    user_addr = (vm_map_offset_t)uap->addr;
	vm_map_size_t      user_size = (vm_map_size_t)uap->len;
	vm_map_offset_t    user_start_addr;
	vm_map_size_t      map_size, mapped_size;
	int                prot = uap->prot;
	int                max_prot = VM_PROT_DEFAULT;
	int                flags = uap->flags;
	vm_object_offset_t file_pos = (vm_object_offset_t)uap->pos;
	vm_object_offset_t map_pos;
	vm_map_t           user_map;
	int                alloc_flags;
	vm_map_kernel_flags_t vmk_flags;
	bool               docow;
	kern_return_t      kret = KERN_SUCCESS;
	pshm_info_t        *pinfo;
	pshmnode_t         *pnode;
	pshm_mobj_t        *pshmobj;
	int                error;

	if (user_size == 0) {
		return 0;
	}

	if (!(flags & MAP_SHARED)) {
		return EINVAL;
	}

	/* Can't allow write permission if the shm_open() didn't allow them. */
	if (!(fp->f_flag & FWRITE)) {
		if (prot & VM_PROT_WRITE) {
			return EPERM;
		}
		max_prot &= ~VM_PROT_WRITE;
	}

	PSHM_SUBSYS_LOCK();
	pnode = (pshmnode_t *)fp->f_data;
	if (pnode == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	pinfo = pnode->pinfo;
	if (pinfo == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	if (!(pinfo->pshm_flags & PSHM_ALLOCATED)) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	if (user_size > (vm_map_size_t)pinfo->pshm_length) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	vm_map_size_t end_pos = 0;
	if (os_add_overflow(user_size, file_pos, &end_pos)) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}
	if (end_pos > (vm_map_size_t)pinfo->pshm_length) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	pshmobj = SLIST_FIRST(&pinfo->pshm_mobjs);
	if (pshmobj == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

#if CONFIG_MACF
	error = mac_posixshm_check_mmap(kauth_cred_get(), &pinfo->pshm_hdr, prot, flags);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return error;
	}
#endif
	/* Grab an extra reference, so we can drop the lock while mapping. */
	error = pshm_ref(pinfo);
	if (error) {
		PSHM_SUBSYS_UNLOCK();
		return error;
	}

	PSHM_SUBSYS_UNLOCK();
	user_map = current_map();

	if (!(flags & MAP_FIXED)) {
		alloc_flags = VM_FLAGS_ANYWHERE;
		user_addr = vm_map_round_page(user_addr,
		    vm_map_page_mask(user_map));
	} else {
		if (user_addr != vm_map_round_page(user_addr,
		    vm_map_page_mask(user_map))) {
			error = EINVAL;
			goto out_deref;
		}

		/*
		 * We do not get rid of the existing mappings here because
		 * it wouldn't be atomic (see comment in mmap()).  We let
		 * Mach VM know that we want it to replace any existing
		 * mapping with the new one.
		 */
		alloc_flags = VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE;
	}
	docow = false;

	mapped_size = 0;
	vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
	/* reserve the entire space first... */
	kret = vm_map_enter_mem_object(user_map,
	    &user_addr,
	    user_size,
	    0,
	    alloc_flags,
	    vmk_flags,
	    VM_KERN_MEMORY_NONE,
	    IPC_PORT_NULL,
	    0,
	    false,
	    VM_PROT_NONE,
	    VM_PROT_NONE,
	    VM_INHERIT_NONE);
	user_start_addr = user_addr;
	if (kret != KERN_SUCCESS) {
		goto out_deref;
	}

	/* Now overwrite with the real mappings. */
	for (map_pos = 0, pshmobj = SLIST_FIRST(&pinfo->pshm_mobjs);
	    user_size != 0;
	    map_pos += pshmobj->pshmo_size, pshmobj = SLIST_NEXT(pshmobj, pshmo_next)) {
		if (pshmobj == NULL) {
			/* nothing there to map !? */
			goto out_deref;
		}
		if (file_pos >= map_pos + pshmobj->pshmo_size) {
			continue;
		}
		map_size = pshmobj->pshmo_size - (file_pos - map_pos);
		if (map_size > user_size) {
			map_size = user_size;
		}
		vmk_flags = VM_MAP_KERNEL_FLAGS_NONE;
		kret = vm_map_enter_mem_object(
			user_map,
			&user_addr,
			map_size,
			0,
			VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
			vmk_flags,
			VM_KERN_MEMORY_NONE,
			pshmobj->pshmo_memobject,
			file_pos - map_pos,
			docow,
			prot,
			max_prot,
			VM_INHERIT_SHARE);
		if (kret != KERN_SUCCESS) {
			goto out_deref;
		}

		user_addr += map_size;
		user_size -= map_size;
		mapped_size += map_size;
		file_pos += map_size;
	}

	PSHM_SUBSYS_LOCK();
	pnode->mapp_addr = user_start_addr;
	pinfo->pshm_flags |= (PSHM_MAPPED | PSHM_INUSE);
	PSHM_SUBSYS_UNLOCK();
out_deref:
	PSHM_SUBSYS_LOCK();
	pshm_deref(pinfo);      /* drop the extra reference we had while mapping. */
	PSHM_SUBSYS_UNLOCK();
	if (kret != KERN_SUCCESS) {
		if (mapped_size != 0) {
			(void) mach_vm_deallocate(current_map(),
			    user_start_addr,
			    mapped_size);
		}
	}

	switch (kret) {
	case KERN_SUCCESS:
		*retval = (user_start_addr + pageoff);
		return 0;
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return ENOMEM;
	case KERN_PROTECTION_FAILURE:
		return EACCES;
	default:
		return EINVAL;
	}
}

/*
 * Remove a shared memory region name from the name lookup cache.
 */
static int
pshm_unlink_internal(pshm_info_t *pinfo)
{
	PSHM_SUBSYS_ASSERT_HELD();

	if (pinfo == NULL) {
		return EINVAL;
	}

	pshm_cache_delete(pinfo);
	pinfo->pshm_flags |= PSHM_REMOVED;

	/* release the "unlink" reference */
	pshm_deref(pinfo);

	return 0;
}

int
shm_unlink(proc_t p, struct shm_unlink_args *uap, __unused int32_t *retval)
{
	int         error = 0;
	pshm_info_t *pinfo = NULL;
	pshm_info_t *name_pinfo = NULL;

	/*
	 * Get the name from user args.
	 */
	MALLOC(name_pinfo, pshm_info_t *, sizeof(pshm_info_t), M_SHM, M_WAITOK | M_ZERO);
	if (name_pinfo == NULL) {
		error = ENOSPC;
		goto bad;
	}
	error = pshm_get_name(name_pinfo, uap->name);
	if (error != 0) {
		error = EINVAL;
		goto bad;
	}

	PSHM_SUBSYS_LOCK();
	pinfo = pshm_cache_search(name_pinfo);

	if (pinfo == NULL) {
		error = ENOENT;
		goto bad_unlock;
	}

#if CONFIG_MACF
	error = mac_posixshm_check_unlink(kauth_cred_get(), &pinfo->pshm_hdr, name_pinfo->pshm_hdr.pshm_name);
	if (error) {
		goto bad_unlock;
	}
#endif

	AUDIT_ARG(posix_ipc_perm, pinfo->pshm_uid, pinfo->pshm_gid, pinfo->pshm_mode);

	/*
	 * Following file semantics, unlink should normally be allowed
	 * for users with write permission only. We also allow the creator
	 * of a segment to be able to delete, even w/o write permission.
	 * That's because there's no equivalent of write permission for the
	 * directory containing a file.
	 */
	error = pshm_access(pinfo, FWRITE, kauth_cred_get(), p);
	if (error != 0 && pinfo->pshm_uid != kauth_getuid()) {
		goto bad_unlock;
	}

	error = pshm_unlink_internal(pinfo);
bad_unlock:
	PSHM_SUBSYS_UNLOCK();
bad:
	if (name_pinfo != NULL) {
		FREE(name_pinfo, M_SHM);
	}
	return error;
}

/*
 * Add a new reference to a shared memory region.
 * Fails if we will overflow the reference counter.
 */
static int
pshm_ref(pshm_info_t *pinfo)
{
	PSHM_SUBSYS_ASSERT_HELD();

	if (pinfo->pshm_usecount == PSHM_MAXCOUNT) {
		return EMFILE;
	}
	pinfo->pshm_usecount++;
	return 0;
}

/*
 * Dereference a pshm_info_t. Delete the region if
 * this was the final reference count.
 */
static void
pshm_deref(pshm_info_t *pinfo)
{
	pshm_mobj_t *pshmobj;

	PSHM_SUBSYS_ASSERT_HELD();
	if (pinfo->pshm_usecount == 0) {
		panic("negative usecount in pshm_close\n");
	}
	pinfo->pshm_usecount--; /* release this fd's reference */

	if (pinfo->pshm_usecount == 0) {
#if CONFIG_MACF
		mac_posixshm_label_destroy(&pinfo->pshm_hdr);
#endif
		PSHM_SUBSYS_UNLOCK();

		/*
		 * Release references to any backing objects.
		 */
		while ((pshmobj = SLIST_FIRST(&pinfo->pshm_mobjs)) != NULL) {
			SLIST_REMOVE_HEAD(&pinfo->pshm_mobjs, pshmo_next);
			mach_memory_entry_port_release(pshmobj->pshmo_memobject);
			FREE(pshmobj, M_SHM);
		}

		/* free the pinfo itself */
		FREE(pinfo, M_SHM);

		PSHM_SUBSYS_LOCK();
	}
}

/* vfs_context_t passed to match prototype for struct fileops */
static int
pshm_closefile(struct fileglob *fg, __unused vfs_context_t ctx)
{
	int        error = EINVAL;
	pshmnode_t *pnode;

	PSHM_SUBSYS_LOCK();

	pnode = (pshmnode_t *)fg->fg_data;
	if (pnode != NULL) {
		error = 0;
		fg->fg_data = NULL; /* set fg_data to NULL to avoid racing close()es */
		if (pnode->pinfo != NULL) {
			pshm_deref(pnode->pinfo);
			pnode->pinfo = NULL;
		}
	}

	PSHM_SUBSYS_UNLOCK();
	if (pnode != NULL) {
		FREE(pnode, M_SHM);
	}

	return error;
}

int
fill_pshminfo(pshmnode_t * pshm, struct pshm_info * info)
{
	pshm_info_t *pinfo;
	struct vinfo_stat *sb;

	PSHM_SUBSYS_LOCK();
	if ((pinfo = pshm->pinfo) == NULL) {
		PSHM_SUBSYS_UNLOCK();
		return EINVAL;
	}

	sb = &info->pshm_stat;

	bzero(sb, sizeof(struct vinfo_stat));
	sb->vst_mode = pinfo->pshm_mode;
	sb->vst_uid = pinfo->pshm_uid;
	sb->vst_gid = pinfo->pshm_gid;
	sb->vst_size = pinfo->pshm_length;

	info->pshm_mappaddr = pshm->mapp_addr;
	bcopy(&pinfo->pshm_hdr.pshm_name[0], &info->pshm_name[0], PSHMNAMLEN + 1);

	PSHM_SUBSYS_UNLOCK();
	return 0;
}

#if CONFIG_MACF
void
pshm_label_associate(struct fileproc *fp, struct vnode *vp, vfs_context_t ctx)
{
	pshmnode_t *pnode;
	pshm_info_t *pshm;

	PSHM_SUBSYS_LOCK();
	pnode = (pshmnode_t *)fp->f_data;
	if (pnode != NULL) {
		pshm = pnode->pinfo;
		if (pshm != NULL) {
			mac_posixshm_vnode_label_associate(
				vfs_context_ucred(ctx), &pshm->pshm_hdr, pshm->pshm_label,
				vp, vp->v_label);
		}
	}
	PSHM_SUBSYS_UNLOCK();
}
#endif
