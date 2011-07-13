/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
#include <sys/cprotect.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/xattr.h>
#include <sys/uio_internal.h>
#include <sys/ubc_internal.h>
#include <sys/vnode_if.h>
#include <sys/vnode_internal.h>
#include <libkern/OSByteOrder.h>

#include "hfs.h"
#include "hfs_cnode.h"

#ifdef CONFIG_PROTECT
static struct cp_wrap_func		g_cp_wrap_func = {NULL, NULL};
static struct cp_global_state	g_cp_state = {0, 0};

extern int (**hfs_vnodeop_p) (void *);

/*
 * CP private functions
 */
static int cp_is_valid_class(int);
static int cp_getxattr(cnode_t *, struct cp_xattr *);
static int cp_setxattr(cnode_t *, struct cp_xattr *, int);
static struct cprotect *cp_entry_alloc(void);
static int cp_make_keys (struct cprotect *);
static int cp_restore_keys(struct cprotect *);
static int cp_lock_vfs_callback(mount_t, void *);
static int cp_lock_vnode_callback(vnode_t, void *);
static int cp_vnode_is_eligible (vnode_t);
static int cp_check_access (cnode_t *, int);
static int cp_wrap(int, void *, void *);
static int cp_unwrap(int, void *, void *);



#if DEVELOPMENT || DEBUG
#define CP_ASSERT(x)		\
	if ((x) == 0) {			\
		panic("CP: failed assertion in %s", __FUNCTION__); 	\
	}
#else
#define CP_ASSERT(x)
#endif

int 
cp_key_store_action(int action)
{
	g_cp_state.lock_state = action;
	if (action == CP_LOCKED_STATE)
		return vfs_iterate(0, cp_lock_vfs_callback, (void *)action);
	else
		return 0;
}


int 
cp_register_wraps(cp_wrap_func_t key_store_func)
{
	g_cp_wrap_func.wrapper = key_store_func->wrapper;
	g_cp_wrap_func.unwrapper = key_store_func->unwrapper;
	
	g_cp_state.wrap_functions_set = 1;
	
	return 0;
}

/*
 * Allocate and initialize a cprotect blob for a new cnode.
 * Called from hfs_getnewcnode: cnode is locked exclusive.
 * Read xattr data off the cnode. Then, if conditions permit,
 * unwrap the file key and cache it in the cprotect blob.
 */
int 
cp_entry_init(cnode_t *cnode, struct mount *mp)
{
	struct cprotect *entry;
	struct cp_xattr xattr;
	int error = 0;
	
	if (!cp_fs_protected (mp)) {
		cnode->c_cpentry = NULL;
		return 0;
	}
	
	if (!S_ISREG(cnode->c_mode)) {
		cnode->c_cpentry = NULL;
		return 0;
	}

	if (!g_cp_state.wrap_functions_set) {
		printf("hfs: cp_update_entry: wrap functions not yet set\n");
		return ENXIO;
	}
	
	CP_ASSERT (cnode->c_cpentry == NULL);
	
	entry = cp_entry_alloc();
	if (!entry)
		return ENOMEM;
	
	entry->cp_flags |= CP_KEY_FLUSHED;
	cnode->c_cpentry = entry;
	
	error = cp_getxattr(cnode, &xattr);
	if (error == ENOATTR) {
		/* 
		 * Can't tell if the file is new, or was previously created but never
		 * written to or set-classed. In either case, it'll need a fresh 
		 * per-file key.
		 */
		entry->cp_flags |= CP_NEEDS_KEYS;
		error = 0;
	} else {
		if (xattr.xattr_major_version != CP_CURRENT_MAJOR_VERS) {
			printf("hfs: cp_entry_init: bad xattr version\n");
			error = EINVAL;
			goto out;
		}

		/* set up entry with information from xattr */
		entry->cp_pclass = xattr.persistent_class;
		bcopy(&xattr.persistent_key, &entry->cp_persistent_key, CP_WRAPPEDKEYSIZE);
	}

out:
	if (error) {
		cp_entry_destroy (cnode);
	}
	return error;
}

/*
 * Set up initial key/class pair on cnode. The cnode is locked exclusive.
 */
int 
cp_entry_create_keys(cnode_t *cnode)
{
	struct cprotect *entry = cnode->c_cpentry;

	if (!entry) {
		//unprotected file: continue
		return 0;
	}

	CP_ASSERT((entry->cp_flags & CP_NEEDS_KEYS));

	return cp_make_keys(entry);
}

/*
 * Tear down and clear a cprotect blob for a closing file.
 * Called at hfs_reclaim_cnode: cnode is locked exclusive. 
 */
void
cp_entry_destroy(cnode_t *cnode)
{
	struct cprotect *entry = cnode->c_cpentry;
	if (!entry) {
		/* nothing to clean up */
		return;
	}
	cnode->c_cpentry = NULL;
	bzero(entry, sizeof(*entry));
	FREE(entry, M_TEMP);
}

int 
cp_fs_protected (mount_t mnt) {
	return (vfs_flags(mnt) & MNT_CPROTECT);
}


/*
 * Return a pointer to underlying cnode if there is one for this vnode.
 * Done without taking cnode lock, inspecting only vnode state.
 */
cnode_t *
cp_get_protected_cnode(vnode_t vp)
{
	if (!cp_vnode_is_eligible(vp)) {
		return NULL;
	}
	
	if (!cp_fs_protected(VTOVFS(vp))) {
		/* mount point doesn't support it */
		return NULL;
	}
	
	return (cnode_t *) vp->v_data;
}


/*
 * Sets *class to persistent class associated with vnode,
 * or returns error.
 */
int 
cp_vnode_getclass(vnode_t vp, int *class)
{
	struct cp_xattr xattr;
	int error = 0;
	struct cnode *cnode;
	
	if (!cp_vnode_is_eligible (vp)) {
		return EBADF;
	}
	
	cnode = VTOC(vp);

	hfs_lock(cnode, HFS_SHARED_LOCK);

	if (cp_fs_protected(VTOVFS(vp))) {
		/* pull the class from the live entry */
		struct cprotect *entry = cnode->c_cpentry;
		if (!entry) {
			panic("Content Protection: uninitialized cnode %p", cnode);
		}

		if ((entry->cp_flags & CP_NEEDS_KEYS)) {
			error = cp_make_keys(entry);
		}
		*class = entry->cp_pclass;

	} else {
		/* 
		 * Mount point is not formatted for content protection. If a class
		 * has been specified anyway, report it. Otherwise, report D.
		 */
		error = cp_getxattr(cnode, &xattr);
		if (error == ENOATTR) {
			*class = PROTECTION_CLASS_D;
			error = 0;
		} else if (error == 0) {
			*class = xattr.persistent_class;
		}
	}
	
	hfs_unlock(cnode);
	return error;
}


/*
 * Sets persistent class for this file.
 * If vnode cannot be protected (system file, non-regular file, non-hfs), EBADF.
 * If the new class can't be accessed now, EPERM.
 * Otherwise, record class and re-wrap key if the mount point is content-protected.
 */
int 
cp_vnode_setclass(vnode_t vp, uint32_t newclass)
{
	struct cnode *cnode;
	struct cp_xattr xattr;
	struct cprotect *entry = 0;
	int error = 0;
	
	if (!cp_is_valid_class(newclass)) {
		printf("hfs: CP: cp_setclass called with invalid class %d\n", newclass);
		return EINVAL;
	}

	/* is this an interesting file? */
	if (!cp_vnode_is_eligible(vp)) {
		return EBADF;
	}

	cnode = VTOC(vp);

	if (hfs_lock(cnode, HFS_EXCLUSIVE_LOCK)) {
		return EINVAL;
	}
	
	/* is the volume formatted for content protection? */
	if (cp_fs_protected(VTOVFS(vp))) {
		entry = cnode->c_cpentry;
		if (entry == NULL) { 
			error = EINVAL;
			goto out;
		}

		if ((entry->cp_flags & CP_NEEDS_KEYS)) {
			if ((error = cp_make_keys(entry)) != 0) {
				goto out;
			}
		}

		if (entry->cp_flags & CP_KEY_FLUSHED) {
			error = cp_restore_keys(entry);
			if (error)
				goto out;
		}

		/* re-wrap per-file key with new class */
		error = cp_wrap(newclass,
						&entry->cp_cache_key[0], 
						&entry->cp_persistent_key[0]);
		if (error) {
			/* we didn't have perms to set this class. leave file as-is and error out */
			goto out;
		}

		entry->cp_pclass = newclass;

		/* prepare to write the xattr out */
		bcopy(&entry->cp_persistent_key, &xattr.persistent_key, CP_WRAPPEDKEYSIZE);
	} else {
		/* no live keys for this file. just remember intended class */
		bzero(&xattr.persistent_key, CP_WRAPPEDKEYSIZE);
	}

	xattr.xattr_major_version = CP_CURRENT_MAJOR_VERS;
	xattr.xattr_minor_version = CP_CURRENT_MINOR_VERS;
	xattr.key_size = CP_WRAPPEDKEYSIZE;
	xattr.flags = 0;
	xattr.persistent_class = newclass;
	error = cp_setxattr(cnode, &xattr, XATTR_REPLACE);
	
	if (error == ENOATTR) {
		error = cp_setxattr (cnode, &xattr, XATTR_CREATE);
	}

out:
	hfs_unlock(cnode);
	return error;
}

/*
 * Check permission for the given operation (read, write, page in) on this node.
 * Additionally, if the node needs work, do it:
 * - create a new key for the file if one hasn't been set before
 * - write out the xattr if it hasn't already been saved
 * - unwrap the key if needed
 *
 * Takes cnode lock, and upgrades to exclusive if modifying cprotect.
 */
	int
cp_handle_vnop(cnode_t *cnode, int vnop)
{
	struct cprotect *entry;
	int error = 0;
	struct cp_xattr xattr;

	if ((error = hfs_lock(cnode, HFS_SHARED_LOCK)) != KERN_SUCCESS) {
		return error;
	}

	entry = cnode->c_cpentry;
	if (!entry)
		goto out;

	if ((error = cp_check_access(cnode, vnop)) != KERN_SUCCESS) {
		goto out;
	}

	if (entry->cp_flags == 0) {
		/* no more work to do */
		goto out;
	}

	/* upgrade to exclusive lock */
	if (lck_rw_lock_shared_to_exclusive(&cnode->c_rwlock) == FALSE) {
		if ((error = hfs_lock(cnode, HFS_EXCLUSIVE_LOCK)) != KERN_SUCCESS) {
			return error;
		}
	} else {
		cnode->c_lockowner = current_thread();
	}

	/* generate new keys if none have ever been saved */
	if ((entry->cp_flags & CP_NEEDS_KEYS)) {
		if ((error = cp_make_keys(entry)) != 0) {
			goto out;
		}
	}

	/* unwrap keys if needed */
	if (entry->cp_flags & CP_KEY_FLUSHED) {
		error = cp_restore_keys(entry);
		if (error)
			goto out;
	}

	/* write out the xattr if it's new */
	if (entry->cp_flags & CP_NO_XATTR) {
		bcopy(&entry->cp_persistent_key[0], &xattr.persistent_key, CP_WRAPPEDKEYSIZE);
		xattr.xattr_major_version = CP_CURRENT_MAJOR_VERS;
		xattr.xattr_minor_version = CP_CURRENT_MINOR_VERS;
		xattr.key_size = CP_WRAPPEDKEYSIZE;
		xattr.persistent_class = entry->cp_pclass;
		error = cp_setxattr(cnode, &xattr, XATTR_CREATE);
	}

out:
	hfs_unlock(cnode);
	return error;
}

/*  
 * During hfs resize operations, we have slightly different constraints than during
 * normal VNOPS that read/write data to files.  Specifically, we already have the cnode
 * locked (so nobody else can modify it), and we are doing the IO with root privileges, since
 * we are moving the data behind the user's back.  So, we skip access checks here (for unlock
 * vs. lock), and don't worry about non-existing keys.  If the file exists on-disk with valid
 * payload, then it must have keys set up already by definition.
 */
int cp_handle_relocate (cnode_t *cp) {
	struct cprotect *entry;
	int error = -1;

	/* cp is already locked */	
	entry = cp->c_cpentry;
	if (!entry)
		goto out;

	/* 
	 * Still need to validate whether to permit access to the file or not 
	 * based on lock status 
	 */
	if ((error = cp_check_access(cp, CP_READ_ACCESS | CP_WRITE_ACCESS)) != KERN_SUCCESS) {
		goto out;
	}	

	if (entry->cp_flags == 0) {
		/* no more work to do */
		error = 0;
		goto out;
	}

	/* it must have keys since it is an existing file with actual payload */

	/* unwrap keys if needed */
	if (entry->cp_flags & CP_KEY_FLUSHED) {
		error = cp_restore_keys(entry);
	}

	/* don't need to write out the EA since the file is extant */
out:	

	/* return the cp still locked */
	return error;
}



/*
 * cp_getrootxattr:
 * Gets the EA we set on the root folder (fileid 1) to get information about the
 * version of Content Protection that was used to write to this filesystem.
 * Note that all multi-byte fields are written to disk little endian so they must be
 * converted to native endian-ness as needed.
 */

int cp_getrootxattr(struct hfsmount* hfsmp, struct cp_root_xattr *outxattr) {
	uio_t   auio;
	char    uio_buf[UIO_SIZEOF(1)];
	size_t attrsize = sizeof(struct cp_root_xattr);
	int error = 0;
	struct vnop_getxattr_args args;

	if (!outxattr) {
		panic("cp_xattr called with xattr == NULL");
	}

	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(outxattr), attrsize);

	args.a_desc = NULL; // unused
	args.a_vp = NULL; //unused since we're writing EA to root folder.
	args.a_name = CONTENT_PROTECTION_XATTR_NAME;
	args.a_uio = auio;
	args.a_size = &attrsize;
	args.a_options = XATTR_REPLACE;
	args.a_context = NULL; // unused

	error = hfs_getxattr_internal(NULL, &args, hfsmp, 1);

	/* Now convert the multi-byte fields to native endianness */
	outxattr->major_version = OSSwapLittleToHostInt16(outxattr->major_version);
	outxattr->minor_version = OSSwapLittleToHostInt16(outxattr->minor_version);
	outxattr->flags = OSSwapLittleToHostInt64(outxattr->flags);

	if (error != KERN_SUCCESS) {
		goto out;
	}

out:
	uio_free(auio);
	return error;
}

/*
 * cp_setrootxattr:
 * Sets the EA we set on the root folder (fileid 1) to get information about the
 * version of Content Protection that was used to write to this filesystem.
 * Note that all multi-byte fields are written to disk little endian so they must be
 * converted to little endian as needed.
 *
 * This will be written to the disk when it detects the EA is not there, or when we need
 * to make a modification to the on-disk version that can be done in-place.
 */
	int
cp_setrootxattr(struct hfsmount *hfsmp, struct cp_root_xattr *newxattr)
{
	int error = 0;
	struct vnop_setxattr_args args;

	args.a_desc = NULL;
	args.a_vp = NULL;
	args.a_name = CONTENT_PROTECTION_XATTR_NAME;
	args.a_uio = NULL; //pass data ptr instead
	args.a_options = 0; 
	args.a_context = NULL; //no context needed, only done from mount.

	/* Now convert the multi-byte fields to little endian before writing to disk. */
	newxattr->major_version = OSSwapHostToLittleInt16(newxattr->major_version);
	newxattr->minor_version = OSSwapHostToLittleInt16(newxattr->minor_version);
	newxattr->flags = OSSwapHostToLittleInt64(newxattr->flags);

	error = hfs_setxattr_internal(NULL, (caddr_t)newxattr, 
			sizeof(struct cp_root_xattr), &args, hfsmp, 1);
	return error;
}




/********************
 * Private Functions
 *******************/

static int
cp_vnode_is_eligible(vnode_t vp)
{
	return ((vp->v_op == hfs_vnodeop_p) &&
			(!vnode_issystem(vp)) &&
			(vnode_isreg(vp)));
}



static int
cp_is_valid_class(int class)
{
	return ((class >= PROTECTION_CLASS_A) &&
			(class <= PROTECTION_CLASS_F));
}


static struct cprotect *
cp_entry_alloc(void)
{
	struct cprotect *cp_entry;
	
	MALLOC(cp_entry, struct cprotect *, sizeof(struct cprotect), 
		   M_TEMP, M_WAITOK);
	if (cp_entry == NULL)
		return (NULL);
	
	bzero(cp_entry, sizeof(*cp_entry));
	return (cp_entry);
}


/*
 * Reads xattr data off the cnode and into provided xattr.
 * cnode lock held shared
 */
static int 
cp_getxattr(cnode_t *cnode, struct cp_xattr *outxattr)
{
	uio_t	auio;
	char	uio_buf[UIO_SIZEOF(1)];
	size_t attrsize = sizeof(struct cp_xattr);
	int error = 0;
	struct vnop_getxattr_args args;
		
	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(outxattr), attrsize);
	
	args.a_desc = NULL; // unused
	args.a_vp = cnode->c_vp;
	args.a_name = CONTENT_PROTECTION_XATTR_NAME;
	args.a_uio = auio;
	args.a_size = &attrsize;
	args.a_options = XATTR_REPLACE;
	args.a_context = vfs_context_current(); // unused
	error = hfs_getxattr_internal(cnode, &args, VTOHFS(cnode->c_vp), 0);
	if (error != KERN_SUCCESS) {
		goto out;
	}

	/* Endian swap the multi-byte fields into host endianness from L.E. */
	outxattr->xattr_major_version = OSSwapLittleToHostInt16(outxattr->xattr_major_version);
	outxattr->xattr_minor_version = OSSwapLittleToHostInt16(outxattr->xattr_minor_version);
	outxattr->key_size = OSSwapLittleToHostInt32(outxattr->key_size);
	outxattr->flags = OSSwapLittleToHostInt32(outxattr->flags);
	outxattr->persistent_class = OSSwapLittleToHostInt32(outxattr->persistent_class);

out:
	uio_free(auio);
	return error;
}

/*
 * Stores new xattr data on the cnode.
 * cnode lock held exclusive
 */
static int
cp_setxattr(cnode_t *cnode, struct cp_xattr *newxattr, int options)
{
	int error = 0;
	struct vnop_setxattr_args args;
	
	args.a_desc = NULL;
	args.a_vp = cnode->c_vp;
	args.a_name = CONTENT_PROTECTION_XATTR_NAME;
	args.a_uio = NULL; //pass data ptr instead
	args.a_options = options; 
	args.a_context = vfs_context_current();

	/* Endian swap the multi-byte fields into L.E from host. */
	newxattr->xattr_major_version = OSSwapHostToLittleInt16(newxattr->xattr_major_version);
	newxattr->xattr_minor_version = OSSwapHostToLittleInt16(newxattr->xattr_minor_version);
	newxattr->key_size = OSSwapHostToLittleInt32(newxattr->key_size);
	newxattr->flags = OSSwapHostToLittleInt32(newxattr->flags);
	newxattr->persistent_class = OSSwapHostToLittleInt32(newxattr->persistent_class);

	error = hfs_setxattr_internal(cnode, (caddr_t)newxattr, 
								  sizeof(struct cp_xattr), &args, VTOHFS(cnode->c_vp), 0);

	if ((error == KERN_SUCCESS) && (cnode->c_cpentry)) {
		cnode->c_cpentry->cp_flags &= ~CP_NO_XATTR;
	}

	return error;
}


/*
 * Make a new random per-file key and wrap it.
 */
static int
cp_make_keys(struct cprotect *entry)
{
	int error = 0;

	if (g_cp_state.wrap_functions_set != 1) {
		printf("hfs: CP: could not create keys: no wrappers set\n");
		return ENXIO;
	}

	/* create new cp data: key and class */
	read_random(&entry->cp_cache_key[0], CP_KEYSIZE);
	entry->cp_pclass = PROTECTION_CLASS_D;

	/* wrap the new key in the class key */
	error = cp_wrap(PROTECTION_CLASS_D,
					&entry->cp_cache_key[0], 
					&entry->cp_persistent_key[0]);
	
	if (error) {
		panic("could not wrap new key in class D\n");
	}

	/* ready for business */
	entry->cp_flags &= ~CP_NEEDS_KEYS;
	entry->cp_flags |= CP_NO_XATTR;

	return error;
}

/*
 * If permitted, restore entry's unwrapped key from the persistent key.
 * If not, clear key and set CP_ENTRY_FLUSHED.
 * cnode lock held exclusive
 */
static int
cp_restore_keys(struct cprotect *entry)
{
	int error = 0;

 	error = cp_unwrap(entry->cp_pclass,
					  &entry->cp_persistent_key[0],
					  &entry->cp_cache_key[0]);
	
	if (error) {
		entry->cp_flags |= CP_KEY_FLUSHED;
		bzero(entry->cp_cache_key, CP_KEYSIZE);
		error = EPERM;
	}
	else {
		entry->cp_flags &= ~CP_KEY_FLUSHED;
	}
	return error;
}

static int
cp_lock_vfs_callback(mount_t mp, void *arg)
{
	if (!cp_fs_protected(mp)) {
		/* not interested in this mount point */
		return 0;
	}
	
	return vnode_iterate(mp, 0, cp_lock_vnode_callback, arg);
}


/*
 * Deny access to protected files if keys have been locked.
 *
 * cnode lock is taken shared.
 */
	static int
cp_check_access(cnode_t *cnode, int vnop)
{
	int error = 0;

	if (g_cp_state.lock_state == CP_UNLOCKED_STATE) {
		return KERN_SUCCESS;
	}

	if (!cnode->c_cpentry) {
		/* unprotected node */
		return KERN_SUCCESS;
	}

	/* Deny all access for class A files, and read access for class B */
	switch (cnode->c_cpentry->cp_pclass) {
		case PROTECTION_CLASS_A: {
			error = EPERM;
			break;
		}
		case PROTECTION_CLASS_B: {
			if (vnop & CP_READ_ACCESS)
				error = EPERM;
			else
				error = 0;
			break;
		}
		default:
			error = 0;
			break;
	}

	return error;
}



/*
 * Respond to a lock or unlock event.
 * On lock: clear out keys from memory, then flush file contents.
 * On unlock: nothing (function not called).
 */
static int
cp_lock_vnode_callback(vnode_t vp, void *arg)
{
	cnode_t *cp = NULL;
	struct cprotect *entry = NULL;
	int error = 0;
	int locked = 1;
	int action = 0;

	error = vnode_getwithref (vp);
	if (error) {
		return error;
	}

	cp = VTOC(vp);
	hfs_lock(cp, HFS_FORCE_LOCK);
	
	entry = cp->c_cpentry;
	if (!entry) {
		/* unprotected vnode: not a regular file */
		goto out;
	}
	
	action = (int)((uintptr_t) arg);
	switch (action) {
		case CP_LOCKED_STATE: {
			vfs_context_t ctx;
			if (entry->cp_pclass != PROTECTION_CLASS_A) {
				/* no change at lock for other classes */
				goto out;
			}
			
			/* Before doing anything else, zero-fille sparse ranges as needed */
			ctx = vfs_context_current();
			(void) hfs_filedone (vp, ctx);

			/* first, sync back dirty pages */
			hfs_unlock (cp);
			ubc_msync (vp, 0, ubc_getsize(vp), NULL, UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
			hfs_lock (cp, HFS_FORCE_LOCK);
			
			/* flush keys */
			entry->cp_flags |= CP_KEY_FLUSHED;
			bzero(&entry->cp_cache_key, CP_KEYSIZE);
			/* some write may have arrived in the mean time. dump those pages */
			hfs_unlock(cp);
			locked = 0;
		
			ubc_msync (vp, 0, ubc_getsize(vp), NULL, UBC_INVALIDATE | UBC_SYNC);	
			break;
		}
		case CP_UNLOCKED_STATE: {
			/* no-op */
			break;
		}
		default:
			panic("unknown lock action %d\n", action);
	}
	
out:
	if (locked)
		hfs_unlock(cp);
	vnode_put (vp);
	return error;
}

static int
cp_wrap(int class, void *inkey, void *outkey)
{
	int error = 0;
	size_t keyln = CP_WRAPPEDKEYSIZE;
	
	if (class == PROTECTION_CLASS_F) {
		bzero(outkey, CP_WRAPPEDKEYSIZE);
		return 0;
	}
	
	error = g_cp_wrap_func.wrapper(class,
								   inkey,
								   CP_KEYSIZE,
								   outkey,
								   &keyln);
	
	return error;
}


static int
cp_unwrap(int class, void *inkey, void *outkey)
{
	int error = 0;
	size_t keyln = CP_KEYSIZE;
	
	if (class == PROTECTION_CLASS_F) {
		/* we didn't save a wrapped key, so nothing to unwrap */
		return EPERM;
	}
	
	error = g_cp_wrap_func.unwrapper(class,
									 inkey,
									 CP_WRAPPEDKEYSIZE,
									 outkey,
									 &keyln);
	
	return error;
	
}


#else

int cp_key_store_action(int action __unused)
{
	return ENOTSUP;
}


int cp_register_wraps(cp_wrap_func_t key_store_func __unused)
{
	return ENOTSUP;
}

#endif /* CONFIG_PROTECT */
