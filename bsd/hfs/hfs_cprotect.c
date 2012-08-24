/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
#include <sys/fcntl.h>
#include <libkern/OSByteOrder.h>

#include "hfs.h"
#include "hfs_cnode.h"

#if CONFIG_PROTECT
static struct cp_wrap_func		g_cp_wrap_func = {NULL, NULL};
static struct cp_global_state	g_cp_state = {0, 0, 0};

extern int (**hfs_vnodeop_p) (void *);

/*
 * CP private functions
 */
static int cp_is_valid_class(int);
static int cp_root_major_vers(mount_t mp);
static int cp_getxattr(cnode_t *, struct hfsmount *hfsmp, struct cprotect **);
static struct cprotect *cp_entry_alloc(size_t);
static void cp_entry_dealloc(struct cprotect *entry);
static int cp_setup_aes_ctx(struct cprotect *);
static int cp_make_keys (struct cprotect **, struct hfsmount *hfsmp, cnid_t,  int);
static int cp_restore_keys(struct cprotect *, struct hfsmount *hfsmp);
static int cp_lock_vfs_callback(mount_t, void *);
static int cp_lock_vnode_callback(vnode_t, void *);
static int cp_vnode_is_eligible (vnode_t);
static int cp_check_access (cnode_t *, int);
static int cp_wrap(int, struct hfsmount *hfsmp, cnid_t, struct cprotect**);
static int cp_unwrap(int, struct cprotect *);



#if DEVELOPMENT || DEBUG
#define CP_ASSERT(x)		\
	if ((x) == 0) {			\
		panic("Content Protection: failed assertion in %s", __FUNCTION__); 	\
	}
#else
#define CP_ASSERT(x)
#endif

int 
cp_key_store_action(int action)
{
	g_cp_state.lock_state = action;
	if (action == CP_LOCKED_STATE) {
		/*
		 * Note that because we are using the void* arg to pass the key store
		 * value into the vfs cp iteration, we need to pass around the int as an ptr.
		 * This may silence 32-64 truncation warnings.
		 */
		return vfs_iterate(0, cp_lock_vfs_callback, (void*)((uintptr_t)action));
    }
    
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

#if 0
/* 
 * If necessary, this function can be used to 
 * query the device's lock state.
 */
int 
cp_isdevice_locked (void) {	
	if (g_cp_state.lock_state == CP_UNLOCKED_STATE) {
		return 0;
	}
	return 1;
}
#endif

/*
 * Allocate and initialize a cprotect blob for a new cnode.
 * Called from hfs_getnewvnode: cnode is locked exclusive.
 * Read xattr data off the cnode. Then, if conditions permit,
 * unwrap the file key and cache it in the cprotect blob.
 */
int 
cp_entry_init(struct cnode *cp, struct mount *mp)
{
	struct cprotect *entry = NULL;
	int error = 0;
	struct hfsmount *hfsmp = VFSTOHFS(mp);

	if (!cp_fs_protected (mp)) {
		cp->c_cpentry = NULL;
		return 0;
	}
	
	if (!S_ISREG(cp->c_mode) && !S_ISDIR(cp->c_mode)) {
		cp->c_cpentry = NULL;
		return 0;
	}
	
	if (!g_cp_state.wrap_functions_set) {
		printf("hfs: cp_update_entry: wrap functions not yet set\n");
		return ENXIO;
	}
	
	if (hfsmp->hfs_running_cp_major_vers == 0) {
		cp_root_major_vers(mp);
	}
	
	CP_ASSERT (cp->c_cpentry == NULL);

	error = cp_getxattr(cp, hfsmp, &entry);

	/*
	 * Normally, we should always have a CP EA for a file or directory that
	 * we are initializing here. However, there are some extenuating circumstances,
	 * such as the root directory immediately following a newfs_hfs.
	 *
	 * As a result, we leave code here to deal with an ENOATTR which will always 
	 * default to a 'D' key, though we don't expect to use it much.
	 */
	if (error == ENOATTR) {
		int sub_error;
		
		sub_error = cp_entry_create_keys (&entry, NULL, hfsmp, PROTECTION_CLASS_D, cp->c_fileid, cp->c_mode);

		/* Now we have keys.  Write them out. */
		if (sub_error == 0) {
			sub_error = cp_setxattr (cp, entry, hfsmp, cp->c_fileid, XATTR_CREATE);
		}
		error = sub_error;
	}
	else if (error == 0) {
		if (S_ISREG(cp->c_mode)) {
			entry->cp_flags |= CP_KEY_FLUSHED;
		}
	}	
	/* 
	 * For errors other than ENOATTR, we don't do anything. 
	 * cp_entry_destroy can deal with a NULL argument if cp_getxattr
	 * failed malloc or there was a B-Tree error.
	 */

	cp->c_cpentry = entry;

	if (error)  {
		cp_entry_destroy(&cp->c_cpentry);
	}
	
	return error;
}

/*
 * Set up initial key/class pair on cnode. The cnode does not yet exist,
 * so we must take a pointer to the cprotect struct.  
 * 
 * NOTE:
 * We call this function in two places:
 * 1) hfs_makenode *prior* to taking the journal/b-tree locks.
 * A successful return value from this function is a pre-requisite for continuing on
 * with file creation, as a wrap failure should immediately preclude the creation of
 * the file.
 *
 * 2) cp_entry_init if we are trying to establish keys for a file/directory that did not
 * have them already.  (newfs_hfs may create entries in the namespace).
 *
 * At this point, we hold the directory cnode lock exclusive if it is available.
 */ 
int
cp_entry_create_keys(struct cprotect **entry_ptr, struct cnode *dcp, struct hfsmount *hfsmp,
		uint32_t input_class, cnid_t fileid, mode_t cmode)
{
	int error = 0;
	struct cprotect *entry = NULL;
	size_t keylen;

	/* Default to class D */
	uint32_t target_class = PROTECTION_CLASS_D;

	/* Decide the target class.  Input argument takes priority. */
	if (cp_is_valid_class (input_class)) {
		target_class = input_class;
		/* 
		 * One exception, F is never valid for a directory 
		 * because its children may inherit and userland will be
		 * unable to read/write to the files.
		 */
		if (S_ISDIR(cmode)) {
			if (target_class == PROTECTION_CLASS_F) {
				return EINVAL;
			}
		}
	}
	else {
		/* If no valid class was supplied, then inherit from parent if possible */
		if ((dcp) && (dcp->c_cpentry)) {
			uint32_t parentclass = dcp->c_cpentry->cp_pclass;
			/* If the parent class is not valid, default back to D */
			if (cp_is_valid_class(parentclass)) {
				/* Parent class was good. use it. */
				target_class = parentclass;
			}
			/* Otherwise, we already defaulted to 'D' */
		}
	}

	keylen = S_ISDIR(cmode) ? 0 : CP_INITIAL_WRAPPEDKEYSIZE;
	entry = cp_entry_alloc (keylen);
	if (!entry) {
		*entry_ptr = NULL;
		return ENOMEM;
	}

	if (S_ISREG(cmode)) {
		entry->cp_pclass = target_class;
		entry->cp_flags |= CP_NEEDS_KEYS;
		/* 
		 * The 'fileid' argument to this function will either be 
		 * a valid fileid for an existing file/dir, or it will be 0.
		 * If it is 0, then that is an indicator to the layer below
		 * that the file does not yet exist and we need to bypass the
		 * cp_wrap work to the keybag.
		 *
		 * If we are being invoked on behalf of a file/dir that does
		 * not yet have a key, then it will be a valid key and we
		 * need to behave like a setclass.
		 */
		error = cp_make_keys(&entry, hfsmp, fileid, entry->cp_pclass);
	}
	else if (S_ISDIR(cmode)) {
		/* Directories just get their cp_pclass set */
		entry->cp_pclass = target_class;
	}
	else {
		/* Unsupported for non-dir and non-file. */
		error = EINVAL;
	}

	/* 
	 * We only initialize and create the keys here; we cannot 
	 * write out the EA until the journal lock and EA b-tree locks
	 * are acquired.
	 */

	if (error) {
		/* destroy the CP blob */
		cp_entry_destroy (&entry);
		*entry_ptr = NULL;
	}
	else {
		/* otherwise, emit the cprotect entry */
		*entry_ptr = entry;
	}

	return error;
}

/*
 * Set up an initial key/class pair for a disassociated cprotect entry.
 * This function is used to generate transient keys that will never be 
 * written to disk.  We use class F for this since it provides the exact
 * semantics that are needed here.  Because we never attach this blob to
 * a cnode directly, we take a pointer to the cprotect struct.
 *
 * This function is primarily used in the HFS FS truncation codepath
 * where we may rely on AES symmetry to relocate encrypted data from
 * one spot in the disk to another.
 */
int cp_entry_gentempkeys(struct cprotect **entry_ptr, struct hfsmount *hfsmp) {
	int error = 0;
	struct cprotect *entry = NULL;
	size_t keylen;

	/* Default to class F */
	uint32_t target_class = PROTECTION_CLASS_F;

	/* 
	 * This should only be  used for files, so we default to the
	 * initial wrapped key size
	 */
	keylen = CP_INITIAL_WRAPPEDKEYSIZE;
	entry = cp_entry_alloc (keylen);
	if (!entry) {
		*entry_ptr = NULL;
		return ENOMEM;
	}

	error = cp_make_keys (&entry, hfsmp, 0, target_class);

	/* 
	 * We only initialize the keys here; we don't write anything out
	 */

	if (error) {
		/* destroy the CP blob */
		cp_entry_destroy (&entry);
		*entry_ptr = NULL;
	}
	else {
		/* otherwise, emit the cprotect entry */
		*entry_ptr = entry;
	}

	return error;

}

/*
 * Tear down and clear a cprotect blob for a closing file.
 * Called at hfs_reclaim_cnode: cnode is locked exclusive. 
 */
void
cp_entry_destroy(struct cprotect **entry_ptr) {
	struct cprotect *entry = *entry_ptr;
	if (!entry) {
		/* nothing to clean up */
		return;
	}
	*entry_ptr = NULL;
	cp_entry_dealloc(entry);
}


int 
cp_fs_protected (mount_t mnt) {
	return (vfs_flags(mnt) & MNT_CPROTECT);
}


/*
 * Return a pointer to underlying cnode if there is one for this vnode.
 * Done without taking cnode lock, inspecting only vnode state.
 */
struct cnode *
cp_get_protected_cnode(struct vnode *vp)
{
	if (!cp_vnode_is_eligible(vp)) {
		return NULL;
	}
	
	if (!cp_fs_protected(VTOVFS(vp))) {
		/* mount point doesn't support it */
		return NULL;
	}
	
	return (struct cnode*) vp->v_data;
}


/*
 * Sets *class to persistent class associated with vnode,
 * or returns error.
 */
int 
cp_vnode_getclass(struct vnode *vp, int *class)
{
	struct cprotect *entry;
	int error = 0;
	struct cnode *cp;
	int took_truncate_lock = 0;
	struct hfsmount *hfsmp = NULL;

	/* Is this an interesting vp? */
	if (!cp_vnode_is_eligible (vp)) {
		return EBADF;
	}

	/* Is the mount point formatted for content protection? */
	if (!cp_fs_protected(VTOVFS(vp))) {
		return EPERM;
	}
	
	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);
	
	/*
	 * Take the truncate lock up-front in shared mode because we may need 
	 * to manipulate the CP blob. Pend lock events until we're done here. 
	 */
	hfs_lock_truncate (cp, HFS_SHARED_LOCK);
	took_truncate_lock = 1;

	/*
	 * We take only the shared cnode lock up-front.  If it turns out that
	 * we need to manipulate the CP blob to write a key out, drop the 
	 * shared cnode lock and acquire an exclusive lock. 
	 */
	error = hfs_lock(cp, HFS_SHARED_LOCK);
	if (error) {
		hfs_unlock_truncate(cp, 0);
		return error;
	}
	
	/* pull the class from the live entry */
	entry = cp->c_cpentry;
	
	if (!entry) {
		panic("Content Protection: uninitialized cnode %p", cp);
	}
	
	/*
	 * Any vnode on a content protected filesystem must have keys
	 * created by the time the vnode is vended out.  If we generate
	 * a vnode that does not have keys, something bad happened.
	 */
	if ((entry->cp_flags & CP_NEEDS_KEYS)) {
		panic ("cp_vnode_getclass: cp %p has no keys!", cp);
	}

	if (error == 0) {
		*class = entry->cp_pclass;
	}
	
	if (took_truncate_lock) {
		hfs_unlock_truncate(cp, 0);
	}
	
	hfs_unlock(cp);
	return error;
}


/*
 * Sets persistent class for this file or directory.
 * If vnode cannot be protected (system file, non-regular file, non-hfs), EBADF.
 * If the new class can't be accessed now, EPERM.
 * Otherwise, record class and re-wrap key if the mount point is content-protected.
 */
int 
cp_vnode_setclass(struct vnode *vp, uint32_t newclass)
{
	struct cnode *cp;
	struct cprotect *entry = 0;
	int error = 0;
	int took_truncate_lock = 0;
	u_int32_t keylen = 0;
	struct hfsmount *hfsmp = NULL;
	
	if (!cp_is_valid_class(newclass)) {
		printf("hfs: CP: cp_setclass called with invalid class %d\n", newclass);
		return EINVAL;
	}

	if (vnode_isdir(vp)) {
		if (newclass == PROTECTION_CLASS_F) {
			/* 
			 * Directories are not allowed to set to class F, since the
			 * children may inherit it and then userland will not be able
			 * to read/write to the file.
			 */
			return EINVAL;
		}
	}

	/* Is this an interesting vp? */
	if (!cp_vnode_is_eligible(vp)) {
		return EBADF;
	}

	/* Is the mount point formatted for content protection? */
	if (!cp_fs_protected(VTOVFS(vp))) {
		return EPERM;
	}

	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	/* 
	 * Take the cnode truncate lock exclusive because we want to manipulate the 
	 * CP blob. The lock-event handling code is doing the same.  This also forces
	 * all pending IOs to drain before we can re-write the persistent and cache keys.
	 */
	hfs_lock_truncate (cp, HFS_EXCLUSIVE_LOCK);
	took_truncate_lock = 1;
	
	if (hfs_lock(cp, HFS_EXCLUSIVE_LOCK)) {
		return EINVAL;
	}
	
	entry = cp->c_cpentry;
	if (entry == NULL) {
		error = EINVAL;
		goto out;
	}

	if ((entry->cp_flags & CP_NEEDS_KEYS)) {
		/* 
		 * We should have created this vnode and its keys atomically during
		 * file/directory creation.  If we get here and it doesn't have keys yet,
		 * something bad happened.
		 */
		panic ("cp_vnode_setclass: cp %p has no keys!\n", cp);
	}

	if (entry->cp_flags & CP_KEY_FLUSHED) {
		error = cp_restore_keys(entry, hfsmp);
		if (error)
			goto out;
	}

	/* re-wrap per-file key with new class */
	if (vnode_isreg(vp)) {
		error = cp_wrap(newclass, hfsmp, cp->c_fileid, &cp->c_cpentry);
		if (error) {
			/* we didn't have perms to set this class. leave file as-is and error out */
			goto out;
		}
	}

	/* cp_wrap() potentially updates c_cpentry because we passed in its ptr */
	entry = cp->c_cpentry;
	
	entry->cp_pclass = newclass;

	/* prepare to write the xattr out */
	keylen = entry->cp_persistent_key_len;
	
	error = cp_setxattr(cp, entry, VTOHFS(vp), 0,XATTR_REPLACE);	
	if (error == ENOATTR) 
		error = cp_setxattr(cp, entry, VTOHFS(vp), 0, XATTR_CREATE);		
	
out:
	
	if (took_truncate_lock) {
		hfs_unlock_truncate (cp, 0);
	}
	hfs_unlock(cp);
	return error;
}


int cp_vnode_transcode(vnode_t vp)
{
	struct cnode *cp;
	struct cprotect *entry = 0;
	int error = 0;
	int took_truncate_lock = 0;
	struct hfsmount *hfsmp = NULL;

	/* Is this an interesting vp? */
	if (!cp_vnode_is_eligible(vp)) {
		return EBADF;
	}

	/* Is the mount point formatted for content protection? */
	if (!cp_fs_protected(VTOVFS(vp))) {
		return EPERM;
	}

	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	/* 
	 * Take the cnode truncate lock exclusive because we want to manipulate the 
	 * CP blob. The lock-event handling code is doing the same.  This also forces
	 * all pending IOs to drain before we can re-write the persistent and cache keys.
	 */
	hfs_lock_truncate (cp, HFS_EXCLUSIVE_LOCK);
	took_truncate_lock = 1;
	
	if (hfs_lock(cp, HFS_EXCLUSIVE_LOCK)) {
		return EINVAL;
	}
	
	entry = cp->c_cpentry;
	if (entry == NULL) {
		error = EINVAL;
		goto out;
	}

	if ((entry->cp_flags & CP_NEEDS_KEYS)) {
		/*
		 * If we are transcoding keys for AKB, then we should have already established
		 * a set of keys for this vnode. IF we don't have keys yet, then something bad 
		 * happened.
		 */
		panic ("cp_vnode_transcode: cp %p has no keys!", cp);
	}

	if (entry->cp_flags & CP_KEY_FLUSHED) {
		error = cp_restore_keys(entry, hfsmp);

		if (error) {
			goto out;
        }
	}

	/* Send the per-file key for re-wrap with the current class information
	 * Send NULLs in the output parameters of the wrapper() and AKS will do the rest.
	 * Don't need to process any outputs, so just clear the locks and pass along the error. */
	if (vnode_isreg(vp)) {

		/* Picked up the following from cp_wrap().
		 * If needed, more comments available there. */

		if (entry->cp_pclass == PROTECTION_CLASS_F) {
			error = EINVAL;
			goto out;
		}

		error = g_cp_wrap_func.wrapper(entry->cp_pclass,
									   cp->c_fileid,
									   entry->cp_cache_key,
									   entry->cp_cache_key_len,
									   NULL,
									   NULL);

		if(error)
			error = EPERM;
	}

out:
	if (took_truncate_lock) {
		hfs_unlock_truncate (cp, 0);
	}
	hfs_unlock(cp);
	return error;
}


/*
 * Check permission for the given operation (read, write) on this node.
 * Additionally, if the node needs work, do it:
 * - create a new key for the file if one hasn't been set before
 * - write out the xattr if it hasn't already been saved
 * - unwrap the key if needed
 *
 * Takes cnode lock, and upgrades to exclusive if modifying cprotect.
 *
 * Note that this function does *NOT* take the cnode truncate lock.  This is because 
 * the thread calling us may already have the truncate lock.  It is not necessary
 * because either we successfully finish this function before the keys are tossed
 * and the IO will fail, or the keys are tossed and then this function will fail. 
 * Either way, the cnode lock still ultimately guards the keys.  We only rely on the
 * truncate lock to protect us against tossing the keys as a cluster call is in-flight. 
 */
int
cp_handle_vnop(struct vnode *vp, int vnop, int ioflag)
{
	struct cprotect *entry;
	int error = 0;
	struct hfsmount *hfsmp = NULL;
	struct cnode *cp = NULL;

	/* 
	 * First, do validation against the vnode before proceeding any further:
	 * Is this vnode originating from a valid content-protected filesystem ?
	 */
	if (cp_vnode_is_eligible(vp) == 0) {
		/* 
		 * It is either not HFS or not a file/dir.  Just return success. This is a valid
		 * case if servicing i/o against another filesystem type from VFS
		 */
		return 0;
	}

	if (cp_fs_protected (VTOVFS(vp)) == 0) {
		/*
		 * The underlying filesystem does not support content protection.  This is also 
		 * a valid case.  Simply return success.
		 */
		return 0;
	}
	
	/* 
	 * At this point, we know we have a HFS vnode that backs a file or directory on a
	 * filesystem that supports content protection
	 */
	cp = VTOC(vp);

	if ((error = hfs_lock(cp, HFS_SHARED_LOCK))) {
		return error;
	}

	entry = cp->c_cpentry;
	
	if (!entry) {
		/*
		 * If this cnode is not content protected, simply return success.
		 * Note that this function is called by all I/O-based call sites 
		 * when CONFIG_PROTECT is enabled during XNU building.
		 */

		goto out;
	}

	vp = CTOV(cp, 0);
	if (vp == NULL) {
		/* is it a rsrc */
		vp = CTOV(cp,1);
		if (vp == NULL) {
			error = EINVAL;
			goto out;
		}
	}
	hfsmp = VTOHFS(vp);

	if ((error = cp_check_access(cp, vnop))) {
		/* check for raw encrypted access before bailing out */
		if ((vnop == CP_READ_ACCESS) && (ioflag & IO_ENCRYPTED)) {
			/* 
			 * read access only + asking for the raw encrypted bytes 
			 * is legitimate, so reset the error value to 0
			 */
			error = 0;
		}
		else {
			goto out;
		}
	}

	if (entry->cp_flags == 0) {
		/* no more work to do */
		goto out;
	}

	/* upgrade to exclusive lock */
	if (lck_rw_lock_shared_to_exclusive(&cp->c_rwlock) == FALSE) {
		if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK))) { 
			return error;
		}
	} else {
		cp->c_lockowner = current_thread();
	}
	
	/* generate new keys if none have ever been saved */
	if ((entry->cp_flags & CP_NEEDS_KEYS)) {
		/*
		 * By the time we're trying to initiate I/O against a content
		 * protected vnode, we should have already created keys for this
		 * file/dir. If we don't have keys, something bad happened.
		 */
		panic ("cp_handle_vnop: cp %p has no keys!", cp);
	}

	/* unwrap keys if needed */
	if (entry->cp_flags & CP_KEY_FLUSHED) {
		if ((vnop == CP_READ_ACCESS) && (ioflag & IO_ENCRYPTED)) {
			/* no need to try to restore keys; they are not going to be used */
			error = 0;
		}
		else {
			error = cp_restore_keys(entry, hfsmp);

			if (error) {
				goto out;
			}
		}
	}

	/* write out the xattr if it's new */
	if (entry->cp_flags & CP_NO_XATTR)
		error = cp_setxattr(cp, entry, VTOHFS(cp->c_vp), 0, XATTR_CREATE);

out:

	hfs_unlock(cp);
	return error;
}


int
cp_handle_open(struct vnode *vp, int mode)
{
	struct cnode *cp = NULL ;
	struct cprotect *entry = NULL;
	int error = 0;
	
	/* If vnode not eligible, just return success */
	if (!cp_vnode_is_eligible(vp)) {
		return 0;
	}
	
	/* If mount point not properly set up, then also return success */
	if (!cp_fs_protected(VTOVFS(vp))) {
		return 0;
	}

	/* We know the vnode is in a valid state. acquire cnode and validate */
	cp = VTOC(vp);

	if ((error = hfs_lock(cp, HFS_SHARED_LOCK))) {
		return error;
	}

	entry = cp->c_cpentry;
	if (!entry)
		goto out;

	if (!S_ISREG(cp->c_mode))
		goto out;

	switch (entry->cp_pclass) {
		case PROTECTION_CLASS_B:
			/* Class B always allows creation */
			if (mode & O_CREAT)
				goto out;
		case PROTECTION_CLASS_A:
			error = g_cp_wrap_func.unwrapper(entry->cp_pclass,
											entry->cp_persistent_key,
											entry->cp_persistent_key_len,
											NULL, NULL);
			if (error)
				error = EPERM;
			break;
		default:
			break;
	}

out:
	hfs_unlock(cp);
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
int 
cp_handle_relocate (struct cnode *cp, struct hfsmount *hfsmp) {
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
	if ((error = cp_check_access(cp, CP_READ_ACCESS | CP_WRITE_ACCESS))) {
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
		error = cp_restore_keys(entry, hfsmp);
	}

	/* 
	 * Don't need to write out the EA since if the file has actual extents,
	 * it must have an EA
	 */
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
int 
cp_getrootxattr(struct hfsmount* hfsmp, struct cp_root_xattr *outxattr) {
	uio_t   auio;
	char    uio_buf[UIO_SIZEOF(1)];
	size_t attrsize = sizeof(struct cp_root_xattr);
	int error = 0;
	struct vnop_getxattr_args args;

	if (!outxattr) {
		panic("Content Protection: cp_xattr called with xattr == NULL");
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

	if (error != 0) { 
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


/*
 * Stores new xattr data on the cnode.
 * cnode lock held exclusive (if available).
 *
 * This function is also invoked during file creation.
 */
int cp_setxattr(struct cnode *cp, struct cprotect *entry, struct hfsmount *hfsmp, uint32_t fileid, int options)
{
	int error = 0;
	size_t attrsize; 
	struct vnop_setxattr_args args;
	uint32_t target_fileid;
	struct cnode *arg_cp = NULL;
	uint32_t tempflags = 0;

	args.a_desc = NULL;
	if (cp) {
		args.a_vp = cp->c_vp;
		target_fileid = 0;
		arg_cp = cp;
	}
	else {
		/* 
		 * When we set the EA in the same txn as the file creation,
		 * we do not have a vnode/cnode yet. Use the specified fileid.
		 */
		args.a_vp = NULL;
		target_fileid = fileid;
	}
	args.a_name = CONTENT_PROTECTION_XATTR_NAME;
	args.a_uio = NULL; //pass data ptr instead
	args.a_options = options; 
	args.a_context = vfs_context_current();
	
	/* Add asserts for the CP flags in the CP blob. */
	if (entry->cp_flags & CP_NEEDS_KEYS) {
		panic ("cp_setxattr: cp %p , cpentry %p still needs keys!", cp, entry);
	}

	/* Disable flags that will be invalid as we're writing the EA out at this point. */
	tempflags = entry->cp_flags;
	tempflags &= ~CP_NO_XATTR;

	switch(hfsmp->hfs_running_cp_major_vers) {
		case CP_NEW_MAJOR_VERS: {
			struct cp_xattr_v4 *newxattr = NULL; // 70+ bytes; don't alloc on stack.
			MALLOC (newxattr, struct cp_xattr_v4*, sizeof(struct cp_xattr_v4), M_TEMP, M_WAITOK);
			if (newxattr == NULL) {
				error = ENOMEM;
				break;
			}
			bzero (newxattr, sizeof(struct cp_xattr_v4));

			attrsize = sizeof(*newxattr) - CP_MAX_WRAPPEDKEYSIZE + entry->cp_persistent_key_len;
			
			/* Endian swap the multi-byte fields into L.E from host. */
			newxattr->xattr_major_version = OSSwapHostToLittleInt16 (hfsmp->hfs_running_cp_major_vers);
			newxattr->xattr_minor_version = OSSwapHostToLittleInt16(CP_MINOR_VERS);
			newxattr->key_size = OSSwapHostToLittleInt32(entry->cp_persistent_key_len);
			newxattr->flags = OSSwapHostToLittleInt32(tempflags);
			newxattr->persistent_class = OSSwapHostToLittleInt32(entry->cp_pclass);	
			bcopy(entry->cp_persistent_key, newxattr->persistent_key, entry->cp_persistent_key_len);
			
			error = hfs_setxattr_internal(arg_cp, (caddr_t)newxattr, attrsize, &args, hfsmp, target_fileid);			

			FREE(newxattr, M_TEMP);
			break;
		}
		case CP_PREV_MAJOR_VERS: {
			struct cp_xattr_v2 *newxattr = NULL;
			MALLOC (newxattr, struct cp_xattr_v2*, sizeof(struct cp_xattr_v2), M_TEMP, M_WAITOK);
			if (newxattr == NULL) {
				error = ENOMEM;
				break;
			}
			bzero (newxattr, sizeof(struct cp_xattr_v2));
			
			attrsize = sizeof(*newxattr);
			
			/* Endian swap the multi-byte fields into L.E from host. */
			newxattr->xattr_major_version = OSSwapHostToLittleInt16(hfsmp->hfs_running_cp_major_vers);
			newxattr->xattr_minor_version = OSSwapHostToLittleInt16(CP_MINOR_VERS);
			newxattr->key_size = OSSwapHostToLittleInt32(entry->cp_persistent_key_len);
			newxattr->flags = OSSwapHostToLittleInt32(tempflags);
			newxattr->persistent_class = OSSwapHostToLittleInt32(entry->cp_pclass);	
			bcopy(entry->cp_persistent_key, newxattr->persistent_key, entry->cp_persistent_key_len);
						
			error = hfs_setxattr_internal(arg_cp, (caddr_t)newxattr, attrsize, &args, hfsmp, target_fileid);

			FREE (newxattr, M_TEMP);
			break;
		}
	}
	
	if (error == 0 ) {
		entry->cp_flags &= ~CP_NO_XATTR;
	}

	return error;


}

/*
 * This function takes a cprotect struct with the cache keys and re-wraps them for 
 * MKB's sake so that it can update its own data structures.  It is useful when
 * there may not be a cnode in existence yet (for example, after creating
 * a file).
 */
int 
cp_update_mkb (struct cprotect *entry, uint32_t fileid) {

	int error = 0;

	/* We already validated this pclass earlier */
	if (entry->cp_pclass != PROTECTION_CLASS_F ) {
		error = g_cp_wrap_func.wrapper (entry->cp_pclass, fileid, entry->cp_cache_key, 
				entry->cp_cache_key_len, NULL, NULL);
	}		

	if (error) {
		error = EPERM;
	}

	return error;
}

/*
 * Used by an fcntl to query the underlying FS for its content protection version #
 */

int 
cp_get_root_major_vers(vnode_t vp, uint32_t *level) {
	int err = 0;
	struct hfsmount *hfsmp = NULL;
	struct mount *mp = NULL;

	mp = VTOVFS(vp);

	/* check if it supports content protection */
	if (cp_fs_protected(mp) == 0) {
		return EINVAL;
	}

	hfsmp = VFSTOHFS(mp);
	/* figure out the level */

	err = cp_root_major_vers(mp);

	if (err == 0) {
		*level = hfsmp->hfs_running_cp_major_vers;
	}
	/* in error case, cp_root_major_vers will just return EINVAL. Use that */

	return err;
}

/********************
 * Private Functions
 *******************/

static int
cp_root_major_vers(mount_t mp)
{
	int err = 0;
	struct cp_root_xattr xattr;
	struct hfsmount *hfsmp = NULL;

	hfsmp = vfs_fsprivate(mp);
	err = cp_getrootxattr (hfsmp, &xattr);

	if (err == 0) {
		hfsmp->hfs_running_cp_major_vers = xattr.major_version;	
	}
	else {
		return EINVAL;
	}

	return 0;
}

static int
cp_vnode_is_eligible(struct vnode *vp)
{
	return ((vp->v_op == hfs_vnodeop_p) &&
			(!vnode_issystem(vp)) &&
			(vnode_isreg(vp) || vnode_isdir(vp)));
}



static int
cp_is_valid_class(int class)
{
	return ((class >= PROTECTION_CLASS_A) &&
			(class <= PROTECTION_CLASS_F));
}


static struct cprotect *
cp_entry_alloc(size_t keylen)
{
	struct cprotect *cp_entry;

	if (keylen > CP_MAX_WRAPPEDKEYSIZE)
		return (NULL);
	
	MALLOC(cp_entry, struct cprotect *, sizeof(struct cprotect) + keylen, 
		   M_TEMP, M_WAITOK);
	if (cp_entry == NULL)
		return (NULL);

	bzero(cp_entry, sizeof(*cp_entry) + keylen);
	cp_entry->cp_persistent_key_len = keylen;
	return (cp_entry);
}

static void
cp_entry_dealloc(struct cprotect *entry)
{
	uint32_t keylen = entry->cp_persistent_key_len;
	bzero(entry, (sizeof(*entry) + keylen));
	FREE(entry, M_TEMP);	
}


/*
 * Initializes a new cprotect entry with xattr data from the cnode.
 * cnode lock held shared
 */
static int 
cp_getxattr(struct cnode *cp, struct hfsmount *hfsmp, struct cprotect **outentry)
{
	int error = 0;
	uio_t auio;
	size_t attrsize;
	char uio_buf[UIO_SIZEOF(1)];
	struct vnop_getxattr_args args;
	struct cprotect *entry = NULL;

	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
	args.a_desc = NULL; // unused
	args.a_vp = cp->c_vp;
	args.a_name = CONTENT_PROTECTION_XATTR_NAME;
	args.a_uio = auio;
	args.a_options = XATTR_REPLACE;
	args.a_context = vfs_context_current(); // unused

	switch (hfsmp->hfs_running_cp_major_vers) {
		case CP_NEW_MAJOR_VERS: {
			struct cp_xattr_v4 *xattr = NULL;
			MALLOC (xattr, struct cp_xattr_v4*, sizeof(struct cp_xattr_v4), M_TEMP, M_WAITOK);
			if (xattr == NULL) {
				error = ENOMEM;
				break;
			}
			bzero(xattr, sizeof (struct cp_xattr_v4));
			attrsize = sizeof(*xattr);

			uio_addiov(auio, CAST_USER_ADDR_T(xattr), attrsize);
			args.a_size = &attrsize;

			error = hfs_getxattr_internal(cp, &args, VTOHFS(cp->c_vp), 0);
			if (error != 0) {
				FREE (xattr, M_TEMP);
				goto out;
			}
			
			/* Endian swap the multi-byte fields into host endianness from L.E. */
			xattr->xattr_major_version = OSSwapLittleToHostInt16(xattr->xattr_major_version);
			xattr->xattr_minor_version = OSSwapLittleToHostInt16(xattr->xattr_minor_version);
			xattr->key_size = OSSwapLittleToHostInt32(xattr->key_size);
			xattr->flags = OSSwapLittleToHostInt32(xattr->flags);
			xattr->persistent_class = OSSwapLittleToHostInt32(xattr->persistent_class);
			
			if (xattr->xattr_major_version != hfsmp->hfs_running_cp_major_vers ) {
				printf("hfs: cp_getxattr: bad xattr version %d expecting %d\n", 
					xattr->xattr_major_version, hfsmp->hfs_running_cp_major_vers);
				error = EINVAL;
				FREE (xattr, M_TEMP);

				goto out;
			}
			/*
			 * Prevent a buffer overflow, and validate the key length obtained from the
			 * EA. If it's too big, then bail out, because the EA can't be trusted at this
			 * point.
			 */
			if (xattr->key_size > CP_MAX_WRAPPEDKEYSIZE) {
				error = EINVAL;
				FREE (xattr, M_TEMP);

				goto out;	
			}

			/* set up entry with information from xattr */
			entry = cp_entry_alloc(xattr->key_size);
			if (!entry) {
				FREE (xattr, M_TEMP);

				return ENOMEM;
			}
			
			entry->cp_pclass = xattr->persistent_class;	
			if (xattr->xattr_major_version >= CP_NEW_MAJOR_VERS) {
				entry->cp_flags |= CP_OFF_IV_ENABLED;
			}
			bcopy(xattr->persistent_key, entry->cp_persistent_key, xattr->key_size);			

			FREE (xattr, M_TEMP);

			break;
		}
		case CP_PREV_MAJOR_VERS: {
			struct cp_xattr_v2 *xattr = NULL;
			MALLOC (xattr, struct cp_xattr_v2*, sizeof(struct cp_xattr_v2), M_TEMP, M_WAITOK);
			if (xattr == NULL) {
				error = ENOMEM;
				break;
			}
			bzero (xattr, sizeof (struct cp_xattr_v2));
			attrsize = sizeof(*xattr);

			uio_addiov(auio, CAST_USER_ADDR_T(xattr), attrsize);
			args.a_size = &attrsize;
			
			error = hfs_getxattr_internal(cp, &args, VTOHFS(cp->c_vp), 0);
			if (error != 0) {
				FREE (xattr, M_TEMP);
				goto out;
			}
			
			/* Endian swap the multi-byte fields into host endianness from L.E. */
			xattr->xattr_major_version = OSSwapLittleToHostInt16(xattr->xattr_major_version);
			xattr->xattr_minor_version = OSSwapLittleToHostInt16(xattr->xattr_minor_version);
			xattr->key_size = OSSwapLittleToHostInt32(xattr->key_size);
			xattr->flags = OSSwapLittleToHostInt32(xattr->flags);
			xattr->persistent_class = OSSwapLittleToHostInt32(xattr->persistent_class);
			
			if (xattr->xattr_major_version != hfsmp->hfs_running_cp_major_vers) {
				printf("hfs: cp_getxattr: bad xattr version %d expecting %d\n", 
					xattr->xattr_major_version, hfsmp->hfs_running_cp_major_vers);
				error = EINVAL;
				FREE (xattr, M_TEMP);
				goto out;
			}	

			/*
			 * Prevent a buffer overflow, and validate the key length obtained from the
			 * EA. If it's too big, then bail out, because the EA can't be trusted at this
			 * point.
			 */
			if (xattr->key_size > CP_V2_WRAPPEDKEYSIZE) {
				error = EINVAL;
				FREE (xattr, M_TEMP);
				goto out;	
			}
			/* set up entry with information from xattr */
			entry = cp_entry_alloc(xattr->key_size);
			if (!entry) {
				FREE (xattr, M_TEMP);
				return ENOMEM;
			}
			
			entry->cp_pclass = xattr->persistent_class;
			bcopy(xattr->persistent_key, entry->cp_persistent_key, xattr->key_size);
			FREE (xattr, M_TEMP);
			break;
		}
	}

out:
	uio_free(auio);
	
	*outentry = entry;	
	return error;
}


/* Setup AES context */
static int
cp_setup_aes_ctx(struct cprotect *entry)
{
	SHA1_CTX sha1ctxt;
	uint8_t	cp_cache_iv_key[CP_IV_KEYSIZE]; /* Kiv */
	
	/* First init the cp_cache_iv_key[] */
	SHA1Init(&sha1ctxt);
	SHA1Update(&sha1ctxt, &entry->cp_cache_key[0], CP_MAX_KEYSIZE);
	SHA1Final(&cp_cache_iv_key[0], &sha1ctxt);
	
	aes_encrypt_key128(&cp_cache_iv_key[0], &entry->cp_cache_iv_ctx);

	return 0;
}


/*
 * Make a new random per-file key and wrap it.
 * Normally this will get default_pclass as PROTECTION_CLASS_D.
 *
 * But when the directory's class is set, we use that as the default.
 */
static int
cp_make_keys(struct cprotect **entry_arg, struct hfsmount *hfsmp, cnid_t fileid, int default_pclass)
{
	struct cprotect *entry = *entry_arg;
	int target_pclass = 0;
	int error = 0;

	if (g_cp_state.wrap_functions_set != 1) {
		printf("hfs: CP: could not create keys: no wrappers set\n");
		return ENXIO;
	}

	/* create new cp data: key and class */
	entry->cp_cache_key_len = CP_MAX_KEYSIZE;
	read_random(&entry->cp_cache_key[0], entry->cp_cache_key_len);

	if (cp_is_valid_class(default_pclass) == 0) {
		target_pclass = PROTECTION_CLASS_D;
	} else {
		target_pclass = default_pclass;
	}

	/*
	 * Attempt to wrap the new key in the class key specified by target_pclass
	 * Note that because we may be inheriting a protection level specified
	 * by the containing directory, this can fail;  we could be trying to
	 * wrap this cache key in the class 'A' key while the device is locked.  
	 * As such, emit an error if we fail to wrap the key here, instead of
	 * panicking.
	 */

	error = cp_wrap(target_pclass, hfsmp, fileid, entry_arg);

	if (error) {
		goto out;
	}
	/* cp_wrap() potentially updates c_cpentry */
	entry = *entry_arg;

	/* set the pclass to the target since the wrap was successful */
	entry->cp_pclass = target_pclass;

	/* No need to go here for older EAs */
	if (hfsmp->hfs_running_cp_major_vers == CP_NEW_MAJOR_VERS) {
		cp_setup_aes_ctx(entry);
		entry->cp_flags |= CP_OFF_IV_ENABLED;
	}

	/* ready for business */
	entry->cp_flags &= ~CP_NEEDS_KEYS;
	entry->cp_flags |= CP_NO_XATTR;

out:
	return error;
}

/*
 * If permitted, restore entry's unwrapped key from the persistent key.
 * If not, clear key and set CP_KEY_FLUSHED.
 * cnode lock held exclusive
 */
static int
cp_restore_keys(struct cprotect *entry, struct hfsmount *hfsmp)
{
	int error = 0;

 	error = cp_unwrap(entry->cp_pclass, entry);
	if (error) {
		entry->cp_flags |= CP_KEY_FLUSHED;
		bzero(entry->cp_cache_key, entry->cp_cache_key_len);
		error = EPERM;
	}
	else {
		/* No need to go here for older EAs */
		if (hfsmp->hfs_running_cp_major_vers == CP_NEW_MAJOR_VERS) {		
			cp_setup_aes_ctx(entry);
			entry->cp_flags |= CP_OFF_IV_ENABLED;
		}
		
		/* ready for business */
		entry->cp_flags &= ~CP_KEY_FLUSHED;
		
	}
	return error;
}

static int
cp_lock_vfs_callback(mount_t mp, void *arg) {
    
    /*
     * When iterating the various mount points that may 
     * be present on a content-protected device, we need to skip
     * those that do not have it enabled.
     */
    if (!cp_fs_protected(mp)) {
        return 0;
    }
    
    return vnode_iterate(mp, 0, cp_lock_vnode_callback, arg);
}


/*
 * Deny access to protected files if keys have been locked.
 */
static int
cp_check_access(struct cnode *cp, int vnop __unused)
{
	int error = 0;

	if (g_cp_state.lock_state == CP_UNLOCKED_STATE) {
		return 0;
	}

	if (!cp->c_cpentry) {
		/* unprotected node */
		return 0;
	}

	if (!S_ISREG(cp->c_mode)) {
		return 0;
	}

	/* Deny all access for class A files */
	switch (cp->c_cpentry->cp_pclass) {
		case PROTECTION_CLASS_A: {
			error = EPERM;
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
cp_lock_vnode_callback(struct vnode *vp, void *arg)
{
	cnode_t *cp = NULL;
	struct cprotect *entry = NULL;
	int error = 0;
	int locked = 1;
	int action = 0;
	int took_truncate_lock = 0;

	error = vnode_getwithref (vp);
	if (error) {
		return error;
	}

	cp = VTOC(vp);
	
	/*
	 * When cleaning cnodes due to a lock event, we must
	 * take the truncate lock AND the cnode lock.  By taking
	 * the truncate lock here, we force (nearly) all pending IOs 
	 * to drain before we can acquire the truncate lock.  All HFS cluster
	 * io calls except for swapfile IO need to acquire the truncate lock
	 * prior to calling into the cluster layer.
	 */
	hfs_lock_truncate (cp, HFS_EXCLUSIVE_LOCK);
	took_truncate_lock = 1;
	
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
			if (entry->cp_pclass != PROTECTION_CLASS_A ||
				vnode_isdir(vp)) {
				/* 
				 * There is no change at lock for other classes than A.
				 * B is kept in memory for writing, and class F (for VM) does
				 * not have a wrapped key, so there is no work needed for 
				 * wrapping/unwrapping.  
				 * 
				 * Note that 'class F' is relevant here because if 
				 * hfs_vnop_strategy does not take the cnode lock
				 * to protect the cp blob across IO operations, we rely 
				 * implicitly on the truncate lock to be held when doing IO.  
				 * The only case where the truncate lock is not held is during 
				 * swapfile IO because HFS just funnels the VNOP_PAGEOUT 
				 * directly to cluster_pageout.  
				 */
				goto out;
			}
			
			/* Before doing anything else, zero-fill sparse ranges as needed */
			ctx = vfs_context_current();
			(void) hfs_filedone (vp, ctx);

			/* first, sync back dirty pages */
			hfs_unlock (cp);
			ubc_msync (vp, 0, ubc_getsize(vp), NULL, UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
			hfs_lock (cp, HFS_FORCE_LOCK);

			/* flush keys:
			 * There was a concern here(9206856) about flushing keys before nand layer is done using them.
			 * But since we are using ubc_msync with UBC_SYNC, it blocks until all IO is completed.
			 * Once IOFS caches or is done with these keys, it calls the completion routine in IOSF.
			 * Which in turn calls buf_biodone() and eventually unblocks ubc_msync()
			 * Also verified that the cached data in IOFS is overwritten by other data, and there 
			 * is no key leakage in that layer.
			 */

			entry->cp_flags |= CP_KEY_FLUSHED;
			bzero(&entry->cp_cache_key, entry->cp_cache_key_len);
			bzero(&entry->cp_cache_iv_ctx, sizeof(aes_encrypt_ctx));
			
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
			panic("Content Protection: unknown lock action %d\n", action);
	}
	
out:
	if (locked) {
		hfs_unlock(cp);
	}
	
	if (took_truncate_lock) {
		hfs_unlock_truncate (cp, 0);
	}
	
	vnode_put (vp);
	return error;
}

static int
cp_wrap(int class, struct hfsmount *hfsmp, cnid_t fileid, struct cprotect **entry_ptr)
{
	
	struct cprotect *entry = *entry_ptr;
	uint8_t newkey[CP_MAX_WRAPPEDKEYSIZE];
	size_t keylen = CP_MAX_WRAPPEDKEYSIZE;
	int error = 0;

	/*
	 * PROTECTION_CLASS_F is in-use by VM swapfile; it represents a transient 
	 * key that is only good as long as the file is open.  There is no
	 * wrapped key, so there isn't anything to wrap. 
	 */
	if (class == PROTECTION_CLASS_F) {
		bzero(entry->cp_persistent_key, entry->cp_persistent_key_len);
		entry->cp_persistent_key_len = 0;
		return 0;
	}

	/*
	 * inode is passed here to find the backup bag wrapped blob
	 * from userspace.  This lookup will occur shortly after creation
	 * and only if the file still exists.  Beyond this lookup the 
	 * inode is not used.  Technically there is a race, we practically
	 * don't lose.
	 */
	error = g_cp_wrap_func.wrapper(class,
								   fileid,
								   entry->cp_cache_key,
								   entry->cp_cache_key_len,
								   newkey,
								   &keylen);

	if (!error) {
		/*
		 * v2 EA's don't support the larger class B keys 
		 */
		if ((keylen != CP_V2_WRAPPEDKEYSIZE) &&
			(hfsmp->hfs_running_cp_major_vers == CP_PREV_MAJOR_VERS)) {
			return EINVAL;
		}

		/*
		 * Reallocate the entry if the new persistent key changed length
		 */
		if (entry->cp_persistent_key_len != keylen) {
			struct cprotect *oldentry = entry;

			entry = cp_entry_alloc(keylen);
			if (entry == NULL)
				return ENOMEM;

			bcopy(oldentry, entry, sizeof(struct cprotect));
			entry->cp_persistent_key_len = keylen;

			cp_entry_destroy (&oldentry);

			*entry_ptr = entry;
		}

		bcopy(newkey, entry->cp_persistent_key, keylen);		
	} 
	else {
		error = EPERM;
	}

	return error;
}


static int
cp_unwrap(int class, struct cprotect *entry)
{
	int error = 0;
	size_t keylen = CP_MAX_KEYSIZE;

	/*
	 * PROTECTION_CLASS_F is in-use by VM swapfile; it represents a transient 
	 * key that is only good as long as the file is open.  There is no
	 * wrapped key, so there isn't anything to unwrap. 
	 */
	if (class == PROTECTION_CLASS_F) {
		return EPERM;
	}

	error = g_cp_wrap_func.unwrapper(class,
									 entry->cp_persistent_key,
									 entry->cp_persistent_key_len,
									 entry->cp_cache_key,
									 &keylen);
	if (!error) {
		entry->cp_cache_key_len = keylen;
	} else {
		error = EPERM;
	}
	
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
