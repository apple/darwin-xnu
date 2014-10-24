/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
#include <sys/proc.h>
#include <sys/kauth.h>

#include "hfs.h"
#include "hfs_cnode.h"
#include "hfs_fsctl.h"

#if CONFIG_PROTECT
/* 
 * The wrap function pointers and the variable to indicate if they 
 * are initialized are system-wide, and hence are defined globally.
 */ 
static struct cp_wrap_func g_cp_wrap_func = {};
static int are_wraps_initialized = false;

extern int (**hfs_vnodeop_p) (void *);

/*
 * CP private functions
 */
static int cp_root_major_vers(mount_t mp);
static int cp_getxattr(cnode_t *, struct hfsmount *hfsmp, struct cprotect **);
static struct cprotect *cp_entry_alloc(size_t);
static void cp_entry_dealloc(struct cprotect *entry);
static int cp_restore_keys(struct cprotect *, struct hfsmount *hfsmp, struct cnode *);
static int cp_lock_vfs_callback(mount_t, void *);
static int cp_lock_vnode_callback(vnode_t, void *);
static int cp_vnode_is_eligible (vnode_t);
static int cp_check_access (cnode_t *cp, struct hfsmount *hfsmp, int vnop);
static int cp_new(int newclass, struct hfsmount *hfsmp, struct cnode *cp, mode_t cmode, 
		uint32_t flags, struct cprotect **output_entry);
static int cp_rewrap(struct cnode *cp, struct hfsmount *hfsmp, int newclass);
static int cp_unwrap(struct hfsmount *, struct cprotect *, struct cnode *);
static int cp_setup_aes_ctx(struct cprotect *entry);
static void cp_init_access(cp_cred_t access, struct cnode *cp);

static inline int cp_get_crypto_generation (uint32_t protclass) {
	if (protclass & CP_CRYPTO_G1) {
		return 1;
	}	
	else return 0;
}


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

	if (action < 0 || action > CP_MAX_STATE) {
		return -1;
	}
	
	/* 
	 * The lock state is kept locally to each data protected filesystem to 
	 * avoid using globals.  Pass along the lock request to each filesystem
	 * we iterate through.
	 */

	/*
	 * Upcast the value in 'action' to be a pointer-width unsigned integer.
	 * This avoids issues relating to pointer-width. 
	 */
	unsigned long action_arg = (unsigned long) action;
	return vfs_iterate(0, cp_lock_vfs_callback, (void*)action_arg);
}


int
cp_register_wraps(cp_wrap_func_t key_store_func)
{
	g_cp_wrap_func.new_key = key_store_func->new_key;
	g_cp_wrap_func.unwrapper = key_store_func->unwrapper;
	g_cp_wrap_func.rewrapper = key_store_func->rewrapper;
	/* do not use invalidater until rdar://12170050 goes in ! */
	g_cp_wrap_func.invalidater = key_store_func->invalidater;
	g_cp_wrap_func.backup_key = key_store_func->backup_key;

	/* Mark the functions as initialized in the function pointer container */
	are_wraps_initialized = true;

	return 0;
}

/*
 * Allocate and initialize a cprotect blob for a new cnode.
 * Called from hfs_getnewvnode: cnode is locked exclusive.
 * 
 * Read xattr data off the cnode. Then, if conditions permit,
 * unwrap the file key and cache it in the cprotect blob.
 */
int
cp_entry_init(struct cnode *cp, struct mount *mp)
{
	struct cprotect *entry = NULL;
	int error = 0;
	struct hfsmount *hfsmp = VFSTOHFS(mp);

	/*
	 * The cnode should be locked at this point, regardless of whether or not
	 * we are creating a new item in the namespace or vending a vnode on behalf
	 * of lookup.  The only time we tell getnewvnode to skip the lock is when 
	 * constructing a resource fork vnode. But a resource fork vnode must come
	 * after the regular data fork cnode has already been constructed.
	 */
	if (!cp_fs_protected (mp)) {
		cp->c_cpentry = NULL;
		return 0;
	}

	if (!S_ISREG(cp->c_mode) && !S_ISDIR(cp->c_mode)) {
		cp->c_cpentry = NULL;
		return 0;
	}

	if (are_wraps_initialized == false)  {
		printf("hfs: cp_update_entry: wrap functions not yet set\n");
		return ENXIO;
	}

	if (hfsmp->hfs_running_cp_major_vers == 0) {
		panic ("hfs cp: no running mount point version! ");		
	}

	CP_ASSERT (cp->c_cpentry == NULL);

	error = cp_getxattr(cp, hfsmp, &entry);
	if (error == 0) {
		/* 
		 * Success; attribute was found, though it may not have keys.
		 * If the entry is not returned without keys, we will delay generating
		 * keys until the first I/O.
		 */
		if (S_ISREG(cp->c_mode)) {
			if (entry->cp_flags & CP_NEEDS_KEYS) {
				entry->cp_flags &= ~CP_KEY_FLUSHED;
			}
			else {
				entry->cp_flags |= CP_KEY_FLUSHED;
			}
		}
	} 
	else if (error == ENOATTR) {
		/*
		 * Normally, we should always have a CP EA for a file or directory that
		 * we are initializing here. However, there are some extenuating circumstances,
		 * such as the root directory immediately following a newfs_hfs.
		 *
		 * As a result, we leave code here to deal with an ENOATTR which will always
		 * default to a 'D/NONE' key, though we don't expect to use it much.
		 */
		int target_class = PROTECTION_CLASS_D;
		
		if (S_ISDIR(cp->c_mode)) {
			target_class = PROTECTION_CLASS_DIR_NONE;
		}	
		/* allow keybag to override our class preferences */
		uint32_t keyflags = CP_KEYWRAP_DIFFCLASS;
		error = cp_new (target_class, hfsmp, cp, cp->c_mode, keyflags, &entry);
		if (error == 0) {
			error = cp_setxattr (cp, entry, hfsmp, cp->c_fileid, XATTR_CREATE);
		}
	}

	/* 
	 * Bail out if:
	 * a) error was not ENOATTR (we got something bad from the getxattr call)
	 * b) we encountered an error setting the xattr above.
	 * c) we failed to generate a new cprotect data structure.
	 */
	if (error) {
		goto out;
	}	

	cp->c_cpentry = entry;

out:
	if (error == 0) {
		entry->cp_backing_cnode = cp;
	}
	else {
		if (entry) {
			cp_entry_destroy(entry);
		}
		cp->c_cpentry = NULL;
	}

	return error;
}

/*
 * cp_setup_newentry
 * 
 * Generate a keyless cprotect structure for use with the new AppleKeyStore kext.
 * Since the kext is now responsible for vending us both wrapped/unwrapped keys
 * we need to create a keyless xattr upon file / directory creation. When we have the inode value
 * and the file/directory is established, then we can ask it to generate keys.  Note that
 * this introduces a potential race;  If the device is locked and the wrapping
 * keys are purged between the time we call this function and the time we ask it to generate
 * keys for us, we could have to fail the open(2) call and back out the entry.
 */

int cp_setup_newentry (struct hfsmount *hfsmp, struct cnode *dcp, int32_t suppliedclass, 
		mode_t cmode, struct cprotect **tmpentry) 
{
	int isdir = 0;
	struct cprotect *entry = NULL;
	uint32_t target_class = hfsmp->default_cp_class;
	suppliedclass = CP_CLASS(suppliedclass);

	if (hfsmp->hfs_running_cp_major_vers == 0) {
		panic ("CP: major vers not set in mount!");
	}
	
	if (S_ISDIR (cmode))  {
		isdir = 1;
	}

	/* Decide the target class.  Input argument takes priority. */
	if (cp_is_valid_class (isdir, suppliedclass)) {
		/* caller supplies -1 if it was not specified so we will default to the mount point value */
		target_class = suppliedclass;
		/*
		 * One exception, F is never valid for a directory
		 * because its children may inherit and userland will be
		 * unable to read/write to the files.
		 */
		if (isdir) {
			if (target_class == PROTECTION_CLASS_F) {
				*tmpentry = NULL;
				return EINVAL;
			}
		}
	}
	else {
		/* 
		 * If no valid class was supplied, behave differently depending on whether or not
		 * the item being created is a file or directory.
		 * 
		 * for FILE:
		 * 		If parent directory has a non-zero class, use that.
		 * 		If parent directory has a zero class (not set), then attempt to
		 *		apply the mount point default.
		 * 
		 * for DIRECTORY:
		 *		Directories always inherit from the parent; if the parent
		 * 		has a NONE class set, then we can continue to use that.
		 */
		if ((dcp) && (dcp->c_cpentry)) {
			uint32_t parentclass = CP_CLASS(dcp->c_cpentry->cp_pclass);
			/* If the parent class is not valid, default to the mount point value */
			if (cp_is_valid_class(1, parentclass)) {
				if (isdir) {
					target_class = parentclass;	
				}
				else if (parentclass != PROTECTION_CLASS_DIR_NONE) {
					/* files can inherit so long as it's not NONE */
					target_class = parentclass;
				}
			}
			/* Otherwise, we already defaulted to the mount point's default */
		}
	}

	/* Generate the cprotect to vend out */
	entry = cp_entry_alloc (0);
	if (entry == NULL) {
		*tmpentry = NULL;
		return ENOMEM;
	}	

	/* 
	 * We don't have keys yet, so fill in what we can.  At this point
	 * this blob has no keys and it has no backing xattr.  We just know the
	 * target class.
	 */
	entry->cp_flags = (CP_NEEDS_KEYS | CP_NO_XATTR);
	/* Note this is only the effective class */
	entry->cp_pclass = target_class;
	*tmpentry = entry;

	return 0;
}


/*
 * cp_needs_tempkeys
 * 
 * Relay to caller whether or not the filesystem should generate temporary keys
 * during resize operations.
 */

int cp_needs_tempkeys (struct hfsmount *hfsmp, int *needs) 
{

	if (hfsmp->hfs_running_cp_major_vers < CP_PREV_MAJOR_VERS || 
			hfsmp->hfs_running_cp_major_vers > CP_NEW_MAJOR_VERS)  {
		return -1;
	}

	/* CP_NEW_MAJOR_VERS implies CP_OFF_IV_ENABLED */
	if (hfsmp->hfs_running_cp_major_vers < CP_NEW_MAJOR_VERS) {
		*needs = 0;
	}
	else {
		*needs = 1;
	}

	return 0;
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
int cp_entry_gentempkeys(struct cprotect **entry_ptr, struct hfsmount *hfsmp) 
{

	struct cprotect *entry = NULL;

	if (hfsmp->hfs_running_cp_major_vers < CP_NEW_MAJOR_VERS) {
		return EPERM;
	}

	/*
	 * This should only be  used for files and won't be written out.  
	 * We don't need a persistent key.
	 */
	entry = cp_entry_alloc (0);
	if (entry == NULL) {
		*entry_ptr = NULL;
		return ENOMEM;
	}
	/* This is generated in-kernel so we leave it at the max key*/
	entry->cp_cache_key_len = CP_MAX_KEYSIZE;

	/* This pclass is only the effective class */
	entry->cp_pclass = PROTECTION_CLASS_F;
	entry->cp_persistent_key_len = 0;

	/* Generate the class F key */
	read_random (&entry->cp_cache_key[0], entry->cp_cache_key_len);

	/* Generate the IV key */
	cp_setup_aes_ctx(entry);
	entry->cp_flags |= CP_OFF_IV_ENABLED;

	*entry_ptr = entry;
	return 0;

}

/*
 * Tear down and clear a cprotect blob for a closing file.
 * Called at hfs_reclaim_cnode: cnode is locked exclusive.
 */
void
cp_entry_destroy(struct cprotect *entry_ptr) 
{
	if (entry_ptr == NULL) {
		/* nothing to clean up */
		return;
	}
	cp_entry_dealloc(entry_ptr);
}


int
cp_fs_protected (mount_t mnt) 
{
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
		return ENOTSUP;
	}

	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	/*
	 * Take the truncate lock up-front in shared mode because we may need
	 * to manipulate the CP blob. Pend lock events until we're done here.
	 */
	hfs_lock_truncate (cp, HFS_SHARED_LOCK, HFS_LOCK_DEFAULT);
	took_truncate_lock = 1;

	/*
	 * We take only the shared cnode lock up-front.  If it turns out that
	 * we need to manipulate the CP blob to write a key out, drop the
	 * shared cnode lock and acquire an exclusive lock.
	 */
	error = hfs_lock(cp, HFS_SHARED_LOCK, HFS_LOCK_DEFAULT);
	if (error) {
		hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
		return error;
	}

	/* pull the class from the live entry */
	entry = cp->c_cpentry;

	if (entry == NULL) {
		panic("Content Protection: uninitialized cnode %p", cp);
	}
	
	/* Note that we may not have keys yet, but we know the target class. */

	if (error == 0) {
		*class = CP_CLASS(entry->cp_pclass);
	}

	if (took_truncate_lock) {
		hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
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
	struct hfsmount *hfsmp = NULL;
	int isdir = 0;

	if (vnode_isdir (vp)) {
		isdir = 1;
	}

	/* Ensure we only use the effective class here */
	newclass = CP_CLASS(newclass);

	if (!cp_is_valid_class(isdir, newclass)) {
		printf("hfs: CP: cp_setclass called with invalid class %d\n", newclass);
		return EINVAL;
	}

	/* Is this an interesting vp? */
	if (!cp_vnode_is_eligible(vp)) {
		return EBADF;
	}

	/* Is the mount point formatted for content protection? */
	if (!cp_fs_protected(VTOVFS(vp))) {
		return ENOTSUP;
	}

	hfsmp = VTOHFS(vp);
	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		return EROFS;
	}

	/*
	 * Take the cnode truncate lock exclusive because we want to manipulate the
	 * CP blob. The lock-event handling code is doing the same.  This also forces
	 * all pending IOs to drain before we can re-write the persistent and cache keys.
	 */
	cp = VTOC(vp);
	hfs_lock_truncate (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
	took_truncate_lock = 1;

	/*
	 * The truncate lock is not sufficient to guarantee the CP blob
	 * isn't being used.  We must wait for existing writes to finish.
	 */
	vnode_waitforwrites(vp, 0, 0, 0, "cp_vnode_setclass");

	if (hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT)) {
		return EINVAL;
	}

	entry = cp->c_cpentry;
	if (entry == NULL) {
		error = EINVAL;
		goto out;
	}

	/* 
	 * re-wrap per-file key with new class.  
	 * Generate an entirely new key if switching to F. 
	 */
	if (vnode_isreg(vp)) {
		/*
		 * The vnode is a file.  Before proceeding with the re-wrap, we need
		 * to unwrap the keys before proceeding.  This is to ensure that 
		 * the destination class's properties still work appropriately for the
		 * target class (since B allows I/O but an unwrap prior to the next unlock
		 * will not be allowed).
		 */
		if (entry->cp_flags & CP_KEY_FLUSHED) {
			error = cp_restore_keys (entry, hfsmp, cp);
			if (error) {
				goto out;
			}
		}
		if (newclass == PROTECTION_CLASS_F) {
			/* Verify that file is blockless if switching to class F */
			if (cp->c_datafork->ff_size > 0) {
				error = EINVAL;
				goto out;	
			}

			/* newclass is only the effective class */
			entry->cp_pclass = newclass;

			/* Class F files are not wrapped, so they continue to use MAX_KEYSIZE */
			entry->cp_cache_key_len = CP_MAX_KEYSIZE;
			read_random (&entry->cp_cache_key[0], entry->cp_cache_key_len);
			if (hfsmp->hfs_running_cp_major_vers == CP_NEW_MAJOR_VERS) {
				cp_setup_aes_ctx (entry);
				entry->cp_flags |= CP_OFF_IV_ENABLED;
			}	
			bzero(entry->cp_persistent_key, entry->cp_persistent_key_len);
			entry->cp_persistent_key_len = 0;
		} else {
			/* Deny the setclass if file is to be moved from F to something else */
			if (entry->cp_pclass == PROTECTION_CLASS_F) {
				error = EPERM;
				goto out;
			}
			/* We cannot call cp_rewrap unless the keys were already in existence. */
			if (entry->cp_flags & CP_NEEDS_KEYS) {
				struct cprotect *newentry = NULL;
				/* 
				 * We want to fail if we can't wrap to the target class. By not setting
				 * CP_KEYWRAP_DIFFCLASS, we tell keygeneration that if it can't wrap 
				 * to 'newclass' then error out.
				 */
				uint32_t flags = 0;
				error = cp_generate_keys (hfsmp, cp, newclass, flags,  &newentry);
				if (error == 0) {
					cp_replace_entry (cp, newentry);
				}
				/* Bypass the setxattr code below since generate_keys does it for us */
				goto out;
			}
			else {
				error = cp_rewrap(cp, hfsmp, newclass);
			}
		}
		if (error) {
			/* we didn't have perms to set this class. leave file as-is and error out */
			goto out;
		}
	}
	else if (vnode_isdir(vp)) {
		/* For directories, just update the pclass.  newclass is only effective class */
		entry->cp_pclass = newclass;
		error = 0;	
	}
	else {
		/* anything else, just error out */
		error = EINVAL;
		goto out;	
	}
	
	/* 
	 * We get here if the new class was F, or if we were re-wrapping a cprotect that already
	 * existed. If the keys were never generated, then they'll skip the setxattr calls.
	 */

	error = cp_setxattr(cp, cp->c_cpentry, VTOHFS(vp), 0, XATTR_REPLACE);
	if (error == ENOATTR) {
		error = cp_setxattr(cp, cp->c_cpentry, VTOHFS(vp), 0, XATTR_CREATE);
	}

out:

	if (took_truncate_lock) {
		hfs_unlock_truncate (cp, HFS_LOCK_DEFAULT);
	}
	hfs_unlock(cp);
	return error;
}


int cp_vnode_transcode(vnode_t vp, void *key, unsigned *len)
{
	struct cnode *cp;
	struct cprotect *entry = 0;
	int error = 0;
	int took_truncate_lock = 0;
	struct hfsmount *hfsmp = NULL;

	/* Structures passed between HFS and AKS */
	cp_cred_s access_in;
	cp_wrapped_key_s wrapped_key_in, wrapped_key_out;

	/* Is this an interesting vp? */
	if (!cp_vnode_is_eligible(vp)) {
		return EBADF;
	}

	/* Is the mount point formatted for content protection? */
	if (!cp_fs_protected(VTOVFS(vp))) {
		return ENOTSUP;
	}

	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	/*
	 * Take the cnode truncate lock exclusive because we want to manipulate the
	 * CP blob. The lock-event handling code is doing the same.  This also forces
	 * all pending IOs to drain before we can re-write the persistent and cache keys.
	 */
	hfs_lock_truncate (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
	took_truncate_lock = 1;

	if (hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT)) {
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
		error = EINVAL;
		goto out;
	}

	/* Send the per-file key in wrapped form for re-wrap with the current class information
	 * Send NULLs in the output parameters of the wrapper() and AKS will do the rest.
	 * Don't need to process any outputs, so just clear the locks and pass along the error. */
	if (vnode_isreg(vp)) {

		/* Picked up the following from cp_wrap().
		 * If needed, more comments available there. */

		if (CP_CLASS(entry->cp_pclass) == PROTECTION_CLASS_F) {
			error = EINVAL;
			goto out;
		}

		cp_init_access(&access_in, cp);

		bzero(&wrapped_key_in, sizeof(wrapped_key_in));
		bzero(&wrapped_key_out, sizeof(wrapped_key_out));
		wrapped_key_in.key = entry->cp_persistent_key;
		wrapped_key_in.key_len = entry->cp_persistent_key_len;
		/* Use the actual persistent class when talking to AKS */
		wrapped_key_in.dp_class = entry->cp_pclass;
		wrapped_key_out.key = key;
		wrapped_key_out.key_len = *len;

		error = g_cp_wrap_func.backup_key(&access_in,
						&wrapped_key_in,
						&wrapped_key_out);

		if(error)
			error = EPERM;
		else
			*len = wrapped_key_out.key_len;
	}

out:
	if (took_truncate_lock) {
		hfs_unlock_truncate (cp, HFS_LOCK_DEFAULT);
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

	if ((error = hfs_lock(cp, HFS_SHARED_LOCK, HFS_LOCK_DEFAULT))) {
		return error;
	}

	entry = cp->c_cpentry;

	if (entry == NULL) {
		/*
		 * If this cnode is not content protected, simply return success.
		 * Note that this function is called by all I/O-based call sites
		 * when CONFIG_PROTECT is enabled during XNU building.
		 */

		/* 
		 * All files should have cprotect structs.  It's possible to encounter
		 * a directory from a V2.0 CP system but all files should have protection
		 * EAs
		 */
		if (vnode_isreg(vp)) {
			error = EPERM;
		}

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

	if ((error = cp_check_access(cp, hfsmp, vnop))) {
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
		if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT))) {
			return error;
		}
	} else {
		cp->c_lockowner = current_thread();
	}

	/* generate new keys if none have ever been saved */
	if ((entry->cp_flags & CP_NEEDS_KEYS)) {
		struct cprotect *newentry = NULL;
		/* 
		 * It's ok if this ends up being wrapped in a different class than 'pclass'.
		 * class modification is OK here. 
		 */		
		uint32_t flags = CP_KEYWRAP_DIFFCLASS;

		error = cp_generate_keys (hfsmp, cp, CP_CLASS(cp->c_cpentry->cp_pclass), flags, &newentry);	
		if (error == 0) {
			cp_replace_entry (cp, newentry);
			entry = newentry;
		}
		else {
			goto out;
		}
	}

	/* unwrap keys if needed */
	if (entry->cp_flags & CP_KEY_FLUSHED) {
		if ((vnop == CP_READ_ACCESS) && (ioflag & IO_ENCRYPTED)) {
			/* no need to try to restore keys; they are not going to be used */
			error = 0;
		}
		else {
			error = cp_restore_keys(entry, hfsmp, cp);
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
	struct hfsmount *hfsmp;
	int error = 0;

	/* If vnode not eligible, just return success */
	if (!cp_vnode_is_eligible(vp)) {
		return 0;
	}

	/* If mount point not properly set up, then also return success */
	if (!cp_fs_protected(VTOVFS(vp))) {
		return 0;
	}

	/* We know the vnode is in a valid state. Acquire cnode and validate */
	cp = VTOC(vp);
	hfsmp = VTOHFS(vp);

	if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT))) {
		return error;
	}

	entry = cp->c_cpentry;
	if (entry == NULL) {
		/* 
		 * If the mount is protected and we couldn't get a cprotect for this vnode,
		 * then it's not valid for opening.
		 */
		if (vnode_isreg(vp)) {
			error = EPERM;
		}
		goto out;
	}

	if (!S_ISREG(cp->c_mode))
		goto out;

	/*
	 * Does the cnode have keys yet?  If not, then generate them.
	 */
	if (entry->cp_flags & CP_NEEDS_KEYS) {
		struct cprotect *newentry = NULL;
		/* Allow the keybag to override our class preferences */
		uint32_t flags = CP_KEYWRAP_DIFFCLASS;
		error = cp_generate_keys (hfsmp, cp, CP_CLASS(cp->c_cpentry->cp_pclass), flags, &newentry);
		if (error == 0) {
			cp_replace_entry (cp, newentry);
			entry = newentry;
		}	
		else {
			goto out;
		}
	}	

	/*
	 * We want to minimize the number of unwraps that we'll have to do since 
	 * the cost can vary, depending on the platform we're running. 
	 */
	switch (CP_CLASS(entry->cp_pclass)) {
		case PROTECTION_CLASS_B:
			if (mode & O_CREAT) {
				/* 
				 * Class B always allows creation.  Since O_CREAT was passed through
				 * we infer that this was a newly created vnode/cnode.  Even though a potential
				 * race exists when multiple threads attempt to create/open a particular
				 * file, only one can "win" and actually create it.  VFS will unset the
				 * O_CREAT bit on the loser.	 
				 * 
				 * Note that skipping the unwrap check here is not a security issue -- 
				 * we have to unwrap the key permanently upon the first I/O.
				 */
				break;
			}
			
			if ((entry->cp_flags & CP_KEY_FLUSHED) == 0) {
				/*
				 * For a class B file, attempt the unwrap if we have the key in
				 * core already. 
				 * The device could have just transitioned into the lock state, and 
				 * this vnode may not yet have been purged from the vnode cache (which would
				 * remove the keys). 
				 */
				cp_cred_s access_in;
				cp_wrapped_key_s wrapped_key_in;

				cp_init_access(&access_in, cp);
				bzero(&wrapped_key_in, sizeof(wrapped_key_in));
				wrapped_key_in.key = entry->cp_persistent_key;
				wrapped_key_in.key_len = entry->cp_persistent_key_len;
				/* Use the persistent class when talking to AKS */
				wrapped_key_in.dp_class = entry->cp_pclass;
				error = g_cp_wrap_func.unwrapper(&access_in, &wrapped_key_in, NULL);
				if (error) {
					error = EPERM;
				}
				break;
			}
			/* otherwise, fall through to attempt the unwrap/restore */
		case PROTECTION_CLASS_A:
		case PROTECTION_CLASS_C:
			/*
			 * At this point, we know that we need to attempt an unwrap if needed; we want
			 * to makes sure that open(2) fails properly if the device is either just-locked
			 * or never made it past first unlock.  Since the keybag serializes access to the
			 * unwrapping keys for us and only calls our VFS callback once they've been purged, 
			 * we will get here in two cases:
			 * 
			 * A) we're in a window before the wrapping keys are purged; this is OK since when they get 
			 * purged, the vnode will get flushed if needed.
			 * 
			 * B) The keys are already gone.  In this case, the restore_keys call below will fail. 
			 *
			 * Since this function is bypassed entirely if we're opening a raw encrypted file, 
			 * we can always attempt the restore.
			 */
			if (entry->cp_flags & CP_KEY_FLUSHED) {
				error = cp_restore_keys(entry, hfsmp, cp);
			}
	
			if (error) {
				error = EPERM;
			}
	
			break;

		case PROTECTION_CLASS_D:
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
cp_handle_relocate (struct cnode *cp, struct hfsmount *hfsmp) 
{
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
	if ((error = cp_check_access(cp, hfsmp,  CP_READ_ACCESS | CP_WRITE_ACCESS))) {
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
		error = cp_restore_keys(entry, hfsmp, cp);
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
cp_getrootxattr(struct hfsmount* hfsmp, struct cp_root_xattr *outxattr) 
{
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
	
	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		return EROFS;
	}
	
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

	/* Note that it's OK to write out an XATTR without keys. */
	/* Disable flags that will be invalid as we're writing the EA out at this point. */
	tempflags = entry->cp_flags;

	/* we're writing the EA; CP_NO_XATTR is invalid */
	tempflags &= ~CP_NO_XATTR;
	
	/* CP_SEP_WRAPPEDKEY is informational/runtime only. */
	tempflags &= ~CP_SEP_WRAPPEDKEY;

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
		default:
			printf("hfs: cp_setxattr: Unknown CP version running \n");
			break;
	}

	if (error == 0 ) {
		entry->cp_flags &= ~CP_NO_XATTR;
	}

	return error;


}

/*
 * Used by an fcntl to query the underlying FS for its content protection version #
 */

int
cp_get_root_major_vers(vnode_t vp, uint32_t *level) 
{
	int err = 0;
	struct hfsmount *hfsmp = NULL;
	struct mount *mp = NULL;

	mp = VTOVFS(vp);

	/* check if it supports content protection */
	if (cp_fs_protected(mp) == 0) {
		return ENOTSUP;
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

/* Used by fcntl to query default protection level of FS */
int cp_get_default_level (struct vnode *vp, uint32_t *level) {
	int err = 0;
	struct hfsmount *hfsmp = NULL;
	struct mount *mp = NULL;

	mp = VTOVFS(vp);

	/* check if it supports content protection */
	if (cp_fs_protected(mp) == 0) {
		return ENOTSUP;
	}

	hfsmp = VFSTOHFS(mp);
	/* figure out the default */

	*level = hfsmp->default_cp_class;
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



int
cp_is_valid_class(int isdir, int32_t protectionclass)
{
	/* 
	 * The valid protection classes are from 0 -> N
	 * We use a signed argument to detect unassigned values from 
	 * directory entry creation time in HFS.
	 */
	if (isdir) {
		/* Directories are not allowed to have F, but they can have "NONE" */
		return ((protectionclass >= PROTECTION_CLASS_DIR_NONE) && 
				(protectionclass <= PROTECTION_CLASS_D));
	}
	else {
		return ((protectionclass >= PROTECTION_CLASS_A) &&
				(protectionclass <= PROTECTION_CLASS_F));
	}
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

			/* 
			 * Class F files have no backing key; their keylength should be 0,
			 * though they should have the proper flags set.
			 *
			 * A request to instantiate a CP for a class F file should result 
			 * in a bzero'd cp that just says class F, with key_flushed set.
			 */

			/* set up entry with information from xattr */
			entry = cp_entry_alloc(xattr->key_size);
			if (!entry) {
				FREE (xattr, M_TEMP);

				return ENOMEM;
			}

			entry->cp_pclass = xattr->persistent_class;

			/* 
			 * Suppress invalid flags that should not be set. 
			 * If we have gotten this far, then CP_NO_XATTR cannot possibly
			 * be valid; the EA exists.
			 */
			xattr->flags &= ~CP_NO_XATTR;

			entry->cp_flags = xattr->flags;
			if (xattr->xattr_major_version >= CP_NEW_MAJOR_VERS) {
				entry->cp_flags |= CP_OFF_IV_ENABLED;
			}

			if (CP_CLASS(entry->cp_pclass) != PROTECTION_CLASS_F ) {
				bcopy(xattr->persistent_key, entry->cp_persistent_key, xattr->key_size);
			}

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

			/* 
			 * Suppress invalid flags that should not be set. 
			 * If we have gotten this far, then CP_NO_XATTR cannot possibly
			 * be valid; the EA exists.
			 */
			xattr->flags &= ~CP_NO_XATTR;

			entry->cp_flags = xattr->flags;

			if (CP_CLASS(entry->cp_pclass) != PROTECTION_CLASS_F ) {
				bcopy(xattr->persistent_key, entry->cp_persistent_key, xattr->key_size);
			}

			FREE (xattr, M_TEMP);
			break;
		}
	}

out:
	uio_free(auio);

	*outentry = entry;
	return error;
}

/*
 * If permitted, restore entry's unwrapped key from the persistent key.
 * If not, clear key and set CP_KEY_FLUSHED.
 * cnode lock held exclusive
 */
static int
cp_restore_keys(struct cprotect *entry, struct hfsmount *hfsmp, struct cnode *cp)
{
	int error = 0;

 	error = cp_unwrap(hfsmp, entry, cp);
	if (error) {
		entry->cp_flags |= CP_KEY_FLUSHED;
		bzero(entry->cp_cache_key, entry->cp_cache_key_len);
		error = EPERM;
	}
	else {
		/* ready for business */
		entry->cp_flags &= ~CP_KEY_FLUSHED;

	}
	return error;
}

static int
cp_lock_vfs_callback(mount_t mp, void *arg) 
{

	/* Use a pointer-width integer field for casting */
	unsigned long new_state;
	struct hfsmount *hfsmp;

	/*
	 * When iterating the various mount points that may
	 * be present on a content-protected device, we need to skip
	 * those that do not have it enabled.
	 */
	if (!cp_fs_protected(mp)) {
		return 0;
	}
	new_state = (unsigned long) arg;
	
	hfsmp = VFSTOHFS(mp);

	hfs_lock_mount(hfsmp);
	/* this loses all of the upper bytes of precision; that's OK */
	hfsmp->hfs_cp_lock_state = (uint8_t) new_state;
	hfs_unlock_mount(hfsmp);

	if (new_state == CP_LOCKED_STATE) { 
		/* 
		 * We respond only to lock events.  Since cprotect structs
		 * decrypt/restore keys lazily, the unlock events don't
		 * actually cause anything to happen.
		 */
		return vnode_iterate(mp, 0, cp_lock_vnode_callback, arg);
	}
	/* Otherwise just return 0. */
	return 0;

}


/*
 * Deny access to protected files if keys have been locked.
 */
static int
cp_check_access(struct cnode *cp, struct hfsmount *hfsmp, int vnop __unused)
{
	int error = 0;

	/* 
	 * For now it's OK to examine the state variable here without
	 * holding the HFS lock.  This is only a short-circuit; if the state
	 * transitions (or is in transition) after we examine this field, we'd
	 * have to handle that anyway. 
	 */
	if (hfsmp->hfs_cp_lock_state == CP_UNLOCKED_STATE) {
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
	switch (CP_CLASS(cp->c_cpentry->cp_pclass)) {
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
	unsigned long action = 0;
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
	hfs_lock_truncate (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
	took_truncate_lock = 1;

	hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);

	entry = cp->c_cpentry;
	if (!entry) {
		/* unprotected vnode: not a regular file */
		goto out;
	}

	action = (unsigned long) arg;
	switch (action) {
		case CP_LOCKED_STATE: {
			vfs_context_t ctx;
			if (CP_CLASS(entry->cp_pclass) != PROTECTION_CLASS_A ||
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
			(void) hfs_filedone (vp, ctx, 0);

			/* first, sync back dirty pages */
			hfs_unlock (cp);
			ubc_msync (vp, 0, ubc_getsize(vp), NULL, UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
			hfs_lock (cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);

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
			panic("Content Protection: unknown lock action %lu\n", action);
	}

out:
	if (locked) {
		hfs_unlock(cp);
	}

	if (took_truncate_lock) {
		hfs_unlock_truncate (cp, HFS_LOCK_DEFAULT);
	}

	vnode_put (vp);
	return error;
}


/* 
 * cp_rewrap:
 *
 * Generate a new wrapped key based on the existing cache key.
 */

static int
cp_rewrap(struct cnode *cp, struct hfsmount *hfsmp, int newclass) 
{

	struct cprotect *entry = cp->c_cpentry;
	uint8_t new_persistent_key[CP_MAX_WRAPPEDKEYSIZE];
	size_t keylen = CP_MAX_WRAPPEDKEYSIZE;
	int error = 0;
	newclass = CP_CLASS(newclass);

	/* Structures passed between HFS and AKS */
	cp_cred_s access_in;
	cp_wrapped_key_s wrapped_key_in;
	cp_wrapped_key_s wrapped_key_out;

	/*
	 * PROTECTION_CLASS_F is in-use by VM swapfile; it represents a transient
	 * key that is only good as long as the file is open.  There is no
	 * wrapped key, so there isn't anything to wrap.
	 */
	if (newclass == PROTECTION_CLASS_F) {
		return EINVAL;
	}

	cp_init_access(&access_in, cp);

	bzero(&wrapped_key_in, sizeof(wrapped_key_in));
	wrapped_key_in.key = entry->cp_persistent_key;
	wrapped_key_in.key_len = entry->cp_persistent_key_len;
	/* Use the persistent class when talking to AKS */
	wrapped_key_in.dp_class = entry->cp_pclass;

	bzero(&wrapped_key_out, sizeof(wrapped_key_out));
	wrapped_key_out.key = new_persistent_key;
	wrapped_key_out.key_len = keylen;

	/*
	 * inode is passed here to find the backup bag wrapped blob
	 * from userspace.  This lookup will occur shortly after creation
	 * and only if the file still exists.  Beyond this lookup the
	 * inode is not used.  Technically there is a race, we practically
	 * don't lose.
	 */
	error = g_cp_wrap_func.rewrapper(&access_in,
			newclass, /* new class */
			&wrapped_key_in,
			&wrapped_key_out);

	keylen = wrapped_key_out.key_len;

	if (error == 0) {
		struct cprotect *newentry = NULL;
		/* 
		 * Verify that AKS returned to us a wrapped key of the 
		 * target class requested.   
		 */
		/* Get the effective class here */
		int effective = CP_CLASS(wrapped_key_out.dp_class);
		if (effective != newclass) {
			/* 
			 * Fail the operation if defaults or some other enforcement
			 * dictated that the class be wrapped differently. 
			 */

			/* TODO: Invalidate the key when 12170074 unblocked */
			return EPERM;
		}

		/* v2 EA's don't support the larger class B keys */
		if ((keylen != CP_V2_WRAPPEDKEYSIZE) &&
				(hfsmp->hfs_running_cp_major_vers == CP_PREV_MAJOR_VERS)) {
			return EINVAL;
		}

		/* Allocate a new cpentry */
		newentry = cp_entry_alloc (keylen);
		bcopy (entry, newentry, sizeof(struct cprotect));

		/* copy the new key into the entry */
		bcopy (new_persistent_key, newentry->cp_persistent_key, keylen);
		newentry->cp_persistent_key_len = keylen;
		newentry->cp_backing_cnode = cp;

		/* Actually record/store what AKS reported back, not the effective class stored in newclass */
		newentry->cp_pclass = wrapped_key_out.dp_class;

		/* Attach the new entry to the cnode */
		cp->c_cpentry = newentry;

		/* destroy the old entry */
		cp_entry_destroy (entry);
	}
	else {
		error = EPERM;
	}

	return error;
}


static int
cp_unwrap(struct hfsmount *hfsmp, struct cprotect *entry, struct cnode *cp)
{
	int error = 0;
	uint8_t iv_key[CP_IV_KEYSIZE];

	/* Structures passed between HFS and AKS */
	cp_cred_s access_in;
	cp_wrapped_key_s wrapped_key_in;
	cp_raw_key_s key_out;

	/*
	 * PROTECTION_CLASS_F is in-use by VM swapfile; it represents a transient
	 * key that is only good as long as the file is open.  There is no
	 * wrapped key, so there isn't anything to unwrap.
	 */
	if (CP_CLASS(entry->cp_pclass) == PROTECTION_CLASS_F) {
		return EPERM;
	}

	cp_init_access(&access_in, cp);

	bzero(&wrapped_key_in, sizeof(wrapped_key_in));
	wrapped_key_in.key = entry->cp_persistent_key;
	wrapped_key_in.key_len = entry->cp_persistent_key_len;
	/* Use the persistent class when talking to AKS */
	wrapped_key_in.dp_class = entry->cp_pclass;

	bzero(&key_out, sizeof(key_out));
	key_out.iv_key = iv_key;
	key_out.key = entry->cp_cache_key;
	/* 
	 * The unwrapper should validate/set the key length for 
	 * the IV key length and the cache key length, however we need
	 * to supply the correct buffer length so that AKS knows how
	 * many bytes it has to work with.
	 */
	key_out.iv_key_len = CP_IV_KEYSIZE;
	key_out.key_len = CP_MAX_CACHEBUFLEN;

	error = g_cp_wrap_func.unwrapper(&access_in, &wrapped_key_in, &key_out);
	if (!error) {
		if (key_out.key_len == 0 || key_out.key_len > CP_MAX_CACHEBUFLEN) {
			panic ("cp_unwrap: invalid key length! (%ul)\n", key_out.key_len);
		}

		if (key_out.iv_key_len == 0 || key_out.iv_key_len > CP_IV_KEYSIZE) {
			panic ("cp_unwrap: invalid iv key length! (%ul)\n", key_out.iv_key_len);
		}
		
		entry->cp_cache_key_len = key_out.key_len;

		/* No need to go here for older EAs */
		if (hfsmp->hfs_running_cp_major_vers == CP_NEW_MAJOR_VERS) {
			aes_encrypt_key128(iv_key, &entry->cp_cache_iv_ctx);
			entry->cp_flags |= CP_OFF_IV_ENABLED;
		}

		/* Is the key a raw wrapped key? */
		if (key_out.flags & CP_RAW_KEY_WRAPPEDKEY) {
			/* OR in the right bit for the cprotect */
			entry->cp_flags |= CP_SEP_WRAPPEDKEY;
		}

	} else {
		error = EPERM;
	}

	return error;
}

/* Setup AES context */
static int
cp_setup_aes_ctx(struct cprotect *entry)
{
    SHA1_CTX sha1ctxt;
    uint8_t cp_cache_iv_key[CP_IV_KEYSIZE]; /* Kiv */

    /* First init the cp_cache_iv_key[] */
    SHA1Init(&sha1ctxt);
	
	/*
	 * We can only use this when the keys are generated in the AP; As a result
	 * we only use the first 32 bytes of key length in the cache key 
	 */
    SHA1Update(&sha1ctxt, &entry->cp_cache_key[0], CP_MAX_KEYSIZE);
    SHA1Final(&cp_cache_iv_key[0], &sha1ctxt);

    aes_encrypt_key128(&cp_cache_iv_key[0], &entry->cp_cache_iv_ctx);

    return 0;
}

/*
 * cp_generate_keys
 *
 * Take a cnode that has already been initialized and establish persistent and
 * cache keys for it at this time. Note that at the time this is called, the
 * directory entry has already been created and we are holding the cnode lock
 * on 'cp'.
 * 
 */
int cp_generate_keys (struct hfsmount *hfsmp, struct cnode *cp, int targetclass, 
		uint32_t keyflags, struct cprotect **newentry) 
{

	int error = 0;
	struct cprotect *newcp = NULL;
	*newentry = NULL;

	/* Target class must be an effective class only */
	targetclass = CP_CLASS(targetclass);

	/* Validate that it has a cprotect already */
	if (cp->c_cpentry == NULL) {
		/* We can't do anything if it shouldn't be protected. */
		return 0;
	}	

	/* Asserts for the underlying cprotect */
	if (cp->c_cpentry->cp_flags & CP_NO_XATTR) {
		/* should already have an xattr by this point. */
		error = EINVAL;
		goto out;
	}

	if (S_ISREG(cp->c_mode)) {
		if ((cp->c_cpentry->cp_flags & CP_NEEDS_KEYS) == 0){
			error = EINVAL;
			goto out;
		}
	}

	error = cp_new (targetclass, hfsmp, cp, cp->c_mode, keyflags, &newcp);
	if (error) {
		/* 
		 * Key generation failed. This is not necessarily fatal
		 * since the device could have transitioned into the lock 
		 * state before we called this.  
		 */	
		error = EPERM;
		goto out;
	}
	
	/* 
	 * If we got here, then we have a new cprotect.
	 * Attempt to write the new one out.
	 */
	error = cp_setxattr (cp, newcp, hfsmp, cp->c_fileid, XATTR_REPLACE);

	if (error) {
		/* Tear down the new cprotect; Tell MKB that it's invalid. Bail out */
		/* TODO: rdar://12170074 needs to be fixed before we can tell MKB */
		if (newcp) {
			cp_entry_destroy(newcp);
		}	
		goto out;
	}

	/* 
	 * If we get here then we can assert that:
	 * 1) generated wrapped/unwrapped keys.
	 * 2) wrote the new keys to disk.
	 * 3) cprotect is ready to go.
	 */
	
	newcp->cp_flags &= ~CP_NEEDS_KEYS;
	*newentry = newcp;
	
out:
	return error;

}

void cp_replace_entry (struct cnode *cp, struct cprotect *newentry) 
{
	
	if (cp->c_cpentry) {
		cp_entry_destroy (cp->c_cpentry);	
	}
	cp->c_cpentry = newentry;
	newentry->cp_backing_cnode = cp;

	return;
}


/*
 * cp_new
 *
 * Given a double-pointer to a cprotect, generate keys (either in-kernel or from keystore),
 * allocate a cprotect, and vend it back to the caller.
 * 
 * Additionally, decide if keys are even needed -- directories get cprotect data structures
 * but they do not have keys.
 *
 */ 

static int
cp_new(int newclass_eff, struct hfsmount *hfsmp, struct cnode *cp, mode_t cmode, 
		uint32_t keyflags, struct cprotect **output_entry)
{
	struct cprotect *entry = NULL;
	int error = 0;
	uint8_t new_key[CP_MAX_CACHEBUFLEN];
	size_t new_key_len = CP_MAX_CACHEBUFLEN;  /* AKS tell us the proper key length, how much of this is used */
	uint8_t new_persistent_key[CP_MAX_WRAPPEDKEYSIZE];
	size_t new_persistent_len = CP_MAX_WRAPPEDKEYSIZE;
	uint8_t iv_key[CP_IV_KEYSIZE];
	size_t iv_key_len = CP_IV_KEYSIZE;
	int iswrapped = 0;

	newclass_eff = CP_CLASS(newclass_eff);

	/* Structures passed between HFS and AKS */
	cp_cred_s access_in;
	cp_wrapped_key_s wrapped_key_out;
	cp_raw_key_s key_out;

	if (*output_entry != NULL) {
		panic ("cp_new with non-null entry!");
	}

	if (are_wraps_initialized == false) {
		printf("hfs: cp_new: wrap/gen functions not yet set\n");
		return ENXIO;
	}

	/* Sanity check that it's a file or directory here */
	if (!(S_ISREG(cmode)) && !(S_ISDIR(cmode))) {
		return EPERM;
	}

	/*
	 * Step 1: Generate Keys if needed.
	 * 
	 * For class F files, the kernel provides the key.
	 * PROTECTION_CLASS_F is in-use by VM swapfile; it represents a transient
	 * key that is only good as long as the file is open.  There is no
	 * wrapped key, so there isn't anything to wrap.
	 *
	 * For class A->D files, the key store provides the key 
	 * 
	 * For Directories, we only give them a class ; no keys.
	 */
	if (S_ISDIR (cmode)) {
		/* Directories */
		new_persistent_len = 0;
		new_key_len = 0;

		error = 0;
	}
	else {
		/* Must be a file */         
		if (newclass_eff == PROTECTION_CLASS_F) {
			/* class F files are not wrapped; they can still use the max key size */
			new_key_len = CP_MAX_KEYSIZE;
			read_random (&new_key[0], new_key_len);
			new_persistent_len = 0;

			error = 0;
		}
		else {
			/* 
			 * The keystore is provided the file ID so that it can associate
			 * the wrapped backup blob with this key from userspace. This 
			 * lookup occurs after successful file creation.  Beyond this, the
			 * file ID is not used.  Note that there is a potential race here if
			 * the file ID is re-used.  
			 */
			cp_init_access(&access_in, cp);
		
			bzero(&key_out, sizeof(key_out));
			key_out.key = new_key;
			key_out.iv_key = iv_key;
			/* 
			 * AKS will override our key length fields, but we need to supply
			 * the length of the buffer in those length fields so that 
			 * AKS knows hoa many bytes it has to work with.
			 */
			key_out.key_len = new_key_len;
			key_out.iv_key_len = iv_key_len;

			bzero(&wrapped_key_out, sizeof(wrapped_key_out));
			wrapped_key_out.key = new_persistent_key;
			wrapped_key_out.key_len = new_persistent_len;

			error = g_cp_wrap_func.new_key(&access_in, 
					newclass_eff, 
					&key_out,
					&wrapped_key_out);

			if (error) {
				/* keybag returned failure */
				error = EPERM;
				goto cpnew_fail;
			}

			/* Now sanity-check the output from new_key */
			if (key_out.key_len == 0 || key_out.key_len > CP_MAX_CACHEBUFLEN) {
				panic ("cp_new: invalid key length! (%ul) \n", key_out.key_len);
			}

			if (key_out.iv_key_len == 0 || key_out.iv_key_len > CP_IV_KEYSIZE) {
				panic ("cp_new: invalid iv key length! (%ul) \n", key_out.iv_key_len);
			}	
		
			/* 
			 * AKS is allowed to override our preferences and wrap with a 
			 * different class key for policy reasons. If we were told that 
			 * any class other than the one specified is unacceptable then error out 
			 * if that occurred.  Check that the effective class returned by 
			 * AKS is the same as our effective new class 
			 */
			if ((int)(CP_CLASS(wrapped_key_out.dp_class)) != newclass_eff) {
				if (keyflags & CP_KEYWRAP_DIFFCLASS) {
					newclass_eff = CP_CLASS(wrapped_key_out.dp_class);
				}
				else {
					error = EPERM;	
					/* TODO: When 12170074 fixed, release/invalidate the key! */
					goto cpnew_fail;
				}
			}

			new_key_len = key_out.key_len;
			iv_key_len = key_out.iv_key_len;
			new_persistent_len = wrapped_key_out.key_len;

			/* Is the key a SEP wrapped key? */
			if (key_out.flags & CP_RAW_KEY_WRAPPEDKEY) {
				iswrapped = 1;
			}
		}
	}

	/*
	 * Step 2: allocate cprotect and initialize it.
	 */


	/*
	 * v2 EA's don't support the larger class B keys
	 */
	if ((new_persistent_len != CP_V2_WRAPPEDKEYSIZE) &&
			(hfsmp->hfs_running_cp_major_vers == CP_PREV_MAJOR_VERS)) {
		return EINVAL;
	}

	entry = cp_entry_alloc (new_persistent_len);
	if (entry == NULL) {
		return ENOMEM;
	}

	*output_entry = entry;

	/*
	 * For directories and class F files, just store the effective new class. 
	 * AKS does not interact with us in generating keys for F files, and directories
	 * don't actually have keys. 
	 */
	if ( S_ISDIR (cmode) || (newclass_eff == PROTECTION_CLASS_F)) {
		entry->cp_pclass = newclass_eff;
	}
	else {			
		/* 
		 * otherwise, store what AKS actually returned back to us. 
		 * wrapped_key_out is only valid if we have round-tripped to AKS
		 */
		entry->cp_pclass = wrapped_key_out.dp_class;
	}

	/* Copy the cache key & IV keys into place if needed. */
	if (new_key_len > 0) {
		bcopy (new_key, entry->cp_cache_key, new_key_len);
		entry->cp_cache_key_len = new_key_len;


		/* Initialize the IV key */
		if (hfsmp->hfs_running_cp_major_vers == CP_NEW_MAJOR_VERS) {
			if (newclass_eff == PROTECTION_CLASS_F) {
				/* class F needs a full IV initialize */
				cp_setup_aes_ctx(entry);
			}
			else {
				/* Key store gave us an iv key. Just need to wrap it.*/
				aes_encrypt_key128(iv_key, &entry->cp_cache_iv_ctx);
			}
			entry->cp_flags |= CP_OFF_IV_ENABLED;
		}
	}
	if (new_persistent_len > 0) {
		bcopy(new_persistent_key, entry->cp_persistent_key, new_persistent_len);
	}

	/* Mark it as a wrapped key if necessary */
	if (iswrapped) {
		entry->cp_flags |= CP_SEP_WRAPPEDKEY;
	}

cpnew_fail:
	return error;
}

/* Initialize the cp_cred_t structure passed to AKS */
static void cp_init_access(cp_cred_t access, struct cnode *cp)
{
	vfs_context_t context = vfs_context_current();
	kauth_cred_t cred = vfs_context_ucred(context);
	proc_t proc = vfs_context_proc(context);

	bzero(access, sizeof(*access));

	/* Note: HFS uses 32-bit fileID, even though inode is a 64-bit value */
	access->inode = cp->c_fileid;
	access->pid = proc_pid(proc);
	access->uid = kauth_cred_getuid(cred);

	return;
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
