/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/systm.h>
#include <sys/systm.h>
#include <sys/mount_internal.h>
#include <sys/filedesc.h>
#include <sys/vnode_internal.h>
#include <sys/imageboot.h>
#include <kern/assert.h>

#include <pexpert/pexpert.h>

extern struct filedesc filedesc0;

extern int (*mountroot)(void);
extern char rootdevice[];

#define DEBUG_IMAGEBOOT 0

#if DEBUG_IMAGEBOOT
#define DBG_TRACE(...) printf(__VA_ARGS__)
#else
#define DBG_TRACE(...) do {} while(0)
#endif

extern int di_root_image(const char *path, char devname[], dev_t *dev_p);
static boolean_t imageboot_setup_new(void);

#define kIBFilePrefix "file://"

__private_extern__ int
imageboot_format_is_valid(const char *root_path)
{
	return (strncmp(root_path, kIBFilePrefix,
				strlen(kIBFilePrefix)) == 0);
}

static void
vnode_get_and_drop_always(vnode_t vp) 
{
	vnode_getalways(vp);
	vnode_rele(vp);
	vnode_put(vp);
}

__private_extern__ int
imageboot_needed(void)
{
	int result = 0;
	char *root_path = NULL;
	
	DBG_TRACE("%s: checking for presence of root path\n", __FUNCTION__);

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (root_path == NULL)
		panic("%s: M_NAMEI zone exhausted", __FUNCTION__);

	/* Check for first layer */
	if (!(PE_parse_boot_argn("rp0", root_path, MAXPATHLEN) || 
			PE_parse_boot_argn("rp", root_path, MAXPATHLEN) ||
			PE_parse_boot_argn(IMAGEBOOT_ROOT_ARG, root_path, MAXPATHLEN))) {
		goto out;
	}
	
	/* Sanity-check first layer */
	if (imageboot_format_is_valid(root_path)) {
		DBG_TRACE("%s: Found %s\n", __FUNCTION__, root_path);
	} else {
		goto out;
	}

	result = 1;

	/* Check for second layer */
	if (!(PE_parse_boot_argn("rp1", root_path, MAXPATHLEN) ||
			PE_parse_boot_argn(IMAGEBOOT_CONTAINER_ARG, root_path, MAXPATHLEN))) {
		goto out;
	}

	/* Sanity-check second layer */
	if (imageboot_format_is_valid(root_path)) {
		DBG_TRACE("%s: Found %s\n", __FUNCTION__, root_path);
	} else {
		panic("%s: Invalid URL scheme for %s\n",
				__FUNCTION__, root_path);
	}

out:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);

	return (result);
}


/*
 * Swaps in new root filesystem based on image path.
 * Current root filesystem is removed from mount list and
 * tagged MNTK_BACKS_ROOT, MNT_ROOTFS is cleared on it, and 
 * "rootvnode" is reset.  Root vnode of currentroot filesystem 
 * is returned with usecount (no iocount).
 */
__private_extern__ int
imageboot_mount_image(const char *root_path, int height)
{
	dev_t       	dev;
	int 		error;
	vnode_t 	old_rootvnode = NULL;
	vnode_t 	newdp;
	mount_t 	new_rootfs;

	error = di_root_image(root_path, rootdevice, &dev);
	if (error) {
		panic("%s: di_root_image failed: %d\n", __FUNCTION__, error);
	}

	rootdev = dev;
	mountroot = NULL;
	printf("%s: root device 0x%x\n", __FUNCTION__, rootdev);
	error = vfs_mountroot();
	if (error != 0) {
		panic("vfs_mountroot() failed.\n");
	}

	/*
	 * Get the vnode for '/'.
	 * Set fdp->fd_fd.fd_cdir to reference it.
	 */
	if (VFS_ROOT(TAILQ_LAST(&mountlist,mntlist), &newdp, vfs_context_kernel()))
		panic("%s: cannot find root vnode", __FUNCTION__);

	if (rootvnode != NULL) {
		/* remember the old rootvnode, but remove it from mountlist */
		mount_t 	old_rootfs;

		old_rootvnode = rootvnode;
		old_rootfs = rootvnode->v_mount;
	
		mount_list_remove(old_rootfs);
	
		mount_lock(old_rootfs);
#ifdef CONFIG_IMGSRC_ACCESS
		old_rootfs->mnt_kern_flag |= MNTK_BACKS_ROOT;
#endif /* CONFIG_IMGSRC_ACCESS */
		old_rootfs->mnt_flag &= ~MNT_ROOTFS;
		mount_unlock(old_rootfs);
	}

	/* switch to the new rootvnode */
	rootvnode = newdp;

	new_rootfs = rootvnode->v_mount;
	mount_lock(new_rootfs);
	new_rootfs->mnt_flag |= MNT_ROOTFS;
	mount_unlock(new_rootfs);

	vnode_ref(newdp);
	vnode_put(newdp);
	filedesc0.fd_cdir = newdp;
	DBG_TRACE("%s: root switched\n", __FUNCTION__);

	if (old_rootvnode != NULL) {
#ifdef CONFIG_IMGSRC_ACCESS
	    if (height >= 0 && PE_imgsrc_mount_supported()) {
		imgsrc_rootvnodes[height] = old_rootvnode;
	    } else {
		vnode_get_and_drop_always(old_rootvnode);
	    }
#else 
	    height = 0; /* keep the compiler from complaining */
	    vnode_get_and_drop_always(old_rootvnode);
#endif /* CONFIG_IMGSRC_ACCESS */
	}
	return 0;
}

static boolean_t 
imageboot_setup_new()
{
	int error;
	char *root_path = NULL;
	int height = 0;
	boolean_t done = FALSE;

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	assert(root_path != NULL);

	if(PE_parse_boot_argn(IMAGEBOOT_CONTAINER_ARG, root_path, MAXPATHLEN) == TRUE) {
		printf("%s: container image url is %s\n", __FUNCTION__, root_path);
		error = imageboot_mount_image(root_path, height);
		if (error != 0) {
			panic("Failed to mount container image.");
		}

		height++;
	}

	if (PE_parse_boot_argn(IMAGEBOOT_ROOT_ARG, root_path, MAXPATHLEN) == FALSE) {
		if (height > 0) {
			panic("%s specified without %s?\n", IMAGEBOOT_CONTAINER_ARG, IMAGEBOOT_ROOT_ARG);
		}
		goto out;

	}

	printf("%s: root image url is %s\n", __FUNCTION__, root_path);

	error = imageboot_mount_image(root_path, height);
	if (error != 0) {
		panic("Failed to mount root image.");
	}

	done = TRUE;

out:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);
	return done;
}

__private_extern__ void
imageboot_setup()
{
	int         error = 0;
	char *root_path = NULL;

	DBG_TRACE("%s: entry\n", __FUNCTION__);

	if (rootvnode == NULL) {	
		panic("imageboot_setup: rootvnode is NULL.");
	}

	/*
	 * New boot-arg scheme:
	 * 	root-dmg : the dmg that will be the root filesystem.
	 * 	container-dmg : an optional dmg that contains the root-dmg.
	 */
	if (imageboot_setup_new()) {
		return;
	}
	
	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	assert(root_path != NULL);

	/*
	 * Look for outermost disk image to root from.  If we're doing a nested boot,
	 * there's some sense in which the outer image never needs to be the root filesystem,
	 * but it does need very similar treatment: it must not be unmounted, needs a fake
	 * device vnode created for it, and should not show up in getfsstat() until exposed 
	 * with MNT_IMGSRC. We just make it the temporary root.
	 */
	if((PE_parse_boot_argn("rp", root_path, MAXPATHLEN) == FALSE) &&
		(PE_parse_boot_argn("rp0", root_path, MAXPATHLEN) == FALSE)) {
		panic("%s: no valid path to image.\n", __FUNCTION__);
	}

	printf("%s: root image url is %s\n", __FUNCTION__, root_path);
	
	error = imageboot_mount_image(root_path, 0);
	if (error) {
		panic("Failed on first stage of imageboot.");
	}

	/*
	 * See if we are rooting from a nested image
	 */
	if(PE_parse_boot_argn("rp1", root_path, MAXPATHLEN) == FALSE) {
		goto done;
	}
	
	printf("%s: second level root image url is %s\n", __FUNCTION__, root_path);

	/*
	 * If we fail to set up second image, it's not a given that we
	 * can safely root off the first.  
	 */
	error = imageboot_mount_image(root_path, 1);
	if (error) {
		panic("Failed on second stage of imageboot.");	
	}

done:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);

	DBG_TRACE("%s: exit\n", __FUNCTION__);

	return;
}
