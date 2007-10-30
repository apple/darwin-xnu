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

#define kIBFilePrefix "file://"

int
imageboot_needed(void)
{
	int result = 0;
	char *root_path = NULL;

	DBG_TRACE("%s: checking for presence of root path\n", __FUNCTION__);

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (root_path == NULL)
		panic("%s: M_NAMEI zone exhausted", __FUNCTION__);

	if(PE_parse_boot_arg("rp", root_path) == TRUE) {
		/* Got it, now verify scheme */

		if (strncmp(root_path, kIBFilePrefix,
					strlen(kIBFilePrefix)) == 0) {
			DBG_TRACE("%s: Found %s\n", __FUNCTION__, root_path);
			result = 1;
		} else {
			DBG_TRACE("%s: Invalid URL scheme for %s\n",
					__FUNCTION__, root_path);
		}
	}
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);

	return (result);
}


/*
 * We know there's an image. Attach it, and
 * switch over to root off it
 *
 * NB: p is always kernproc
 */

int
imageboot_setup()
{
	dev_t       dev;
	int         error = 0;
	char *root_path = NULL;

	DBG_TRACE("%s: entry\n", __FUNCTION__);

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (root_path == NULL)
		return (ENOMEM);

	if(PE_parse_boot_arg("rp", root_path) == FALSE) {
		error = ENOENT;
		goto done;
	}

	printf("%s: root image url is %s\n", __FUNCTION__, root_path);
	error = di_root_image(root_path, rootdevice, &dev);
	if(error) {
		printf("%s: di_root_image failed: %d\n", __FUNCTION__, error);
		goto done;
	}

	rootdev = dev;
	mountroot = NULL;
	printf("%s: root device 0x%x\n", __FUNCTION__, rootdev);
	error = vfs_mountroot();

	if (error == 0 && rootvnode != NULL) {
		struct vnode *tvp;
		struct vnode *newdp;

		/*
		 * Get the vnode for '/'.
		 * Set fdp->fd_fd.fd_cdir to reference it.
		 */
		if (VFS_ROOT(TAILQ_LAST(&mountlist,mntlist), &newdp, vfs_context_kernel()))
			panic("%s: cannot find root vnode", __FUNCTION__);

		vnode_ref(newdp);
		vnode_put(newdp);
		tvp = rootvnode;
		vnode_rele(tvp);
		filedesc0.fd_cdir = newdp;
		rootvnode = newdp;
		mount_list_lock();
		TAILQ_REMOVE(&mountlist, TAILQ_FIRST(&mountlist), mnt_list);
		mount_list_unlock();
		mountlist.tqh_first->mnt_flag |= MNT_ROOTFS;
		DBG_TRACE("%s: root switched\n", __FUNCTION__);
	}
done:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);

	DBG_TRACE("%s: exit\n", __FUNCTION__);

	return (error);
}
