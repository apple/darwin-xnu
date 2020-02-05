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

#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/sysproto.h>
#include <sys/csr.h>
#include <miscfs/devfs/devfsdefs.h>
#include <libkern/crypto/sha2.h>
#include <libkern/crypto/rsa.h>
#include <libkern/OSKextLibPrivate.h>

#if CONFIG_IMAGEBOOT_IMG4
#include <libkern/img4/interface.h>
#include <img4/img4.h>
#endif

#include <kern/kalloc.h>

#include <pexpert/pexpert.h>
#include <kern/chunklist.h>

extern struct filedesc filedesc0;

extern int (*mountroot)(void);
extern char rootdevice[DEVMAXNAMESIZE];

#if CONFIG_LOCKERBOOT
typedef struct _locker_mount_args {
	char lmnt_path[PATH_MAX];
	uint16_t lmnt_preferred_hash;
} locker_mount_args_t;
#endif

#define DEBUG_IMAGEBOOT 0

#if DEBUG_IMAGEBOOT
#define DBG_TRACE(...) printf("imageboot: " __VA_ARGS__)
#else
#define DBG_TRACE(...) do {} while(0)
#endif

#define AUTHDBG(fmt, args...) do { printf("%s: " fmt "\n", __func__, ##args); } while (0)
#define AUTHPRNT(fmt, args...) do { printf("%s: " fmt "\n", __func__, ##args); } while (0)
#define kfree_safe(x) do { if ((x)) { kfree_addr((x)); (x) = NULL; } } while (0)

extern int di_root_image(const char *path, char *devname, size_t devsz, dev_t *dev_p);
extern int di_root_ramfile_buf(void *buf, size_t bufsz, char *devname, size_t devsz, dev_t *dev_p);

static boolean_t imageboot_setup_new(imageboot_type_t type);

vnode_t imgboot_get_image_file(const char *path, off_t *fsize, int *errp); /* may be required by chunklist.c */
int read_file(const char *path, void **bufp, size_t *bufszp); /* may be required by chunklist.c */

#define kIBFilePrefix "file://"

__private_extern__ int
imageboot_format_is_valid(const char *root_path)
{
	return strncmp(root_path, kIBFilePrefix,
	           strlen(kIBFilePrefix)) == 0;
}

static void
vnode_get_and_drop_always(vnode_t vp)
{
	vnode_getalways(vp);
	vnode_rele(vp);
	vnode_put(vp);
}

__private_extern__ imageboot_type_t
imageboot_needed(void)
{
	imageboot_type_t result = IMAGEBOOT_NONE;
	char *root_path = NULL;

	DBG_TRACE("%s: checking for presence of root path\n", __FUNCTION__);

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (root_path == NULL) {
		panic("%s: M_NAMEI zone exhausted", __FUNCTION__);
	}

#if CONFIG_LOCKERBOOT
	if (PE_parse_boot_argn(IMAGEBOOT_LOCKER_ARG, root_path, MAXPATHLEN)) {
		result = IMAGEBOOT_LOCKER;
		goto out;
	}
#endif

	/* Check for first layer */
	if (!(PE_parse_boot_argn("rp0", root_path, MAXPATHLEN) ||
#if CONFIG_IMAGEBOOT_IMG4
	    PE_parse_boot_argn("arp0", root_path, MAXPATHLEN) ||
#endif
	    PE_parse_boot_argn("rp", root_path, MAXPATHLEN) ||
	    PE_parse_boot_argn(IMAGEBOOT_ROOT_ARG, root_path, MAXPATHLEN) ||
	    PE_parse_boot_argn(IMAGEBOOT_AUTHROOT_ARG, root_path, MAXPATHLEN))) {
		goto out;
	}

	/* Sanity-check first layer */
	if (imageboot_format_is_valid(root_path)) {
		DBG_TRACE("%s: Found %s\n", __FUNCTION__, root_path);
	} else {
		goto out;
	}

	result = IMAGEBOOT_DMG;

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

	return result;
}


/*
 * Swaps in new root filesystem based on image path.
 * Current root filesystem is removed from mount list and
 * tagged MNTK_BACKS_ROOT, MNT_ROOTFS is cleared on it, and
 * "rootvnode" is reset.  Root vnode of currentroot filesystem
 * is returned with usecount (no iocount).
 */
__private_extern__ int
imageboot_mount_image(const char *root_path, int height, imageboot_type_t type)
{
	dev_t           dev;
	int             error;
	/*
	 * Need to stash this here since we may do a kernel_mount() on /, which will
	 * automatically update the rootvnode global. Note that vfs_mountroot() does
	 * not update that global, which is a bit weird.
	 */
	vnode_t         old_rootvnode = rootvnode;
	vnode_t         newdp;
	mount_t         new_rootfs;
	boolean_t update_rootvnode = FALSE;

	if (type == IMAGEBOOT_DMG) {
		error = di_root_image(root_path, rootdevice, DEVMAXNAMESIZE, &dev);
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

		update_rootvnode = TRUE;
	}
#if CONFIG_LOCKERBOOT
	else if (type == IMAGEBOOT_LOCKER) {
		locker_mount_args_t *mntargs = kalloc(sizeof(*mntargs));
		if (!mntargs) {
			panic("could not alloc mount args");
		}

		strlcpy(mntargs->lmnt_path, root_path, sizeof(mntargs->lmnt_path));
		mntargs->lmnt_preferred_hash = 0;

		DBG_TRACE("%s: mounting locker: %s\n", __FUNCTION__, root_path);
		error = kernel_mount(LOCKERFS_NAME, NULLVP, NULLVP, "/",
		    mntargs, sizeof(*mntargs), 0, 0, vfs_context_kernel());
		if (error) {
			panic("failed to mount locker: %d", error);
		}
		kfree(mntargs, sizeof(*mntargs));

		/* Clear the old mount association. */
		old_rootvnode->v_mountedhere = NULL;
		rootvnode->v_mount->mnt_vnodecovered = NULL;
	}
#endif
	else {
		panic("invalid imageboot type: %d", type);
	}

	/*
	 * Get the vnode for '/'.
	 * Set fdp->fd_fd.fd_cdir to reference it.
	 */
	if (VFS_ROOT(TAILQ_LAST(&mountlist, mntlist), &newdp, vfs_context_kernel())) {
		panic("%s: cannot find root vnode", __FUNCTION__);
	}
	DBG_TRACE("%s: old root fsname: %s\n", __FUNCTION__, old_rootvnode->v_mount->mnt_vtable->vfc_name);

	if (old_rootvnode != NULL) {
		/* remember the old rootvnode, but remove it from mountlist */
		mount_t old_rootfs = old_rootvnode->v_mount;

		mount_list_remove(old_rootfs);
		mount_lock(old_rootfs);
#ifdef CONFIG_IMGSRC_ACCESS
		old_rootfs->mnt_kern_flag |= MNTK_BACKS_ROOT;
#endif /* CONFIG_IMGSRC_ACCESS */
		old_rootfs->mnt_flag &= ~MNT_ROOTFS;
		mount_unlock(old_rootfs);
	}

	/* switch to the new rootvnode */
	if (update_rootvnode) {
		rootvnode = newdp;
	}

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
#pragma unused(height)
		vnode_get_and_drop_always(old_rootvnode);
#endif /* CONFIG_IMGSRC_ACCESS */
	}
	return 0;
}

int
read_file(const char *path, void **bufp, size_t *bufszp)
{
	int err = 0;
	struct nameidata ndp = {};
	struct vnode *vp = NULL;
	off_t fsize = 0;
	int resid = 0;
	char *buf = NULL;
	bool doclose = false;

	vfs_context_t ctx = vfs_context_kernel();
	proc_t p = vfs_context_proc(ctx);
	kauth_cred_t kerncred = vfs_context_ucred(ctx);

	NDINIT(&ndp, LOOKUP, OP_OPEN, LOCKLEAF, UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);
	if ((err = namei(&ndp)) != 0) {
		AUTHPRNT("namei failed (%s) - %d", path, err);
		goto out;
	}
	nameidone(&ndp);
	vp = ndp.ni_vp;

	if ((err = vnode_size(vp, &fsize, ctx)) != 0) {
		AUTHPRNT("failed to get vnode size of %s - %d", path, err);
		goto out;
	}
	if (fsize < 0) {
		panic("negative file size");
	}

	if ((err = VNOP_OPEN(vp, FREAD, ctx)) != 0) {
		AUTHPRNT("failed to open %s - %d", path, err);
		goto out;
	}
	doclose = true;

	/* if bufsz is non-zero, cap the read at bufsz bytes */
	if (*bufszp && *bufszp < (size_t)fsize) {
		fsize = *bufszp;
	}

	buf = kalloc(fsize);
	if (buf == NULL) {
		err = ENOMEM;
		goto out;
	}

	if ((err = vn_rdwr(UIO_READ, vp, (caddr_t)buf, fsize, 0, UIO_SYSSPACE, IO_NODELOCKED, kerncred, &resid, p)) != 0) {
		AUTHPRNT("Cannot read %d bytes from %s - %d", (int)fsize, path, err);
		goto out;
	}

	if (resid) {
		/* didnt get everything we wanted */
		AUTHPRNT("Short read of %d bytes from %s - %d", (int)fsize, path, resid);
		err = EINVAL;
		goto out;
	}

out:
	if (doclose) {
		VNOP_CLOSE(vp, FREAD, ctx);
	}
	if (vp) {
		vnode_put(vp);
		vp = NULL;
	}

	if (err) {
		kfree_safe(buf);
	} else {
		*bufp = buf;
		*bufszp = fsize;
	}

	return err;
}

#if CONFIG_IMAGEBOOT_IMG4 || CONFIG_IMAGEBOOT_CHUNKLIST
vnode_t
imgboot_get_image_file(const char *path, off_t *fsize, int *errp)
{
	struct nameidata ndp = {};
	vnode_t vp = NULL;
	vfs_context_t ctx = vfs_context_kernel();
	int err;

	NDINIT(&ndp, LOOKUP, OP_OPEN, LOCKLEAF, UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);
	if ((err = namei(&ndp)) != 0) {
		AUTHPRNT("Cannot find %s - error %d", path, err);
	} else {
		nameidone(&ndp);
		vp = ndp.ni_vp;

		if (vp->v_type != VREG) {
			err = EINVAL;
			AUTHPRNT("%s it not a regular file", path);
		} else if (fsize) {
			if ((err = vnode_size(vp, fsize, ctx)) != 0) {
				AUTHPRNT("Cannot get file size of %s - error %d", path, err);
			}
		}
	}

	if (err) {
		*errp = err;
		vp = NULL;
	}
	return vp;
}
#endif /* CONFIG_IMAGEBOOT_CHUNKLIST || CONFIG_IMAGEBOOT_CHUNKLIST */

#if CONFIG_IMAGEBOOT_IMG4

#define APTICKET_NAME "apticket.der"

static char *
imgboot_get_apticket_path(const char *rootpath)
{
	size_t plen = strlen(rootpath) + sizeof(APTICKET_NAME);
	char *path = kalloc(plen);

	if (path) {
		char *slash;

		strlcpy(path, rootpath, plen);
		slash = strrchr(path, '/');
		if (slash == NULL) {
			slash = path;
		} else {
			slash++;
		}
		strlcpy(slash, APTICKET_NAME, sizeof(APTICKET_NAME) + 1);
	}
	return path;
}

static int
authenticate_root_with_img4(const char *rootpath)
{
	errno_t rv;
	img4_t i4;
	img4_payload_t i4pl;
	vnode_t vp;
	char *ticket_path;
	size_t tcksz = 0;
	void *tckbuf = NULL;

	DBG_TRACE("Check %s\n", rootpath);

	if (img4if == NULL) {
		AUTHPRNT("AppleImage4 is not ready");
		return EAGAIN;
	}

	ticket_path = imgboot_get_apticket_path(rootpath);
	if (ticket_path == NULL) {
		AUTHPRNT("Cannot construct ticket path - out of memory");
		return ENOMEM;
	}

	rv = read_file(ticket_path, &tckbuf, &tcksz);
	if (rv) {
		AUTHPRNT("Cannot get a ticket from %s - %d\n", ticket_path, rv);
		goto out_with_ticket_path;
	}

	DBG_TRACE("Got %d bytes of manifest from %s\n", (int)tcksz, ticket_path);

	rv = img4_init(&i4, 0, tckbuf, tcksz, NULL);
	if (rv) {
		AUTHPRNT("Cannot initialise verification handle - error %d", rv);
		goto out_with_ticket_bytes;
	}

	vp = imgboot_get_image_file(rootpath, NULL, &rv);
	if (vp == NULL) {
		/* Error message had been printed already */
		goto out;
	}

	rv = img4_payload_init_with_vnode_4xnu(&i4pl, 'rosi', vp, I4PLF_UNWRAPPED);
	if (rv) {
		AUTHPRNT("failed to init payload: %d", rv);
		goto out;
	}

	rv = img4_get_trusted_external_payload(&i4, &i4pl, IMG4_ENVIRONMENT_PPL, NULL, NULL);
	if (rv) {
		AUTHPRNT("failed to validate root image %s: %d", rootpath, rv);
	}

	img4_payload_destroy(&i4pl);
out:
	img4_destroy(&i4);
out_with_ticket_bytes:
	kfree_safe(tckbuf);
out_with_ticket_path:
	kfree_safe(ticket_path);
	return rv;
}
#endif /* CONFIG_IMAGEBOOT_IMG4 */


/*
 * Attach the image at 'path' as a ramdisk and mount it as our new rootfs.
 * All existing mounts are first umounted.
 */
static int
imageboot_mount_ramdisk(const char *path)
{
	int err = 0;
	size_t bufsz = 0;
	void *buf = NULL;
	dev_t dev;
	vnode_t newdp;
	mount_t new_rootfs;

	/* Read our target image from disk */
	err = read_file(path, &buf, &bufsz);
	if (err) {
		printf("%s: failed: read_file() = %d\n", __func__, err);
		goto out;
	}
	DBG_TRACE("%s: read '%s' sz = %lu\n", __func__, path, bufsz);

#if CONFIG_IMGSRC_ACCESS
	/* Re-add all root mounts to the mount list in the correct order... */
	mount_list_remove(rootvnode->v_mount);
	for (int i = 0; i < MAX_IMAGEBOOT_NESTING; i++) {
		struct vnode *vn = imgsrc_rootvnodes[i];
		if (vn) {
			vnode_getalways(vn);
			imgsrc_rootvnodes[i] = NULLVP;

			mount_t mnt = vn->v_mount;
			mount_lock(mnt);
			mnt->mnt_flag |= MNT_ROOTFS;
			mount_list_add(mnt);
			mount_unlock(mnt);

			vnode_rele(vn);
			vnode_put(vn);
		}
	}
	mount_list_add(rootvnode->v_mount);
#endif

	/* ... and unmount everything */
	vnode_get_and_drop_always(rootvnode);
	filedesc0.fd_cdir = NULL;
	rootvnode = NULL;
	vfs_unmountall();

	/* Attach the ramfs image ... */
	err = di_root_ramfile_buf(buf, bufsz, rootdevice, DEVMAXNAMESIZE, &dev);
	if (err) {
		printf("%s: failed: di_root_ramfile_buf() = %d\n", __func__, err);
		goto out;
	}

	/* ... and mount it */
	rootdev = dev;
	mountroot = NULL;
	err = vfs_mountroot();
	if (err) {
		printf("%s: failed: vfs_mountroot() = %d\n", __func__, err);
		goto out;
	}

	/* Switch to new root vnode */
	if (VFS_ROOT(TAILQ_LAST(&mountlist, mntlist), &newdp, vfs_context_kernel())) {
		panic("%s: cannot find root vnode", __func__);
	}
	rootvnode = newdp;
	rootvnode->v_flag |= VROOT;
	new_rootfs = rootvnode->v_mount;
	mount_lock(new_rootfs);
	new_rootfs->mnt_flag |= MNT_ROOTFS;
	mount_unlock(new_rootfs);

	vnode_ref(newdp);
	vnode_put(newdp);
	filedesc0.fd_cdir = newdp;

	DBG_TRACE("%s: root switched\n", __func__);

out:
	if (err) {
		kfree_safe(buf);
	}
	return err;
}

/*
 * If the path is in <file://> URL format then we allocate memory and decode it,
 * otherwise return the same pointer.
 *
 * Caller is expected to check if the pointers are different.
 */
static char *
url_to_path(char *url_path)
{
	char *path = url_path;
	size_t len = strlen(kIBFilePrefix);

	if (strncmp(kIBFilePrefix, url_path, len) == 0) {
		/* its a URL - remove the file:// prefix and percent-decode */
		url_path += len;

		len = strlen(url_path);
		if (len) {
			/* Make a copy of the path to URL-decode */
			path = kalloc(len + 1);
			if (path == NULL) {
				panic("imageboot path allocation failed - cannot allocate %d bytes\n", (int)len);
			}

			strlcpy(path, url_path, len + 1);
			url_decode(path);
		} else {
			panic("Bogus imageboot path URL - missing path\n");
		}

		DBG_TRACE("%s: root image URL <%s> becomes %s\n", __func__, url_path, path);
	}

	return path;
}

static boolean_t
imageboot_setup_new(imageboot_type_t type)
{
	int error;
	char *root_path = NULL;
	int height = 0;
	boolean_t done = FALSE;
	boolean_t auth_root = TRUE;
	boolean_t ramdisk_root = FALSE;

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	assert(root_path != NULL);

#if CONFIG_LOCKERBOOT
	if (type == IMAGEBOOT_LOCKER) {
		if (!PE_parse_boot_argn(IMAGEBOOT_LOCKER_ARG, root_path, MAXPATHLEN)) {
			panic("locker boot with no locker given");
		}

		DBG_TRACE("%s: root fsname: %s\n", __FUNCTION__, rootvnode->v_mount->mnt_vtable->vfc_name);

		/*
		 * The locker path is a path, not a URL, so just pass it directly to
		 * imageboot_mount_image().
		 */
		error = imageboot_mount_image(root_path, 0, type);
		if (error) {
			panic("failed to mount system locker: %d", error);
		}

		done = TRUE;
		goto out;
	}
#endif /* CONFIG_LOCKERBOOT */

	unsigned imgboot_arg;
	if (PE_parse_boot_argn("-rootdmg-ramdisk", &imgboot_arg, sizeof(imgboot_arg))) {
		ramdisk_root = TRUE;
	}

	if (PE_parse_boot_argn(IMAGEBOOT_CONTAINER_ARG, root_path, MAXPATHLEN) == TRUE) {
		printf("%s: container image url is %s\n", __FUNCTION__, root_path);
		error = imageboot_mount_image(root_path, height, type);
		if (error != 0) {
			panic("Failed to mount container image.");
		}

		height++;
	}

	if (PE_parse_boot_argn(IMAGEBOOT_AUTHROOT_ARG, root_path, MAXPATHLEN) == FALSE &&
	    PE_parse_boot_argn(IMAGEBOOT_ROOT_ARG, root_path, MAXPATHLEN) == FALSE) {
		if (height > 0) {
			panic("%s specified without %s or %s?\n", IMAGEBOOT_CONTAINER_ARG, IMAGEBOOT_AUTHROOT_ARG, IMAGEBOOT_ROOT_ARG);
		}
		goto out;
	}

	printf("%s: root image URL is '%s'\n", __func__, root_path);

#if CONFIG_CSR
	if (auth_root && (csr_check(CSR_ALLOW_ANY_RECOVERY_OS) == 0)) {
		AUTHPRNT("CSR_ALLOW_ANY_RECOVERY_OS set, skipping root image authentication");
		auth_root = FALSE;
	}
#endif

	/* Make a copy of the path to URL-decode */
	char *path = url_to_path(root_path);
	assert(path);

#if CONFIG_IMAGEBOOT_CHUNKLIST
	if (auth_root) {
		AUTHDBG("authenticating root image at %s", path);
		error = authenticate_root_with_chunklist(path);
		if (error) {
			panic("root image authentication failed (err = %d)\n", error);
		}
		AUTHDBG("successfully authenticated %s", path);
	}
#endif

	if (ramdisk_root) {
		error = imageboot_mount_ramdisk(path);
	} else {
		error = imageboot_mount_image(root_path, height, type);
	}

	if (path != root_path) {
		kfree_safe(path);
	}

	if (error) {
		panic("Failed to mount root image (err=%d, auth=%d, ramdisk=%d)\n",
		    error, auth_root, ramdisk_root);
	}

#if CONFIG_IMAGEBOOT_CHUNKLIST
	if (auth_root) {
		/* check that the image version matches the running kernel */
		AUTHDBG("checking root image version");
		error = authenticate_root_version_check();
		if (error) {
			panic("root image version check failed");
		} else {
			AUTHDBG("root image version matches kernel");
		}
	}
#endif

	done = TRUE;

out:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);
	return done;
}

__private_extern__ void
imageboot_setup(imageboot_type_t type)
{
	int         error = 0;
	char *root_path = NULL;

	DBG_TRACE("%s: entry\n", __FUNCTION__);

	if (rootvnode == NULL) {
		panic("imageboot_setup: rootvnode is NULL.");
	}

	/*
	 * New boot-arg scheme:
	 *      root-dmg : the dmg that will be the root filesystem, authenticated by default.
	 *      auth-root-dmg : same as root-dmg.
	 *      container-dmg : an optional dmg that contains the root-dmg.
	 *  locker : the locker that will be the root filesystem -- mutually
	 *           exclusive with any other boot-arg.
	 */
	if (imageboot_setup_new(type)) {
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
#if CONFIG_IMAGEBOOT_IMG4
	if (PE_parse_boot_argn("arp0", root_path, MAXPATHLEN)) {
		char *path = url_to_path(root_path);

		assert(path);

		if (authenticate_root_with_img4(path)) {
			panic("Root image %s does not match the manifest\n", root_path);
		}
		if (path != root_path) {
			kfree_safe(path);
		}
	} else
#endif /* CONFIG_IMAGEBOOT_IMG4 */
	if ((PE_parse_boot_argn("rp", root_path, MAXPATHLEN) == FALSE) &&
	    (PE_parse_boot_argn("rp0", root_path, MAXPATHLEN) == FALSE)) {
		panic("%s: no valid path to image.\n", __FUNCTION__);
	}

	DBG_TRACE("%s: root image url is %s\n", __FUNCTION__, root_path);

	error = imageboot_mount_image(root_path, 0, type);
	if (error) {
		panic("Failed on first stage of imageboot.");
	}

	/*
	 * See if we are rooting from a nested image
	 */
	if (PE_parse_boot_argn("rp1", root_path, MAXPATHLEN) == FALSE) {
		goto done;
	}

	printf("%s: second level root image url is %s\n", __FUNCTION__, root_path);

	/*
	 * If we fail to set up second image, it's not a given that we
	 * can safely root off the first.
	 */
	error = imageboot_mount_image(root_path, 1, type);
	if (error) {
		panic("Failed on second stage of imageboot.");
	}

done:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);

	DBG_TRACE("%s: exit\n", __FUNCTION__);

	return;
}
