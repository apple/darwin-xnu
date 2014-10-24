/*
 * Copyright (c) 2004-2012 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>

#include <sys/fcntl.h>
#include <sys/fsevents.h>
#include <sys/kernel.h>
#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utfconv.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/xattr.h>

#include <libkern/OSByteOrder.h>
#include <vm/vm_kern.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif


#if NAMEDSTREAMS

static int shadow_sequence;

/*
 * We use %p to prevent loss of precision for pointers on varying architectures.
 */

#define SHADOW_NAME_FMT		".vfs_rsrc_stream_%p%08x%p"
#define SHADOW_DIR_FMT		".vfs_rsrc_streams_%p%x"
#define SHADOW_DIR_CONTAINER "/var/run"

#define MAKE_SHADOW_NAME(VP, NAME)  \
	snprintf((NAME), sizeof((NAME)), (SHADOW_NAME_FMT), \
			((void*)(VM_KERNEL_ADDRPERM(VP))), \
			(VP)->v_id, \
			((void*)(VM_KERNEL_ADDRPERM((VP)->v_data))))

/* The full path to the shadow directory */
#define MAKE_SHADOW_DIRNAME(VP, NAME)	\
	snprintf((NAME), sizeof((NAME)), (SHADOW_DIR_CONTAINER "/" SHADOW_DIR_FMT), \
			((void*)(VM_KERNEL_ADDRPERM(VP))), shadow_sequence)

/* The shadow directory as a 'leaf' entry */
#define MAKE_SHADOW_DIR_LEAF(VP, NAME)	\
	snprintf((NAME), sizeof((NAME)), (SHADOW_DIR_FMT), \
			((void*)(VM_KERNEL_ADDRPERM(VP))), shadow_sequence)

static int  default_getnamedstream(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation op, vfs_context_t context);

static int  default_makenamedstream(vnode_t vp, vnode_t *svpp, const char *name, vfs_context_t context);

static int  default_removenamedstream(vnode_t vp, const char *name, vfs_context_t context);

static int  getshadowfile(vnode_t vp, vnode_t *svpp, int makestream, size_t *rsrcsize, int *creator, vfs_context_t context);

static int  get_shadow_dir(vnode_t *sdvpp);

#endif /* NAMEDSTREAMS */

/*
 * Default xattr support routines.
 */

static int default_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size, int options,
    vfs_context_t context);
static int default_setxattr(vnode_t vp, const char *name, uio_t uio, int options,
    vfs_context_t context);
static int default_listxattr(vnode_t vp, uio_t uio, size_t *size, int options,
    vfs_context_t context);
static int default_removexattr(vnode_t vp, const char *name, int options,
    vfs_context_t context);

/*
 *  Retrieve the data of an extended attribute.
 */
int
vn_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size,
            int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return (EPERM);
	}
#if NAMEDSTREAMS
	/* getxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	/*
	 * Non-kernel request need extra checks performed.
	 *
	 * The XATTR_NOSECURITY flag implies a kernel request.
	 */
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_getextattr(context, vp, name, uio);
		if (error)
			goto out;
#endif /* MAC */
		if ((error = xattr_validatename(name))) {
			goto out;
		}
		if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context))) {
			goto out;
		}
		/* The offset can only be non-zero for resource forks. */
		if (uio != NULL && uio_offset(uio) != 0 && 
		    bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
			error = EINVAL;
			goto out;
		}
	}

	/* The offset can only be non-zero for resource forks. */
	if (uio != NULL && uio_offset(uio) != 0 && 
	    bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = EINVAL;
		goto out;
	}

	error = VNOP_GETXATTR(vp, name, uio, size, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_getxattr(vp, name, uio, size, options, context);
	}
out:
	return (error);
}

/*
 * Set the data of an extended attribute.
 */
int
vn_setxattr(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return (EPERM);
	}
#if NAMEDSTREAMS
	/* setxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	if ((options & (XATTR_REPLACE|XATTR_CREATE)) == (XATTR_REPLACE|XATTR_CREATE)) {
		return (EINVAL);
	}
	if ((error = xattr_validatename(name))) {
		return (error);
	}
 	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_setextattr(context, vp, name, uio);
		if (error)
			goto out;
#endif /* MAC */
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context);
		if (error)
			goto out;
	}
	/* The offset can only be non-zero for resource forks. */
	if (uio_offset(uio) != 0 && 
	    bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0 ) {
		error = EINVAL;
		goto out;
	}

	error = VNOP_SETXATTR(vp, name, uio, options, context);
#ifdef DUAL_EAS
	/*
	 * An EJUSTRETURN is from a filesystem which keeps this xattr
	 * natively as well as in a dot-underscore file.  In this case the
	 * EJUSTRETURN means the filesytem has done nothing, but identifies the
	 * EA as one which may be represented natively and/or in a DU, and
	 * since XATTR_CREATE or XATTR_REPLACE was specified, only up here in
	 * in vn_setxattr can we do the getxattrs needed to ascertain whether
	 * the XATTR_{CREATE,REPLACE} should yield an error.
	 */
	if (error == EJUSTRETURN) {
		int native = 0, dufile = 0;
		size_t sz;	/* not used */

		native = VNOP_GETXATTR(vp, name, NULL, &sz, 0, context) ? 0 : 1;
		dufile = default_getxattr(vp, name, NULL, &sz, 0, context) ? 0 : 1;
		if (options & XATTR_CREATE && (native || dufile)) {
			error = EEXIST;
			goto out;
		}
		if (options & XATTR_REPLACE && !(native || dufile)) {
			error = ENOATTR;
			goto out;
		}
		/*
		 * Having determined no CREATE/REPLACE error should result, we
		 * zero those bits, so both backing stores get written to.
		 */
		options &= ~(XATTR_CREATE | XATTR_REPLACE);
		error = VNOP_SETXATTR(vp, name, uio, options, context);
		/* the mainline path here is to have error==ENOTSUP ... */
	}
#endif /* DUAL_EAS */
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_setxattr(vp, name, uio, options, context);
	}
#if CONFIG_MACF
	if ((error == 0) && !(options & XATTR_NOSECURITY) &&
	    (vfs_flags(vnode_mount(vp)) & MNT_MULTILABEL))
		mac_vnode_label_update_extattr(vnode_mount(vp), vp, name);
#endif
out:
	return (error);
}

/*
 * Remove an extended attribute.
 */
int
vn_removexattr(vnode_t vp, const char * name, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return (EPERM);
	}
#if NAMEDSTREAMS
	/* removexattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif
	if ((error = xattr_validatename(name))) {
		return (error);
	}
	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_deleteextattr(context, vp, name);
		if (error)
			goto out;
#endif /* MAC */
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context);
		if (error)
			goto out;
	}
	error = VNOP_REMOVEXATTR(vp, name, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 */
		error = default_removexattr(vp, name, options, context);
#ifdef DUAL_EAS
	} else if (error == EJUSTRETURN) {
		/*
		 * EJUSTRETURN is from a filesystem which keeps this xattr natively as well
		 * as in a dot-underscore file.  EJUSTRETURN means the filesytem did remove
		 * a native xattr, so failure to find it in a DU file during
		 * default_removexattr should not be considered an error.
		 */
		error = default_removexattr(vp, name, options, context);
		if (error == ENOATTR)
			error = 0;
#endif /* DUAL_EAS */
	}
#if CONFIG_MACF
	if ((error == 0) && !(options & XATTR_NOSECURITY) &&
	    (vfs_flags(vnode_mount(vp)) & MNT_MULTILABEL))
		mac_vnode_label_update_extattr(vnode_mount(vp), vp, name);
#endif
out:
	return (error);
}

/*
 * Retrieve the list of extended attribute names.
 */
int
vn_listxattr(vnode_t vp, uio_t uio, size_t *size, int options, vfs_context_t context)
{
	int error;

	if (!XATTR_VNODE_SUPPORTED(vp)) {
		return (EPERM);
	}
#if NAMEDSTREAMS
	/* listxattr calls are not allowed for streams. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		return (EPERM);
	}
#endif

	if (!(options & XATTR_NOSECURITY)) {
#if CONFIG_MACF
		error = mac_vnode_check_listextattr(context, vp);
		if (error)
			goto out;
#endif /* MAC */

		error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context);
		if (error)
			goto out;
	}

	error = VNOP_LISTXATTR(vp, uio, size, options, context);
	if (error == ENOTSUP && !(options & XATTR_NODEFAULT)) {
		/*
		 * A filesystem may keep some but not all EAs natively, in which case
		 * the native EA names will have been uiomove-d out (or *size updated)
		 * and the default_listxattr here will finish the job.  
		 */
		error = default_listxattr(vp, uio, size, options, context);
	}
out:
	return (error);
}

int
xattr_validatename(const char *name)
{
	int namelen;

	if (name == NULL || name[0] == '\0') {
		return (EINVAL);
	}
	namelen = strnlen(name, XATTR_MAXNAMELEN);
	if (name[namelen] != '\0') 
		return (ENAMETOOLONG);
	
	if (utf8_validatestr((const unsigned char *)name, namelen) != 0) 
		return (EINVAL);
	
	return (0);
}


/*
 * Determine whether an EA is a protected system attribute.
 */
int
xattr_protected(const char *attrname)
{
	return(!strncmp(attrname, "com.apple.system.", 17));
}


#if NAMEDSTREAMS

/*
 * Obtain a named stream from vnode vp.
 */
errno_t
vnode_getnamedstream(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation op, int flags, vfs_context_t context)
{
	int error;

	if (vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS)
		error = VNOP_GETNAMEDSTREAM(vp, svpp, name, op, flags, context);
	else
		error = default_getnamedstream(vp, svpp, name, op, context);

	if (error == 0) {
		uint32_t streamflags = VISNAMEDSTREAM;
		vnode_t svp = *svpp;

		if ((vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0) {
			streamflags |= VISSHADOW;
		}
		
		/* Tag the vnode. */
		vnode_lock_spin(svp);
		svp->v_flag |= streamflags;
		vnode_unlock(svp);

		/* Tag the parent so we know to flush credentials for streams on setattr */
		vnode_lock_spin(vp);
		vp->v_lflag |= VL_HASSTREAMS;
		vnode_unlock(vp);

		/* Make the file it's parent.  
		 * Note:  This parent link helps us distinguish vnodes for 
		 * shadow stream files from vnodes for resource fork on file 
		 * systems that support namedstream natively (both have 
		 * VISNAMEDSTREAM set) by allowing access to mount structure 
		 * for checking MNTK_NAMED_STREAMS bit at many places in the 
		 * code.
		 */
		vnode_update_identity(svp, vp, NULL, 0, 0, VNODE_UPDATE_PARENT);
	}		

	return (error);
}

/*
 * Make a named stream for vnode vp.
 */
errno_t 
vnode_makenamedstream(vnode_t vp, vnode_t *svpp, const char *name, int flags, vfs_context_t context)
{
	int error;

	if (vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS)
		error = VNOP_MAKENAMEDSTREAM(vp, svpp, name, flags, context);
	else
		error = default_makenamedstream(vp, svpp, name, context);

	if (error == 0) {
		uint32_t streamflags = VISNAMEDSTREAM;
		vnode_t svp = *svpp;

		/* Tag the vnode. */
		if ((vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0) {
			streamflags |= VISSHADOW;
		}
		
		/* Tag the vnode. */
		vnode_lock_spin(svp);
		svp->v_flag |= streamflags;
		vnode_unlock(svp);

		/* Tag the parent so we know to flush credentials for streams on setattr */
		vnode_lock_spin(vp);
		vp->v_lflag |= VL_HASSTREAMS;
		vnode_unlock(vp);

		/* Make the file it's parent.
		 * Note:  This parent link helps us distinguish vnodes for 
		 * shadow stream files from vnodes for resource fork on file 
		 * systems that support namedstream natively (both have 
		 * VISNAMEDSTREAM set) by allowing access to mount structure 
		 * for checking MNTK_NAMED_STREAMS bit at many places in the 
		 * code.
		 */
		vnode_update_identity(svp, vp, NULL, 0, 0, VNODE_UPDATE_PARENT);
	}
	return (error);
}

/*
 * Remove a named stream from vnode vp.
 */
errno_t 
vnode_removenamedstream(vnode_t vp, vnode_t svp, const char *name, int flags, vfs_context_t context)
{
	int error;

	if (vp->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS)
		error = VNOP_REMOVENAMEDSTREAM(vp, svp, name, flags, context);
	else
		error = default_removenamedstream(vp, name, context);

	return (error);
}

#define NS_IOBUFSIZE  (128 * 1024)

/*
 * Release a named stream shadow file.
 *
 * Note: This function is called from two places where we do not need 
 * to check if the vnode has any references held before deleting the 
 * shadow file.  Once from vclean() when the vnode is being reclaimed 
 * and we do not hold any references on the vnode.  Second time from 
 * default_getnamedstream() when we get an error during shadow stream 
 * file initialization so that other processes who are waiting for the 
 * shadow stream file initialization by the creator will get opportunity 
 * to create and initialize the file again.
 */
errno_t
vnode_relenamedstream(vnode_t vp, vnode_t svp) {
	vnode_t dvp;
	struct componentname cn;
	char tmpname[80];
	errno_t err;
	
	/* 
	 * We need to use the kernel context here.  If we used the supplied
	 * VFS context we have no clue whether or not it originated from userland
	 * where it could be subject to a chroot jail.  We need to ensure that all
	 * filesystem access to shadow files is done on the same FS regardless of
	 * userland process restrictions.
	 */
	vfs_context_t kernelctx = vfs_context_kernel();

	cache_purge(svp);

	vnode_lock(svp);
	MAKE_SHADOW_NAME(vp, tmpname);
	vnode_unlock(svp);

	cn.cn_nameiop = DELETE;
	cn.cn_flags = ISLASTCN;
	cn.cn_context = kernelctx;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = strlen(tmpname);

	/* 
	 * Obtain the vnode for the shadow files directory.  Make sure to 
	 * use the kernel ctx as described above.
	 */
	err = get_shadow_dir(&dvp);
	if (err != 0) {
		return err;
	}

	(void) VNOP_REMOVE(dvp, svp, &cn, 0, kernelctx);
	vnode_put(dvp);

	return (0);
}

/*
 * Flush a named stream shadow file.
 * 
 * 'vp' represents the AppleDouble file.
 * 'svp' represents the shadow file.
 */
errno_t 
vnode_flushnamedstream(vnode_t vp, vnode_t svp, vfs_context_t context)
{
	struct vnode_attr va;
	uio_t auio = NULL;
	caddr_t  bufptr = NULL;
	size_t  bufsize = 0;
	size_t  offset;
	size_t  iosize;
	size_t datasize;
	int error;
	/* 
	 * The kernel context must be used for all I/O to the shadow file 
	 * and its namespace operations
	 */
	vfs_context_t kernelctx = vfs_context_kernel();

	/* The supplied context is used for access to the AD file itself */

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_data_size);
	if (VNOP_GETATTR(svp, &va, context) != 0  ||
		!VATTR_IS_SUPPORTED(&va, va_data_size)) {
		return (0);
	}
	datasize = va.va_data_size;
	if (datasize == 0) {
		(void) default_removexattr(vp, XATTR_RESOURCEFORK_NAME, 0, context);
		return (0);
	}

	iosize = bufsize = MIN(datasize, NS_IOBUFSIZE);
	if (kmem_alloc(kernel_map, (vm_offset_t *)&bufptr, bufsize)) {
		return (ENOMEM);
	}
	auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	offset = 0;

	/*
	 * Copy the shadow stream file data into the resource fork.
	 */
	error = VNOP_OPEN(svp, 0, kernelctx);
	if (error) {
		printf("vnode_flushnamedstream: err %d opening file\n", error);
		goto out;
	}
	while (offset < datasize) {
		iosize = MIN(datasize - offset, iosize);

		uio_reset(auio, offset, UIO_SYSSPACE, UIO_READ);
		uio_addiov(auio, (uintptr_t)bufptr, iosize);
		error = VNOP_READ(svp, auio, 0, kernelctx);
		if (error) {
			break;
		}
		/* Since there's no truncate xattr we must remove the resource fork. */
		if (offset == 0) {
			error = default_removexattr(vp, XATTR_RESOURCEFORK_NAME, 0, context);
			if ((error != 0) && (error != ENOATTR)) {
				break;
			}
		}
		uio_reset(auio, offset, UIO_SYSSPACE, UIO_WRITE);
		uio_addiov(auio, (uintptr_t)bufptr, iosize);
		error = vn_setxattr(vp, XATTR_RESOURCEFORK_NAME, auio, XATTR_NOSECURITY, context);
		if (error) {
			break;
		}
		offset += iosize;
	}

	/* close shadowfile */
	(void) VNOP_CLOSE(svp, 0, kernelctx);
out:
	if (bufptr) {
		kmem_free(kernel_map, (vm_offset_t)bufptr, bufsize);
	}
	if (auio) {
		uio_free(auio);
	}
	return (error);
}


/* 
 * Verify that the vnode 'vp' is a vnode that lives in the shadow
 * directory.  We can't just query the parent pointer directly since
 * the shadowfile is hooked up to the actual file it's a stream for.
 */
errno_t vnode_verifynamedstream(vnode_t vp) {
	int error;
	struct vnode *shadow_dvp = NULL;
	struct vnode *shadowfile = NULL;
	struct componentname cn;
	
	/* 
	 * We need to use the kernel context here.  If we used the supplied
	 * VFS context we have no clue whether or not it originated from userland
	 * where it could be subject to a chroot jail.  We need to ensure that all
	 * filesystem access to shadow files is done on the same FS regardless of
	 * userland process restrictions.
	 */
	vfs_context_t kernelctx = vfs_context_kernel();
	char tmpname[80];
	

	/* Get the shadow directory vnode */
	error = get_shadow_dir(&shadow_dvp);
	if (error) {
		return error;
	}

	/* Re-generate the shadow name in the buffer */
	MAKE_SHADOW_NAME (vp, tmpname);

	/* Look up item in shadow dir */
	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN | CN_ALLOWRSRCFORK;
	cn.cn_context = kernelctx;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = strlen(tmpname);

	if (VNOP_LOOKUP (shadow_dvp, &shadowfile, &cn, kernelctx) == 0) {
		/* is the pointer the same? */
		if (shadowfile == vp) {
			error = 0;	
		}
		else {
			error = EPERM;
		}
		/* drop the iocount acquired */
		vnode_put (shadowfile);
	}	

	/* Drop iocount on shadow dir */
	vnode_put (shadow_dvp);
	return error;
}	

/* 
 * Access or create the shadow file as needed. 
 * 
 * 'makestream' with non-zero value means that we need to guarantee we were the
 * creator of the shadow file.
 *
 * 'context' is the user supplied context for the original VFS operation that
 * caused us to need a shadow file.
 *
 * int pointed to by 'creator' is nonzero if we created the shadowfile.
 */
static int
getshadowfile(vnode_t vp, vnode_t *svpp, int makestream, size_t *rsrcsize,
              int *creator, vfs_context_t context)
{
	vnode_t  dvp = NULLVP;
	vnode_t  svp = NULLVP;
	struct componentname cn;
	struct vnode_attr va;
	char tmpname[80];
	size_t datasize = 0;
	int  error = 0;
	int retries = 0;
	vfs_context_t kernelctx = vfs_context_kernel();

retry_create:
	*creator = 0;
	/* Establish a unique file name. */
	MAKE_SHADOW_NAME(vp, tmpname);
	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_context = context;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = strlen(tmpname);

	/* Pick up uid, gid, mode and date from original file. */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_create_time);
	VATTR_WANTED(&va, va_modify_time);
	if (VNOP_GETATTR(vp, &va, context) != 0  ||
		!VATTR_IS_SUPPORTED(&va, va_uid)  ||
		!VATTR_IS_SUPPORTED(&va, va_gid)  ||
		!VATTR_IS_SUPPORTED(&va, va_mode)) {
		va.va_uid = KAUTH_UID_NONE;
		va.va_gid = KAUTH_GID_NONE;
		va.va_mode = S_IRUSR | S_IWUSR;
	}
	va.va_vaflags = VA_EXCLUSIVE;
	VATTR_SET(&va, va_type, VREG);
	/* We no longer change the access, but we still hide it. */
	VATTR_SET(&va, va_flags, UF_HIDDEN);

	/* Obtain the vnode for the shadow files directory. */
	if (get_shadow_dir(&dvp) != 0) {
		error = ENOTDIR;
		goto out;
	}
	if (!makestream) {
		/* See if someone else already has it open. */
		if (VNOP_LOOKUP(dvp, &svp, &cn, kernelctx) == 0) {
			/* Double check existence by asking for size. */
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_data_size);
			if (VNOP_GETATTR(svp, &va, context) == 0  &&
			    VATTR_IS_SUPPORTED(&va, va_data_size)) {
				goto out;  /* OK to use. */
			}
		}
		
		/* 
		 * Otherwise make sure the resource fork data exists. 
		 * Use the supplied context for accessing the AD file.
		 */
		error = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, NULL, &datasize,
		                    XATTR_NOSECURITY, context);
		/*
		 * To maintain binary compatibility with legacy Carbon
		 * emulated resource fork support, if the resource fork
		 * doesn't exist but the Finder Info does,  then act as
		 * if an empty resource fork is present (see 4724359).
		 */
		if ((error == ENOATTR) &&
		    (vn_getxattr(vp, XATTR_FINDERINFO_NAME, NULL, &datasize,
		                 XATTR_NOSECURITY, context) == 0)) {
			datasize = 0;
			error = 0;
		} else {
			if (error) {
				goto out;
			}
	
			/* If the resource fork exists, its size is expected to be non-zero. */
			if (datasize == 0) {
				error = ENOATTR;
				goto out;
			}
		}
	}
	/* Create the shadow stream file. */
	error = VNOP_CREATE(dvp, &svp, &cn, &va, kernelctx);
	if (error == 0) {
		vnode_recycle(svp);
		*creator = 1;
	} 
	else if ((error == EEXIST) && !makestream) {
		error = VNOP_LOOKUP(dvp, &svp, &cn, kernelctx);
	}
	else if ((error == ENOENT) && !makestream) {
		/*
		 * We could have raced with a rmdir on the shadow directory
		 * post-lookup.  Retry from the beginning, 1x only, to
		 * try and see if we need to re-create the shadow directory	
		 * in get_shadow_dir.
		 */
		if (retries == 0) {
			retries++;
			if (dvp) {
				vnode_put (dvp);
				dvp = NULLVP;
			}
			if (svp) {
				vnode_put (svp);
				svp = NULLVP;
			}
			goto retry_create;
		}
		/* Otherwise, just error out normally below */
	}
	
out:
	if (dvp) {
		vnode_put(dvp);
	}
	if (error) {
		/* On errors, clean up shadow stream file. */
		if (svp) {
			vnode_put(svp);
			svp = NULLVP;
		}
	}
	*svpp = svp;
	if (rsrcsize) {
		*rsrcsize = datasize;
	}
	return (error);
}


static int
default_getnamedstream(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation op, vfs_context_t context)
{
	vnode_t  svp = NULLVP;
	uio_t auio = NULL;
	caddr_t  bufptr = NULL;
	size_t  bufsize = 0;
	size_t  datasize = 0;
	int  creator;
	int  error;

	/* need the kernel context for accessing the shadowfile */
	vfs_context_t kernelctx = vfs_context_kernel();

	/*
	 * Only the "com.apple.ResourceFork" stream is supported here.
	 */
	if (bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		*svpp = NULLVP;
		return (ENOATTR);
	}
retry:
	/*
	 * Obtain a shadow file for the resource fork I/O.
	 * 
	 * Need to pass along the supplied context so that getshadowfile
	 * can access the AD file as needed, using it.
	 */
	error = getshadowfile(vp, &svp, 0, &datasize, &creator, context);
	if (error) {
		*svpp = NULLVP;
		return (error);
	}

	/*
	 * The creator of the shadow file provides its file data,
	 * all other threads should wait until its ready.  In order to 
	 * prevent a deadlock during error codepaths, we need to check if the
	 * vnode is being created, or if it has failed out. Regardless of success or 
	 * failure, we set the VISSHADOW bit on the vnode, so we check that
	 * if the vnode's flags don't have VISNAMEDSTREAM set.  If it doesn't,
	 * then we can infer the creator isn't done yet.  If it's there, but
	 * VISNAMEDSTREAM is not set, then we can infer it errored out and we should
	 * try again.
	 */
	if (!creator) {
		vnode_lock(svp);
		if (svp->v_flag & VISNAMEDSTREAM) {
			/* data is ready, go use it */
			vnode_unlock(svp);
			goto out;
		} else {
			/* It's not ready, wait for it (sleep using v_parent as channel) */
			if ((svp->v_flag & VISSHADOW)) {
				/* 
				 * No VISNAMEDSTREAM, but we did see VISSHADOW, indicating that the other
				 * thread is done with this vnode. Just unlock the vnode and try again
				 */
				vnode_unlock(svp);
			}	
			else {
				/* Otherwise, sleep if the shadow file is not created yet */
				msleep((caddr_t)&svp->v_parent, &svp->v_lock, PINOD | PDROP,
						"getnamedstream", NULL);
			}
			vnode_put(svp);
			svp = NULLVP;
			goto retry;
		}
	}

	/*
	 * Copy the real resource fork data into shadow stream file.
	 */
	if (op == NS_OPEN && datasize != 0) {
		size_t  offset;
        	size_t  iosize;

		iosize = bufsize = MIN(datasize, NS_IOBUFSIZE);
		if (kmem_alloc(kernel_map, (vm_offset_t *)&bufptr, bufsize)) {
			error = ENOMEM;
			goto out;
		}

		auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
		offset = 0;

		/* open the shadow file */
		error = VNOP_OPEN(svp, 0, kernelctx);
		if (error) {
			goto out;
		}
		while (offset < datasize) {
			size_t	tmpsize;

			iosize = MIN(datasize - offset, iosize);

			uio_reset(auio, offset, UIO_SYSSPACE, UIO_READ);
			uio_addiov(auio, (uintptr_t)bufptr, iosize);
			/* use supplied ctx for AD file */
			error = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, auio, &tmpsize,
			                    XATTR_NOSECURITY, context);
			if (error) {
				break;
			}
		
			uio_reset(auio, offset, UIO_SYSSPACE, UIO_WRITE);
			uio_addiov(auio, (uintptr_t)bufptr, iosize);
			/* kernel context for writing shadowfile */
			error = VNOP_WRITE(svp, auio, 0, kernelctx);
			if (error) {
				break;
			}
			offset += iosize;
		}

		/* close shadow file */
		(void) VNOP_CLOSE(svp, 0, kernelctx);
	}
out:
	/* Wake up anyone waiting for svp file content */
	if (creator) {
		if (error == 0) {
			vnode_lock(svp);
			/* VISSHADOW would be set later on anyway, so we set it now */
			svp->v_flag |= (VISNAMEDSTREAM | VISSHADOW);
			wakeup((caddr_t)&svp->v_parent);
			vnode_unlock(svp);
		} else {
			/* On post create errors, get rid of the shadow file.  This 
			 * way if there is another process waiting for initialization 
			 * of the shadowfile by the current process will wake up and 
			 * retry by creating and initializing the shadow file again.
			 * Also add the VISSHADOW bit here to indicate we're done operating
			 * on this vnode.
			 */
			(void)vnode_relenamedstream(vp, svp);
			vnode_lock (svp);
			svp->v_flag |= VISSHADOW;
			wakeup((caddr_t)&svp->v_parent);
			vnode_unlock(svp);
		}
	}

	if (bufptr) {
		kmem_free(kernel_map, (vm_offset_t)bufptr, bufsize);
	}
	if (auio) {
		uio_free(auio);
	}
	if (error) {
		/* On errors, clean up shadow stream file. */
		if (svp) {
			vnode_put(svp);
			svp = NULLVP;
		}
	}
	*svpp = svp;
	return (error);
}

static int
default_makenamedstream(vnode_t vp, vnode_t *svpp, const char *name, vfs_context_t context)
{
	int creator;
	int error;

	/*
	 * Only the "com.apple.ResourceFork" stream is supported here.
	 */
	if (bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		*svpp = NULLVP;
		return (ENOATTR);
	}

	/* Supply the context to getshadowfile so it can manipulate the AD file */
	error = getshadowfile(vp, svpp, 1, NULL, &creator, context);

	/*
	 * Wake up any waiters over in default_getnamedstream().
	 */
	if ((error == 0) && (*svpp != NULL) && creator) {
		vnode_t svp = *svpp;

		vnode_lock(svp);
		/* If we're the creator, mark it as a named stream */
		svp->v_flag |= (VISNAMEDSTREAM | VISSHADOW);
		/* Wakeup any waiters on the v_parent channel */
		wakeup((caddr_t)&svp->v_parent);
		vnode_unlock(svp);

	}

	return (error);
}

static int 
default_removenamedstream(vnode_t vp, const char *name, vfs_context_t context)
{
	/*
	 * Only the "com.apple.ResourceFork" stream is supported here.
	 */
	if (bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		return (ENOATTR);
	}
	/*
	 * XXX - what about other opened instances?
	 */
	return default_removexattr(vp, XATTR_RESOURCEFORK_NAME, 0, context);
}

static int
get_shadow_dir(vnode_t *sdvpp) {
	vnode_t  dvp = NULLVP;
	vnode_t  sdvp = NULLVP;
	struct componentname  cn;
	struct vnode_attr  va;
	char tmpname[80];
	uint32_t  tmp_fsid;
	int  error;
	vfs_context_t kernelctx = vfs_context_kernel();

	bzero(tmpname, sizeof(tmpname));
	MAKE_SHADOW_DIRNAME(rootvnode, tmpname);
	/* 
	 * Look up the shadow directory to ensure that it still exists. 
	 * By looking it up, we get an iocounted dvp to use, and avoid some coherency issues
	 * in caching it when multiple threads may be trying to manipulate the pointers.
	 * 
	 * Make sure to use the kernel context.  We want a singular view of
	 * the shadow dir regardless of chrooted processes.
	 */
	error = vnode_lookup(tmpname, 0, &sdvp, kernelctx);
	if (error == 0) {
		/*
		 * If we get here, then we have successfully looked up the shadow dir, 
		 * and it has an iocount from the lookup. Return the vp in the output argument.
		 */
		*sdvpp = sdvp;
		return (0);
	}
	/* In the failure case, no iocount is acquired */
	sdvp = NULLVP;
	bzero (tmpname, sizeof(tmpname));

	/* 
	 * Obtain the vnode for "/var/run" directory using the kernel
	 * context.
	 *
	 * This is defined in the SHADOW_DIR_CONTAINER macro
	 */
	if (vnode_lookup(SHADOW_DIR_CONTAINER, 0, &dvp, kernelctx) != 0) {
		error = ENOTSUP;
		goto out;
	}

	/* 
	 * Create the shadow stream directory.
	 * 'dvp' below suggests the parent directory so 
	 * we only need to provide the leaf entry name
	 */
	MAKE_SHADOW_DIR_LEAF(rootvnode, tmpname);
	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_context = kernelctx;
	cn.cn_pnbuf = tmpname;
	cn.cn_pnlen = sizeof(tmpname);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = strlen(tmpname);

	/*
	 * owned by root, only readable by root, hidden
	 */
	VATTR_INIT(&va);
	VATTR_SET(&va, va_uid, 0);
	VATTR_SET(&va, va_gid, 0);
	VATTR_SET(&va, va_mode, S_IRUSR | S_IXUSR);
	VATTR_SET(&va, va_type, VDIR);
	VATTR_SET(&va, va_flags, UF_HIDDEN);
	va.va_vaflags = VA_EXCLUSIVE;

	error = VNOP_MKDIR(dvp, &sdvp, &cn, &va, kernelctx);
	
	/*
	 * There can be only one winner for an exclusive create.
	 */
	if (error == EEXIST) {
		/* loser has to look up directory */
		error = VNOP_LOOKUP(dvp, &sdvp, &cn, kernelctx);
		if (error == 0) {
			/* Make sure its in fact a directory */
			if (sdvp->v_type != VDIR) {
				goto baddir;
			}
			/* Obtain the fsid for /var/run directory */
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_fsid);
			if (VNOP_GETATTR(dvp, &va, kernelctx) != 0  ||
			    !VATTR_IS_SUPPORTED(&va, va_fsid)) {
				goto baddir;
			}
			tmp_fsid = va.va_fsid;

			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_uid);
			VATTR_WANTED(&va, va_gid);
			VATTR_WANTED(&va, va_mode);
			VATTR_WANTED(&va, va_fsid);
			VATTR_WANTED(&va, va_dirlinkcount);
			VATTR_WANTED(&va, va_acl);
			/* Provide defaults for attrs that may not be supported */
			va.va_dirlinkcount = 1;
			va.va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;

			if (VNOP_GETATTR(sdvp, &va, kernelctx) != 0  ||
			    !VATTR_IS_SUPPORTED(&va, va_uid)  ||
			    !VATTR_IS_SUPPORTED(&va, va_gid)  ||
			    !VATTR_IS_SUPPORTED(&va, va_mode)  ||
			    !VATTR_IS_SUPPORTED(&va, va_fsid)) {
				goto baddir;
			}
			/*
			 * Make sure its what we want: 
			 * 	- owned by root
			 *	- not writable by anyone
			 *	- on same file system as /var/run
			 *	- not a hard-linked directory
			 *	- no ACLs (they might grant write access)
			 */
			if ((va.va_uid != 0) || (va.va_gid != 0) ||
			    (va.va_mode & (S_IWUSR | S_IRWXG | S_IRWXO)) ||
			    (va.va_fsid != tmp_fsid) ||
			    (va.va_dirlinkcount != 1) ||
			     (va.va_acl != (kauth_acl_t) KAUTH_FILESEC_NONE)) {
				goto baddir;
			}
		}
	}
out:
	if (dvp) {
		vnode_put(dvp);
	}
	if (error) {
		/* On errors, clean up shadow stream directory. */
		if (sdvp) {
			vnode_put(sdvp);
			sdvp = NULLVP;
		}
	}
	*sdvpp = sdvp;
	return (error);

baddir:
	/* This is not the dir we're looking for, move along */
	++shadow_sequence;  /* try something else next time */
	error = ENOTDIR;
	goto out;
}
#endif /* NAMEDSTREAMS */


#if CONFIG_APPLEDOUBLE
/*
 * Default Implementation (Non-native EA) 
 */


/*
   Typical "._" AppleDouble Header File layout:
  ------------------------------------------------------------
         MAGIC          0x00051607
         VERSION        0x00020000
         FILLER         0
         COUNT          2
     .-- AD ENTRY[0]    Finder Info Entry (must be first)
  .--+-- AD ENTRY[1]    Resource Fork Entry (must be last)
  |  '-> FINDER INFO
  |      /////////////  Fixed Size Data (32 bytes)
  |      EXT ATTR HDR
  |      /////////////
  |      ATTR ENTRY[0] --.
  |      ATTR ENTRY[1] --+--.
  |      ATTR ENTRY[2] --+--+--.
  |         ...          |  |  |
  |      ATTR ENTRY[N] --+--+--+--.
  |      ATTR DATA 0   <-'  |  |  |
  |      ////////////       |  |  |
  |      ATTR DATA 1   <----'  |  |
  |      /////////////         |  |
  |      ATTR DATA 2   <-------'  |
  |      /////////////            |
  |         ...                   |
  |      ATTR DATA N   <----------'
  |      /////////////
  |                      Attribute Free Space
  |
  '----> RESOURCE FORK
         /////////////   Variable Sized Data
         /////////////
         /////////////
         /////////////
         /////////////
         /////////////
            ...
         /////////////
 
  ------------------------------------------------------------

   NOTE: The EXT ATTR HDR, ATTR ENTRY's and ATTR DATA's are
   stored as part of the Finder Info.  The length in the Finder
   Info AppleDouble entry includes the length of the extended
   attribute header, attribute entries, and attribute data.
*/


/*
 * On Disk Data Structures
 *
 * Note: Motorola 68K alignment and big-endian.
 *
 * See RFC 1740 for additional information about the AppleDouble file format.
 *
 */

#define ADH_MAGIC     0x00051607
#define ADH_VERSION   0x00020000
#define ADH_MACOSX    "Mac OS X        "

/*
 * AppleDouble Entry ID's
 */
#define AD_DATA          1   /* Data fork */
#define AD_RESOURCE      2   /* Resource fork */
#define AD_REALNAME      3   /* FileÕs name on home file system */
#define AD_COMMENT       4   /* Standard Mac comment */
#define AD_ICONBW        5   /* Mac black & white icon */
#define AD_ICONCOLOR     6   /* Mac color icon */
#define AD_UNUSED        7   /* Not used */
#define AD_FILEDATES     8   /* File dates; create, modify, etc */
#define AD_FINDERINFO    9   /* Mac Finder info & extended info */
#define AD_MACINFO      10   /* Mac file info, attributes, etc */
#define AD_PRODOSINFO   11   /* Pro-DOS file info, attrib., etc */
#define AD_MSDOSINFO    12   /* MS-DOS file info, attributes, etc */
#define AD_AFPNAME      13   /* Short name on AFP server */
#define AD_AFPINFO      14   /* AFP file info, attrib., etc */
#define AD_AFPDIRID     15   /* AFP directory ID */ 
#define AD_ATTRIBUTES   AD_FINDERINFO


#define ATTR_FILE_PREFIX   "._"
#define ATTR_HDR_MAGIC     0x41545452   /* 'ATTR' */

#define ATTR_BUF_SIZE      4096        /* default size of the attr file and how much we'll grow by */

/* Implementation Limits */
#define ATTR_MAX_SIZE      AD_XATTR_MAXSIZE
#define ATTR_MAX_HDR_SIZE  65536
/*
 * Note: ATTR_MAX_HDR_SIZE is the largest attribute header
 * size supported (including the attribute entries). All of
 * the attribute entries must reside within this limit.  If
 * any of the attribute data crosses the ATTR_MAX_HDR_SIZE
 * boundry, then all of the attribute data I/O is performed
 * separately from the attribute header I/O.
 *
 * In particular, all of the attr_entry structures must lie
 * completely within the first ATTR_MAX_HDR_SIZE bytes of the
 * AppleDouble file.  However, the attribute data (i.e. the
 * contents of the extended attributes) may extend beyond the
 * first ATTR_MAX_HDR_SIZE bytes of the file.  Note that this
 * limit is to allow the implementation to optimize by reading
 * the first ATTR_MAX_HDR_SIZE bytes of the file.
 */


#define FINDERINFOSIZE	32

typedef struct apple_double_entry {
	u_int32_t   type;     /* entry type: see list, 0 invalid */ 
	u_int32_t   offset;   /* entry data offset from the beginning of the file. */
 	u_int32_t   length;   /* entry data length in bytes. */
} __attribute__((aligned(2), packed)) apple_double_entry_t;


typedef struct apple_double_header {
	u_int32_t   magic;         /* == ADH_MAGIC */
	u_int32_t   version;       /* format version: 2 = 0x00020000 */ 
	u_int32_t   filler[4];
	u_int16_t   numEntries;	   /* number of entries which follow */ 
	apple_double_entry_t   entries[2];  /* 'finfo' & 'rsrc' always exist */
	u_int8_t    finfo[FINDERINFOSIZE];  /* Must start with Finder Info (32 bytes) */
	u_int8_t    pad[2];        /* get better alignment inside attr_header */
} __attribute__((aligned(2), packed)) apple_double_header_t;

#define ADHDRSIZE  (4+4+16+2)

/* Entries are aligned on 4 byte boundaries */
typedef struct attr_entry {
	u_int32_t   offset;     /* file offset to data */
	u_int32_t   length;     /* size of attribute data */
	u_int16_t   flags;
	u_int8_t    namelen;
	u_int8_t    name[1];    /* NULL-terminated UTF-8 name (up to 128 bytes max) */
} __attribute__((aligned(2), packed)) attr_entry_t;


/* Header + entries must fit into 64K.  Data may extend beyond 64K. */
typedef struct attr_header {
	apple_double_header_t  appledouble;
	u_int32_t   magic;        /* == ATTR_HDR_MAGIC */
	u_int32_t   debug_tag;    /* for debugging == file id of owning file */
	u_int32_t   total_size;   /* file offset of end of attribute header + entries + data */ 
	u_int32_t   data_start;   /* file offset to attribute data area */
	u_int32_t   data_length;  /* length of attribute data area */
	u_int32_t   reserved[3];
	u_int16_t   flags;
	u_int16_t   num_attrs;
} __attribute__((aligned(2), packed)) attr_header_t;


/* Empty Resource Fork Header */
typedef struct rsrcfork_header {
	u_int32_t    fh_DataOffset;
	u_int32_t    fh_MapOffset;
	u_int32_t    fh_DataLength;
	u_int32_t    fh_MapLength;
	u_int8_t     systemData[112];
	u_int8_t     appData[128];
	u_int32_t    mh_DataOffset;
	u_int32_t    mh_MapOffset;
	u_int32_t    mh_DataLength;
	u_int32_t    mh_MapLength;
	u_int32_t    mh_Next;
	u_int16_t    mh_RefNum;
	u_int8_t     mh_Attr;
	u_int8_t     mh_InMemoryAttr;
	u_int16_t    mh_Types;
	u_int16_t    mh_Names;
	u_int16_t    typeCount;
} __attribute__((aligned(2), packed)) rsrcfork_header_t;

#define RF_FIRST_RESOURCE    256
#define RF_NULL_MAP_LENGTH    30
#define RF_EMPTY_TAG  "This resource fork intentionally left blank   "

/* Runtime information about the attribute file. */
typedef struct attr_info {
	vfs_context_t          context;
	vnode_t                filevp;
	size_t                 filesize;
	size_t                 iosize;
	u_int8_t               *rawdata;
	size_t                 rawsize;  /* minimum of filesize or ATTR_MAX_HDR_SIZE */
	apple_double_header_t  *filehdr;
	apple_double_entry_t   *finderinfo;
	apple_double_entry_t   *rsrcfork;
	attr_header_t          *attrhdr;
	attr_entry_t           *attr_entry;
	u_int8_t               readonly;
	u_int8_t               emptyfinderinfo;
} attr_info_t;


#define ATTR_SETTING  1

#define ATTR_ALIGN 3L  /* Use four-byte alignment */

#define ATTR_ENTRY_LENGTH(namelen)  \
        ((sizeof(attr_entry_t) - 1 + (namelen) + ATTR_ALIGN) & (~ATTR_ALIGN))

#define ATTR_NEXT(ae)  \
	 (attr_entry_t *)((u_int8_t *)(ae) + ATTR_ENTRY_LENGTH((ae)->namelen))

#define ATTR_VALID(ae, ai)  \
	((u_int8_t *)ATTR_NEXT(ae) <= ((ai).rawdata + (ai).rawsize))

#define SWAP16(x)  OSSwapBigToHostInt16((x))
#define SWAP32(x)  OSSwapBigToHostInt32((x))
#define SWAP64(x)  OSSwapBigToHostInt64((x))


static u_int32_t emptyfinfo[8] = {0};


/*
 * Local support routines
 */
static void  close_xattrfile(vnode_t xvp, int fileflags, vfs_context_t context);

static int  open_xattrfile(vnode_t vp, int fileflags, vnode_t *xvpp, vfs_context_t context);

static int  create_xattrfile(vnode_t xvp, u_int32_t fileid, vfs_context_t context);

static int  remove_xattrfile(vnode_t xvp, vfs_context_t context);

static int  get_xattrinfo(vnode_t xvp, int setting, attr_info_t *ainfop, vfs_context_t context);

static void  rel_xattrinfo(attr_info_t *ainfop);

static int  write_xattrinfo(attr_info_t *ainfop);

static void  init_empty_resource_fork(rsrcfork_header_t * rsrcforkhdr);

static int  lock_xattrfile(vnode_t xvp, short locktype, vfs_context_t context);

static int  unlock_xattrfile(vnode_t xvp, vfs_context_t context);


#if BYTE_ORDER == LITTLE_ENDIAN
  static void  swap_adhdr(apple_double_header_t *adh);
  static void  swap_attrhdr(attr_header_t *ah, attr_info_t* info);

#else
#define swap_adhdr(x)
#define swap_attrhdr(x, y)
#endif

static int  check_and_swap_attrhdr(attr_header_t *ah, attr_info_t* ainfop);
static int  shift_data_down(vnode_t xvp, off_t start, size_t len, off_t delta, vfs_context_t context);
static int  shift_data_up(vnode_t xvp, off_t start, size_t len, off_t delta, vfs_context_t context);


/*
 * Sanity check and swap the header of an AppleDouble file.  Assumes the buffer
 * is in big endian (as it would exist on disk).  Verifies the following:
 * - magic field
 * - version field
 * - number of entries
 * - that each entry fits within the file size
 *
 * If the header is invalid, ENOATTR is returned.
 *
 * NOTE: Does not attempt to validate the extended attributes header that
 * may be embedded in the Finder Info entry.
 */
static int check_and_swap_apple_double_header(attr_info_t *ainfop)
{
	int i, j;
	u_int32_t header_end;
	u_int32_t entry_end;
	size_t rawsize;
	apple_double_header_t *header;
	
	rawsize = ainfop->rawsize;
	header = (apple_double_header_t *) ainfop->rawdata;
	
	/* Is the file big enough to contain an AppleDouble header? */
	if (rawsize < offsetof(apple_double_header_t, entries))
		return ENOATTR;
	
	/* Swap the AppleDouble header fields to native order */
	header->magic = SWAP32(header->magic);
	header->version = SWAP32(header->version);
	header->numEntries = SWAP16(header->numEntries);
	
	/* Sanity check the AppleDouble header fields */
	if (header->magic != ADH_MAGIC ||
	    header->version != ADH_VERSION ||
	    header->numEntries < 1 ||
	    header->numEntries > 15) {
		return ENOATTR;
	}
	
	/* Calculate where the entries[] array ends */
	header_end = offsetof(apple_double_header_t, entries) +
		header->numEntries * sizeof(apple_double_entry_t);
	
	/* Is the file big enough to contain the AppleDouble entries? */
	if (rawsize < header_end) {
	    	return ENOATTR;
	}
	
	/* Swap and sanity check each AppleDouble entry */
	for (i=0; i<header->numEntries; i++) {
		/* Swap the per-entry fields to native order */
		header->entries[i].type   = SWAP32(header->entries[i].type);
		header->entries[i].offset = SWAP32(header->entries[i].offset);
		header->entries[i].length = SWAP32(header->entries[i].length);
		
		entry_end = header->entries[i].offset + header->entries[i].length;
		
		/*
		 * Does the entry's content start within the header itself,
		 * did the addition overflow, or does the entry's content
		 * extend past the end of the file?
		 */
		if (header->entries[i].offset < header_end ||
		    entry_end < header->entries[i].offset  ||
		    entry_end > ainfop->filesize) {
			return ENOATTR;
		}
		
		/*
		 * Does the current entry's content overlap with a previous
		 * entry's content?
		 *
		 * Yes, this is O(N**2), and there are more efficient algorithms
		 * for testing pairwise overlap of N ranges when N is large.
		 * But we have already ensured N < 16, and N is almost always 2.
		 * So there's no point in using a more complex algorithm.
		 */
		
		for (j=0; j<i; j++) {
			if (entry_end > header->entries[j].offset &&
			    header->entries[j].offset + header->entries[j].length > header->entries[i].offset) {
				return ENOATTR;
			}
		}
	}
	
	return 0;
}



/*
 * Retrieve the data of an extended attribute.
 */
static int
default_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size,
                 __unused int options, vfs_context_t context)
{
	vnode_t xvp = NULL;
	attr_info_t ainfo;
	attr_header_t *header;
	attr_entry_t *entry;
	u_int8_t *attrdata;
	size_t datalen;
	int namelen;
	int isrsrcfork;
	int fileflags;
	int i;
	int error;

	fileflags = FREAD;
	if (bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) == 0) {
		isrsrcfork = 1;
		/*
		 * Open the file locked (shared) since the Carbon
		 * File Manager may have the Apple Double file open
		 * and could be changing the resource fork.
		 */
		fileflags |= O_SHLOCK;
	} else {
		isrsrcfork = 0;
	}

	if ((error = open_xattrfile(vp, fileflags, &xvp, context))) {
		return (error);
	}
	if ((error = get_xattrinfo(xvp, 0, &ainfo, context))) {
		close_xattrfile(xvp, fileflags, context);
		return (error);
	}

	/* Get the Finder Info. */
	if (bcmp(name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
	
		if (ainfo.finderinfo == NULL || ainfo.emptyfinderinfo) {
			error = ENOATTR;
		} else if (uio == NULL) {
			*size = FINDERINFOSIZE;
			error = 0;
		} else if (uio_offset(uio) != 0) {
			error = EINVAL;
		} else if (uio_resid(uio) < FINDERINFOSIZE) {
			error = ERANGE;
		} else {
			attrdata = (u_int8_t*)ainfo.filehdr + ainfo.finderinfo->offset;
			error = uiomove((caddr_t)attrdata, FINDERINFOSIZE, uio);
		}
		goto out;
	}

	/* Read the Resource Fork. */
	if (isrsrcfork) {
		if (!vnode_isreg(vp)) {
			error = EPERM;
		} else if (ainfo.rsrcfork == NULL) {
			error = ENOATTR;
		} else if (uio == NULL) {
			*size = (size_t)ainfo.rsrcfork->length;
		} else {
			uio_setoffset(uio, uio_offset(uio) + ainfo.rsrcfork->offset);
			error = VNOP_READ(xvp, uio, 0, context);
			if (error == 0)
				uio_setoffset(uio, uio_offset(uio) - ainfo.rsrcfork->offset);
		}
		goto out;
	}
	
	if (ainfo.attrhdr == NULL || ainfo.attr_entry == NULL) {
		error = ENOATTR;
		goto out;
	}
	if (uio_offset(uio) != 0) {
		error = EINVAL;
		goto out;
	}
	error = ENOATTR;
	namelen = strlen(name) + 1;
	header = ainfo.attrhdr;
	entry = ainfo.attr_entry;
	/*
	 * Search for attribute name in the header.
	 */
	for (i = 0; i < header->num_attrs && ATTR_VALID(entry, ainfo); i++) {
		if (strncmp((const char *)entry->name, name, namelen) == 0) {
			datalen = (size_t)entry->length;
			if (uio == NULL) {
				*size = datalen;
				error = 0;
				break;
			}
			if (uio_resid(uio) < (user_ssize_t)datalen) {
				error = ERANGE;
				break;
			}
			if (entry->offset + datalen < ATTR_MAX_HDR_SIZE) {
				attrdata = ((u_int8_t *)header + entry->offset);
				error = uiomove((caddr_t)attrdata, datalen, uio);
			} else {
				uio_setoffset(uio, entry->offset);
				error = VNOP_READ(xvp, uio, 0, context);
				uio_setoffset(uio, 0);
			}
			break;
		}
		entry = ATTR_NEXT(entry);
	}
out:	
	rel_xattrinfo(&ainfo);
	close_xattrfile(xvp, fileflags, context);

	return (error);
}

/*
 * Set the data of an extended attribute.
 */
static int
default_setxattr(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t context)
{
	vnode_t xvp = NULL;
	attr_info_t ainfo;
	attr_header_t *header;
	attr_entry_t *entry;
	attr_entry_t *lastentry;
	u_int8_t *attrdata;
	size_t datalen;
	size_t entrylen;
	size_t datafreespace;
	int namelen;
	int found = 0;
	int i;
	int splitdata;
	int fileflags;
	int error;
	char finfo[FINDERINFOSIZE];
	
	datalen = uio_resid(uio);
	namelen = strlen(name) + 1;
	entrylen = ATTR_ENTRY_LENGTH(namelen);

	/*
	 * By convention, Finder Info that is all zeroes is equivalent to not
	 * having a Finder Info EA.  So if we're trying to set the Finder Info
	 * to all zeroes, then delete it instead.  If a file didn't have an
	 * AppleDouble file before, this prevents creating an AppleDouble file
	 * with no useful content.
	 *
	 * If neither XATTR_CREATE nor XATTR_REPLACE were specified, we check
	 * for all zeroes Finder Info before opening the AppleDouble file.
	 * But if either of those options were specified, we need to open the
	 * AppleDouble file to see whether there was already Finder Info (so we
	 * can return an error if needed); this case is handled further below.
	 *
	 * NOTE: this copies the Finder Info data into the "finfo" local.
	 */
	if (bcmp(name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		/*
		 * TODO: check the XATTR_CREATE and XATTR_REPLACE flags.
		 * That means we probably have to open_xattrfile and get_xattrinfo.
		 */
		if (uio_offset(uio) != 0 || datalen != FINDERINFOSIZE) {
			return EINVAL;
		}
		error = uiomove(finfo, datalen, uio);
		if (error)
			return error;
		if ((options & (XATTR_CREATE|XATTR_REPLACE)) == 0 &&
		    bcmp(finfo, emptyfinfo, FINDERINFOSIZE) == 0) {
			error = default_removexattr(vp, name, 0, context);
			if (error == ENOATTR)
				error = 0;
			return error;
		}
	}
	
start:
	/*
	 * Open the file locked since setting an attribute
	 * can change the layout of the Apple Double file.
	 */
	fileflags = FREAD | FWRITE | O_EXLOCK;
	if ((error = open_xattrfile(vp, O_CREAT | fileflags, &xvp, context))) {
		return (error);
	}
	if ((error = get_xattrinfo(xvp, ATTR_SETTING, &ainfo, context))) {
		close_xattrfile(xvp, fileflags, context);
		return (error);
	}

	/* Set the Finder Info. */
	if (bcmp(name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		if (ainfo.finderinfo && !ainfo.emptyfinderinfo) {
			/* attr exists and "create" was specified? */
			if (options & XATTR_CREATE) {
				error = EEXIST;
				goto out;
			}
		} else {
			/* attr doesn't exists and "replace" was specified? */
			if (options & XATTR_REPLACE) {
				error = ENOATTR;
				goto out;
			}
		}
		if (options != 0 && bcmp(finfo, emptyfinfo, FINDERINFOSIZE) == 0) {
			/*
			 * Setting the Finder Info to all zeroes is equivalent to
			 * removing it.  Close the xattr file and let
			 * default_removexattr do the work (including deleting
			 * the xattr file if there are no other xattrs).
			 *
			 * Note that we have to handle the case where the
			 * Finder Info was already all zeroes, and we ignore
			 * ENOATTR.
			 *
			 * The common case where options == 0 was handled above.
			 */
			rel_xattrinfo(&ainfo);
			close_xattrfile(xvp, fileflags, context);
			error = default_removexattr(vp, name, 0, context);
			if (error == ENOATTR)
				error = 0;
			return error;
		}
		if (ainfo.finderinfo) {
			attrdata = (u_int8_t *)ainfo.filehdr + ainfo.finderinfo->offset;
			bcopy(finfo, attrdata, datalen);
			ainfo.iosize = sizeof(attr_header_t);
			error = write_xattrinfo(&ainfo);
			goto out;
		}
		error = ENOATTR;
		goto out;
	}

	/* Write the Resource Fork. */
	if (bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) == 0) {
		u_int32_t endoffset;

		if (!vnode_isreg(vp)) {
			error = EPERM;
			goto out;
		}
		/* Make sure we have a rsrc fork pointer.. */
		if (ainfo.rsrcfork == NULL) {
			error = ENOATTR;
			goto out;
		}
		if (ainfo.rsrcfork) {
			if (ainfo.rsrcfork->length != 0) {
				if (options & XATTR_CREATE) {
					/* attr exists, and create specified ? */
					error = EEXIST;
					goto out;
				}	
			}
			else {
				/* Zero length AD rsrc fork */
				if (options & XATTR_REPLACE) {
					/* attr doesn't exist (0-length), but replace specified ? */
					error = ENOATTR;
					goto out;
				}
			}
		}
		else {
			/* We can't do much if we somehow didn't get an AD rsrc pointer */
			error = ENOATTR;
			goto out;
		}

		endoffset = uio_resid(uio) + uio_offset(uio); /* new size */
		uio_setoffset(uio, uio_offset(uio) + ainfo.rsrcfork->offset);
		error = VNOP_WRITE(xvp, uio, 0, context);
		if (error)
			goto out;
		uio_setoffset(uio, uio_offset(uio) - ainfo.rsrcfork->offset);
		if (endoffset > ainfo.rsrcfork->length) {
			ainfo.rsrcfork->length = endoffset;
			ainfo.iosize = sizeof(attr_header_t);
			error = write_xattrinfo(&ainfo);
			goto out;
		}
		goto out;
	}

	if (datalen > ATTR_MAX_SIZE) {
		return (E2BIG);  /* EINVAL instead ? */
	}

	if (ainfo.attrhdr == NULL) {
		error = ENOATTR;
		goto out;
	}
	header = ainfo.attrhdr;
	entry = ainfo.attr_entry;

	/* Check if data area crosses the maximum header size. */
	if ((header->data_start + header->data_length + entrylen + datalen) > ATTR_MAX_HDR_SIZE)
		splitdata = 1;  /* do data I/O separately */
	else
		splitdata = 0;
	
	/*
	 * See if attribute already exists.
	 */
	for (i = 0; i < header->num_attrs && ATTR_VALID(entry, ainfo); i++) {
		if (strncmp((const char *)entry->name, name, namelen) == 0) {
			found = 1;
			break;
		}
		entry = ATTR_NEXT(entry);
	}

	if (found) {
		if (options & XATTR_CREATE) {
			error = EEXIST;
			goto out;
		}
		if (datalen == entry->length) {
			if (splitdata) {
				uio_setoffset(uio, entry->offset);
				error = VNOP_WRITE(xvp, uio, 0, context);
				uio_setoffset(uio, 0);
				if (error) {
					printf("setxattr: VNOP_WRITE error %d\n", error);
				}
			} else {
				attrdata = (u_int8_t *)header + entry->offset;
				error = uiomove((caddr_t)attrdata, datalen, uio);
				if (error)
					goto out;
				ainfo.iosize = ainfo.attrhdr->data_start + ainfo.attrhdr->data_length;
				error = write_xattrinfo(&ainfo);
				if (error) {
					printf("setxattr: write_xattrinfo error %d\n", error);
				}
			}
			goto out;
		} else {
			/*
			 * Brute force approach - just remove old entry and set new entry.
			 */
			found = 0;
			rel_xattrinfo(&ainfo);
			close_xattrfile(xvp, fileflags, context);
			error = default_removexattr(vp, name, options, context);
			if (error) {
				return (error);
			}
			/* Clear XATTR_REPLACE option since we just removed the attribute. */
			options &= ~XATTR_REPLACE;
			goto start; /* start over */
		}

	}

	if (options & XATTR_REPLACE) {
		error = ENOATTR;  /* nothing there to replace */
		goto out;
	}
	/* Check if header size limit has been reached. */
	if ((header->data_start + entrylen) > ATTR_MAX_HDR_SIZE) {
		error = ENOSPC;
		goto out;
	}

	datafreespace = header->total_size - (header->data_start + header->data_length);

	/* Check if we need more space. */
	if ((datalen + entrylen) > datafreespace) {
		size_t growsize;

		growsize = roundup((datalen + entrylen) - datafreespace, ATTR_BUF_SIZE);
		
		/* Clip roundup size when we can still fit in ATTR_MAX_HDR_SIZE. */
		if (!splitdata && (header->total_size + growsize) > ATTR_MAX_HDR_SIZE) {
			growsize = ATTR_MAX_HDR_SIZE - header->total_size;
		}

		ainfo.filesize += growsize;
		error = vnode_setsize(xvp, ainfo.filesize, 0, context);
		if (error) {
			printf("setxattr: VNOP_TRUNCATE error %d\n", error);
		}
		if (error)
			goto out;

		/*
		 * Move the resource fork out of the way.
		 */
		if (ainfo.rsrcfork) {
			if (ainfo.rsrcfork->length != 0) {
				shift_data_down(xvp,
						ainfo.rsrcfork->offset,
						ainfo.rsrcfork->length,
						growsize, context);
			}
			ainfo.rsrcfork->offset += growsize;
		}
		ainfo.finderinfo->length += growsize;
		header->total_size += growsize;
	}

	/* Make space for a new entry. */
	if (splitdata) {
		shift_data_down(xvp,
				header->data_start,
				header->data_length,
				entrylen, context);
	} else {
		bcopy((u_int8_t *)header + header->data_start,
		      (u_int8_t *)header + header->data_start + entrylen,
		      header->data_length);
	}
	header->data_start += entrylen;

	/* Fix up entry data offsets. */
	lastentry = entry;
	for (entry = ainfo.attr_entry; entry != lastentry && ATTR_VALID(entry, ainfo); entry = ATTR_NEXT(entry)) {
		entry->offset += entrylen;
	}
	
	/*
	 * If the attribute data area is entirely within
	 * the header buffer, then just update the buffer,
	 * otherwise we'll write it separately to the file.
	 */
	if (splitdata) {
		off_t offset;

		/* Write new attribute data after the end of existing data. */
		offset = header->data_start + header->data_length;
		uio_setoffset(uio, offset);
		error = VNOP_WRITE(xvp, uio, 0, context);
		uio_setoffset(uio, 0);
		if (error) {
			printf("setxattr: VNOP_WRITE error %d\n", error);
			goto out;
		}
	} else {
		attrdata = (u_int8_t *)header + header->data_start + header->data_length;
		
		error = uiomove((caddr_t)attrdata, datalen, uio);
		if (error) {
			printf("setxattr: uiomove error %d\n", error);
			goto out;
		}
	}

	/* Create the attribute entry. */
	lastentry->length = datalen;
	lastentry->offset = header->data_start + header->data_length;
	lastentry->namelen = namelen;
	lastentry->flags = 0;
	bcopy(name, &lastentry->name[0], namelen);

	/* Update the attributes header. */
	header->num_attrs++;
	header->data_length += datalen;

	if (splitdata) {
		/* Only write the entries, since the data was written separately. */
		ainfo.iosize = ainfo.attrhdr->data_start;
	} else {
		 /* The entry and data are both in the header; write them together. */
		ainfo.iosize = ainfo.attrhdr->data_start + ainfo.attrhdr->data_length;
	}
	error = write_xattrinfo(&ainfo);
	if (error) {
		printf("setxattr: write_xattrinfo error %d\n", error);
	}

out:	
	rel_xattrinfo(&ainfo);
	close_xattrfile(xvp, fileflags, context);

	/* Touch the change time if we changed an attribute. */
	if (error == 0) {
		struct vnode_attr va;

		/* Re-write the mtime to cause a ctime change. */
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_modify_time);
		if (vnode_getattr(vp, &va, context) == 0) {
			VATTR_INIT(&va);
			VATTR_SET(&va, va_modify_time, va.va_modify_time);
			(void) vnode_setattr(vp, &va, context);
		}
	}
	
	post_event_if_success(vp, error, NOTE_ATTRIB);

	return (error);
}


/*
 * Remove an extended attribute.
 */
static int
default_removexattr(vnode_t vp, const char *name, __unused int options, vfs_context_t context)
{
	vnode_t xvp = NULL;
	attr_info_t ainfo;
	attr_header_t *header;
	attr_entry_t *entry;
	attr_entry_t *oldslot;
	u_int8_t *attrdata;
	u_int32_t dataoff;
	size_t datalen;
	size_t entrylen;
	int namelen;
	int found = 0, lastone = 0;
	int i;
	int splitdata;
	int attrcount = 0;
	int isrsrcfork;
	int fileflags;
	int error;

	fileflags = FREAD | FWRITE;
	if (bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) == 0) {
		isrsrcfork = 1;
		/*
		 * Open the file locked (exclusive) since the Carbon
		 * File Manager may have the Apple Double file open
		 * and could be changing the resource fork.
		 */
		fileflags |= O_EXLOCK;
	} else {
		isrsrcfork = 0;
	}

	if ((error = open_xattrfile(vp, fileflags, &xvp, context))) {
		return (error);
	}
	if ((error = get_xattrinfo(xvp, 0, &ainfo, context))) {
		close_xattrfile(xvp, fileflags, context);
		return (error);
	}
	if (ainfo.attrhdr)
		attrcount += ainfo.attrhdr->num_attrs;
	if (ainfo.rsrcfork)
		++attrcount;
	if (ainfo.finderinfo && !ainfo.emptyfinderinfo)
		++attrcount;

	/* Clear the Finder Info. */
	if (bcmp(name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		if (ainfo.finderinfo == NULL || ainfo.emptyfinderinfo) {
			error = ENOATTR;
			goto out;
		}
		/* On removal of last attribute the ._ file is removed. */
		if (--attrcount == 0)
			goto out;
		attrdata = (u_int8_t *)ainfo.filehdr + ainfo.finderinfo->offset;
		bzero((caddr_t)attrdata, FINDERINFOSIZE);
		ainfo.iosize = sizeof(attr_header_t);
		error = write_xattrinfo(&ainfo);
		goto out;
	}

	/* Clear the Resource Fork. */
	if (isrsrcfork) {
		if (!vnode_isreg(vp)) {
			error = EPERM;
			goto out;
		}
		if (ainfo.rsrcfork == NULL || ainfo.rsrcfork->length == 0) {
			error = ENOATTR;
			goto out;
		}
		/* On removal of last attribute the ._ file is removed. */
		if (--attrcount == 0)
			goto out;
		/*
		 * XXX
		 * If the resource fork isn't the last AppleDouble
		 * entry then the space needs to be reclaimed by
		 * shifting the entries after the resource fork.
		 */
		if ((ainfo.rsrcfork->offset + ainfo.rsrcfork->length) == ainfo.filesize) {
			ainfo.filesize -= ainfo.rsrcfork->length;
			error = vnode_setsize(xvp, ainfo.filesize, 0, context);
		}
		if (error == 0) {
			ainfo.rsrcfork->length = 0;
			ainfo.iosize = sizeof(attr_header_t);
			error = write_xattrinfo(&ainfo);
		}
		goto out;
	}

	if (ainfo.attrhdr == NULL) {
		error = ENOATTR;
		goto out;
	}
	namelen = strlen(name) + 1;
	header = ainfo.attrhdr;
	entry = ainfo.attr_entry;

	/*
	 * See if this attribute exists.
	 */
	for (i = 0; i < header->num_attrs && ATTR_VALID(entry, ainfo); i++) {
		if (strncmp((const char *)entry->name, name, namelen) == 0) {
			found = 1;
			if ((i+1) == header->num_attrs)
				lastone = 1;
			break;
		}
		entry = ATTR_NEXT(entry);
	}
	if (!found) {
		error = ENOATTR;
		goto out;
	}
	/* On removal of last attribute the ._ file is removed. */
	if (--attrcount == 0)
		goto out;

	datalen = entry->length;
	dataoff = entry->offset;
	entrylen = ATTR_ENTRY_LENGTH(namelen);
	if ((header->data_start + header->data_length) > ATTR_MAX_HDR_SIZE)
		splitdata = 1;
	else
		splitdata = 0;

	/* Remove the attribute entry. */
	if (!lastone) {
		bcopy((u_int8_t *)entry + entrylen, (u_int8_t *)entry,
		      ((size_t)header + header->data_start) - ((size_t)entry + entrylen));
	}

	/* Adjust the attribute data. */
	if (splitdata) {
		shift_data_up(xvp,
		              header->data_start,
		              dataoff - header->data_start,
		              entrylen,
		              context);
		if (!lastone) {
			shift_data_up(xvp,
			              dataoff + datalen,
			              (header->data_start + header->data_length) - (dataoff + datalen),
			              datalen + entrylen,
			              context);
		}
		/* XXX write zeros to freed space ? */
		ainfo.iosize = ainfo.attrhdr->data_start - entrylen;
	} else {


		bcopy((u_int8_t *)header + header->data_start,
		      (u_int8_t *)header + header->data_start - entrylen,
		      dataoff - header->data_start);
		if (!lastone) {
			bcopy((u_int8_t *)header + dataoff + datalen,
			      (u_int8_t *)header + dataoff - entrylen,
			      (header->data_start + header->data_length) - (dataoff + datalen));
		}
		bzero (((u_int8_t *)header + header->data_start + header->data_length) - (datalen + entrylen), (datalen + entrylen));
		ainfo.iosize = ainfo.attrhdr->data_start + ainfo.attrhdr->data_length;
	}

	/* Adjust the header values and entry offsets. */
	header->num_attrs--;
	header->data_start -= entrylen;
	header->data_length -= datalen;

	oldslot = entry;
	entry = ainfo.attr_entry;
	for (i = 0; i < header->num_attrs && ATTR_VALID(entry, ainfo); i++) {
		entry->offset -= entrylen;
		if (entry >= oldslot)
			entry->offset -= datalen;
		entry = ATTR_NEXT(entry);
	}
	error = write_xattrinfo(&ainfo);
	if (error) {
		printf("removexattr: write_xattrinfo error %d\n", error);
	}
out:
	rel_xattrinfo(&ainfo);

	/* When there are no more attributes remove the ._ file. */
	if (attrcount == 0) {
		if (fileflags & O_EXLOCK)
			(void) unlock_xattrfile(xvp, context);
		VNOP_CLOSE(xvp, fileflags, context);
		vnode_rele(xvp);
		error = remove_xattrfile(xvp, context);
		vnode_put(xvp);
	} else {
		close_xattrfile(xvp, fileflags, context);
	}
	/* Touch the change time if we changed an attribute. */
	if (error == 0) {
		struct vnode_attr va;

		/* Re-write the mtime to cause a ctime change. */
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_modify_time);
		if (vnode_getattr(vp, &va, context) == 0) {
			VATTR_INIT(&va);
			VATTR_SET(&va, va_modify_time, va.va_modify_time);
			(void) vnode_setattr(vp, &va, context);
		}
	}

	post_event_if_success(vp, error, NOTE_ATTRIB);

	return (error);
	
}


/*
 * Retrieve the list of extended attribute names.
 */
static int
default_listxattr(vnode_t vp, uio_t uio, size_t *size, __unused int options, vfs_context_t context)
{
	vnode_t xvp = NULL;
	attr_info_t ainfo;
	attr_entry_t *entry;
	int i, count;
	int error;

	/*
	 * We do not zero "*size" here as we don't want to stomp a size set when
	 * VNOP_LISTXATTR processed any native EAs.  That size is initially zeroed by the
	 * system call layer, up in listxattr or flistxattr.
	 */

	if ((error = open_xattrfile(vp, FREAD, &xvp, context))) {
		if (error == ENOATTR)
			error = 0;
		return (error);
	}
	if ((error = get_xattrinfo(xvp, 0, &ainfo, context))) {
		if (error == ENOATTR)
			error = 0;
		close_xattrfile(xvp, FREAD, context);
		return (error);
	}

	/* Check for Finder Info. */
	if (ainfo.finderinfo && !ainfo.emptyfinderinfo) {
		if (uio == NULL) {
			*size += sizeof(XATTR_FINDERINFO_NAME);
		} else if (uio_resid(uio) < (user_ssize_t)sizeof(XATTR_FINDERINFO_NAME)) {
			error = ERANGE;
			goto out;
		} else {
			error = uiomove(XATTR_FINDERINFO_NAME,
			                sizeof(XATTR_FINDERINFO_NAME), uio);
			if (error) {
				error = ERANGE;
				goto out;
			}
		}
	}

	/* Check for Resource Fork. */
	if (vnode_isreg(vp) && ainfo.rsrcfork) {
		if (uio == NULL) {
			*size += sizeof(XATTR_RESOURCEFORK_NAME);
		} else if (uio_resid(uio) < (user_ssize_t)sizeof(XATTR_RESOURCEFORK_NAME)) {
			error = ERANGE;
			goto out;
		} else {
			error = uiomove(XATTR_RESOURCEFORK_NAME,
			                sizeof(XATTR_RESOURCEFORK_NAME), uio);
			if (error) {
				error = ERANGE;
				goto out;
			}
		}
	}

	/* Check for attributes. */
	if (ainfo.attrhdr) {
		count = ainfo.attrhdr->num_attrs;
		for (i = 0, entry = ainfo.attr_entry; i < count && ATTR_VALID(entry, ainfo); i++) {
			if (xattr_protected((const char *)entry->name) ||
			    xattr_validatename((const char *)entry->name) != 0) {
				entry = ATTR_NEXT(entry);
				continue;
			}
			if (uio == NULL) {
				*size += entry->namelen;
				entry = ATTR_NEXT(entry);
				continue;
			}
			if (uio_resid(uio) < entry->namelen) {
				error = ERANGE;
				break;
			}
			error = uiomove((caddr_t) entry->name, entry->namelen, uio);
			if (error) {
				if (error != EFAULT)
					error = ERANGE;
				break;
			}		
			entry = ATTR_NEXT(entry);
		}
	}
out:	
	rel_xattrinfo(&ainfo);
	close_xattrfile(xvp, FREAD, context);

	return (error);
}

static int
open_xattrfile(vnode_t vp, int fileflags, vnode_t *xvpp, vfs_context_t context)
{
	vnode_t xvp = NULLVP;
	vnode_t dvp = NULLVP;
	struct vnode_attr va;
	struct nameidata nd;
	char smallname[64];
	char *filename = NULL;
	const char *basename = NULL;
	size_t len;
	errno_t error;
	int opened = 0;
	int referenced = 0;

	if (vnode_isvroot(vp) && vnode_isdir(vp)) {
		/*
		 * For the root directory use "._." to hold the attributes.
		 */
		filename = &smallname[0];
		snprintf(filename, sizeof(smallname), "%s%s", ATTR_FILE_PREFIX, ".");
		dvp = vp;  /* the "._." file resides in the root dir */
		goto lookup;
	}
	if ( (dvp = vnode_getparent(vp)) == NULLVP) {
		error = ENOATTR;
		goto out;
	}
	if ( (basename = vnode_getname(vp)) == NULL) {
		error = ENOATTR;
		goto out;
	}

	/* "._" Attribute files cannot have attributes */
	if (vp->v_type == VREG && strlen(basename) > 2 &&
	    basename[0] == '.' && basename[1] == '_') {
		error = EPERM;
		goto out;
	}
	filename = &smallname[0];
	len = snprintf(filename, sizeof(smallname), "%s%s", ATTR_FILE_PREFIX, basename);
	if (len >= sizeof(smallname)) {
		len++;  /* snprintf result doesn't include '\0' */
		MALLOC(filename, char *, len, M_TEMP, M_WAITOK);
		len = snprintf(filename, len, "%s%s", ATTR_FILE_PREFIX, basename);
	}
	/*
	 * Note that the lookup here does not authorize.  Since we are looking
	 * up in the same directory that we already have the file vnode in,
	 * we must have been given the file vnode legitimately.  Read/write
	 * access has already been authorized in layers above for calls from
	 * userspace, and the authorization code using this path to read
	 * file security from the EA must always get access
	 */
lookup:
	NDINIT(&nd, LOOKUP, OP_OPEN, LOCKLEAF | NOFOLLOW | USEDVP | DONOTAUTH,
	       UIO_SYSSPACE, CAST_USER_ADDR_T(filename), context);
   	nd.ni_dvp = dvp;

	if (fileflags & O_CREAT) {
		nd.ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
		nd.ni_op = OP_LINK;
#endif
		if (dvp != vp) {
			nd.ni_cnd.cn_flags |= LOCKPARENT;
		}
		if ( (error = namei(&nd))) {
		        nd.ni_dvp = NULLVP;
			error = ENOATTR;
			goto out;
		}
		if ( (xvp = nd.ni_vp) == NULLVP) {
			uid_t uid;
			gid_t gid;
			mode_t umode;
	
			/*
			 * Pick up uid/gid/mode from target file.
			 */
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_uid);
			VATTR_WANTED(&va, va_gid);
			VATTR_WANTED(&va, va_mode);
			if (VNOP_GETATTR(vp, &va, context) == 0  &&
			    VATTR_IS_SUPPORTED(&va, va_uid)  &&
			    VATTR_IS_SUPPORTED(&va, va_gid)  &&
			    VATTR_IS_SUPPORTED(&va, va_mode)) {
				uid = va.va_uid;
				gid = va.va_gid;
				umode = va.va_mode & (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
			} else /* fallback values */ {
				uid = KAUTH_UID_NONE;
				gid = KAUTH_GID_NONE;
				umode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
			}

			VATTR_INIT(&va);
			VATTR_SET(&va, va_type, VREG);
			VATTR_SET(&va, va_mode, umode);
			if (uid != KAUTH_UID_NONE)
				VATTR_SET(&va, va_uid, uid);
			if (gid != KAUTH_GID_NONE)
				VATTR_SET(&va, va_gid, gid);

			error = vn_create(dvp, &nd.ni_vp, &nd, &va,
			                  VN_CREATE_NOAUTH | VN_CREATE_NOINHERIT | VN_CREATE_NOLABEL,
					  0, NULL,
			                  context);
			if (error)
				error = ENOATTR;
			else
				xvp = nd.ni_vp;
		}
		nameidone(&nd);
		if (dvp != vp) {
			vnode_put(dvp);  /* drop iocount from LOCKPARENT request above */
		}
		if (error)
		        goto out;
	} else {
		if ((error = namei(&nd))) {
			nd.ni_dvp = NULLVP;
			error = ENOATTR;
			goto out;
		}
	        xvp = nd.ni_vp;
		nameidone(&nd);
	}
	nd.ni_dvp = NULLVP;

	if (xvp->v_type != VREG) {
		error = ENOATTR;
		goto out;
	}
	/*
	 * Owners must match.
	 */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	if (VNOP_GETATTR(vp, &va, context) == 0 && VATTR_IS_SUPPORTED(&va, va_uid)) {
		uid_t owner = va.va_uid;

		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_uid);
		if (VNOP_GETATTR(xvp, &va, context) == 0 && (owner != va.va_uid)) {
			error = ENOATTR;  /* don't use this "._" file */
			goto out;
		}
	}
	
	if ( (error = VNOP_OPEN(xvp, fileflags & ~(O_EXLOCK | O_SHLOCK), context))) {
		error = ENOATTR;
		goto out;
	}
	opened = 1;

	if ((error = vnode_ref(xvp))) {
		goto out;
	}
	referenced = 1;

	/* If create was requested, make sure file header exists. */
	if (fileflags & O_CREAT) {
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_data_size);
		VATTR_WANTED(&va, va_fileid);
		VATTR_WANTED(&va, va_nlink);
		if ( (error = vnode_getattr(xvp, &va, context)) != 0) {
			error = EPERM;
			goto out;
		}
	
		/* If the file is empty then add a default header. */
		if (va.va_data_size == 0) {
			/* Don't adopt hard-linked "._" files. */
			if (VATTR_IS_SUPPORTED(&va, va_nlink) && va.va_nlink > 1) {
				error = EPERM;
				goto out;
			}
			if ( (error = create_xattrfile(xvp, (u_int32_t)va.va_fileid, context)))
				goto out;
		}
	}
	/* Apply file locking if requested. */	
	if (fileflags & (O_EXLOCK | O_SHLOCK)) {
		short locktype;

		locktype = (fileflags & O_EXLOCK) ? F_WRLCK : F_RDLCK;
		error = lock_xattrfile(xvp, locktype, context);
		if (error)
			error = ENOATTR;
	}
out:
	if (error) {
		if (xvp != NULLVP) {
			if (opened) {
				(void) VNOP_CLOSE(xvp, fileflags, context);
			}

			if (fileflags & O_CREAT) {
				/* Delete the xattr file if we encountered any errors */
				(void) remove_xattrfile (xvp, context);	
			}

			if (referenced) {
				(void) vnode_rele(xvp);
			}
			(void) vnode_put(xvp);
			xvp = NULLVP;
		}
		if ((error == ENOATTR) && (fileflags & O_CREAT)) {
			error = EPERM;
		}
	}
	/* Release resources after error-handling */
	if (dvp && (dvp != vp)) {
		vnode_put(dvp);
	}
	if (basename) {
		vnode_putname(basename);
	}
	if (filename && filename != &smallname[0]) {
		FREE(filename, M_TEMP);
	}

	*xvpp = xvp;  /* return a referenced vnode */
	return (error);
}

static void
close_xattrfile(vnode_t xvp, int fileflags, vfs_context_t context)
{
//	if (fileflags & FWRITE)
//		(void) VNOP_FSYNC(xvp, MNT_WAIT, context);

	if (fileflags & (O_EXLOCK | O_SHLOCK))
		(void) unlock_xattrfile(xvp, context);

	(void) VNOP_CLOSE(xvp, fileflags, context);
	(void) vnode_rele(xvp);
	(void) vnode_put(xvp);
}

static int
remove_xattrfile(vnode_t xvp, vfs_context_t context)
{
	vnode_t dvp;
	struct nameidata nd;
	char *path = NULL;
	int pathlen;
	int error = 0;

	MALLOC_ZONE(path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (path == NULL)
		return ENOMEM;

	pathlen = MAXPATHLEN;
	error = vn_getpath(xvp, path, &pathlen);
	if (error) {
		FREE_ZONE(path, MAXPATHLEN, M_NAMEI);
		return (error);
	}

	NDINIT(&nd, DELETE, OP_UNLINK, LOCKPARENT | NOFOLLOW | DONOTAUTH,
	       UIO_SYSSPACE, CAST_USER_ADDR_T(path), context);
	error = namei(&nd);
	FREE_ZONE(path, MAXPATHLEN, M_NAMEI);
	if (error) {
		return (error);
	}
	dvp = nd.ni_dvp;
	xvp = nd.ni_vp;

	error = VNOP_REMOVE(dvp, xvp, &nd.ni_cnd, 0, context);
	nameidone(&nd);
	vnode_put(dvp);
	vnode_put(xvp);

	return (error);
}

/*
 * Read in and parse the AppleDouble header and entries, and the extended
 * attribute header and entries if any.  Populates the fields of ainfop
 * based on the headers and entries found.
 *
 * The basic idea is to:
 * - Read in up to ATTR_MAX_HDR_SIZE bytes of the start of the file.  All
 *   AppleDouble entries, the extended attribute header, and extended
 *   attribute entries must lie within this part of the file; the rest of
 *   the AppleDouble handling code assumes this.  Plus it allows us to
 *   somewhat optimize by doing a smaller number of larger I/Os.
 * - Swap and sanity check the AppleDouble header (including the AppleDouble
 *   entries).
 * - Find the Finder Info and Resource Fork entries, if any.
 * - If we're going to be writing, try to make sure the Finder Info entry has
 *   room to store the extended attribute header, plus some space for extended
 *   attributes.
 * - Swap and sanity check the extended attribute header and entries (if any).
 */
static int
get_xattrinfo(vnode_t xvp, int setting, attr_info_t *ainfop, vfs_context_t context)
{
	uio_t auio = NULL;
	void * buffer = NULL;
	apple_double_header_t  *filehdr;
	struct vnode_attr va;
	size_t iosize;
	int i;
	int error;

	bzero(ainfop, sizeof(attr_info_t));
	ainfop->filevp = xvp;
	ainfop->context = context;
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_data_size);
	VATTR_WANTED(&va, va_fileid);
	if ((error = vnode_getattr(xvp, &va, context))) {
		goto bail;
	}
	ainfop->filesize = va.va_data_size;

	/* When setting attributes, allow room for the header to grow. */
	if (setting)
		iosize = ATTR_MAX_HDR_SIZE;
	else
		iosize = MIN(ATTR_MAX_HDR_SIZE, ainfop->filesize);

	if (iosize == 0) {
		error = ENOATTR;
		goto bail;
	}
	ainfop->iosize = iosize;
	MALLOC(buffer, void *, iosize, M_TEMP, M_WAITOK);
	if (buffer == NULL){
		error = ENOMEM;
		goto bail;
	}

	auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	uio_addiov(auio, (uintptr_t)buffer, iosize);

	/* Read the file header. */
	error = VNOP_READ(xvp, auio, 0, context);
	if (error) {
		goto bail;
	}
	ainfop->rawsize = iosize - uio_resid(auio);
	ainfop->rawdata = (u_int8_t *)buffer;
	
	filehdr = (apple_double_header_t *)buffer;

	error = check_and_swap_apple_double_header(ainfop);
	if (error)
		goto bail;
	
	ainfop->filehdr = filehdr;  /* valid AppleDouble header */

	/* rel_xattrinfo is responsible for freeing the header buffer */
	buffer = NULL;

	/* Find the Finder Info and Resource Fork entries, if any */
	for (i = 0; i < filehdr->numEntries; ++i) {
		if (filehdr->entries[i].type == AD_FINDERINFO &&
		    filehdr->entries[i].length >= FINDERINFOSIZE) {
			/* We found the Finder Info entry. */
			ainfop->finderinfo = &filehdr->entries[i];
			
			/*
			 * Is the Finder Info "empty" (all zeroes)?  If so,
			 * we'll pretend like the Finder Info extended attribute
			 * does not exist.
			 *
			 * Note: we have to make sure the Finder Info is
			 * contained within the buffer we have already read,
			 * to avoid accidentally accessing a bogus address.
			 * If it is outside the buffer, we just assume the
			 * Finder Info is non-empty.
			 */
			if (ainfop->finderinfo->offset + FINDERINFOSIZE <= ainfop->rawsize &&
			    bcmp((u_int8_t*)ainfop->filehdr + ainfop->finderinfo->offset, emptyfinfo, sizeof(emptyfinfo)) == 0) {
				ainfop->emptyfinderinfo = 1;
			}
		}
		if (filehdr->entries[i].type == AD_RESOURCE) {
			/*
			 * Ignore zero-length resource forks when getting.  If setting,
			 * we need to remember the resource fork entry so it can be
			 * updated once the new content has been written.
			 */
			if (filehdr->entries[i].length == 0 && !setting)
				continue;
			
			/*
			 * Check to see if any "empty" resource fork is ours (i.e. is ignorable).
			 *
			 * The "empty" resource headers we created have a system data tag of:
			 * "This resource fork intentionally left blank   "
			 */
			if (filehdr->entries[i].length == sizeof(rsrcfork_header_t) && !setting) {
				uio_t  rf_uio;
				u_int8_t  systemData[64];
				int  rf_err;


				/* Read the system data which starts at byte 16 */
				rf_uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
				uio_addiov(rf_uio, (uintptr_t)systemData, sizeof(systemData));
				uio_setoffset(rf_uio, filehdr->entries[i].offset + 16);
				rf_err = VNOP_READ(xvp, rf_uio, 0, context);
				uio_free(rf_uio);

				if (rf_err != 0 ||
				    bcmp(systemData, RF_EMPTY_TAG, sizeof(RF_EMPTY_TAG)) == 0) {
					continue;  /* skip this resource fork */
				}
			}
			ainfop->rsrcfork = &filehdr->entries[i];
			if (i != (filehdr->numEntries - 1)) {
				printf("get_xattrinfo: resource fork not last entry\n");
				ainfop->readonly = 1;
			}
			continue;
		}
	}
	
	/*
	 * See if this file looks like it is laid out correctly to contain
	 * extended attributes.  If so, then do the following:
	 *
	 * - If we're going to be writing, try to make sure the Finder Info
	 *   entry has room to store the extended attribute header, plus some
	 *   space for extended attributes.
	 *
	 * - Swap and sanity check the extended attribute header and entries
	 *   (if any).
	 */
	if (filehdr->numEntries == 2 &&
	    ainfop->finderinfo == &filehdr->entries[0] &&
	    ainfop->rsrcfork == &filehdr->entries[1] &&
	    ainfop->finderinfo->offset == offsetof(apple_double_header_t, finfo)) {
		attr_header_t *attrhdr;
		attrhdr = (attr_header_t *)filehdr;
		/*
		 * If we're going to be writing, try to make sure the Finder
		 * Info entry has room to store the extended attribute header,
		 * plus some space for extended attributes.
		 */
		if (setting && ainfop->finderinfo->length == FINDERINFOSIZE) {
			size_t delta;
			size_t writesize;
	
			delta = ATTR_BUF_SIZE - (filehdr->entries[0].offset + FINDERINFOSIZE);
			if (ainfop->rsrcfork && filehdr->entries[1].length) {
				/* Make some room before existing resource fork. */
				shift_data_down(xvp,
						filehdr->entries[1].offset,
						filehdr->entries[1].length,
						delta, context);
				writesize = sizeof(attr_header_t);
			} else {
				/* Create a new, empty resource fork. */
				rsrcfork_header_t *rsrcforkhdr;
	
				vnode_setsize(xvp, filehdr->entries[1].offset + delta, 0, context);
	
				/* Steal some space for an empty RF header. */
				delta -= sizeof(rsrcfork_header_t);
	
				bzero(&attrhdr->appledouble.pad[0], delta);
				rsrcforkhdr = (rsrcfork_header_t *)((char *)filehdr + filehdr->entries[1].offset + delta);
	
				/* Fill in Empty Resource Fork Header. */
				init_empty_resource_fork(rsrcforkhdr);
				
				filehdr->entries[1].length = sizeof(rsrcfork_header_t);
				writesize = ATTR_BUF_SIZE;
			}
			filehdr->entries[0].length += delta;
			filehdr->entries[1].offset += delta;
	
			/* Fill in Attribute Header. */
			attrhdr->magic       = ATTR_HDR_MAGIC;
			attrhdr->debug_tag   = (u_int32_t)va.va_fileid;
			attrhdr->total_size  = filehdr->entries[1].offset;
			attrhdr->data_start  = sizeof(attr_header_t);
			attrhdr->data_length = 0;
			attrhdr->reserved[0] = 0;
			attrhdr->reserved[1] = 0;
			attrhdr->reserved[2] = 0;
			attrhdr->flags       = 0;
			attrhdr->num_attrs   = 0;
	
			/* Push out new header */
			uio_reset(auio, 0, UIO_SYSSPACE, UIO_WRITE);
			uio_addiov(auio, (uintptr_t)filehdr, writesize);
	
			swap_adhdr(filehdr);	/* to big endian */
			swap_attrhdr(attrhdr, ainfop);	/* to big endian */
			error = VNOP_WRITE(xvp, auio, 0, context);
			swap_adhdr(filehdr);	/* back to native */
			/* The attribute header gets swapped below. */
		}
	}
	/*
	 * Swap and sanity check the extended attribute header and
	 * entries (if any).  The Finder Info content must be big enough
	 * to include the extended attribute header; if not, we just
	 * ignore it.
	 *
	 * Note that we're passing the offset + length (i.e. the end)
	 * of the Finder Info instead of rawsize to validate_attrhdr.
	 * This ensures that all extended attributes lie within the
	 * Finder Info content according to the AppleDouble entry.
	 *
	 * Sets ainfop->attrhdr and ainfop->attr_entry if a valid
	 * header was found.
	 */
	if (ainfop->finderinfo &&
		ainfop->finderinfo == &filehdr->entries[0] &&
		ainfop->finderinfo->length >= (sizeof(attr_header_t) - sizeof(apple_double_header_t))) {
		attr_header_t *attrhdr = (attr_header_t*)filehdr;

		if ((error = check_and_swap_attrhdr(attrhdr, ainfop)) == 0) {
			ainfop->attrhdr = attrhdr;  /* valid attribute header */
			/* First attr_entry starts immediately following attribute header */
			ainfop->attr_entry = (attr_entry_t *)&attrhdr[1];
		}
	}

	error = 0;
bail:
	if (auio != NULL)
		uio_free(auio);
	if (buffer != NULL)
		FREE(buffer, M_TEMP);
	return (error);
}


static int
create_xattrfile(vnode_t xvp, u_int32_t fileid, vfs_context_t context)
{
	attr_header_t *xah;
	rsrcfork_header_t *rsrcforkhdr;
	void * buffer;
	uio_t auio;
	int rsrcforksize;
	int error;

	MALLOC(buffer, void *, ATTR_BUF_SIZE, M_TEMP, M_WAITOK);
	bzero(buffer, ATTR_BUF_SIZE);

	xah = (attr_header_t *)buffer;
	auio = uio_create(1, 0, UIO_SYSSPACE, UIO_WRITE);
	uio_addiov(auio, (uintptr_t)buffer, ATTR_BUF_SIZE);
	rsrcforksize = sizeof(rsrcfork_header_t);
	rsrcforkhdr = (rsrcfork_header_t *) ((char *)buffer + ATTR_BUF_SIZE - rsrcforksize);

	/* Fill in Apple Double Header. */
	xah->appledouble.magic             = SWAP32 (ADH_MAGIC);
	xah->appledouble.version           = SWAP32 (ADH_VERSION);
	xah->appledouble.numEntries        = SWAP16 (2);
	xah->appledouble.entries[0].type   = SWAP32 (AD_FINDERINFO);
	xah->appledouble.entries[0].offset = SWAP32 (offsetof(apple_double_header_t, finfo));
	xah->appledouble.entries[0].length = SWAP32 (ATTR_BUF_SIZE - offsetof(apple_double_header_t, finfo) - rsrcforksize);
	xah->appledouble.entries[1].type   = SWAP32 (AD_RESOURCE);
	xah->appledouble.entries[1].offset = SWAP32 (ATTR_BUF_SIZE - rsrcforksize);
	xah->appledouble.entries[1].length = SWAP32 (rsrcforksize);
	bcopy(ADH_MACOSX, xah->appledouble.filler, sizeof(xah->appledouble.filler));

	/* Fill in Attribute Header. */
	xah->magic       = SWAP32 (ATTR_HDR_MAGIC);
	xah->debug_tag   = SWAP32 (fileid);
	xah->total_size  = SWAP32 (ATTR_BUF_SIZE - rsrcforksize);
	xah->data_start  = SWAP32 (sizeof(attr_header_t));

	/* Fill in Empty Resource Fork Header. */
	init_empty_resource_fork(rsrcforkhdr);

	/* Push it out. */
	error = VNOP_WRITE(xvp, auio, IO_UNIT, context);

	/* Did we write out the full uio? */
	if (uio_resid(auio) > 0) {
		error = ENOSPC;
	}

	uio_free(auio);
	FREE(buffer, M_TEMP);

	return (error);
}

static void
init_empty_resource_fork(rsrcfork_header_t * rsrcforkhdr)
{
	bzero(rsrcforkhdr, sizeof(rsrcfork_header_t));
	rsrcforkhdr->fh_DataOffset = SWAP32 (RF_FIRST_RESOURCE);
	rsrcforkhdr->fh_MapOffset  = SWAP32 (RF_FIRST_RESOURCE);
	rsrcforkhdr->fh_MapLength  = SWAP32 (RF_NULL_MAP_LENGTH);
	rsrcforkhdr->mh_DataOffset = SWAP32 (RF_FIRST_RESOURCE);
	rsrcforkhdr->mh_MapOffset  = SWAP32 (RF_FIRST_RESOURCE);
	rsrcforkhdr->mh_MapLength  = SWAP32 (RF_NULL_MAP_LENGTH);
	rsrcforkhdr->mh_Types      = SWAP16 (RF_NULL_MAP_LENGTH - 2 );
	rsrcforkhdr->mh_Names      = SWAP16 (RF_NULL_MAP_LENGTH);
	rsrcforkhdr->typeCount     = SWAP16 (-1);
	bcopy(RF_EMPTY_TAG, rsrcforkhdr->systemData, sizeof(RF_EMPTY_TAG));
}

static void
rel_xattrinfo(attr_info_t *ainfop)
{
	FREE(ainfop->filehdr, M_TEMP);
	bzero(ainfop, sizeof(attr_info_t));
}

static int
write_xattrinfo(attr_info_t *ainfop)
{
	uio_t auio;
	int error;

	auio = uio_create(1, 0, UIO_SYSSPACE, UIO_WRITE);
	uio_addiov(auio, (uintptr_t)ainfop->filehdr, ainfop->iosize);

	swap_adhdr(ainfop->filehdr);
	if (ainfop->attrhdr != NULL) {
		swap_attrhdr(ainfop->attrhdr, ainfop);
	}

	error = VNOP_WRITE(ainfop->filevp, auio, 0, ainfop->context);

	swap_adhdr(ainfop->filehdr);
	if (ainfop->attrhdr != NULL) {
		swap_attrhdr(ainfop->attrhdr, ainfop);
	}
	uio_free(auio);	

	return (error);
}

#if BYTE_ORDER == LITTLE_ENDIAN
/*
 * Endian swap apple double header 
 */
static void
swap_adhdr(apple_double_header_t *adh)
{
	int count;
	int i;

	count = (adh->magic == ADH_MAGIC) ? adh->numEntries : SWAP16(adh->numEntries);

	adh->magic      = SWAP32 (adh->magic);
	adh->version    = SWAP32 (adh->version);
	adh->numEntries = SWAP16 (adh->numEntries);

	for (i = 0; i < count; i++) {
		adh->entries[i].type   = SWAP32 (adh->entries[i].type);
		adh->entries[i].offset = SWAP32 (adh->entries[i].offset);
		adh->entries[i].length = SWAP32 (adh->entries[i].length);
	}
}

/*
 * Endian swap extended attributes header 
 */
static void
swap_attrhdr(attr_header_t *ah, attr_info_t* info)
{
	attr_entry_t *ae;
	int count;
	int i;

	count = (ah->magic == ATTR_HDR_MAGIC) ? ah->num_attrs : SWAP16(ah->num_attrs);

	ah->magic       = SWAP32 (ah->magic);
	ah->debug_tag   = SWAP32 (ah->debug_tag);
	ah->total_size  = SWAP32 (ah->total_size);
	ah->data_start  = SWAP32 (ah->data_start);
	ah->data_length = SWAP32 (ah->data_length);
	ah->flags       = SWAP16 (ah->flags);
	ah->num_attrs   = SWAP16 (ah->num_attrs);

	ae = (attr_entry_t *)(&ah[1]);
	for (i = 0; i < count && ATTR_VALID(ae, *info); i++, ae = ATTR_NEXT(ae)) {
		ae->offset = SWAP32 (ae->offset);
		ae->length = SWAP32 (ae->length);
		ae->flags  = SWAP16 (ae->flags);
	}
}
#endif

/*
 * Validate and swap the attributes header contents, and each attribute's
 * attr_entry_t.
 *
 * Note: Assumes the caller has verified that the Finder Info content is large
 * enough to contain the attr_header structure itself.  Therefore, we can
 * swap the header fields before sanity checking them.
 */
static int
check_and_swap_attrhdr(attr_header_t *ah, attr_info_t *ainfop)
{
	attr_entry_t *ae;
	u_int8_t *buf_end;
	u_int32_t end;
	int count;
	int i;

	if (ah == NULL)
		return EINVAL;

	if (SWAP32(ah->magic) != ATTR_HDR_MAGIC)
		return EINVAL;
	
	/* Swap the basic header fields */
	ah->magic	= SWAP32(ah->magic);
	ah->debug_tag   = SWAP32 (ah->debug_tag);
	ah->total_size  = SWAP32 (ah->total_size);
	ah->data_start  = SWAP32 (ah->data_start);
	ah->data_length = SWAP32 (ah->data_length);
	ah->flags       = SWAP16 (ah->flags);
	ah->num_attrs   = SWAP16 (ah->num_attrs);

	/*
	 * Make sure the total_size fits within the Finder Info area, and the
	 * extended attribute data area fits within total_size.
	 */
	end = ah->data_start + ah->data_length;
	if (ah->total_size > ainfop->finderinfo->offset + ainfop->finderinfo->length ||
	    end < ah->data_start ||
	    end > ah->total_size) {
		return EINVAL;
	}
	
	/*
	 * Make sure each of the attr_entry_t's fits within total_size.
	 */
	buf_end = ainfop->rawdata + ah->total_size;
	count = ah->num_attrs;
	ae = (attr_entry_t *)(&ah[1]);
	
	for (i=0; i<count; i++) {
		/* Make sure the fixed-size part of this attr_entry_t fits. */
		if ((u_int8_t *) &ae[1] > buf_end)
			return EINVAL;
		
		/* Make sure the variable-length name fits (+1 is for NUL terminator) */
		/* TODO: Make sure namelen matches strnlen(name,namelen+1)? */
		if (&ae->name[ae->namelen+1] > buf_end)
			return EINVAL;
		
		/* Swap the attribute entry fields */
		ae->offset	= SWAP32(ae->offset);
		ae->length	= SWAP32(ae->length);
		ae->flags	= SWAP16(ae->flags);
		
		/* Make sure the attribute content fits. */
		end = ae->offset + ae->length;
		if (end < ae->offset || end > ah->total_size)
			return EINVAL;
		
		ae = ATTR_NEXT(ae);
	}
	
	/*
	 * TODO: Make sure the contents of attributes don't overlap the header
	 * and don't overlap each other.  The hard part is that we don't know
	 * what the actual header size is until we have looped over all of the
	 * variable-sized attribute entries.
	 *
	 * XXX  Is there any guarantee that attribute entries are stored in
	 * XXX  order sorted by the contents' file offset?  If so, that would
	 * XXX  make the pairwise overlap check much easier.
	 */

	return 0;
}

//
// "start" & "end" are byte offsets in the file.
// "to" is the byte offset we want to move the
// data to.  "to" should be > "start".
//
// we do the copy backwards to avoid problems if
// there's an overlap.
//
static int
shift_data_down(vnode_t xvp, off_t start, size_t len, off_t delta, vfs_context_t context)
{
	int ret, iolen;
	size_t chunk, orig_chunk;
	char *buff;
	off_t pos;
	kauth_cred_t ucred = vfs_context_ucred(context);
	proc_t p = vfs_context_proc(context);
    
	if (delta == 0 || len == 0) {
		return 0;
	}
	
	chunk = 4096;
	if (len < chunk) {
		chunk = len;
	}
	orig_chunk = chunk;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&buff, chunk)) {
		return ENOMEM;
	}

	for(pos=start+len-chunk; pos >= start; pos-=chunk) {
		ret = vn_rdwr(UIO_READ, xvp, buff, chunk, pos, UIO_SYSSPACE, IO_NODELOCKED|IO_NOAUTH, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error reading data @ %lld (read %d of %lu) (%d)\n",
				pos, ret, chunk, ret);
			break;
		}
		
		ret = vn_rdwr(UIO_WRITE, xvp, buff, chunk, pos + delta, UIO_SYSSPACE, IO_NODELOCKED|IO_NOAUTH, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error writing data @ %lld (wrote %d of %lu) (%d)\n",
				pos+delta, ret, chunk, ret);
			break;
		}
		
		if ((pos - (off_t)chunk) < start) {
			chunk = pos - start;
	    
			if (chunk == 0) {   // we're all done
				break;
			}
		}
	}
	kmem_free(kernel_map, (vm_offset_t)buff, orig_chunk);

	return 0;
}


static int
shift_data_up(vnode_t xvp, off_t start, size_t len, off_t delta, vfs_context_t context)
{
	int ret, iolen;
	size_t chunk, orig_chunk;
	char *buff;
	off_t pos;
	off_t end;
	kauth_cred_t ucred = vfs_context_ucred(context);
	proc_t p = vfs_context_proc(context);
    
	if (delta == 0 || len == 0) {
		return 0;
	}
	
	chunk = 4096;
	if (len < chunk) {
		chunk = len;
	}
	orig_chunk = chunk;
	end = start + len;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&buff, chunk)) {
		return ENOMEM;
	}

	for(pos = start; pos < end; pos += chunk) {
		ret = vn_rdwr(UIO_READ, xvp, buff, chunk, pos, UIO_SYSSPACE, IO_NODELOCKED|IO_NOAUTH, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error reading data @ %lld (read %d of %lu) (%d)\n",
				pos, ret, chunk, ret);
			break;
		}
		
		ret = vn_rdwr(UIO_WRITE, xvp, buff, chunk, pos - delta, UIO_SYSSPACE, IO_NODELOCKED|IO_NOAUTH, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error writing data @ %lld (wrote %d of %lu) (%d)\n",
				pos+delta, ret, chunk, ret);
			break;
		}
		
		if ((pos + (off_t)chunk) > end) {
			chunk = end - pos;
	    
			if (chunk == 0) {   // we're all done
				break;
			}
		}
	}
	kmem_free(kernel_map, (vm_offset_t)buff, orig_chunk);

	return 0;
}

static int
lock_xattrfile(vnode_t xvp, short locktype, vfs_context_t context)
{
	struct flock lf;
	int error;

	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	lf.l_type = locktype; /* F_WRLCK or F_RDLCK */
	/* Note: id is just a kernel address that's not a proc */
	error = VNOP_ADVLOCK(xvp, (caddr_t)xvp, F_SETLK, &lf, F_FLOCK|F_WAIT, context, NULL);
	return (error == ENOTSUP ? 0 : error);
}

 int
unlock_xattrfile(vnode_t xvp, vfs_context_t context)
{
	struct flock lf;
	int error;

	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	lf.l_type = F_UNLCK;
	/* Note: id is just a kernel address that's not a proc */
	error = VNOP_ADVLOCK(xvp, (caddr_t)xvp, F_UNLCK, &lf, F_FLOCK, context, NULL);
	return (error == ENOTSUP ? 0 : error);
}

#else /* CONFIG_APPLEDOUBLE */


static int
default_getxattr(__unused vnode_t vp, __unused const char *name,
    __unused uio_t uio, __unused size_t *size, __unused int options,
    __unused vfs_context_t context)
{
	return (ENOTSUP);
}

static int
default_setxattr(__unused vnode_t vp, __unused const char *name,
    __unused uio_t uio, __unused int options, __unused vfs_context_t context)
{
	return (ENOTSUP);
}

static int
default_listxattr(__unused vnode_t vp,
    __unused uio_t uio, __unused size_t *size, __unused int options,
    __unused vfs_context_t context)
{
	return (ENOTSUP);
}

static int
default_removexattr(__unused vnode_t vp, __unused const char *name,
   __unused int options, __unused vfs_context_t context)
{
	return (ENOTSUP);
}

#endif /* CONFIG_APPLEDOUBLE */
