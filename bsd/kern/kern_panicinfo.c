/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vm.h>

#include <mach/kern_return.h>

/* prototypes not exported by osfmk. */
extern void kmem_free(vm_map_t, vm_offset_t, vm_size_t);
extern kern_return_t kmem_alloc_wired(vm_map_t, vm_offset_t *, vm_size_t);


/* Globals */
static off_t imagesizelimit = (4 * 4096);

/* Information about the current panic image */
static int image_bits = 32;	/* Bitdepth */

static char *image_pathname = NULL;	/* path to it */
static size_t image_pathlen = 0;	/* and the length of the pathname */

static vm_offset_t image_ptr = NULL; /* the image itself */
static off_t image_size = 0; /* and the imagesize */


__private_extern__ void
get_panicimage(vm_offset_t *imageptr, vm_size_t *imagesize, int *imagebits)
{
	*imageptr = image_ptr;
	*imagesize = image_size;
	*imagebits = image_bits;
}

static int
panicimage_from_file(
	char *imname,
	off_t sizelimit,
	vm_offset_t *image,
	off_t *filesize,
	struct proc *p)
{
	int error = 0;
	int error1 = 0;
	int aresid;
	struct nameidata nd;
	struct vattr	vattr;
	struct vnode * vp;
	kern_return_t	kret;
	struct pcred *pcred = p->p_cred;
	struct ucred *cred = pcred->pc_ucred;
	vm_offset_t iobuf;

	/* Open the file */
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, imname, p);
	error = vn_open(&nd, FREAD, S_IRUSR);
	if (error)
		return (error);
	vp = nd.ni_vp;
	
	if (vp->v_type != VREG) { 
		error = EFAULT;
		goto out;
	}

	/* get the file size */
	error = VOP_GETATTR(vp, &vattr, cred, p);
	if (error)
		goto out;

	/* validate the file size */
	if (vattr.va_size > sizelimit) {
		error = EFBIG;
		goto out;
	}

	/* allocate kernel wired memory */
	kret = kmem_alloc_wired(kernel_map, &iobuf,
				(vm_size_t)vattr.va_size);
	if (kret != KERN_SUCCESS) {
		switch (kret) {
		default:
			error = EINVAL;
			break;
		case KERN_NO_SPACE:
		case KERN_RESOURCE_SHORTAGE:
			error = ENOMEM;
			break;
		case KERN_PROTECTION_FAILURE:
			error = EPERM;
			break;
		}
		goto out;
	}

	/* read the file in the kernel buffer */
	error = vn_rdwr(UIO_READ, vp, (caddr_t)iobuf, (int)vattr.va_size,
			(off_t)0, UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT,
			cred, &aresid, p);
	if (error) {
		(void)kmem_free(kernel_map, iobuf, (vm_size_t)vattr.va_size);
		goto out;
	}

	/*
	 * return the image to the caller
	 * freeing this memory is callers responsibility
	 */
	*image = iobuf;
	*filesize = (off_t)vattr.va_size;

out:
	VOP_UNLOCK(vp, 0, p);
	error1 = vn_close(vp, FREAD, cred, p);
	if (error == 0)
		error = error1;
	return (error);
}

__private_extern__ int
sysctl_dopanicinfo(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	int error = 0;
	int bitdepth = 32;	/* default is 32 bits */
	char *imname;

	/* all sysctl names at this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
	default:
		return (EOPNOTSUPP);
	case KERN_PANICINFO_MAXSIZE:
		if (newp != NULL && (error = suser(p->p_ucred, &p->p_acflag)))
			return (error);
		error = sysctl_quad(oldp, oldlenp, newp, newlen, &imagesizelimit);
		return (error);

	case KERN_PANICINFO_IMAGE16:
		bitdepth = 16;
		/* and fall through */
	case KERN_PANICINFO_IMAGE32:
		/* allocate a buffer for the image pathname */
		MALLOC_ZONE(imname, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);

		if (!newp) {
			bcopy(image_pathname, imname, image_pathlen);
			imname[image_pathlen] = '\0';
		} else
			imname[0] = '\0';
		error = sysctl_string(oldp, oldlenp, newp, newlen,
		    imname, MAXPATHLEN);
		if (newp && !error) {
			char *tmpstr, *oldstr;
			off_t filesize = 0;
			size_t len;
			vm_offset_t image;
			vm_offset_t oimage;
			vm_size_t osize;

			len = strlen(imname);
			oldstr = image_pathname;

			error = panicimage_from_file(imname, imagesizelimit,
					&image, &filesize, p);
			if (error)
				goto errout;

			/* release the old image */
			if (image_ptr) {
				oimage = image_ptr;
				osize = image_size;
			}

			/* remember the new one */
			image_ptr = image;
			image_bits = bitdepth;	/* new bith depth */
			image_size = filesize; /* new imagesize */

			if (oimage)
				kmem_free(kernel_map, oimage, osize);

			/* save the new name */
			MALLOC(tmpstr, char *, len+1, M_TEMP, M_WAITOK);
			bcopy(imname, tmpstr, len);
			tmpstr[len] = '\0';

			image_pathname = tmpstr;	/* new pathname */
			image_pathlen = len;	/* new pathname length */

			/* free the old name */
			FREE(oldstr, M_TEMP);
		}
errout:
		FREE_ZONE(imname, MAXPATHLEN, M_NAMEI);
		return (error);
	}
}
