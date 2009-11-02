/*
 * Copyright (c) 1995-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/kernel.h>
#include <sys/stat.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/uio_internal.h>
#include <sys/malloc.h>
#include <sys/attr.h>
#include <sys/sysproto.h>
#include <sys/xattr.h>
#include <sys/fsevents.h>
#include <kern/kalloc.h>
#include <miscfs/specfs/specdev.h>
#include <hfs/hfs.h>

#define ATTR_TIME_SIZE	-1

/*
 * Structure describing the state of an in-progress attrlist operation.
 */
struct _attrlist_buf {
	char	*base;
	char	*fixedcursor;
	char	*varcursor;
	ssize_t	allocated;
	ssize_t needed;
};


/*
 * Pack (count) bytes from (source) into (buf).
 */
static void
attrlist_pack_fixed(struct _attrlist_buf *ab, void *source, ssize_t count)
{
	ssize_t	fit;

	/* how much room left in the buffer? */
	fit = imin(count, ab->allocated - (ab->fixedcursor - ab->base));
	if (fit > 0)
		bcopy(source, ab->fixedcursor, fit);

	/* always move in increments of 4 */
	ab->fixedcursor += roundup(count, 4);
}
static void
attrlist_pack_variable2(struct _attrlist_buf *ab, const void *source, ssize_t count, const void *ext, ssize_t extcount)
{
	struct attrreference	ar;
	ssize_t fit;

	/* pack the reference to the variable object */
	ar.attr_dataoffset = ab->varcursor - ab->fixedcursor;
	ar.attr_length = count + extcount;
	attrlist_pack_fixed(ab, &ar, sizeof(ar));

	/* calculate space and pack the variable object */
	fit = imin(count, ab->allocated - (ab->varcursor - ab->base));
	if (fit > 0) {
		if (source != NULL)
			bcopy(source, ab->varcursor, fit);
		ab->varcursor += fit;
	}
	fit = imin(extcount, ab->allocated - (ab->varcursor - ab->base));
	if (fit > 0) {
		if (ext != NULL)
			bcopy(ext, ab->varcursor, fit);
		ab->varcursor += fit;
	}
	/* always move in increments of 4 */
	ab->varcursor = (char *)roundup((uintptr_t)ab->varcursor, 4);
}
static void
attrlist_pack_variable(struct _attrlist_buf *ab, const void *source, ssize_t count)
{
	attrlist_pack_variable2(ab, source, count, NULL, 0);
}
static void
attrlist_pack_string(struct _attrlist_buf *ab, const char *source, ssize_t count)
{
	struct attrreference	ar;
	ssize_t fit, space;

	
	/*
	 * Supplied count is character count of string text, excluding trailing nul
	 * which we always supply here.
	 */
	if (source == NULL) {
		count = 0;
	} else if (count == 0) {
		count = strlen(source);
	}

	/*
	 * Make the reference and pack it.
	 * Note that this is entirely independent of how much we get into
	 * the buffer.
	 */
	ar.attr_dataoffset = ab->varcursor - ab->fixedcursor;
	ar.attr_length = count + 1;
	attrlist_pack_fixed(ab, &ar, sizeof(ar));
	
	/* calculate how much of the string text we can copy, and do that */
	space = ab->allocated - (ab->varcursor - ab->base);
	fit = imin(count, space);
	if (fit > 0)
		bcopy(source, ab->varcursor, fit);
	/* is there room for our trailing nul? */
	if (space > fit)
		ab->varcursor[fit] = '\0';

	/* always move in increments of 4 */
	ab->varcursor += roundup(count + 1, 4);
}

#define ATTR_PACK(b, v)	attrlist_pack_fixed(b, &v, sizeof(v))
#define ATTR_PACK_CAST(b, t, v)						\
	do {								\
		t _f = (t)v;						\
		ATTR_PACK(b, _f);					\
	} while (0)

#define ATTR_PACK_TIME(b, v, is64)					       		\
	do {										\
		if (is64) {								\
			struct user_timespec us = {v.tv_sec, v.tv_nsec};		\
			ATTR_PACK(b, us);						\
		} else {								\
			ATTR_PACK(b, v);						\
		}									\
	} while(0)


/*
 * Table-driven setup for all valid common/volume attributes.
 */
struct getvolattrlist_attrtab {
	attrgroup_t	attr;
	uint64_t	bits;
#define VFSATTR_BIT(b)	(VFSATTR_ ## b)
	ssize_t		size;
};
static struct getvolattrlist_attrtab getvolattrlist_common_tab[] = {
	{ATTR_CMN_NAME,		0,				sizeof(struct attrreference)},
	{ATTR_CMN_DEVID,	0,				sizeof(dev_t)},
	{ATTR_CMN_FSID,		0,				sizeof(fsid_t)},
	{ATTR_CMN_OBJTYPE,	0,				sizeof(fsobj_type_t)},
	{ATTR_CMN_OBJTAG,	0,				sizeof(fsobj_tag_t)},
	{ATTR_CMN_OBJID,	0,				sizeof(fsobj_id_t)},
	{ATTR_CMN_OBJPERMANENTID, 0,				sizeof(fsobj_id_t)},
	{ATTR_CMN_PAROBJID,	0,				sizeof(fsobj_id_t)},
	{ATTR_CMN_SCRIPT,	0,				sizeof(text_encoding_t)},
	{ATTR_CMN_CRTIME,	VFSATTR_BIT(f_create_time),	ATTR_TIME_SIZE},
	{ATTR_CMN_MODTIME,	VFSATTR_BIT(f_modify_time),	ATTR_TIME_SIZE},
	{ATTR_CMN_CHGTIME,	VFSATTR_BIT(f_modify_time),	ATTR_TIME_SIZE},
	{ATTR_CMN_ACCTIME,	VFSATTR_BIT(f_access_time),	ATTR_TIME_SIZE},
	{ATTR_CMN_BKUPTIME,	VFSATTR_BIT(f_backup_time),	ATTR_TIME_SIZE},
	{ATTR_CMN_FNDRINFO,	0,				32},
	{ATTR_CMN_OWNERID,	0,				sizeof(uid_t)},
	{ATTR_CMN_GRPID,	0,				sizeof(gid_t)},
	{ATTR_CMN_ACCESSMASK,	0,				sizeof(uint32_t)},
	{ATTR_CMN_FLAGS,	0,				sizeof(uint32_t)},
	{ATTR_CMN_USERACCESS,	0,				sizeof(uint32_t)},
	{0, 0, 0}
};

static struct getvolattrlist_attrtab getvolattrlist_vol_tab[] = {
	{ATTR_VOL_FSTYPE,		0,						sizeof(uint32_t)},
	{ATTR_VOL_SIGNATURE,		VFSATTR_BIT(f_signature),			sizeof(uint32_t)},
	{ATTR_VOL_SIZE,			VFSATTR_BIT(f_blocks),				sizeof(off_t)},
	{ATTR_VOL_SPACEFREE,		VFSATTR_BIT(f_bfree) | VFSATTR_BIT(f_bsize),	sizeof(off_t)},
	{ATTR_VOL_SPACEAVAIL,		VFSATTR_BIT(f_bavail) | VFSATTR_BIT(f_bsize),	sizeof(off_t)},
	{ATTR_VOL_MINALLOCATION,	VFSATTR_BIT(f_bsize),				sizeof(off_t)},
	{ATTR_VOL_ALLOCATIONCLUMP,	VFSATTR_BIT(f_bsize),				sizeof(off_t)},
	{ATTR_VOL_IOBLOCKSIZE,		VFSATTR_BIT(f_iosize),				sizeof(uint32_t)},
	{ATTR_VOL_OBJCOUNT,		VFSATTR_BIT(f_objcount),			sizeof(uint32_t)},
	{ATTR_VOL_FILECOUNT,		VFSATTR_BIT(f_filecount),			sizeof(uint32_t)},
	{ATTR_VOL_DIRCOUNT,		VFSATTR_BIT(f_dircount),			sizeof(uint32_t)},
	{ATTR_VOL_MAXOBJCOUNT,		VFSATTR_BIT(f_maxobjcount),			sizeof(uint32_t)},
	{ATTR_VOL_MOUNTPOINT,		0,						sizeof(struct attrreference)},
	{ATTR_VOL_NAME,			VFSATTR_BIT(f_vol_name),				sizeof(struct attrreference)},
	{ATTR_VOL_MOUNTFLAGS,		0,						sizeof(uint32_t)},
	{ATTR_VOL_MOUNTEDDEVICE,	0,						sizeof(struct attrreference)},
	{ATTR_VOL_ENCODINGSUSED,	0,						sizeof(uint64_t)},
	{ATTR_VOL_CAPABILITIES,		VFSATTR_BIT(f_capabilities),			sizeof(vol_capabilities_attr_t)},
	{ATTR_VOL_ATTRIBUTES,		VFSATTR_BIT(f_attributes),			sizeof(vol_attributes_attr_t)},
	{ATTR_VOL_INFO, 0, 0},
	{0, 0, 0}
};

static int
getvolattrlist_parsetab(struct getvolattrlist_attrtab *tab, attrgroup_t attrs, struct vfs_attr *vsp,
    ssize_t *sizep, int is_64bit)
{
	attrgroup_t	recognised;

	recognised = 0;
	do {
		/* is this attribute set? */
		if (tab->attr & attrs) {
			recognised |= tab->attr;
			vsp->f_active |= tab->bits;
			if (tab->size == ATTR_TIME_SIZE) {
				if (is_64bit) {
					*sizep += sizeof(struct user_timespec);
				} else {
					*sizep += sizeof(struct timespec);
				}
			} else {
				*sizep += tab->size;
			}
		}
	} while ((++tab)->attr != 0);
	
	/* check to make sure that we recognised all of the passed-in attributes */
	if (attrs & ~recognised)
		return(EINVAL);
	return(0);
}

/*
 * Given the attributes listed in alp, configure vap to request
 * the data from a filesystem.
 */
static int
getvolattrlist_setupvfsattr(struct attrlist *alp, struct vfs_attr *vsp, ssize_t *sizep, int is_64bit)
{
	int	error;

	/*
	 * Parse the above tables.
	 */
	*sizep = sizeof(uint32_t);	/* length count */
	if (alp->commonattr &&
	    (error = getvolattrlist_parsetab(getvolattrlist_common_tab, alp->commonattr, vsp, sizep, is_64bit)) != 0)
		return(error);
	if (alp->volattr &&
	    (error = getvolattrlist_parsetab(getvolattrlist_vol_tab, alp->volattr, vsp, sizep, is_64bit)) != 0)
		return(error);

	return(0);
}

/*
 * Table-driven setup for all valid common/dir/file/fork attributes against files.
 */
struct getattrlist_attrtab {
	attrgroup_t	attr;
	uint64_t	bits;
#define VATTR_BIT(b)	(VNODE_ATTR_ ## b)
	ssize_t		size;
	kauth_action_t	action;
};
static struct getattrlist_attrtab getattrlist_common_tab[] = {
	{ATTR_CMN_NAME,		VATTR_BIT(va_name),		sizeof(struct attrreference),	KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_DEVID,	0,				sizeof(dev_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FSID,		VATTR_BIT(va_fsid),		sizeof(fsid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_OBJTYPE,	0,				sizeof(fsobj_type_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_OBJTAG,	0,				sizeof(fsobj_tag_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_OBJID,	VATTR_BIT(va_fileid) | VATTR_BIT(va_linkid), sizeof(fsobj_id_t), KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_OBJPERMANENTID, VATTR_BIT(va_fileid) | VATTR_BIT(va_linkid), sizeof(fsobj_id_t), KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_PAROBJID,	VATTR_BIT(va_parentid),		sizeof(fsobj_id_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_SCRIPT,	VATTR_BIT(va_encoding),		sizeof(text_encoding_t),	KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_CRTIME,	VATTR_BIT(va_create_time),	ATTR_TIME_SIZE,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_MODTIME,	VATTR_BIT(va_modify_time),	ATTR_TIME_SIZE,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_CHGTIME,	VATTR_BIT(va_change_time),	ATTR_TIME_SIZE,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_ACCTIME,	VATTR_BIT(va_access_time),	ATTR_TIME_SIZE,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_BKUPTIME,	VATTR_BIT(va_backup_time),	ATTR_TIME_SIZE,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FNDRINFO,	0,				32,				KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_OWNERID,	VATTR_BIT(va_uid),		sizeof(uid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_GRPID,	VATTR_BIT(va_gid),		sizeof(gid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_ACCESSMASK,	VATTR_BIT(va_mode),		sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FLAGS,	VATTR_BIT(va_flags),		sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_USERACCESS,	0,				sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_EXTENDED_SECURITY, VATTR_BIT(va_acl),	sizeof(struct attrreference),		KAUTH_VNODE_READ_SECURITY},
	{ATTR_CMN_UUID,		VATTR_BIT(va_uuuid),		sizeof(guid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_GRPUUID,	VATTR_BIT(va_guuid),		sizeof(guid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{0, 0, 0, 0}
};
static struct getattrlist_attrtab getattrlist_dir_tab[] = {
	{ATTR_DIR_LINKCOUNT,	VATTR_BIT(va_nlink),		sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_DIR_ENTRYCOUNT,	VATTR_BIT(va_nchildren),	sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	/* ATTR_DIR_ENTRYCOUNT falls back to va_nlink-2 if va_nchildren isn't supported, so request va_nlink just in case */
	{ATTR_DIR_ENTRYCOUNT,	VATTR_BIT(va_nlink),		0,				KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_DIR_MOUNTSTATUS,	0,				sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{0, 0, 0, 0}
};
static struct getattrlist_attrtab getattrlist_file_tab[] = {
	{ATTR_FILE_LINKCOUNT,	VATTR_BIT(va_nlink),		sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_TOTALSIZE,	VATTR_BIT(va_total_size),	sizeof(off_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_ALLOCSIZE,	VATTR_BIT(va_total_alloc) | VATTR_BIT(va_total_size), sizeof(off_t), KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_IOBLOCKSIZE,	VATTR_BIT(va_iosize),		sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_DEVTYPE,	VATTR_BIT(va_rdev),		sizeof(dev_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_DATALENGTH,	VATTR_BIT(va_total_size) | VATTR_BIT(va_data_size), sizeof(off_t), KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_DATAALLOCSIZE, VATTR_BIT(va_total_alloc)| VATTR_BIT(va_data_alloc), sizeof(off_t), KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_RSRCLENGTH,	0,				sizeof(off_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_RSRCALLOCSIZE, 0,				sizeof(off_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{0, 0, 0, 0}
};	

static int
getattrlist_parsetab(struct getattrlist_attrtab *tab, attrgroup_t attrs, struct vnode_attr *vap,
    ssize_t *sizep, kauth_action_t *actionp, int is_64bit)
{
	attrgroup_t	recognised;

	recognised = 0;
	do {
		/* is this attribute set? */
		if (tab->attr & attrs) {
			recognised |= tab->attr;
			vap->va_active |= tab->bits;
			if (tab->size == ATTR_TIME_SIZE) {
				if (is_64bit) {
					*sizep += sizeof(struct user_timespec);
				} else {
					*sizep += sizeof(struct timespec);
				}
			} else {
				*sizep += tab->size;
			}
			*actionp |= tab->action;
		}
	} while ((++tab)->attr != 0);
	
	/* check to make sure that we recognised all of the passed-in attributes */
	if (attrs & ~recognised)
		return(EINVAL);
	return(0);
}

/*
 * Given the attributes listed in alp, configure vap to request
 * the data from a filesystem.
 */
static int
getattrlist_setupvattr(struct attrlist *alp, struct vnode_attr *vap, ssize_t *sizep, kauth_action_t *actionp, int is_64bit, int isdir)
{
	int	error;

	/*
	 * Parse the above tables.
	 */
	*sizep = sizeof(uint32_t);	/* length count */
	*actionp = 0;
	if (alp->commonattr &&
	    (error = getattrlist_parsetab(getattrlist_common_tab, alp->commonattr, vap, sizep, actionp, is_64bit)) != 0)
		return(error);
	if (isdir && alp->dirattr &&
	    (error = getattrlist_parsetab(getattrlist_dir_tab, alp->dirattr, vap, sizep, actionp, is_64bit)) != 0)
		return(error);
	if (!isdir && alp->fileattr &&
	    (error = getattrlist_parsetab(getattrlist_file_tab, alp->fileattr, vap, sizep, actionp, is_64bit)) != 0)
		return(error);

	return(0);
}

static int
setattrlist_setfinderinfo(vnode_t vp, char *fndrinfo, struct vfs_context *ctx)
{
	uio_t	auio;
	char	uio_buf[UIO_SIZEOF(1)];
	int	error;

	if ((auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_WRITE, uio_buf, sizeof(uio_buf))) == NULL) {
		error = ENOMEM;
	} else {
		uio_addiov(auio, CAST_USER_ADDR_T(fndrinfo), 32);
		error = vn_setxattr(vp, XATTR_FINDERINFO_NAME, auio, XATTR_NOSECURITY, ctx);
		uio_free(auio);
	}

	if (error == 0 && need_fsevent(FSE_FINDER_INFO_CHANGED, vp)) {
	    add_fsevent(FSE_FINDER_INFO_CHANGED, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
	}

	return (error);
}


/*
 * Find something resembling a terminal component name in the mountedonname for vp
 *
 */
static void
getattrlist_findnamecomp(const char *mn, const char **np, ssize_t *nl)
{
	int		counting;
	const char	*cp;

	/*
	 * We're looking for the last sequence of non / characters, but
	 * not including any trailing / characters.
	 */
	*np = NULL;
	*nl = 0;
	counting = 0;
	for (cp = mn; *cp != 0; cp++) {
		if (!counting) {
			/* start of run of chars */
			if (*cp != '/') {
				*np = cp;
				counting = 1;
			}
		} else {
			/* end of run of chars */
			if (*cp == '/') {
				*nl = cp - *np;
				counting = 0;
			}
		}
	}
	/* need to close run? */
	if (counting)
		*nl = cp - *np;
}


static int
getvolattrlist(vnode_t vp, struct getattrlist_args *uap, struct attrlist *alp,  vfs_context_t ctx, int is_64bit)
{
	struct vfs_attr vs;
	struct vnode_attr va;
	struct _attrlist_buf ab;
	int		error;
	ssize_t		fixedsize, varsize;
	const char	*cnp;
	ssize_t		cnl;
	mount_t		mnt;

	ab.base = NULL;
	VATTR_INIT(&va);
	VFSATTR_INIT(&vs);
	vs.f_vol_name = NULL;
	mnt = vp->v_mount;

	
	/*
	 * For now, the vnode must be the root of its filesystem.
	 * To relax this, we need to be able to find the root vnode of a filesystem
	 * from any vnode in the filesystem.
	 */
	if (!vnode_isvroot(vp)) {
		error = EINVAL;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: volume attributes requested but not the root of a filesystem");
		goto out;
	}
	
	/*
	 * Set up the vfs_attr structure and call the filesystem.
	 */
	if ((error = getvolattrlist_setupvfsattr(alp, &vs, &fixedsize, is_64bit)) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: setup for request failed");
		goto out;
	}
	if (vs.f_active != 0) {
		/* If we're going to ask for f_vol_name, allocate a buffer to point it at */
		if (VFSATTR_IS_ACTIVE(&vs, f_vol_name)) {
			vs.f_vol_name = (char *) kalloc(MAXPATHLEN);
			if (vs.f_vol_name == NULL) {
				error = ENOMEM;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not allocate f_vol_name buffer");
				goto out;
			}
		}

		VFS_DEBUG(ctx, vp, "ATTRLIST -       calling to get %016llx with supported %016llx", vs.f_active, vs.f_supported);
		if ((error = vfs_getattr(mnt, &vs, ctx)) != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: filesystem returned %d", error);
			goto out;
		}

		/*
		 * Did we ask for something the filesystem doesn't support?
		 */
		if (!VFSATTR_ALL_SUPPORTED(&vs)) {
			/* default value for volume subtype */
			if (VFSATTR_IS_ACTIVE(&vs, f_fssubtype)
			    && !VFSATTR_IS_SUPPORTED(&vs, f_fssubtype))
				VFSATTR_RETURN(&vs, f_fssubtype, 0);

			/*
			 * If the file system didn't supply f_signature, then
			 * default it to 'BD', which is the generic signature
			 * that most Carbon file systems should return.
			 */
			if (VFSATTR_IS_ACTIVE(&vs, f_signature)
			    && !VFSATTR_IS_SUPPORTED(&vs, f_signature))
				VFSATTR_RETURN(&vs, f_signature, 0x4244);

			/* default for block size */
			if (VFSATTR_IS_ACTIVE(&vs, f_bsize)
			    && !VFSATTR_IS_SUPPORTED(&vs, f_bsize))
				VFSATTR_RETURN(&vs, f_bsize, mnt->mnt_devblocksize);

			/* check to see if our fixups were enough */
			if (!VFSATTR_ALL_SUPPORTED(&vs)) {
				error = EINVAL;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not get all requested volume attributes");
				VFS_DEBUG(ctx, vp, "ATTRLIST -        wanted %016llx got %016llx missing %016llx",
				    vs.f_active, vs.f_supported, vs.f_active & ~vs.f_supported);
				goto out;
			}
		}
	}

	/*
	 * Some fields require data from the root vp
	 */
	if (alp->commonattr & (ATTR_CMN_OWNERID | ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS | ATTR_CMN_SCRIPT)) {
		VATTR_WANTED(&va, va_uid);
		VATTR_WANTED(&va, va_gid);
		VATTR_WANTED(&va, va_mode);
		VATTR_WANTED(&va, va_flags);
		VATTR_WANTED(&va, va_encoding);

		if ((error = vnode_getattr(vp, &va, ctx)) != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not fetch attributes from root vnode", vp);
			goto out;
		}

		if (VATTR_IS_ACTIVE(&va, va_encoding) && !VATTR_IS_SUPPORTED(&va, va_encoding))
			VATTR_RETURN(&va, va_encoding, 0x7e /* kTextEncodingMacUnicode */);
	}

	/*
	 * Compute variable-size buffer requirements.
	 */
	varsize = 0;
	if (alp->commonattr & ATTR_CMN_NAME) {
		if (vp->v_mount->mnt_vfsstat.f_mntonname[1] == 0x00 &&
			vp->v_mount->mnt_vfsstat.f_mntonname[0] == '/') {
			/* special case for boot volume.  Use root name when it's
			 * available (which is the volume name) or just the mount on
			 * name of "/".  we must do this for binary compatibility with
			 * pre Tiger code.  returning nothing for the boot volume name
			 * breaks installers - 3961058
			 */
			cnp = vnode_getname(vp);
			if (cnp == NULL) {
				/* just use "/" as name */
				cnp = &vp->v_mount->mnt_vfsstat.f_mntonname[0];
			}
			cnl = strlen(cnp);
		}
		else {
			getattrlist_findnamecomp(vp->v_mount->mnt_vfsstat.f_mntonname, &cnp, &cnl);
		}
		if (alp->commonattr & ATTR_CMN_NAME)
			varsize += roundup(cnl + 1, 4);
	}
	if (alp->volattr & ATTR_VOL_MOUNTPOINT)
		varsize += roundup(strlen(mnt->mnt_vfsstat.f_mntonname) + 1, 4);
	if (alp->volattr & ATTR_VOL_NAME) {
		vs.f_vol_name[MAXPATHLEN-1] = '\0'; /* Ensure nul-termination */
		varsize += roundup(strlen(vs.f_vol_name) + 1, 4);
	}
	if (alp->volattr & ATTR_VOL_MOUNTEDDEVICE)
		varsize += roundup(strlen(mnt->mnt_vfsstat.f_mntfromname) + 1, 4);

	/*
	 * Allocate a target buffer for attribute results.
	 * Note that since we won't ever copy out more than the caller requested,
	 * we never need to allocate more than they offer.
	 */
	ab.allocated = imin(uap->bufferSize, fixedsize + varsize);
	if (ab.allocated > ATTR_MAX_BUFFER) {
		error = ENOMEM;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: buffer size too large (%d limit %d)", ab.allocated, ATTR_MAX_BUFFER);
		goto out;
	}
	MALLOC(ab.base, char *, ab.allocated, M_TEMP, M_WAITOK);
	if (ab.base == NULL) {
		error = ENOMEM;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not allocate %d for copy buffer", ab.allocated);
		goto out;
	}

	/*
	 * Pack results into the destination buffer.
	 */
	ab.fixedcursor = ab.base + sizeof(uint32_t);
	ab.varcursor = ab.base + fixedsize;
	ab.needed = fixedsize + varsize;

	/* common attributes **************************************************/
	if (alp->commonattr & ATTR_CMN_NAME)
		attrlist_pack_string(&ab, cnp, cnl);
	if (alp->commonattr & ATTR_CMN_DEVID)
		ATTR_PACK_CAST(&ab, dev_t, mnt->mnt_vfsstat.f_fsid.val[0]);
	if (alp->commonattr & ATTR_CMN_FSID)
		ATTR_PACK(&ab, mnt->mnt_vfsstat.f_fsid);
	if (alp->commonattr & ATTR_CMN_OBJTYPE)
		ATTR_PACK_CAST(&ab, fsobj_type_t, 0);
	if (alp->commonattr & ATTR_CMN_OBJTAG)
		ATTR_PACK_CAST(&ab, fsobj_tag_t, vp->v_tag);
	if (alp->commonattr & ATTR_CMN_OBJID) {
		fsobj_id_t f = {0, 0};
		ATTR_PACK(&ab, f);
	}
	if (alp->commonattr & ATTR_CMN_OBJPERMANENTID) {
		fsobj_id_t f = {0, 0};
		ATTR_PACK(&ab, f);
	}
	if (alp->commonattr & ATTR_CMN_PAROBJID) {
		fsobj_id_t f = {0, 0};
		ATTR_PACK(&ab, f);
	}
	/* note that this returns the encoding for the volume name, not the node name */
	if (alp->commonattr & ATTR_CMN_SCRIPT)
		ATTR_PACK_CAST(&ab, text_encoding_t, va.va_encoding);
	if (alp->commonattr & ATTR_CMN_CRTIME)
		ATTR_PACK_TIME(&ab, vs.f_create_time, is_64bit);
	if (alp->commonattr & ATTR_CMN_MODTIME)
		ATTR_PACK_TIME(&ab, vs.f_modify_time, is_64bit);
	if (alp->commonattr & ATTR_CMN_CHGTIME)
		ATTR_PACK_TIME(&ab, vs.f_modify_time, is_64bit);
	if (alp->commonattr & ATTR_CMN_ACCTIME)
		ATTR_PACK_TIME(&ab, vs.f_access_time, is_64bit);
	if (alp->commonattr & ATTR_CMN_BKUPTIME)
		ATTR_PACK_TIME(&ab, vs.f_backup_time, is_64bit);
	if (alp->commonattr & ATTR_CMN_FNDRINFO) {
		char f[32];
		/*
		 * This attribute isn't really Finder Info, at least for HFS.
		 */
		if (vp->v_tag == VT_HFS) {
			if ((error = VNOP_IOCTL(vp, HFS_GET_BOOT_INFO, (caddr_t)&f, 0, ctx)) != 0)
				goto out;
		} else {
			/* XXX we could at least pass out the volume UUID here */
			bzero(&f, sizeof(f));
		}
		attrlist_pack_fixed(&ab, f, sizeof(f));
	}
	if (alp->commonattr & ATTR_CMN_OWNERID)
		ATTR_PACK(&ab, va.va_uid);
	if (alp->commonattr & ATTR_CMN_GRPID)
		ATTR_PACK(&ab, va.va_gid);
	if (alp->commonattr & ATTR_CMN_ACCESSMASK)
		ATTR_PACK_CAST(&ab, uint32_t, va.va_mode);
	if (alp->commonattr & ATTR_CMN_FLAGS)
		ATTR_PACK(&ab, va.va_flags);
	if (alp->commonattr & ATTR_CMN_USERACCESS) {	/* XXX this is expensive and also duplicate work */
		uint32_t	perms = 0;
		if (vnode_isdir(vp)) {
			if (vnode_authorize(vp, NULL,
				KAUTH_VNODE_ACCESS | KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_ADD_SUBDIRECTORY | KAUTH_VNODE_DELETE_CHILD, ctx) == 0)
				perms |= W_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_LIST_DIRECTORY, ctx) == 0)
				perms |= R_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_SEARCH, ctx) == 0)
				perms |= X_OK;
		} else {
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA, ctx) == 0)
				perms |= W_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_READ_DATA, ctx) == 0)
				perms |= R_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_EXECUTE, ctx) == 0)
				perms |= X_OK;
		}
		KAUTH_DEBUG("ATTRLIST - returning user access %x", perms);
		ATTR_PACK(&ab, perms);
	}

	/* volume attributes **************************************************/

	if (alp->volattr & ATTR_VOL_FSTYPE)
		ATTR_PACK_CAST(&ab, uint32_t, vfs_typenum(mnt));
 	if (alp->volattr & ATTR_VOL_SIGNATURE)
 		ATTR_PACK_CAST(&ab, uint32_t, vs.f_signature);
	if (alp->volattr & ATTR_VOL_SIZE)
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize * vs.f_blocks);
	if (alp->volattr & ATTR_VOL_SPACEFREE)
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize * vs.f_bfree);
	if (alp->volattr & ATTR_VOL_SPACEAVAIL)
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize * vs.f_bavail);
	if (alp->volattr & ATTR_VOL_MINALLOCATION)
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize);
	if (alp->volattr & ATTR_VOL_ALLOCATIONCLUMP)
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize);			/* not strictly true */
	if (alp->volattr & ATTR_VOL_IOBLOCKSIZE)
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_iosize);
	if (alp->volattr & ATTR_VOL_OBJCOUNT)
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_objcount);
	if (alp->volattr & ATTR_VOL_FILECOUNT)
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_filecount);
	if (alp->volattr & ATTR_VOL_DIRCOUNT)
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_dircount);
	if (alp->volattr & ATTR_VOL_MAXOBJCOUNT)
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_maxobjcount);
	if (alp->volattr & ATTR_VOL_MOUNTPOINT) 
		attrlist_pack_string(&ab, mnt->mnt_vfsstat.f_mntonname, 0);
	if (alp->volattr & ATTR_VOL_NAME)
		attrlist_pack_string(&ab, vs.f_vol_name, 0);
	if (alp->volattr & ATTR_VOL_MOUNTFLAGS)
		ATTR_PACK_CAST(&ab, uint32_t, mnt->mnt_flag);
	if (alp->volattr & ATTR_VOL_MOUNTEDDEVICE)
		attrlist_pack_string(&ab, mnt->mnt_vfsstat.f_mntfromname, 0);
	if (alp->volattr & ATTR_VOL_ENCODINGSUSED)
		ATTR_PACK_CAST(&ab, uint64_t, ~0LL);	/* return all encodings */
	if (alp->volattr & ATTR_VOL_CAPABILITIES) {
		/* fix up volume capabilities */
		if (vfs_extendedsecurity(mnt)) {
			vs.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_EXTENDED_SECURITY;
		} else {
			vs.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] &= ~VOL_CAP_INT_EXTENDED_SECURITY;
		}
		vs.f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_EXTENDED_SECURITY;
		ATTR_PACK(&ab, vs.f_capabilities);
	}
	if (alp->volattr & ATTR_VOL_ATTRIBUTES) {
		/* fix up volume attribute information */
		if (vfs_extendedsecurity(mnt)) {
			vs.f_attributes.validattr.commonattr |= (ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID);
		} else {
			vs.f_attributes.validattr.commonattr &= ~(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID);
			vs.f_attributes.nativeattr.commonattr &= ~(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID);
		}
		ATTR_PACK(&ab, vs.f_attributes);
	}
	
	/* diagnostic */
	if ((ab.fixedcursor - ab.base) != fixedsize)
		panic("packed field size mismatch; allocated %d but packed %d for common %08x vol %08x",
		    fixedsize, ab.fixedcursor - ab.base, alp->commonattr, alp->volattr);
	if (ab.varcursor != (ab.base + ab.needed))
		panic("packed variable field size mismatch; used %d but expected %d", ab.varcursor - ab.base, ab.needed);

	/*
	 * In the compatible case, we report the smaller of the required and returned sizes.
	 * If the FSOPT_REPORT_FULLSIZE option is supplied, we report the full (required) size
	 * of the result buffer, even if we copied less out.  The caller knows how big a buffer
	 * they gave us, so they can always check for truncation themselves.
	 */
	*(uint32_t *)ab.base = (uap->options & FSOPT_REPORT_FULLSIZE) ? ab.needed : imin(ab.allocated, ab.needed);
	
	error = copyout(ab.base, uap->attributeBuffer, ab.allocated);

out:
	if (vs.f_vol_name != NULL)
		kfree(vs.f_vol_name, MAXPATHLEN);
	if (ab.base != NULL)
		FREE(ab.base, M_TEMP);
	VFS_DEBUG(ctx, vp, "ATTRLIST - returning %d", error);
	return(error);
}

/*
 * Obtain attribute information about a filesystem object.
 */
int
getattrlist(struct proc *p, struct getattrlist_args *uap, __unused register_t *retval)
{
	struct attrlist	al;
	struct vnode_attr va;
	struct vfs_context context, *ctx;
	struct nameidata nd;
	struct _attrlist_buf ab;
	vnode_t		vp;
	u_long		nameiflags;
	kauth_action_t	action;
	ssize_t		fixedsize, varsize;
	const char	*cnp;
	char		*vname = NULL;
	ssize_t		cnl;
	int		error;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	ctx = &context;
	vp = NULL;
	error = 0;
	VATTR_INIT(&va);
	va.va_name = NULL;
	ab.base = NULL;
	cnp = "unknown";
	cnl = 0;

	/*
	 * Look up the file.
	 */
	nameiflags = AUDITVNPATH1;
	if (!(uap->options & FSOPT_NOFOLLOW))
		nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, uap->path, &context);

	if ((error = namei(&nd)) != 0)
		goto out;
	vp = nd.ni_vp;
	nameidone(&nd);

	/*
	 * Fetch the attribute request.
	 */
	if ((error = copyin(uap->alist, &al, sizeof(al))) != 0)
		goto out;
	if (al.bitmapcount != ATTR_BIT_MAP_COUNT) {
		error = EINVAL;
		goto out;
	}

	VFS_DEBUG(ctx, vp, "%p  ATTRLIST - %s request common %08x vol %08x file %08x dir %08x fork %08x %sfollow on '%s'",
	    vp, p->p_comm, al.commonattr, al.volattr, al.fileattr, al.dirattr, al.forkattr,
	    (uap->options & FSOPT_NOFOLLOW) ? "no":"", vp->v_name);
	
	/*
	 * It is legal to request volume or file attributes,
	 * but not both.
	 */
	if (al.volattr) {
		if (al.fileattr || al.dirattr || al.forkattr) {
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: mixed volume/file/directory/fork attributes");
			goto out;
		}
		/* handle volume attribute request */
		error = getvolattrlist(vp, uap, &al, &context, proc_is64bit(p));
		goto out;
	}

	/*
	 * Set up the vnode_attr structure and authorise.
	 */
	if ((error = getattrlist_setupvattr(&al, &va, &fixedsize, &action, proc_is64bit(p), vnode_isdir(vp))) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: setup for request failed");
		goto out;
	}
	if ((error = vnode_authorize(vp, NULL, action, &context)) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: authorisation failed/denied");
		goto out;
	}

	if (va.va_active != 0) {
		/*
		 * If we're going to ask for va_name, allocate a buffer to point it at
		 */
		if (VATTR_IS_ACTIVE(&va, va_name)) {
			va.va_name = (char *) kalloc(MAXPATHLEN);
			if (va.va_name == NULL) {
				error = ENOMEM;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: cannot allocate va_name buffer");
				goto out;
			}
		}

		/*
		 * Call the filesystem.
		 */
		if ((error = vnode_getattr(vp, &va, &context)) != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: filesystem returned %d", error);
			goto out;
		}

		/* did we ask for something the filesystem doesn't support? */
		if (!VATTR_ALL_SUPPORTED(&va)) {

			/*
			 * There are a couple of special cases.  If we are after object IDs,
			 * we can make do with va_fileid.
			 */
			if ((al.commonattr & (ATTR_CMN_OBJID | ATTR_CMN_OBJPERMANENTID)) && !VATTR_IS_SUPPORTED(&va, va_linkid))
				VATTR_CLEAR_ACTIVE(&va, va_linkid);	/* forget we wanted this */
			/*
			 * Many (most?) filesystems don't know their parent object id.  We can get it the
			 * hard way.
			 */
			if ((al.commonattr & ATTR_CMN_PAROBJID) && !VATTR_IS_SUPPORTED(&va, va_parentid))
				VATTR_CLEAR_ACTIVE(&va, va_parentid);
			/*
			 * And we can report datasize/alloc from total.
			 */
			if ((al.fileattr & ATTR_FILE_DATALENGTH) && !VATTR_IS_SUPPORTED(&va, va_data_size))
				VATTR_CLEAR_ACTIVE(&va, va_data_size);
			if ((al.fileattr & ATTR_FILE_DATAALLOCSIZE) && !VATTR_IS_SUPPORTED(&va, va_data_alloc))
				VATTR_CLEAR_ACTIVE(&va, va_data_alloc);

			/*
			 * If we don't have an encoding, go with UTF-8
			 */
			if ((al.commonattr & ATTR_CMN_SCRIPT) && !VATTR_IS_SUPPORTED(&va, va_encoding))
				VATTR_RETURN(&va, va_encoding, 0x7e /* kTextEncodingMacUnicode */);

			/*
			 * If we don't have a name, we'll get one from the vnode or mount point.
			 */
			if ((al.commonattr & ATTR_CMN_NAME) && !VATTR_IS_SUPPORTED(&va, va_name)) {
				VATTR_CLEAR_ACTIVE(&va, va_name);
			}

			/*
			 * We used to return va_nlink-2 for ATTR_DIR_ENTRYCOUNT.  The va_nchildren
			 * field is preferred, but we'll fall back to va_nlink-2 for compatibility
			 * with file systems which haven't adopted va_nchildren.  Note: the "- 2"
			 * reflects the "." and ".." entries which are reported via POSIX APIs, but
			 * not via Carbon (since they don't in fact exist in HFS).
			 */
			if ((al.dirattr & ATTR_DIR_ENTRYCOUNT) && !VATTR_IS_SUPPORTED(&va, va_nchildren) &&
			    VATTR_IS_SUPPORTED(&va, va_nlink)) {
				VATTR_RETURN(&va, va_nchildren, va.va_nlink - 2);
			}
			
			/* check again */
			if (!VATTR_ALL_SUPPORTED(&va)) {
				error = ENOTSUP;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not get all requested file attributes");
				VFS_DEBUG(ctx, vp, "ATTRLIST -        have %016llx wanted %016llx missing %016llx",
				    va.va_supported, va.va_active, va.va_active & ~va.va_supported);
				goto out;
			}
		}
	}

	/*
	 * Compute variable-space requirements.
	 */
	varsize = 0;			/* length count */
	if (al.commonattr & ATTR_CMN_NAME) {
		if (VATTR_IS_SUPPORTED(&va, va_name)) {
			va.va_name[MAXPATHLEN-1] = '\0';	/* Ensure nul-termination */
			cnp = va.va_name;
			cnl = strlen(cnp);
		} else {
			if (vnode_isvroot(vp)) {
				if (vp->v_mount->mnt_vfsstat.f_mntonname[1] == 0x00 &&
				    vp->v_mount->mnt_vfsstat.f_mntonname[0] == '/') {
					/* special case for boot volume.  Use root name when it's
					 * available (which is the volume name) or just the mount on
					 * name of "/".  we must do this for binary compatibility with
					 * pre Tiger code.  returning nothing for the boot volume name
					 * breaks installers - 3961058
					 */
					cnp = vname = vnode_getname(vp);
					if (cnp == NULL) {
						/* just use "/" as name */
						cnp = &vp->v_mount->mnt_vfsstat.f_mntonname[0];
					}
					cnl = strlen(cnp);
				}
				else {
					getattrlist_findnamecomp(vp->v_mount->mnt_vfsstat.f_mntonname, &cnp, &cnl);
				}
			} else {
				cnp = vname = vnode_getname(vp);
				cnl = 0;
				if (cnp != NULL) {
					cnl = strlen(cnp);
				}
			}
		}
		varsize += roundup(cnl + 1, 4);
	}

	/*
	 * We have a kauth_acl_t but we will be returning a kauth_filesec_t.
	 *
	 * XXX This needs to change at some point; since the blob is opaque in
	 * user-space this is OK.
	 */
	if ((al.commonattr & ATTR_CMN_EXTENDED_SECURITY) &&
	    VATTR_IS_SUPPORTED(&va, va_acl) &&
	    (va.va_acl != NULL))
		varsize += roundup(KAUTH_FILESEC_SIZE(va.va_acl->acl_entrycount), 4);
	
	/*
	 * Allocate a target buffer for attribute results.
	 *
	 * Note that we won't ever copy out more than the caller requested, even though
	 * we might have to allocate more than they offer do that the diagnostic checks
	 * don't result in a panic if the caller's buffer is too small..
	 */
	ab.allocated = fixedsize + varsize;
	if (ab.allocated > ATTR_MAX_BUFFER) {
		error = ENOMEM;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: buffer size too large (%d limit %d)", ab.allocated, ATTR_MAX_BUFFER);
		goto out;
	}
	MALLOC(ab.base, char *, ab.allocated, M_TEMP, M_WAITOK);
	if (ab.base == NULL) {
		error = ENOMEM;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not allocate %d for copy buffer", ab.allocated);
		goto out;
	}

	/*
	 * Pack results into the destination buffer.
	 */
	ab.fixedcursor = ab.base + sizeof(uint32_t);
	ab.varcursor = ab.base + fixedsize;
	ab.needed = ab.allocated;

	/* common attributes **************************************************/
	if (al.commonattr & ATTR_CMN_NAME)
		attrlist_pack_string(&ab, cnp, cnl);
	if (al.commonattr & ATTR_CMN_DEVID)
		ATTR_PACK_CAST(&ab, dev_t, vp->v_mount->mnt_vfsstat.f_fsid.val[0]);
	if (al.commonattr & ATTR_CMN_FSID)
		ATTR_PACK(&ab, vp->v_mount->mnt_vfsstat.f_fsid);
	if (al.commonattr & ATTR_CMN_OBJTYPE)
		ATTR_PACK_CAST(&ab, fsobj_type_t, vp->v_type);
	if (al.commonattr & ATTR_CMN_OBJTAG)
		ATTR_PACK_CAST(&ab, fsobj_tag_t, vp->v_tag);
	if (al.commonattr & ATTR_CMN_OBJID) {
		fsobj_id_t f;
		/*
		 * Carbon can't deal with us reporting the target ID
		 * for links.  So we ask the filesystem to give us the
		 * source ID as well, and if it gives us one, we use
		 * it instead.
		 */
		if (VATTR_IS_SUPPORTED(&va, va_linkid)) {
			f.fid_objno = va.va_linkid;
		} else {
			f.fid_objno = va.va_fileid;
		}
		f.fid_generation = 0;
		ATTR_PACK(&ab, f);
	}
	if (al.commonattr & ATTR_CMN_OBJPERMANENTID) {
		fsobj_id_t f;
		/*
		 * Carbon can't deal with us reporting the target ID
		 * for links.  So we ask the filesystem to give us the
		 * source ID as well, and if it gives us one, we use
		 * it instead.
		 */
		if (VATTR_IS_SUPPORTED(&va, va_linkid)) {
			f.fid_objno = va.va_linkid;
		} else {
			f.fid_objno = va.va_fileid;
		}
		f.fid_generation = 0;
		ATTR_PACK(&ab, f);
	}
	if (al.commonattr & ATTR_CMN_PAROBJID) {
		fsobj_id_t f;
		/*
		 * If the filesystem doesn't know the parent ID, we can
		 * try to get it via v->v_parent.  Don't need to worry
		 * about links here, as we dont allow hardlinks to
		 * directories.
		 */
		if (VATTR_IS_SUPPORTED(&va, va_parentid)) {
			f.fid_objno = va.va_parentid;
		} else {
			struct vnode_attr lva;
			vnode_t	pvp;

			pvp = vnode_getparent(vp);

			if (pvp == NULLVP) {
				error = ENOTSUP;
				goto out;
			}
			VATTR_INIT(&lva);
			VATTR_WANTED(&lva, va_fileid);
			error = vnode_getattr(pvp, &lva, &context);
			vnode_put(pvp);
			
			if (error != 0)
				goto out;
			f.fid_objno = lva.va_fileid;
		}
		f.fid_generation = 0;
		ATTR_PACK(&ab, f);
	}
	if (al.commonattr & ATTR_CMN_SCRIPT)
		ATTR_PACK_CAST(&ab, text_encoding_t, va.va_encoding);
	if (al.commonattr & ATTR_CMN_CRTIME)
		ATTR_PACK_TIME(&ab, va.va_create_time, proc_is64bit(p));
	if (al.commonattr & ATTR_CMN_MODTIME)
		ATTR_PACK_TIME(&ab, va.va_modify_time, proc_is64bit(p));
	if (al.commonattr & ATTR_CMN_CHGTIME)
		ATTR_PACK_TIME(&ab, va.va_change_time, proc_is64bit(p));
	if (al.commonattr & ATTR_CMN_ACCTIME)
		ATTR_PACK_TIME(&ab, va.va_access_time, proc_is64bit(p));
	if (al.commonattr & ATTR_CMN_BKUPTIME)
		ATTR_PACK_TIME(&ab, va.va_backup_time, proc_is64bit(p));
	if (al.commonattr & ATTR_CMN_FNDRINFO) {
		uio_t	auio;
		size_t	fisize;
		char	uio_buf[UIO_SIZEOF(1)];

		fisize = imin(32, ab.allocated - (ab.fixedcursor - ab.base));
		if (fisize > 0) {
			if ((auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, uio_buf, sizeof(uio_buf))) == NULL) {
				error = ENOMEM;
				goto out;
			} else {
				uio_addiov(auio, CAST_USER_ADDR_T(ab.fixedcursor), fisize);
				error = vn_getxattr(vp, XATTR_FINDERINFO_NAME, auio, &fisize, XATTR_NOSECURITY, &context);
				uio_free(auio);
			}
			if (error != 0) {
				if ((error == ENOENT) || (error == ENOATTR) || (error == ENOTSUP) || (error == EPERM)) {
					VFS_DEBUG(ctx, vp, "ATTRLIST - No system.finderinfo attribute, returning zeroes");
					bzero(ab.fixedcursor, 32);
					error = 0;
				} else {
					VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: reading system.finderinfo attribute");
					goto out;
				}
			}
		} else {
			VFS_DEBUG(ctx, vp, "ATTRLIST - no room in caller buffer for FINDERINFO");
		}
		ab.fixedcursor += 32;
	}
	if (al.commonattr & ATTR_CMN_OWNERID)
		ATTR_PACK(&ab, va.va_uid);
	if (al.commonattr & ATTR_CMN_GRPID)
		ATTR_PACK(&ab, va.va_gid);
	if (al.commonattr & ATTR_CMN_ACCESSMASK)
		ATTR_PACK_CAST(&ab, uint32_t, va.va_mode);
	if (al.commonattr & ATTR_CMN_FLAGS)
		ATTR_PACK(&ab, va.va_flags);
	if (al.commonattr & ATTR_CMN_USERACCESS) {	/* this is expensive */
		uint32_t	perms = 0;
		if (vnode_isdir(vp)) {
			if (vnode_authorize(vp, NULL,
				KAUTH_VNODE_ACCESS | KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_ADD_SUBDIRECTORY | KAUTH_VNODE_DELETE_CHILD, &context) == 0)
				perms |= W_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_LIST_DIRECTORY, &context) == 0)
				perms |= R_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_SEARCH, &context) == 0)
				perms |= X_OK;
		} else {
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA, &context) == 0)
				perms |= W_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_READ_DATA, &context) == 0)
				perms |= R_OK;
			if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_EXECUTE, &context) == 0)
				perms |= X_OK;
		}
		VFS_DEBUG(ctx, vp, "ATTRLIST - granting perms %d", perms);
		ATTR_PACK(&ab, perms);
	}
	if (al.commonattr & ATTR_CMN_EXTENDED_SECURITY) {
		if (VATTR_IS_SUPPORTED(&va, va_acl) && (va.va_acl != NULL)) {
			struct kauth_filesec fsec;
			/*
			 * We want to return a kauth_filesec (for now), but all we have is a kauth_acl.
			 */
			fsec.fsec_magic = KAUTH_FILESEC_MAGIC;
			fsec.fsec_owner = kauth_null_guid;
			fsec.fsec_group = kauth_null_guid;
			attrlist_pack_variable2(&ab, &fsec, ((char *)&fsec.fsec_acl - (char *)&fsec), va.va_acl, KAUTH_ACL_COPYSIZE(va.va_acl));
		} else {
			attrlist_pack_variable(&ab, NULL, 0);
		}
	}
  	if (al.commonattr & ATTR_CMN_UUID) {
 		if (!VATTR_IS_SUPPORTED(&va, va_uuuid)) {
  			ATTR_PACK(&ab, kauth_null_guid);
  		} else {
 			ATTR_PACK(&ab, va.va_uuuid);
 		}
 	}
 	if (al.commonattr & ATTR_CMN_GRPUUID) {
 		if (!VATTR_IS_SUPPORTED(&va, va_guuid)) {
 			ATTR_PACK(&ab, kauth_null_guid);
 		} else {
 			ATTR_PACK(&ab, va.va_guuid);
  		}
  	}

	/* directory attributes **************************************************/
	if (vnode_isdir(vp)) {
		if (al.dirattr & ATTR_DIR_LINKCOUNT)			/* full count of entries */
			ATTR_PACK_CAST(&ab, uint32_t, va.va_nlink);
		if (al.dirattr & ATTR_DIR_ENTRYCOUNT)
			ATTR_PACK_CAST(&ab, uint32_t, va.va_nchildren);
		if (al.dirattr & ATTR_DIR_MOUNTSTATUS)
			ATTR_PACK_CAST(&ab, uint32_t, (vp->v_flag & VROOT) ? DIR_MNTSTATUS_MNTPOINT : 0);
	}

	/* file attributes **************************************************/
	if (!vnode_isdir(vp)) {
		if (al.fileattr & ATTR_FILE_LINKCOUNT)
			ATTR_PACK_CAST(&ab, uint32_t, va.va_nlink);
		if (al.fileattr & ATTR_FILE_TOTALSIZE)
			ATTR_PACK(&ab, va.va_total_size);
		if (al.fileattr & ATTR_FILE_ALLOCSIZE)
			ATTR_PACK(&ab, va.va_total_alloc);
		if (al.fileattr & ATTR_FILE_IOBLOCKSIZE)
			ATTR_PACK(&ab, va.va_iosize);
		if (al.fileattr & ATTR_FILE_CLUMPSIZE)
			ATTR_PACK_CAST(&ab, uint32_t, 0);		/* XXX value is deprecated */
		if (al.fileattr & ATTR_FILE_DEVTYPE) {
			if ((vp->v_type == VCHR) || (vp->v_type == VBLK)) {
				ATTR_PACK(&ab, vp->v_specinfo->si_rdev);
			} else {
				ATTR_PACK_CAST(&ab, uint32_t, 0);
			}
		}
		if (al.fileattr & ATTR_FILE_DATALENGTH) {
			if (VATTR_IS_SUPPORTED(&va, va_data_size)) {
				ATTR_PACK(&ab, va.va_data_size);
			} else {
				ATTR_PACK(&ab, va.va_total_size);
			}
		}
		if (al.fileattr & ATTR_FILE_DATAALLOCSIZE) {
			if (VATTR_IS_SUPPORTED(&va, va_data_alloc)) {
				ATTR_PACK(&ab, va.va_data_alloc);
			} else {
				ATTR_PACK(&ab, va.va_total_alloc);
			}
		}
		/* fetch resource fork size/allocation via xattr interface */
		if (al.fileattr & (ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE)) {
			size_t	rsize;
			if ((error = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, NULL, &rsize, XATTR_NOSECURITY, &context)) != 0) {
				if ((error == ENOENT) || (error == ENOATTR) || (error == ENOTSUP) || (error == EPERM)) {
					rsize = 0;
					error = 0;
				} else {
					goto out;
				}
			}
			if (al.fileattr & ATTR_FILE_RSRCLENGTH)
				ATTR_PACK_CAST(&ab, off_t, rsize);
			if (al.fileattr & ATTR_FILE_RSRCALLOCSIZE) {
				uint32_t  blksize = vp->v_mount->mnt_vfsstat.f_bsize;
				if (blksize == 0)
					blksize = 512;
				ATTR_PACK_CAST(&ab, off_t, (roundup(rsize, blksize)));
			}
		}
	}
	
	/* diagnostic */
	if ((ab.fixedcursor - ab.base) != fixedsize)
		panic("packed field size mismatch; allocated %d but packed %d for common %08x vol %08x",
		    fixedsize, ab.fixedcursor - ab.base, al.commonattr, al.volattr);
	if (ab.varcursor != (ab.base + ab.needed))
		panic("packed variable field size mismatch; used %d but expected %d", ab.varcursor - ab.base, ab.needed);

	/*
	 * In the compatible case, we report the smaller of the required and returned sizes.
	 * If the FSOPT_REPORT_FULLSIZE option is supplied, we report the full (required) size
	 * of the result buffer, even if we copied less out.  The caller knows how big a buffer
	 * they gave us, so they can always check for truncation themselves.
	 */
	*(uint32_t *)ab.base = (uap->options & FSOPT_REPORT_FULLSIZE) ? ab.needed : imin(ab.allocated, ab.needed);
	
	/* Only actually copyout as much out as the user buffer can hold */
	error = copyout(ab.base, uap->attributeBuffer, imin(uap->bufferSize, ab.allocated));
	
out:
	if (va.va_name)
		kfree(va.va_name, MAXPATHLEN);
	if (vname)
	        vnode_putname(vname);
	if (vp)
		vnode_put(vp);
	if (ab.base != NULL)
		FREE(ab.base, M_TEMP);
	if (VATTR_IS_SUPPORTED(&va, va_acl) && (va.va_acl != NULL))
		kauth_acl_free(va.va_acl);

	VFS_DEBUG(ctx, vp, "ATTRLIST - returning %d", error);
	return(error);
}

static int
attrlist_unpack_fixed(char **cursor, char *end, void *buf, ssize_t size)
{
	/* make sure we have enough source data */
	if ((*cursor) + size > end)
		return(EINVAL);

	bcopy(*cursor, buf, size);
	*cursor += size;
	return(0);
}

#define ATTR_UNPACK(v)		do {if ((error = attrlist_unpack_fixed(&cursor, bufend, &v, sizeof(v))) != 0) goto out;} while(0);
#define ATTR_UNPACK_CAST(t, v)	do { t _f; ATTR_UNPACK(_f); v = _f;} while(0)
#define ATTR_UNPACK_TIME(v, is64)				\
	do {							\
		if (is64) {					\
			struct user_timespec us;		\
			ATTR_UNPACK(us);			\
			v.tv_sec = us.tv_sec;			\
			v.tv_nsec = us.tv_nsec;			\
		} else {					\
			ATTR_UNPACK(v);				\
		}						\
	} while(0)


/*
 * Write attributes.
 */
int
setattrlist(struct proc *p, register struct setattrlist_args *uap, __unused register_t *retval)
{
	struct attrlist al;
	struct vfs_context context, *ctx;
	struct vnode_attr va;
	struct attrreference ar;
	struct nameidata nd;
	vnode_t		vp;
	u_long		nameiflags;
	kauth_action_t	action;
	char		*user_buf, *cursor, *bufend, *fndrinfo, *cp, *volname;
	int		proc_is64, error;
	uint32_t	nace;
	kauth_filesec_t rfsec;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	ctx = &context;
	vp = NULL;
	user_buf = NULL;
	fndrinfo = NULL;
	volname = NULL;
	error = 0;
	proc_is64 = proc_is64bit(p);
	VATTR_INIT(&va);
	

	/*
	 * Look up the file.
	 */
	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0)
		nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags | AUDITVNPATH1, UIO_USERSPACE, uap->path, &context);
	if ((error = namei(&nd)) != 0)
		goto out;
	vp = nd.ni_vp;
	nameidone(&nd);

	/*
	 * Fetch the attribute set and validate.
	 */
	if ((error = copyin(uap->alist, (caddr_t) &al, sizeof (al))))
		goto out;
	if (al.bitmapcount != ATTR_BIT_MAP_COUNT) {
		error = EINVAL;
		goto out;
	}

	VFS_DEBUG(ctx, vp, "%p  ATTRLIST - %s set common %08x vol %08x file %08x dir %08x fork %08x %sfollow on '%s'",
	    vp, p->p_comm, al.commonattr, al.volattr, al.fileattr, al.dirattr, al.forkattr,
	    (uap->options & FSOPT_NOFOLLOW) ? "no":"", vp->v_name);

	if (al.volattr) {
		if ((al.volattr & ~ATTR_VOL_SETMASK) ||
		    (al.commonattr & ~ATTR_CMN_VOLSETMASK) ||
		    al.fileattr ||
		    al.forkattr) {
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: attempt to set invalid volume attributes");
			goto out;
		}
	} else {
		if ((al.commonattr & ~ATTR_CMN_SETMASK) ||
		    (al.fileattr & ~ATTR_FILE_SETMASK) ||
		    (al.dirattr & ~ATTR_DIR_SETMASK) ||
		    (al.forkattr & ~ATTR_FORK_SETMASK)) {
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: attempt to set invalid file/folder attributes");
			goto out;
		}
	}

	/*
	 * Make the naive assumption that the caller has supplied a reasonable buffer
	 * size.  We could be more careful by pulling in the fixed-size region, checking
	 * the attrref structures, then pulling in the variable section.
	 * We need to reconsider this for handling large ACLs, as they should probably be
	 * brought directly into a buffer.  Multiple copyins will make this slower though.
	 *
	 * We could also map the user buffer if it is larger than some sensible mimimum.
	 */
	if (uap->bufferSize > ATTR_MAX_BUFFER) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: buffer size %d too large", uap->bufferSize);
		error = ENOMEM;
		goto out;
	}
	MALLOC(user_buf, char *, uap->bufferSize, M_TEMP, M_WAITOK);
	if (user_buf == NULL) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not allocate %d bytes for buffer", uap->bufferSize);
		error = ENOMEM;
		goto out;
	}
	if ((error = copyin(uap->attributeBuffer, user_buf, uap->bufferSize)) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: buffer copyin failed");
		goto out;
	}
	VFS_DEBUG(ctx, vp, "ATTRLIST - copied in %d bytes of user attributes to %p", uap->bufferSize, user_buf);

	/*
	 * Unpack the argument buffer.
	 */
	cursor = user_buf;
	bufend = cursor + uap->bufferSize;

	/* common */
	if (al.commonattr & ATTR_CMN_SCRIPT) {
		ATTR_UNPACK(va.va_encoding);
		VATTR_SET_ACTIVE(&va, va_encoding);
	}
	if (al.commonattr & ATTR_CMN_CRTIME) {
		ATTR_UNPACK_TIME(va.va_create_time, proc_is64);
		VATTR_SET_ACTIVE(&va, va_create_time);
	}
	if (al.commonattr & ATTR_CMN_MODTIME) {
		ATTR_UNPACK_TIME(va.va_modify_time, proc_is64);
		VATTR_SET_ACTIVE(&va, va_modify_time);
	}
	if (al.commonattr & ATTR_CMN_CHGTIME) {
		ATTR_UNPACK_TIME(va.va_change_time, proc_is64);
		VATTR_SET_ACTIVE(&va, va_change_time);
	}
	if (al.commonattr & ATTR_CMN_ACCTIME) {
		ATTR_UNPACK_TIME(va.va_access_time, proc_is64);
		VATTR_SET_ACTIVE(&va, va_access_time);
	}
	if (al.commonattr & ATTR_CMN_BKUPTIME) {
		ATTR_UNPACK_TIME(va.va_backup_time, proc_is64);
		VATTR_SET_ACTIVE(&va, va_backup_time);
	}
	if (al.commonattr & ATTR_CMN_FNDRINFO) {
		if ((cursor + 32) > bufend) {
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - not enough data supplied for FINDERINFO");
			goto out;
		}
		fndrinfo = cursor;
		cursor += 32;
	}
	if (al.commonattr & ATTR_CMN_OWNERID) {
		ATTR_UNPACK(va.va_uid);
		VATTR_SET_ACTIVE(&va, va_uid);
	}
	if (al.commonattr & ATTR_CMN_GRPID) {
		ATTR_UNPACK(va.va_gid);
		VATTR_SET_ACTIVE(&va, va_gid);
	}
	if (al.commonattr & ATTR_CMN_ACCESSMASK) {
		ATTR_UNPACK_CAST(uint32_t, va.va_mode);
		VATTR_SET_ACTIVE(&va, va_mode);
	}
	if (al.commonattr & ATTR_CMN_FLAGS) {
		ATTR_UNPACK(va.va_flags);
		VATTR_SET_ACTIVE(&va, va_flags);
	}
	if (al.commonattr & ATTR_CMN_EXTENDED_SECURITY) {

		/*
		 * We are (for now) passed a kauth_filesec_t, but all we want from
		 * it is the ACL.
		 */
		cp = cursor;
		ATTR_UNPACK(ar);
		cp += ar.attr_dataoffset;
		rfsec = (kauth_filesec_t)cp;
		if (((char *)(rfsec + 1) > bufend) ||			/* no space for acl */
		    (rfsec->fsec_magic != KAUTH_FILESEC_MAGIC) ||       /* bad magic */
		    (KAUTH_FILESEC_COPYSIZE(rfsec) != ar.attr_length) || /* size does not match */
		    ((cp + KAUTH_FILESEC_COPYSIZE(rfsec)) > bufend)) {	/* ACEs overrun buffer */
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: bad ACL supplied", ar.attr_length);
			goto out;
		}
		nace = rfsec->fsec_entrycount;
		if (nace == KAUTH_FILESEC_NOACL)
			nace = 0;
		if (nace > KAUTH_ACL_MAX_ENTRIES) {			/* ACL size invalid */
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: bad ACL supplied");
			goto out;
		}
		nace = rfsec->fsec_acl.acl_entrycount;
		if (nace == KAUTH_FILESEC_NOACL) {
			/* deleting ACL */
			VATTR_SET(&va, va_acl, NULL);
		} else {
			
			if (nace > KAUTH_ACL_MAX_ENTRIES) {			/* ACL size invalid */
				error = EINVAL;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: supplied ACL is too large");
				goto out;
			}
			VATTR_SET(&va, va_acl, &rfsec->fsec_acl);
		}
	}
	if (al.commonattr & ATTR_CMN_UUID) {
		ATTR_UNPACK(va.va_uuuid);
		VATTR_SET_ACTIVE(&va, va_uuuid);
	}
	if (al.commonattr & ATTR_CMN_GRPUUID) {
		ATTR_UNPACK(va.va_guuid);
		VATTR_SET_ACTIVE(&va, va_guuid);
	}

	/* volume */
	if (al.volattr & ATTR_VOL_INFO) {
		if (al.volattr & ATTR_VOL_NAME) {
			volname = cursor;
			ATTR_UNPACK(ar);
			volname += ar.attr_dataoffset;
			if ((volname + ar.attr_length) > bufend) {
				error = EINVAL;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: volume name too big for caller buffer");
				goto out;
			}
			/* guarantee NUL termination */
			volname[ar.attr_length - 1] = 0;
		}
	}

	/* file */
	if (al.fileattr & ATTR_FILE_DEVTYPE) {
		/* XXX does it actually make any sense to change this? */
		error = EINVAL;
		VFS_DEBUG(ctx, vp, "ATTRLIST - XXX device type change not implemented");
		goto out;
	}

	/*
	 * Validate and authorize.
	 */
	action = 0;
	if ((va.va_active != 0LL) && ((error = vnode_authattr(vp, &va, &action, &context)) != 0)) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: attribute changes refused: %d", error);
		goto out;
	}
	/*
	 * We can auth file Finder Info here.  HFS volume FinderInfo is really boot data,
	 * and will be auth'ed by the FS.
	 */
	if (fndrinfo != NULL) {
		if (al.volattr & ATTR_VOL_INFO) {
			if (vp->v_tag != VT_HFS) {
				error = EINVAL;
				goto out;
			}
		} else {
			action |= KAUTH_VNODE_WRITE_ATTRIBUTES;
		}
	}

	if ((action != 0) && ((error = vnode_authorize(vp, NULL, action, &context)) != 0)) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: authorization failed");
		goto out;
	}

	/*
	 * When we're setting both the access mask and the finder info, then
	 * check if were about to remove write access for the owner.  Since
	 * vnode_setattr and vn_setxattr invoke two separate vnops, we need
	 * to consider their ordering.
	 *
	 * If were about to remove write access for the owner we'll set the
	 * Finder Info here before vnode_setattr.  Otherwise we'll set it
	 * after vnode_setattr since it may be adding owner write access.
	 */
	if ((fndrinfo != NULL) && !(al.volattr & ATTR_VOL_INFO) &&
	    (al.commonattr & ATTR_CMN_ACCESSMASK) && !(va.va_mode & S_IWUSR)) {
		if ((error = setattrlist_setfinderinfo(vp, fndrinfo, &context)) != 0) {
			goto out;
		}
		fndrinfo = NULL;  /* it was set here so skip setting below */
	}

	/*
	 * Write the attributes if we have any.
	 */
	if ((va.va_active != 0LL) && ((error = vnode_setattr(vp, &va, &context)) != 0)) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: filesystem returned %d", error);
		goto out;
	}

	/*
	 * Write the Finder Info if we have any.
	 */
	if (fndrinfo != NULL) {
		if (al.volattr & ATTR_VOL_INFO) {
			if (vp->v_tag == VT_HFS) {
				error = VNOP_IOCTL(vp, HFS_SET_BOOT_INFO, (caddr_t)fndrinfo, 0, &context);
				if (error != 0)
					goto out;
			} else {
				/* XXX should never get here */
			}
		} else if ((error = setattrlist_setfinderinfo(vp, fndrinfo, &context)) != 0) {
			goto out;
		}
	}

	/* 
	 * Set the volume name, if we have one
	 */
	if (volname != NULL)
	{
		struct vfs_attr vs;
		
		VFSATTR_INIT(&vs);
		
		vs.f_vol_name = volname;	/* References the setattrlist buffer directly */
		VFSATTR_WANTED(&vs, f_vol_name);
		
		if ((error = vfs_setattr(vp->v_mount, &vs, ctx)) != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: setting volume name failed");
			goto out;
		}
		
		if (!VFSATTR_ALL_SUPPORTED(&vs)) {
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not set volume name");
			goto out;
		}
	}

	/* all done and successful */
	
out:
	if (vp != NULL)
		vnode_put(vp);
	if (user_buf != NULL)
		FREE(user_buf, M_TEMP);
	VFS_DEBUG(ctx, vp, "ATTRLIST - set returning %d", error);
	return(error);
}
