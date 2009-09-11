/*
 * Copyright (c) 1995-2008 Apple Inc. All rights reserved.
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

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

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
	attribute_set_t	actual;
	attribute_set_t valid;
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

#define ATTR_PACK4(AB, V)                                                 \
	do {                                                              \
		if ((AB.allocated - (AB.fixedcursor - AB.base)) >= 4) {   \
			*(uint32_t *)AB.fixedcursor = V;                  \
			AB.fixedcursor += 4;                              \
		}                                                         \
	} while (0)

#define ATTR_PACK8(AB, V)                                                 \
	do {                                                              \
		if ((AB.allocated - (AB.fixedcursor - AB.base)) >= 8) {   \
			*(uint64_t *)AB.fixedcursor = *(uint64_t *)&V;    \
			AB.fixedcursor += 8;                              \
		}                                                         \
	} while (0)

#define ATTR_PACK(b, v)	attrlist_pack_fixed(b, &v, sizeof(v))
#define ATTR_PACK_CAST(b, t, v)						\
	do {								\
		t _f = (t)v;						\
		ATTR_PACK(b, _f);					\
	} while (0)

#define ATTR_PACK_TIME(b, v, is64)					       		\
	do {										\
		if (is64) {								\
			struct user64_timespec us = {v.tv_sec, v.tv_nsec};		\
			ATTR_PACK(&b, us);						\
		} else {								\
			struct user32_timespec us = {v.tv_sec, v.tv_nsec};		\
			ATTR_PACK(&b, us);						\
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
	{ATTR_CMN_EXTENDED_SECURITY, 0,				sizeof(struct attrreference)},
	{ATTR_CMN_UUID,		0,				sizeof(guid_t)},
	{ATTR_CMN_GRPUUID,	0,				sizeof(guid_t)},
	{ATTR_CMN_FILEID,	0, 				sizeof(uint64_t)},
	{ATTR_CMN_PARENTID,	0,				sizeof(uint64_t)},
	{ATTR_CMN_RETURNED_ATTRS, 0,				sizeof(attribute_set_t)},
	{0, 0, 0}
};
#define ATTR_CMN_VOL_INVALID \
	(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID | \
	 ATTR_CMN_FILEID | ATTR_CMN_PARENTID)

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
	{ATTR_VOL_UUID,			VFSATTR_BIT(f_uuid),				sizeof(uuid_t)},
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
					*sizep += sizeof(struct user64_timespec);
				} else {
					*sizep += sizeof(struct user32_timespec);
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
	if (alp->commonattr) {
		if ((alp->commonattr & ATTR_CMN_VOL_INVALID) &&
		    (alp->commonattr & ATTR_CMN_RETURNED_ATTRS) == 0) {
			return (EINVAL);
		}
		if ((error = getvolattrlist_parsetab(getvolattrlist_common_tab,
		                                    alp->commonattr, vsp, sizep,
		                                    is_64bit)) != 0) {
			return(error);
		}
	}
	if (alp->volattr &&
	    (error = getvolattrlist_parsetab(getvolattrlist_vol_tab, alp->volattr, vsp, sizep, is_64bit)) != 0)
		return(error);

	return(0);
}

/*
 * Given the attributes listed in asp and those supported
 * in the vsp, fixup the asp attributes to reflect any
 * missing attributes from the file system
 */
static void
getvolattrlist_fixupattrs(attribute_set_t *asp, struct vfs_attr *vsp)
{
	struct getvolattrlist_attrtab *tab;

	if (asp->commonattr) {
		tab = getvolattrlist_common_tab;
		do {
			if ((tab->attr & asp->commonattr) &&
			    (tab->bits != 0) &&
			    ((tab->bits & vsp->f_supported) == 0)) {
				asp->commonattr &= ~tab->attr;
			}
		} while ((++tab)->attr != 0);
	}
	if (asp->volattr) {
		tab = getvolattrlist_vol_tab;
		do {
			if ((tab->attr & asp->volattr) &&
			    (tab->bits != 0) &&
			    ((tab->bits & vsp->f_supported) == 0)) {
				asp->volattr &= ~tab->attr;
			}
		} while ((++tab)->attr != 0);
	}
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

/* 
 * A zero after the ATTR_ bit indicates that we don't expect the underlying FS to report back with this 
 * information, and we will synthesize it at the VFS level.
 */
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
	{ATTR_CMN_FILEID,	VATTR_BIT(va_fileid), 		sizeof(uint64_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_PARENTID,	VATTR_BIT(va_parentid),		sizeof(uint64_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FULLPATH, 0, 	sizeof(struct attrreference),	KAUTH_VNODE_READ_ATTRIBUTES	},
	{ATTR_CMN_RETURNED_ATTRS, 0,				sizeof(attribute_set_t),	0},
	{0, 0, 0, 0}
};

static struct getattrlist_attrtab getattrlist_dir_tab[] = {
	{ATTR_DIR_LINKCOUNT,	VATTR_BIT(va_dirlinkcount),	sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_DIR_ENTRYCOUNT,	VATTR_BIT(va_nchildren),	sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
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

/*
 * The following are attributes that VFS can derive.
 *
 * A majority of them are the same attributes that are required for stat(2) and statfs(2).
 */
#define VFS_DFLT_ATTR_VOL	(ATTR_VOL_FSTYPE | ATTR_VOL_SIGNATURE |  \
				 ATTR_VOL_SIZE | ATTR_VOL_SPACEFREE |  \
				 ATTR_VOL_SPACEAVAIL | ATTR_VOL_MINALLOCATION |  \
				 ATTR_VOL_ALLOCATIONCLUMP |  ATTR_VOL_IOBLOCKSIZE |  \
				 ATTR_VOL_MOUNTPOINT | ATTR_VOL_MOUNTFLAGS |  \
				 ATTR_VOL_MOUNTEDDEVICE | ATTR_VOL_CAPABILITIES |  \
				 ATTR_VOL_ATTRIBUTES | ATTR_VOL_ENCODINGSUSED)

#define VFS_DFLT_ATTR_CMN	(ATTR_CMN_NAME | ATTR_CMN_DEVID |  \
				 ATTR_CMN_FSID | ATTR_CMN_OBJTYPE |  \
				 ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |  \
				 ATTR_CMN_PAROBJID | ATTR_CMN_SCRIPT |  \
				 ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME |  \
				 ATTR_CMN_FNDRINFO |  \
				 ATTR_CMN_OWNERID  | ATTR_CMN_GRPID |  \
				 ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS |  \
				 ATTR_CMN_USERACCESS | ATTR_CMN_FILEID | \
				 ATTR_CMN_PARENTID | ATTR_CMN_RETURNED_ATTRS)

#define VFS_DFLT_ATTR_DIR	(ATTR_DIR_LINKCOUNT | ATTR_DIR_MOUNTSTATUS)

#define VFS_DFLT_ATTR_FILE	(ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE |  \
				 ATTR_FILE_ALLOCSIZE  | ATTR_FILE_IOBLOCKSIZE |  \
				 ATTR_FILE_DEVTYPE | ATTR_FILE_DATALENGTH |  \
				 ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_RSRCLENGTH |  \
				 ATTR_FILE_RSRCALLOCSIZE)

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
					*sizep += sizeof(struct user64_timespec);
				} else {
					*sizep += sizeof(struct user32_timespec);
				}
			} else {
				*sizep += tab->size;
			}
			*actionp |= tab->action;
			if (attrs == recognised)
				break;  /* all done, get out */
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

/*
 * Given the attributes listed in asp and those supported
 * in the vap, fixup the asp attributes to reflect any
 * missing attributes from the file system
 */
static void
getattrlist_fixupattrs(attribute_set_t *asp, struct vnode_attr *vap)
{
	struct getattrlist_attrtab *tab;

	if (asp->commonattr) {
		tab = getattrlist_common_tab;
		do {
			if ((tab->attr & asp->commonattr) &&
			    (tab->bits & vap->va_active) &&
			    (tab->bits & vap->va_supported) == 0) {
				asp->commonattr &= ~tab->attr;
			}
		} while ((++tab)->attr != 0);
	}
	if (asp->dirattr) {
		tab = getattrlist_dir_tab;
		do {
			if ((tab->attr & asp->dirattr) &&
			    (tab->bits & vap->va_active) &&
			    (vap->va_supported & tab->bits) == 0) {
				asp->dirattr &= ~tab->attr;
			}
		} while ((++tab)->attr != 0);
	}
	if (asp->fileattr) {
		tab = getattrlist_file_tab;
		do {
			if ((tab->attr & asp->fileattr) &&
			    (tab->bits & vap->va_active) &&
			    (vap->va_supported & tab->bits) == 0) {
				asp->fileattr &= ~tab->attr;
			}
		} while ((++tab)->attr != 0);
	}
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

#if CONFIG_FSE
	if (error == 0 && need_fsevent(FSE_FINDER_INFO_CHANGED, vp)) {
	    add_fsevent(FSE_FINDER_INFO_CHANGED, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
	}
#endif
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
getvolattrlist(vnode_t vp, struct getattrlist_args *uap, struct attrlist *alp,
               vfs_context_t ctx, int is_64bit)
{
	struct vfs_attr vs;
	struct vnode_attr va;
	struct _attrlist_buf ab;
	int		error;
	ssize_t		fixedsize, varsize;
	const char	*cnp = NULL;	/* protected by ATTR_CMN_NAME */
	ssize_t		cnl = 0;	/* protected by ATTR_CMN_NAME */
	int		release_str = 0;
	mount_t		mnt;
	int		return_valid;
	int		pack_invalid;

	ab.base = NULL;
	VATTR_INIT(&va);
	VFSATTR_INIT(&vs);
	vs.f_vol_name = NULL;
	mnt = vp->v_mount;

	/* Check for special packing semantics */
	return_valid = (alp->commonattr & ATTR_CMN_RETURNED_ATTRS);
	pack_invalid = (uap->options & FSOPT_PACK_INVAL_ATTRS);
	if (pack_invalid) {
		/* FSOPT_PACK_INVAL_ATTRS requires ATTR_CMN_RETURNED_ATTRS */
		if (!return_valid) {
			error = EINVAL;
			goto out;
		}
		/* Keep invalid attrs from being uninitialized */
		bzero(&vs, sizeof (vs));
		/* Generate a valid mask for post processing */
		bcopy(&alp->commonattr, &ab.valid, sizeof (attribute_set_t));
	}

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

#if CONFIG_MACF
		error = mac_mount_check_getattr(ctx, mnt, &vs);
		if (error != 0)
			goto out;
#endif
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

			/* default value for volume f_attributes */
			if (VFSATTR_IS_ACTIVE(&vs, f_attributes)
			    && !VFSATTR_IS_SUPPORTED(&vs, f_attributes)) {
				vol_attributes_attr_t *attrp = &vs.f_attributes;
		
				attrp->validattr.commonattr = VFS_DFLT_ATTR_CMN;
				attrp->validattr.volattr = VFS_DFLT_ATTR_VOL;
				attrp->validattr.dirattr = VFS_DFLT_ATTR_DIR;
				attrp->validattr.fileattr = VFS_DFLT_ATTR_FILE;
				attrp->validattr.forkattr = 0;
		
				attrp->nativeattr.commonattr =  0;
				attrp->nativeattr.volattr = 0;
				attrp->nativeattr.dirattr = 0;
				attrp->nativeattr.fileattr = 0;
				attrp->nativeattr.forkattr = 0;
				VFSATTR_SET_SUPPORTED(&vs, f_attributes);
			}

			/* default value for volume f_capabilities */
			if (VFSATTR_IS_ACTIVE(&vs, f_capabilities)) {
				/* getattrlist is always supported now. */
				if (!VFSATTR_IS_SUPPORTED(&vs, f_capabilities)) {
					vs.f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] = 0;
					vs.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] = VOL_CAP_INT_ATTRLIST;
					vs.f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
					vs.f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2] = 0;
	
					vs.f_capabilities.valid[VOL_CAPABILITIES_FORMAT] = 0;
					vs.f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] = VOL_CAP_INT_ATTRLIST;
					vs.f_capabilities.valid[VOL_CAPABILITIES_RESERVED1] = 0;
					vs.f_capabilities.valid[VOL_CAPABILITIES_RESERVED2] = 0;
					VFSATTR_SET_SUPPORTED(&vs, f_capabilities);
				}
				else {
					/* OR in VOL_CAP_INT_ATTRLIST if f_capabilities is supported */
					vs.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_ATTRLIST;
					vs.f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_ATTRLIST;
				}
			}

			/* check to see if our fixups were enough */
			if (!VFSATTR_ALL_SUPPORTED(&vs)) {
				if (return_valid) {
					if (pack_invalid) {
						/* Fix up valid mask for post processing */
						getvolattrlist_fixupattrs(&ab.valid, &vs);
						
						/* Force packing of everything asked for */
						vs.f_supported = vs.f_active;
					} else {
						/* Adjust the requested attributes */
						getvolattrlist_fixupattrs((attribute_set_t *)&alp->commonattr, &vs);
					}
				} else {
					error = EINVAL;
					goto out;
				}
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

		if (VATTR_IS_ACTIVE(&va, va_encoding) &&
		    !VATTR_IS_SUPPORTED(&va, va_encoding)) {
			if (!return_valid || pack_invalid)
				/* use kTextEncodingMacUnicode */
				VATTR_RETURN(&va, va_encoding, 0x7e);
			else
				/* don't use a default */
				alp->commonattr &= ~ATTR_CMN_SCRIPT;
		}
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
			else {
				release_str = 1;
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
	if (return_valid) {
		ab.fixedcursor += sizeof (attribute_set_t);
		bzero(&ab.actual, sizeof (ab.actual));
	}
	ab.varcursor = ab.base + fixedsize;
	ab.needed = fixedsize + varsize;

	/* common attributes **************************************************/
	if (alp->commonattr & ATTR_CMN_NAME) {
		attrlist_pack_string(&ab, cnp, cnl);
		ab.actual.commonattr |= ATTR_CMN_NAME;
	}
	if (alp->commonattr & ATTR_CMN_DEVID) {
		ATTR_PACK4(ab, mnt->mnt_vfsstat.f_fsid.val[0]);
		ab.actual.commonattr |= ATTR_CMN_DEVID;
	}
	if (alp->commonattr & ATTR_CMN_FSID) {
		ATTR_PACK8(ab, mnt->mnt_vfsstat.f_fsid);
		ab.actual.commonattr |= ATTR_CMN_FSID;
	}
	if (alp->commonattr & ATTR_CMN_OBJTYPE) {
		if (!return_valid || pack_invalid)
			ATTR_PACK4(ab, 0);
	}
	if (alp->commonattr & ATTR_CMN_OBJTAG) {
		ATTR_PACK4(ab, vp->v_tag);
		ab.actual.commonattr |= ATTR_CMN_OBJTAG;
	}
	if (alp->commonattr & ATTR_CMN_OBJID) {
		if (!return_valid || pack_invalid) {
			fsobj_id_t f = {0, 0};
			ATTR_PACK8(ab, f);
		}
	}
	if (alp->commonattr & ATTR_CMN_OBJPERMANENTID) {
		if (!return_valid || pack_invalid) {
			fsobj_id_t f = {0, 0};
			ATTR_PACK8(ab, f);
		}
	}
	if (alp->commonattr & ATTR_CMN_PAROBJID) {
		if (!return_valid || pack_invalid) {
			fsobj_id_t f = {0, 0};
			ATTR_PACK8(ab, f);
		}
	}
	/* note that this returns the encoding for the volume name, not the node name */
	if (alp->commonattr & ATTR_CMN_SCRIPT) {
		ATTR_PACK4(ab, va.va_encoding);
		ab.actual.commonattr |= ATTR_CMN_SCRIPT;
	}
	if (alp->commonattr & ATTR_CMN_CRTIME) {
		ATTR_PACK_TIME(ab, vs.f_create_time, is_64bit);
		ab.actual.commonattr |= ATTR_CMN_CRTIME;
	}
	if (alp->commonattr & ATTR_CMN_MODTIME) {
		ATTR_PACK_TIME(ab, vs.f_modify_time, is_64bit);
		ab.actual.commonattr |= ATTR_CMN_MODTIME;
	}
	if (alp->commonattr & ATTR_CMN_CHGTIME) {
		if (!return_valid || pack_invalid)
			ATTR_PACK_TIME(ab, vs.f_modify_time, is_64bit);
	}
	if (alp->commonattr & ATTR_CMN_ACCTIME) {
		ATTR_PACK_TIME(ab, vs.f_access_time, is_64bit);
		ab.actual.commonattr |= ATTR_CMN_ACCTIME;
	}
	if (alp->commonattr & ATTR_CMN_BKUPTIME) {
		ATTR_PACK_TIME(ab, vs.f_backup_time, is_64bit);
		ab.actual.commonattr |= ATTR_CMN_BKUPTIME;
	}
	if (alp->commonattr & ATTR_CMN_FNDRINFO) {
		char f[32];
		/*
		 * This attribute isn't really Finder Info, at least for HFS.
		 */
		if (vp->v_tag == VT_HFS) {
			error = VNOP_IOCTL(vp, HFS_GET_BOOT_INFO, (caddr_t)&f, 0, ctx);
			if (error == 0) {
				attrlist_pack_fixed(&ab, f, sizeof(f));
				ab.actual.commonattr |= ATTR_CMN_FNDRINFO;
			} else if (!return_valid) {
				goto out;
			}
		} else if (!return_valid || pack_invalid) {
			/* XXX we could at least pass out the volume UUID here */
			bzero(&f, sizeof(f));
			attrlist_pack_fixed(&ab, f, sizeof(f));
		}
	}
	if (alp->commonattr & ATTR_CMN_OWNERID) {
		ATTR_PACK4(ab, va.va_uid);
		ab.actual.commonattr |= ATTR_CMN_OWNERID;
	}
	if (alp->commonattr & ATTR_CMN_GRPID) {
		ATTR_PACK4(ab, va.va_gid);
		ab.actual.commonattr |= ATTR_CMN_GRPID;
	}
	if (alp->commonattr & ATTR_CMN_ACCESSMASK) {
		ATTR_PACK_CAST(&ab, uint32_t, va.va_mode);
		ab.actual.commonattr |= ATTR_CMN_ACCESSMASK;
	}
	if (alp->commonattr & ATTR_CMN_FLAGS) {
		ATTR_PACK4(ab, va.va_flags);
		ab.actual.commonattr |= ATTR_CMN_FLAGS;
	}
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
#if CONFIG_MACF
		/* 
		 * Rather than MAC preceding DAC, in this case we want
		 * the smallest set of permissions granted by both MAC & DAC
		 * checks.  We won't add back any permissions.
		 */
		if (perms & W_OK)
			if (mac_vnode_check_access(ctx, vp, W_OK) != 0)
				perms &= ~W_OK;
		if (perms & R_OK)
			if (mac_vnode_check_access(ctx, vp, R_OK) != 0)
				perms &= ~R_OK;
		if (perms & X_OK)
			if (mac_vnode_check_access(ctx, vp, X_OK) != 0)
				perms &= ~X_OK;
#endif /* MAC */
		KAUTH_DEBUG("ATTRLIST - returning user access %x", perms);
		ATTR_PACK4(ab, perms);
		ab.actual.commonattr |= ATTR_CMN_USERACCESS;
	}
	/*
	 * The following common volume attributes are only
	 * packed when the pack_invalid mode is enabled.
	 */
	if (pack_invalid) {
		uint64_t fid = 0;

		if (alp->commonattr & ATTR_CMN_EXTENDED_SECURITY)
			attrlist_pack_variable(&ab, NULL, 0);
		if (alp->commonattr & ATTR_CMN_UUID)
			ATTR_PACK(&ab, kauth_null_guid);
		if (alp->commonattr & ATTR_CMN_GRPUUID)
			ATTR_PACK(&ab, kauth_null_guid);
		if (alp->commonattr & ATTR_CMN_FILEID)
			ATTR_PACK8(ab, fid);
		if (alp->commonattr & ATTR_CMN_PARENTID)
			ATTR_PACK8(ab, fid);
	}

	/* volume attributes **************************************************/

	if (alp->volattr & ATTR_VOL_FSTYPE) {
		ATTR_PACK_CAST(&ab, uint32_t, vfs_typenum(mnt));
		ab.actual.volattr |= ATTR_VOL_FSTYPE;
	}
 	if (alp->volattr & ATTR_VOL_SIGNATURE) {
 		ATTR_PACK_CAST(&ab, uint32_t, vs.f_signature);
		ab.actual.volattr |= ATTR_VOL_SIGNATURE;
	}
	if (alp->volattr & ATTR_VOL_SIZE) {
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize * vs.f_blocks);
		ab.actual.volattr |= ATTR_VOL_SIZE;
	}
	if (alp->volattr & ATTR_VOL_SPACEFREE) {
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize * vs.f_bfree);
		ab.actual.volattr |= ATTR_VOL_SPACEFREE;
	}
	if (alp->volattr & ATTR_VOL_SPACEAVAIL) {
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize * vs.f_bavail);
		ab.actual.volattr |= ATTR_VOL_SPACEAVAIL;
	}
	if (alp->volattr & ATTR_VOL_MINALLOCATION) {
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize);
		ab.actual.volattr |= ATTR_VOL_MINALLOCATION;
	}
	if (alp->volattr & ATTR_VOL_ALLOCATIONCLUMP) {
		ATTR_PACK_CAST(&ab, off_t, vs.f_bsize);			/* not strictly true */
		ab.actual.volattr |= ATTR_VOL_ALLOCATIONCLUMP;
	}
	if (alp->volattr & ATTR_VOL_IOBLOCKSIZE) {
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_iosize);
		ab.actual.volattr |= ATTR_VOL_IOBLOCKSIZE;
	}
	if (alp->volattr & ATTR_VOL_OBJCOUNT) {
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_objcount);
		ab.actual.volattr |= ATTR_VOL_OBJCOUNT;
	}
	if (alp->volattr & ATTR_VOL_FILECOUNT) {
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_filecount);
		ab.actual.volattr |= ATTR_VOL_FILECOUNT;
	}
	if (alp->volattr & ATTR_VOL_DIRCOUNT) {
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_dircount);
		ab.actual.volattr |= ATTR_VOL_DIRCOUNT;
	}
	if (alp->volattr & ATTR_VOL_MAXOBJCOUNT) {
		ATTR_PACK_CAST(&ab, uint32_t, vs.f_maxobjcount);
		ab.actual.volattr |= ATTR_VOL_MAXOBJCOUNT;
	}
	if (alp->volattr & ATTR_VOL_MOUNTPOINT) {
		attrlist_pack_string(&ab, mnt->mnt_vfsstat.f_mntonname, 0);
		ab.actual.volattr |= ATTR_VOL_MOUNTPOINT;
	}
	if (alp->volattr & ATTR_VOL_NAME) {
		attrlist_pack_string(&ab, vs.f_vol_name, 0);
		ab.actual.volattr |= ATTR_VOL_NAME;
	}
	if (alp->volattr & ATTR_VOL_MOUNTFLAGS) {
		ATTR_PACK_CAST(&ab, uint32_t, mnt->mnt_flag);
		ab.actual.volattr |= ATTR_VOL_MOUNTFLAGS;
	}
	if (alp->volattr & ATTR_VOL_MOUNTEDDEVICE) {
		attrlist_pack_string(&ab, mnt->mnt_vfsstat.f_mntfromname, 0);
		ab.actual.volattr |= ATTR_VOL_MOUNTEDDEVICE;
	}
	if (alp->volattr & ATTR_VOL_ENCODINGSUSED) {
		if (!return_valid || pack_invalid)
			ATTR_PACK_CAST(&ab, uint64_t, ~0LL);  /* return all encodings */
	}
	if (alp->volattr & ATTR_VOL_CAPABILITIES) {
		/* fix up volume capabilities */
		if (vfs_extendedsecurity(mnt)) {
			vs.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_EXTENDED_SECURITY;
		} else {
			vs.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] &= ~VOL_CAP_INT_EXTENDED_SECURITY;
		}
		vs.f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_EXTENDED_SECURITY;
		ATTR_PACK(&ab, vs.f_capabilities);
		ab.actual.volattr |= ATTR_VOL_CAPABILITIES;
	}
	if (alp->volattr & ATTR_VOL_UUID) {
		ATTR_PACK(&ab, vs.f_uuid);
	}
	if (alp->volattr & ATTR_VOL_ATTRIBUTES) {
		/* fix up volume attribute information */

		vs.f_attributes.validattr.commonattr |= VFS_DFLT_ATTR_CMN;
		vs.f_attributes.validattr.volattr |= VFS_DFLT_ATTR_VOL;
		vs.f_attributes.validattr.dirattr |= VFS_DFLT_ATTR_DIR;
		vs.f_attributes.validattr.fileattr |= VFS_DFLT_ATTR_FILE;

		if (vfs_extendedsecurity(mnt)) {
			vs.f_attributes.validattr.commonattr |= (ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID);
		} else {
			vs.f_attributes.validattr.commonattr &= ~(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID);
			vs.f_attributes.nativeattr.commonattr &= ~(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID);
		}
		ATTR_PACK(&ab, vs.f_attributes);
		ab.actual.volattr |= ATTR_VOL_ATTRIBUTES;
	}
	
	/* diagnostic */
	if (!return_valid && (ab.fixedcursor - ab.base) != fixedsize)
		panic("packed field size mismatch; allocated %ld but packed %ld for common %08x vol %08x",
		    fixedsize, (long) (ab.fixedcursor - ab.base), alp->commonattr, alp->volattr);
	if (!return_valid && ab.varcursor != (ab.base + ab.needed))
		panic("packed variable field size mismatch; used %ld but expected %ld", (long) (ab.varcursor - ab.base), ab.needed);

	/*
	 * In the compatible case, we report the smaller of the required and returned sizes.
	 * If the FSOPT_REPORT_FULLSIZE option is supplied, we report the full (required) size
	 * of the result buffer, even if we copied less out.  The caller knows how big a buffer
	 * they gave us, so they can always check for truncation themselves.
	 */
	*(uint32_t *)ab.base = (uap->options & FSOPT_REPORT_FULLSIZE) ? ab.needed : imin(ab.allocated, ab.needed);
	
	/* Return attribute set output if requested. */
	if (return_valid) {
		ab.actual.commonattr |= ATTR_CMN_RETURNED_ATTRS;
		if (pack_invalid) {
			/* Only report the attributes that are valid */
			ab.actual.commonattr &= ab.valid.commonattr;
			ab.actual.volattr &= ab.valid.volattr;
		}
		bcopy(&ab.actual, ab.base + sizeof(uint32_t), sizeof (ab.actual));
	}
	error = copyout(ab.base, uap->attributeBuffer, ab.allocated);

out:
	if (vs.f_vol_name != NULL)
		kfree(vs.f_vol_name, MAXPATHLEN);
	if (release_str) {
		vnode_putname(cnp);
	}
	if (ab.base != NULL)
		FREE(ab.base, M_TEMP);
	VFS_DEBUG(ctx, vp, "ATTRLIST - returning %d", error);
	return(error);
}

/*
 * Obtain attribute information about a filesystem object.
 */

static int
getattrlist_internal(vnode_t vp, struct getattrlist_args *uap, proc_t p, vfs_context_t ctx)
{
	struct attrlist	al;
	struct vnode_attr va;
	struct _attrlist_buf ab;
	kauth_action_t	action;
	ssize_t		fixedsize, varsize;
	const char	*cnp;
	const char	*vname = NULL;
	char 	*fullpathptr;
	ssize_t		fullpathlen;
	ssize_t		cnl;
	int		proc_is64;
	int		error;
	int		return_valid;
	int		pack_invalid;
	int		vtype = 0;

	proc_is64 = proc_is64bit(p);
	VATTR_INIT(&va);
	va.va_name = NULL;
	ab.base = NULL;
	cnp = "unknown";
	cnl = 0;
	fullpathptr = NULL;
	fullpathlen = 0;

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

#if CONFIG_MACF
	error = mac_vnode_check_getattrlist(ctx, vp, &al);
	if (error)
		goto out;
#endif /* MAC */

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
		error = getvolattrlist(vp, uap, &al, ctx, proc_is64);
		goto out;
	}

	/* Check for special packing semantics */
	return_valid = (al.commonattr & ATTR_CMN_RETURNED_ATTRS);
	pack_invalid = (uap->options & FSOPT_PACK_INVAL_ATTRS);
	if (pack_invalid) {
		/* FSOPT_PACK_INVAL_ATTRS requires ATTR_CMN_RETURNED_ATTRS */
		if (!return_valid || al.forkattr) {
			error = EINVAL;
			goto out;
		}
		/* Keep invalid attrs from being uninitialized */
		bzero(&va, sizeof (va));
		/* Generate a valid mask for post processing */
		bcopy(&al.commonattr, &ab.valid, sizeof (attribute_set_t));
	}

	/* Pick up the vnode type.  If the FS is bad and changes vnode types on us, we
	 * will have a valid snapshot that we can work from here.
	 */
	vtype = vp->v_type;


	/*
	 * Set up the vnode_attr structure and authorise.
	 */
	if ((error = getattrlist_setupvattr(&al, &va, &fixedsize, &action, proc_is64, (vtype == VDIR))) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: setup for request failed");
		goto out;
	}
	if ((error = vnode_authorize(vp, NULL, action, ctx)) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: authorisation failed/denied");
		goto out;
	}

	/*
	 * If we're asking for the full path, allocate a buffer for that.
	 */
	if (al.commonattr & (ATTR_CMN_FULLPATH)) {
		fullpathptr = (char*) kalloc(MAXPATHLEN);
		if (fullpathptr == NULL) {
			error = ENOMEM;
			VFS_DEBUG(ctx,vp, "ATTRLIST - ERROR: cannot allocate fullpath buffer");
			goto out;
		}
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
		if ((error = vnode_getattr(vp, &va, ctx)) != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: filesystem returned %d", error);
			goto out;
		}

		/* did we ask for something the filesystem doesn't support? */
		if (!VATTR_ALL_SUPPORTED(&va)) {

			/*
			 * There are a couple of special cases.  If we are after object IDs,
			 * we can make do with va_fileid.
			 */
			if ((al.commonattr & (ATTR_CMN_OBJID | ATTR_CMN_OBJPERMANENTID | ATTR_CMN_FILEID)) && !VATTR_IS_SUPPORTED(&va, va_linkid))
				VATTR_CLEAR_ACTIVE(&va, va_linkid);	/* forget we wanted this */
			
			/*
			 * Many filesystems don't know their parent object id.
			 * If necessary, attempt to derive it from the vnode.
			 */
			if ((al.commonattr & (ATTR_CMN_PAROBJID | ATTR_CMN_PARENTID)) &&
			    !VATTR_IS_SUPPORTED(&va, va_parentid)) {
				vnode_t	dvp;
	
				if ((dvp = vnode_getparent(vp)) != NULLVP) {
					struct vnode_attr lva;
	
					VATTR_INIT(&lva);
					VATTR_WANTED(&lva, va_fileid);
					if (vnode_getattr(dvp, &lva, ctx) == 0 &&
					    VATTR_IS_SUPPORTED(&va, va_fileid)) {
						va.va_parentid = lva.va_fileid;
						VATTR_SET_SUPPORTED(&va, va_parentid);
					}
					vnode_put(dvp);
				}
			}
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
			if ((al.commonattr & ATTR_CMN_SCRIPT) &&
			    !VATTR_IS_SUPPORTED(&va, va_encoding) && !return_valid)
				VATTR_RETURN(&va, va_encoding, 0x7e /* kTextEncodingMacUnicode */);

			/*
			 * If we don't have a name, we'll get one from the vnode or mount point.
			 */
			if ((al.commonattr & ATTR_CMN_NAME) && !VATTR_IS_SUPPORTED(&va, va_name)) {
				VATTR_CLEAR_ACTIVE(&va, va_name);
			}

			/* If va_dirlinkcount isn't supported use a default of 1. */
			if ((al.dirattr & ATTR_DIR_LINKCOUNT) && !VATTR_IS_SUPPORTED(&va, va_dirlinkcount)) {
				VATTR_RETURN(&va, va_dirlinkcount, 1);
			}
			
			/* check again */
			if (!VATTR_ALL_SUPPORTED(&va)) {
				if (return_valid) {
					if (pack_invalid) {
						/* Fix up valid mask for post processing */
						getattrlist_fixupattrs(&ab.valid, &va);
						
						/* Force packing of everything asked for */
						va.va_supported = va.va_active;
					} else {
						/* Adjust the requested attributes */
						getattrlist_fixupattrs((attribute_set_t *)&al.commonattr, &va);
					}
				} else {
					error = EINVAL;
					goto out;
				}
			}
		}
	}

	/*
	 * Compute variable-space requirements.
	 */
	varsize = 0; /* length count */

	/* We may need to fix up the name attribute if requested */
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
	 * Compute the full path to this vnode, if necessary. This attribute is almost certainly
	 * not supported by any filesystem, so build the path to this vnode at this time.
	 */
	if (al.commonattr & ATTR_CMN_FULLPATH) {
		int len = MAXPATHLEN;
		int err;
		/* call build_path making sure NOT to use the cache-only behavior */
		err = build_path(vp, fullpathptr, len, &len, 0, vfs_context_current());
		if (err) {
			error = err;
			goto out;
		}
		fullpathlen = 0;
		if (fullpathptr){
			fullpathlen = strlen(fullpathptr);
		}
		varsize += roundup(fullpathlen+1, 4);
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
	 * we might have to allocate more than they offer so that the diagnostic checks
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

	/* set the S_IFMT bits for the mode */
	if (al.commonattr & ATTR_CMN_ACCESSMASK) {
		switch (vp->v_type) {
		case VREG:
			va.va_mode |= S_IFREG;
			break;
		case VDIR:
			va.va_mode |= S_IFDIR;
			break;
		case VBLK:
			va.va_mode |= S_IFBLK;
			break;
		case VCHR:
			va.va_mode |= S_IFCHR;
			break;
		case VLNK:
			va.va_mode |= S_IFLNK;
			break;
		case VSOCK:
			va.va_mode |= S_IFSOCK;
			break;
		case VFIFO:
			va.va_mode |= S_IFIFO;
			break;
		default:
			error = EBADF;
			goto out;
		}
	}

	/*
	 * Pack results into the destination buffer.
	 */
	ab.fixedcursor = ab.base + sizeof(uint32_t);
	if (return_valid) {
		ab.fixedcursor += sizeof (attribute_set_t);
		bzero(&ab.actual, sizeof (ab.actual));
	}
	ab.varcursor = ab.base + fixedsize;
	ab.needed = ab.allocated;

	/* common attributes **************************************************/
	if (al.commonattr & ATTR_CMN_NAME) {
		attrlist_pack_string(&ab, cnp, cnl);
		ab.actual.commonattr |= ATTR_CMN_NAME;
	}
	if (al.commonattr & ATTR_CMN_DEVID) {
		ATTR_PACK4(ab, vp->v_mount->mnt_vfsstat.f_fsid.val[0]);
		ab.actual.commonattr |= ATTR_CMN_DEVID;
	}
	if (al.commonattr & ATTR_CMN_FSID) {
		ATTR_PACK8(ab, vp->v_mount->mnt_vfsstat.f_fsid);
		ab.actual.commonattr |= ATTR_CMN_FSID;
	}
	if (al.commonattr & ATTR_CMN_OBJTYPE) {
		ATTR_PACK4(ab, vtype);
		ab.actual.commonattr |= ATTR_CMN_OBJTYPE;
	}
	if (al.commonattr & ATTR_CMN_OBJTAG) {
		ATTR_PACK4(ab, vp->v_tag);
		ab.actual.commonattr |= ATTR_CMN_OBJTAG;
	}
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
		ATTR_PACK8(ab, f);
		ab.actual.commonattr |= ATTR_CMN_OBJID;
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
		ATTR_PACK8(ab, f);
		ab.actual.commonattr |= ATTR_CMN_OBJPERMANENTID;
	}
	if (al.commonattr & ATTR_CMN_PAROBJID) {
		fsobj_id_t f;

		f.fid_objno = va.va_parentid;  /* could be lossy here! */
		f.fid_generation = 0;
		ATTR_PACK8(ab, f);
		ab.actual.commonattr |= ATTR_CMN_PAROBJID;
	}
	if (al.commonattr & ATTR_CMN_SCRIPT) {
 		if (VATTR_IS_SUPPORTED(&va, va_encoding)) {
			ATTR_PACK4(ab, va.va_encoding);
			ab.actual.commonattr |= ATTR_CMN_SCRIPT;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4(ab, 0x7e);
		}
	}
	if (al.commonattr & ATTR_CMN_CRTIME) {
		ATTR_PACK_TIME(ab, va.va_create_time, proc_is64);
		ab.actual.commonattr |= ATTR_CMN_CRTIME;
	}
	if (al.commonattr & ATTR_CMN_MODTIME) {
		ATTR_PACK_TIME(ab, va.va_modify_time, proc_is64);
		ab.actual.commonattr |= ATTR_CMN_MODTIME;
	}
	if (al.commonattr & ATTR_CMN_CHGTIME) {
		ATTR_PACK_TIME(ab, va.va_change_time, proc_is64);
		ab.actual.commonattr |= ATTR_CMN_CHGTIME;
	}
	if (al.commonattr & ATTR_CMN_ACCTIME) {
		ATTR_PACK_TIME(ab, va.va_access_time, proc_is64);
		ab.actual.commonattr |= ATTR_CMN_ACCTIME;
	}
	if (al.commonattr & ATTR_CMN_BKUPTIME) {
		ATTR_PACK_TIME(ab, va.va_backup_time, proc_is64);
		ab.actual.commonattr |= ATTR_CMN_BKUPTIME;
	}
	if (al.commonattr & ATTR_CMN_FNDRINFO) {
		uio_t	auio;
		size_t	fisize = 32;
		char	uio_buf[UIO_SIZEOF(1)];

		if ((auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ,
		     uio_buf, sizeof(uio_buf))) == NULL) {
			error = ENOMEM;
			goto out;
		}
		uio_addiov(auio, CAST_USER_ADDR_T(ab.fixedcursor), fisize);
		error = vn_getxattr(vp, XATTR_FINDERINFO_NAME, auio,
				    &fisize, XATTR_NOSECURITY, ctx);
		uio_free(auio);
		/*
		 * Default to zeros if its not available,
		 * unless ATTR_CMN_RETURNED_ATTRS was requested.
		 */
		if (error &&
		    (!return_valid || pack_invalid) &&
		    ((error == ENOATTR) || (error == ENOENT) ||
		     (error == ENOTSUP) || (error == EPERM))) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - No system.finderinfo attribute, returning zeroes");
			bzero(ab.fixedcursor, 32);
			error = 0;
		}
		if (error == 0) {
			ab.fixedcursor += 32;
			ab.actual.commonattr |= ATTR_CMN_FNDRINFO;
		} else if (!return_valid) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: reading system.finderinfo attribute");
			goto out;
		}
	}
	if (al.commonattr & ATTR_CMN_OWNERID) {
		ATTR_PACK4(ab, va.va_uid);
		ab.actual.commonattr |= ATTR_CMN_OWNERID;
	}
	if (al.commonattr & ATTR_CMN_GRPID) {
		ATTR_PACK4(ab, va.va_gid);
		ab.actual.commonattr |= ATTR_CMN_GRPID;
	}
	if (al.commonattr & ATTR_CMN_ACCESSMASK) {
		ATTR_PACK4(ab, va.va_mode);
		ab.actual.commonattr |= ATTR_CMN_ACCESSMASK;
	}
	if (al.commonattr & ATTR_CMN_FLAGS) {
		ATTR_PACK4(ab, va.va_flags);
		ab.actual.commonattr |= ATTR_CMN_FLAGS;
	}
	if (al.commonattr & ATTR_CMN_USERACCESS) {	/* this is expensive */
		uint32_t	perms = 0;
		if (vtype == VDIR) {
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

#if CONFIG_MACF
		/* 
		 * Rather than MAC preceding DAC, in this case we want
		 * the smallest set of permissions granted by both MAC & DAC
		 * checks.  We won't add back any permissions.
		 */
		if (perms & W_OK)
			if (mac_vnode_check_access(ctx, vp, W_OK) != 0)
				perms &= ~W_OK;
		if (perms & R_OK)
			if (mac_vnode_check_access(ctx, vp, R_OK) != 0)
				perms &= ~R_OK;
		if (perms & X_OK)
			if (mac_vnode_check_access(ctx, vp, X_OK) != 0)
				perms &= ~X_OK;
#endif /* MAC */
		VFS_DEBUG(ctx, vp, "ATTRLIST - granting perms %d", perms);
		ATTR_PACK4(ab, perms);
		ab.actual.commonattr |= ATTR_CMN_USERACCESS;
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
			attrlist_pack_variable2(&ab, &fsec, __offsetof(struct kauth_filesec, fsec_acl), va.va_acl, KAUTH_ACL_COPYSIZE(va.va_acl));
			ab.actual.commonattr |= ATTR_CMN_EXTENDED_SECURITY;
		} else if (!return_valid || pack_invalid) {
			attrlist_pack_variable(&ab, NULL, 0);
		}
	}
  	if (al.commonattr & ATTR_CMN_UUID) {
 		if (VATTR_IS_SUPPORTED(&va, va_uuuid)) {
			ATTR_PACK(&ab, va.va_uuuid);
			ab.actual.commonattr |= ATTR_CMN_UUID;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK(&ab, kauth_null_guid);
		}
	}
	if (al.commonattr & ATTR_CMN_GRPUUID) {
		if (VATTR_IS_SUPPORTED(&va, va_guuid)) {
			ATTR_PACK(&ab, va.va_guuid);
			ab.actual.commonattr |= ATTR_CMN_GRPUUID;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK(&ab, kauth_null_guid);
		}
	}
	if (al.commonattr & ATTR_CMN_FILEID) {
		ATTR_PACK8(ab, va.va_fileid);
		ab.actual.commonattr |= ATTR_CMN_FILEID;
	}
	if (al.commonattr & ATTR_CMN_PARENTID) {
		ATTR_PACK8(ab, va.va_parentid);
		ab.actual.commonattr |= ATTR_CMN_PARENTID;
	}
	
	if (al.commonattr & ATTR_CMN_FULLPATH) {
		attrlist_pack_string (&ab, fullpathptr, fullpathlen);
		ab.actual.commonattr |= ATTR_CMN_FULLPATH;
	}

	/* directory attributes *********************************************/
	if (al.dirattr && (vtype == VDIR)) {
		if (al.dirattr & ATTR_DIR_LINKCOUNT) {  /* full count of entries */
			ATTR_PACK4(ab, (uint32_t)va.va_dirlinkcount);
			ab.actual.dirattr |= ATTR_DIR_LINKCOUNT;
		}
		if (al.dirattr & ATTR_DIR_ENTRYCOUNT) {
			ATTR_PACK4(ab, (uint32_t)va.va_nchildren);
			ab.actual.dirattr |= ATTR_DIR_ENTRYCOUNT;
		}
		if (al.dirattr & ATTR_DIR_MOUNTSTATUS) {
			ATTR_PACK_CAST(&ab, uint32_t, (vp->v_flag & VROOT) ?
			               DIR_MNTSTATUS_MNTPOINT : 0);
			ab.actual.dirattr |= ATTR_DIR_MOUNTSTATUS;
		}
	}

	/* file attributes **************************************************/
	if (al.fileattr && (vtype != VDIR)) {
		if (al.fileattr & ATTR_FILE_LINKCOUNT) {
			ATTR_PACK4(ab, (uint32_t)va.va_nlink);
			ab.actual.fileattr |= ATTR_FILE_LINKCOUNT;
		}
		if (al.fileattr & ATTR_FILE_TOTALSIZE) {
			ATTR_PACK8(ab, va.va_total_size);
			ab.actual.fileattr |= ATTR_FILE_TOTALSIZE;
		}
		if (al.fileattr & ATTR_FILE_ALLOCSIZE) {
			ATTR_PACK8(ab, va.va_total_alloc);
			ab.actual.fileattr |= ATTR_FILE_ALLOCSIZE;
		}
		if (al.fileattr & ATTR_FILE_IOBLOCKSIZE) {
			ATTR_PACK4(ab, va.va_iosize);
			ab.actual.fileattr |= ATTR_FILE_IOBLOCKSIZE;
		}
		if (al.fileattr & ATTR_FILE_CLUMPSIZE) {
			if (!return_valid || pack_invalid) {
				ATTR_PACK4(ab, 0);     /* this value is deprecated */
				ab.actual.fileattr |= ATTR_FILE_CLUMPSIZE;
			}
		}
		if (al.fileattr & ATTR_FILE_DEVTYPE) {
			uint32_t dev;

			if ((vp->v_type == VCHR) || (vp->v_type == VBLK)) {
				if (vp->v_specinfo != NULL)
					dev = vp->v_specinfo->si_rdev;
				else
					dev = va.va_rdev;
			} else {
				dev = 0;
			}
			ATTR_PACK4(ab, dev);
			ab.actual.fileattr |= ATTR_FILE_DEVTYPE;
		}
		if (al.fileattr & ATTR_FILE_DATALENGTH) {
			if (VATTR_IS_SUPPORTED(&va, va_data_size)) {
				ATTR_PACK8(ab, va.va_data_size);
			} else {
				ATTR_PACK8(ab, va.va_total_size);
			}
			ab.actual.fileattr |= ATTR_FILE_DATALENGTH;
		}
		if (al.fileattr & ATTR_FILE_DATAALLOCSIZE) {
			if (VATTR_IS_SUPPORTED(&va, va_data_alloc)) {
				ATTR_PACK8(ab, va.va_data_alloc);
			} else {
				ATTR_PACK8(ab, va.va_total_alloc);
			}
			ab.actual.fileattr |= ATTR_FILE_DATAALLOCSIZE;
		}
		/* fetch resource fork size/allocation via xattr interface */
		if (al.fileattr & (ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE)) {
			size_t	rsize;
			uint64_t rlength;

			if ((error = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, NULL, &rsize, XATTR_NOSECURITY, ctx)) != 0) {
				if ((error == ENOENT) || (error == ENOATTR) || (error == ENOTSUP) || (error == EPERM)) {
					rsize = 0;
					error = 0;
				} else {
					goto out;
				}
			}
			if (al.fileattr & ATTR_FILE_RSRCLENGTH) {
				rlength = rsize;
				ATTR_PACK8(ab, rlength);
				ab.actual.fileattr |= ATTR_FILE_RSRCLENGTH;
			}
			if (al.fileattr & ATTR_FILE_RSRCALLOCSIZE) {
				uint32_t  blksize = vp->v_mount->mnt_vfsstat.f_bsize;
				if (blksize == 0)
					blksize = 512;
				rlength = roundup(rsize, blksize);
				ATTR_PACK8(ab, rlength);
				ab.actual.fileattr |= ATTR_FILE_RSRCALLOCSIZE;
			}
		}
	}
	
	/* diagnostic */
	if (!return_valid && (ab.fixedcursor - ab.base) != fixedsize)
		panic("packed field size mismatch; allocated %ld but packed %ld for common %08x vol %08x",
		    fixedsize, (long) (ab.fixedcursor - ab.base), al.commonattr, al.volattr);
	if (!return_valid && ab.varcursor != (ab.base + ab.needed))
		panic("packed variable field size mismatch; used %ld but expected %ld", (long) (ab.varcursor - ab.base), ab.needed);

	/*
	 * In the compatible case, we report the smaller of the required and returned sizes.
	 * If the FSOPT_REPORT_FULLSIZE option is supplied, we report the full (required) size
	 * of the result buffer, even if we copied less out.  The caller knows how big a buffer
	 * they gave us, so they can always check for truncation themselves.
	 */
	*(uint32_t *)ab.base = (uap->options & FSOPT_REPORT_FULLSIZE) ? ab.needed : imin(ab.allocated, ab.needed);

	/* Return attribute set output if requested. */
	if (return_valid) {
		ab.actual.commonattr |= ATTR_CMN_RETURNED_ATTRS;
		if (pack_invalid) {
			/* Only report the attributes that are valid */
			ab.actual.commonattr &= ab.valid.commonattr;
			ab.actual.dirattr &= ab.valid.dirattr;
			ab.actual.fileattr &= ab.valid.fileattr;
		}
		bcopy(&ab.actual, ab.base + sizeof(uint32_t), sizeof (ab.actual));
	}
	
	/* Only actually copyout as much out as the user buffer can hold */
	error = copyout(ab.base, uap->attributeBuffer, imin(uap->bufferSize, ab.allocated));
	
out:
	if (va.va_name)
		kfree(va.va_name, MAXPATHLEN);
	if (fullpathptr)
		kfree(fullpathptr, MAXPATHLEN);
	if (vname)
		vnode_putname(vname);
	if (ab.base != NULL)
		FREE(ab.base, M_TEMP);
	if (VATTR_IS_SUPPORTED(&va, va_acl) && (va.va_acl != NULL))
		kauth_acl_free(va.va_acl);

	VFS_DEBUG(ctx, vp, "ATTRLIST - returning %d", error);
	return(error);
}

int
fgetattrlist(proc_t p, struct fgetattrlist_args *uap, __unused int32_t *retval)
{
	struct vfs_context *ctx;
	vnode_t		vp = NULL;
	int		error;
	struct getattrlist_args	ap;

	ctx = vfs_context_current();
	error = 0;

	if ((error = file_vnode(uap->fd, &vp)) != 0)
		return (error);

	if ((error = vnode_getwithref(vp)) != 0) {
		file_drop(uap->fd);
		return(error);
	}

	ap.path = 0;
	ap.alist = uap->alist;
	ap.attributeBuffer = uap->attributeBuffer;
	ap.bufferSize = uap->bufferSize;
	ap.options = uap->options;

	error = getattrlist_internal(vp, &ap, p, ctx);

	file_drop(uap->fd);
	if (vp)
		vnode_put(vp);

	return error;
}

int
getattrlist(proc_t p, struct getattrlist_args *uap, __unused int32_t *retval)
{
	struct vfs_context *ctx;
	struct nameidata nd;
	vnode_t		vp = NULL;
	u_long		nameiflags;
	int		error;

	ctx = vfs_context_current();
	error = 0;

	/*
	 * Look up the file.
	 */
	nameiflags = NOTRIGGER | AUDITVNPATH1;
	if (!(uap->options & FSOPT_NOFOLLOW))
		nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, uap->path, ctx);

	if ((error = namei(&nd)) != 0)
		goto out;
	vp = nd.ni_vp;
	nameidone(&nd);

	error = getattrlist_internal(vp, uap, p, ctx);
out:
	if (vp)
		vnode_put(vp);
	return error;
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
			struct user64_timespec us;		\
			ATTR_UNPACK(us);			\
			v.tv_sec = us.tv_sec;			\
			v.tv_nsec = us.tv_nsec;			\
		} else {					\
			struct user32_timespec us;		\
			ATTR_UNPACK(us);			\
			v.tv_sec = us.tv_sec;			\
			v.tv_nsec = us.tv_nsec;			\
		}						\
	} while(0)


/*
 * Write attributes.
 */
static int
setattrlist_internal(vnode_t vp, struct setattrlist_args *uap, proc_t p, vfs_context_t ctx)
{
	struct attrlist al;
	struct vnode_attr va;
	struct attrreference ar;
	kauth_action_t	action;
	char		*user_buf, *cursor, *bufend, *fndrinfo, *cp, *volname;
	int		proc_is64, error;
	uint32_t	nace;
	kauth_filesec_t rfsec;

	user_buf = NULL;
	fndrinfo = NULL;
	volname = NULL;
	error = 0;
	proc_is64 = proc_is64bit(p);
	VATTR_INIT(&va);
	
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

#if CONFIG_MACF
	error = mac_vnode_check_setattrlist(ctx, vp, &al);
	if (error)
		goto out;
#endif /* MAC */

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
		if (((((char *)rfsec) + KAUTH_FILESEC_SIZE(0)) > bufend) ||			/* no space for acl */
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
	if ((va.va_active != 0LL) && ((error = vnode_authattr(vp, &va, &action, ctx)) != 0)) {
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
			action |= KAUTH_VNODE_WRITE_EXTATTRIBUTES;
		}
	}

	if ((action != 0) && ((error = vnode_authorize(vp, NULL, action, ctx)) != 0)) {
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
		if ((error = setattrlist_setfinderinfo(vp, fndrinfo, ctx)) != 0) {
			goto out;
		}
		fndrinfo = NULL;  /* it was set here so skip setting below */
	}

	/*
	 * Write the attributes if we have any.
	 */
	if ((va.va_active != 0LL) && ((error = vnode_setattr(vp, &va, ctx)) != 0)) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: filesystem returned %d", error);
		goto out;
	}

	/*
	 * Write the Finder Info if we have any.
	 */
	if (fndrinfo != NULL) {
		if (al.volattr & ATTR_VOL_INFO) {
			if (vp->v_tag == VT_HFS) {
				error = VNOP_IOCTL(vp, HFS_SET_BOOT_INFO, (caddr_t)fndrinfo, 0, ctx);
				if (error != 0)
					goto out;
			} else {
				/* XXX should never get here */
			}
		} else if ((error = setattrlist_setfinderinfo(vp, fndrinfo, ctx)) != 0) {
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
		
#if CONFIG_MACF
		error = mac_mount_check_setattr(ctx, vp->v_mount, &vs);
		if (error != 0)
			goto out;
#endif

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
	if (user_buf != NULL)
		FREE(user_buf, M_TEMP);
	VFS_DEBUG(ctx, vp, "ATTRLIST - set returning %d", error);
	return(error);
}

int
setattrlist(proc_t p, struct setattrlist_args *uap, __unused int32_t *retval)
{
	struct vfs_context *ctx;
	struct nameidata nd;
	vnode_t		vp = NULL;
	u_long		nameiflags;
	int error = 0;

	ctx = vfs_context_current();

	/*
	 * Look up the file.
	 */
	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0)
		nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags | AUDITVNPATH1, UIO_USERSPACE, uap->path, ctx);
	if ((error = namei(&nd)) != 0)
		goto out;
	vp = nd.ni_vp;
	nameidone(&nd);

	error = setattrlist_internal(vp, uap, p, ctx);
out:
	if (vp != NULL)
		vnode_put(vp);
	return error;
}

int
fsetattrlist(proc_t p, struct fsetattrlist_args *uap, __unused int32_t *retval)
{
	struct vfs_context *ctx;
	vnode_t		vp = NULL;
	int		error;
	struct setattrlist_args ap;

	ctx = vfs_context_current();

	if ((error = file_vnode(uap->fd, &vp)) != 0)
		return (error);

	if ((error = vnode_getwithref(vp)) != 0) {
		file_drop(uap->fd);
		return(error);
	}

	ap.path = 0;
	ap.alist = uap->alist;
	ap.attributeBuffer = uap->attributeBuffer;
	ap.bufferSize = uap->bufferSize;
	ap.options = uap->options;

	error = setattrlist_internal(vp, &ap, p, ctx);
	file_drop(uap->fd);
	if (vp != NULL)
		vnode_put(vp);

	return error;
}

