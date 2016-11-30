/*
 * Copyright (c) 1995-2016 Apple Inc. All rights reserved.
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
#include <sys/syslog.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h>
#include <sys/file_internal.h>
#include <sys/kauth.h>
#include <sys/uio_internal.h>
#include <sys/malloc.h>
#include <sys/attr.h>
#include <sys/sysproto.h>
#include <sys/xattr.h>
#include <sys/fsevents.h>
#include <kern/kalloc.h>
#include <miscfs/specfs/specdev.h>

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
 * Attempt to pack a fixed width attribute of size (count) bytes from
 * source to our attrlist buffer.
 */
static void
attrlist_pack_fixed(struct _attrlist_buf *ab, void *source, ssize_t count)
{
	/* 
	 * Use ssize_t for pointer math purposes,
	 * since a ssize_t is a signed long
	 */
	ssize_t	fit;

	/*
	 * Compute the amount of remaining space in the attrlist buffer
	 * based on how much we've used for fixed width fields vs. the
	 * start of the attributes.  
	 * 
	 * If we've still got room, then 'fit' will contain the amount of 
	 * remaining space.  
	 * 
	 * Note that this math is safe because, in the event that the 
	 * fixed-width cursor has moved beyond the end of the buffer,
	 * then, the second input into lmin() below will be negative, and 
	 * we will fail the (fit > 0) check below. 
	 */ 
	fit = lmin(count, ab->allocated - (ab->fixedcursor - ab->base));
	if (fit > 0) {
		/* Copy in as much as we can */
		bcopy(source, ab->fixedcursor, fit);
	}

	/* always move in increments of 4, even if we didn't pack an attribute. */
	ab->fixedcursor += roundup(count, 4);
}

/*
 * Attempt to pack one (or two) variable width attributes into the attrlist
 * buffer.  If we are trying to pack two variable width attributes, they are treated
 * as a single variable-width attribute from the POV of the system call caller.
 * 
 * Recall that a variable-width attribute has two components: the fixed-width 
 * attribute that tells the caller where to look, and the actual variable width data.
 */
static void
attrlist_pack_variable2(struct _attrlist_buf *ab, const void *source, ssize_t count, 
		const void *ext, ssize_t extcount) 
{
	/* Use ssize_t's for pointer math ease */
	struct attrreference ar;
	ssize_t fit;

	/*
	 * Pack the fixed-width component to the variable object. 
	 * Note that we may be able to pack the fixed width attref, but not
	 * the variable (if there's no room).
	 */
	ar.attr_dataoffset = ab->varcursor - ab->fixedcursor;
	ar.attr_length = count + extcount;
	attrlist_pack_fixed(ab, &ar, sizeof(ar));

	/* 
	 * Use an lmin() to do a signed comparison. We use a signed comparison
	 * to detect the 'out of memory' conditions as described above in the
	 * fixed width check above.
	 *
	 * Then pack the first variable attribute as space allows.  Note that we advance
	 * the variable cursor only if we we had some available space. 
	 */
	fit = lmin(count, ab->allocated - (ab->varcursor - ab->base));
	if (fit > 0) {
		if (source != NULL) {
			bcopy(source, ab->varcursor, fit);
		}
		ab->varcursor += fit;
	}

	/* Compute the available space for the second attribute */
	fit = lmin(extcount, ab->allocated - (ab->varcursor - ab->base));
	if (fit > 0) {
		/* Copy in data for the second attribute (if needed) if there is room */
		if (ext != NULL) {
			bcopy(ext, ab->varcursor, fit);
		}
		ab->varcursor += fit;
	}
	/* always move in increments of 4 */
	ab->varcursor = (char *)roundup((uintptr_t)ab->varcursor, 4);
}

/* 
 * Packing a single variable-width attribute is the same as calling the two, but with
 * an invalid 2nd attribute.
 */
static void
attrlist_pack_variable(struct _attrlist_buf *ab, const void *source, ssize_t count)
{
	attrlist_pack_variable2(ab, source, count, NULL, 0);
}

/*
 * Attempt to pack a string. This is a special case of a variable width attribute.
 *
 * If "source" is NULL, then an empty string ("") will be packed.  If "source" is
 * not NULL, but "count" is zero, then "source" is assumed to be a NUL-terminated
 * C-string.  If "source" is not NULL and "count" is not zero, then only the first
 * "count" bytes of "source" will be copied, and a NUL terminator will be added.
 *
 * If the attrlist buffer doesn't have enough room to hold the entire string (including
 * NUL terminator), then copy as much as will fit.  The attrlist buffer's "varcursor"
 * will always be updated based on the entire length of the string (including NUL
 * terminator); this means "varcursor" may end up pointing beyond the end of the
 * allocated buffer space.
 */
static void
attrlist_pack_string(struct _attrlist_buf *ab, const char *source, ssize_t count)
{
	struct attrreference ar;
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
	 * Construct the fixed-width attribute that refers to this string. 
	 */
	ar.attr_dataoffset = ab->varcursor - ab->fixedcursor;
	ar.attr_length = count + 1;
	attrlist_pack_fixed(ab, &ar, sizeof(ar));

	/*
	 * Now compute how much available memory we have to copy the string text.
	 *
	 * space = the number of bytes available in the attribute buffer to hold the
	 *         string's value.
	 *
	 * fit = the number of bytes to copy from the start of the string into the
	 *       attribute buffer, NOT including the NUL terminator.  If the attribute
	 *       buffer is large enough, this will be the string's length; otherwise, it
	 *       will be equal to "space".
	 */
	space = ab->allocated - (ab->varcursor - ab->base);
	fit = lmin(count, space);
	if (space > 0) {
		int bytes_to_zero;

		/* 
		 * If there is space remaining, copy data in, and 
		 * accommodate the trailing NUL terminator.
		 *
		 * NOTE: if "space" is too small to hold the string and its NUL
		 * terminator (space < fit + 1), then the string value in the attribute
		 * buffer will NOT be NUL terminated!
		 *
		 * NOTE 2: bcopy() will do nothing if the length ("fit") is zero.
		 * Therefore, we don't bother checking for that here.
		 */
		bcopy(source, ab->varcursor, fit);
		/* is there room for our trailing nul? */
		if (space > fit) {
			ab->varcursor[fit++] = '\0';
			/* 'fit' now the number of bytes AFTER adding in the NUL */
			/*
			 * Zero out any additional bytes we might have as a
			 * result of rounding up.
			 */
			bytes_to_zero = min((roundup(fit, 4) - fit),
			    space - fit);
			if (bytes_to_zero)
				bzero(&(ab->varcursor[fit]), bytes_to_zero);
		}
	}
	/* 
	 * always move in increments of 4 (including the trailing NUL)
	 */
	ab->varcursor += roundup((count+1), 4);

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
	{ATTR_CMN_ERROR,	0,				sizeof(uint32_t)},
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
	{ATTR_VOL_NAME,			VFSATTR_BIT(f_vol_name),			sizeof(struct attrreference)},
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
	{ATTR_CMN_FSID,		0,				sizeof(fsid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
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
	{ATTR_CMN_GEN_COUNT,	VATTR_BIT(va_write_gencount),	sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_DOCUMENT_ID,	VATTR_BIT(va_document_id),	sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_USERACCESS,	0,				sizeof(uint32_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_EXTENDED_SECURITY, VATTR_BIT(va_acl),		sizeof(struct attrreference),	KAUTH_VNODE_READ_SECURITY},
	{ATTR_CMN_UUID,		VATTR_BIT(va_uuuid),		sizeof(guid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_GRPUUID,	VATTR_BIT(va_guuid),		sizeof(guid_t),			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FILEID,	VATTR_BIT(va_fileid), 		sizeof(uint64_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_PARENTID,	VATTR_BIT(va_parentid),		sizeof(uint64_t),		KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FULLPATH, 	0, 				sizeof(struct attrreference),	KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_ADDEDTIME, 	VATTR_BIT(va_addedtime), 	ATTR_TIME_SIZE,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_RETURNED_ATTRS, 0,				sizeof(attribute_set_t),	0},
	{ATTR_CMN_ERROR, 	0,				sizeof(uint32_t),		0},
	{ATTR_CMN_DATA_PROTECT_FLAGS, VATTR_BIT(va_dataprotect_class), sizeof(uint32_t),	KAUTH_VNODE_READ_ATTRIBUTES},
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
 * This table is for attributes which are only set from the getattrlistbulk(2)
 * call. These attributes have already been set from the common, file and
 * directory tables but the vattr bits have not been recorded. Since these
 * vattr bits are only used from the bulk call, we have a seperate table for
 * these.
 * The sizes are not returned from here since the sizes have already been
 * accounted from the common, file and directory tables.
 */
static struct getattrlist_attrtab getattrlistbulk_common_tab[] = {
	{ATTR_CMN_DEVID,	VATTR_BIT(va_devid),		0,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FSID,		VATTR_BIT(va_fsid64),		0,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_OBJTYPE,	VATTR_BIT(va_objtype),		0,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_OBJTAG,	VATTR_BIT(va_objtag),		0,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_USERACCESS,	VATTR_BIT(va_user_access),	0,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_CMN_FNDRINFO,	VATTR_BIT(va_finderinfo),	0,			KAUTH_VNODE_READ_ATTRIBUTES},
	{0, 0, 0, 0}
};

static struct getattrlist_attrtab getattrlistbulk_file_tab[] = {
	{ATTR_FILE_RSRCLENGTH,	VATTR_BIT(va_rsrc_length),	0,			KAUTH_VNODE_READ_ATTRIBUTES},
	{ATTR_FILE_RSRCALLOCSIZE, VATTR_BIT(va_rsrc_alloc),	0,			KAUTH_VNODE_READ_ATTRIBUTES},
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
				 ATTR_CMN_PARENTID | ATTR_CMN_RETURNED_ATTRS | \
				 ATTR_CMN_DOCUMENT_ID | ATTR_CMN_GEN_COUNT | \
				 ATTR_CMN_DATA_PROTECT_FLAGS)

#define VFS_DFLT_ATT_CMN_EXT	(ATTR_CMN_EXT_GEN_COUNT | ATTR_CMN_EXT_DOCUMENT_ID |\
				 ATTR_CMN_EXT_DATA_PROTECT_FLAGS)

#define VFS_DFLT_ATTR_DIR	(ATTR_DIR_LINKCOUNT | ATTR_DIR_MOUNTSTATUS)

#define VFS_DFLT_ATTR_FILE	(ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE |  \
				 ATTR_FILE_ALLOCSIZE  | ATTR_FILE_IOBLOCKSIZE |  \
				 ATTR_FILE_DEVTYPE | ATTR_FILE_DATALENGTH |  \
				 ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_RSRCLENGTH |  \
				 ATTR_FILE_RSRCALLOCSIZE)

static int
getattrlist_parsetab(struct getattrlist_attrtab *tab, attrgroup_t attrs,
    struct vnode_attr *vap, ssize_t *sizep, kauth_action_t *actionp,
    int is_64bit)
{
	attrgroup_t	recognised;

	recognised = 0;
	do {
		/* is this attribute set? */
		if (tab->attr & attrs) {
			recognised |= tab->attr;
			if (vap)
				vap->va_active |= tab->bits;
			if (sizep) {
				if (tab->size == ATTR_TIME_SIZE) {
					if (is_64bit) {
						*sizep += sizeof(
						    struct user64_timespec);
					} else {
						*sizep += sizeof(
						    struct user32_timespec);
					}
				} else {
					*sizep += tab->size;
				}
			}
			if (actionp)
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
 * Given the attributes listed in alp, configure vap to request
 * the data from a filesystem.
 */
static int
getattrlist_setupvattr_all(struct attrlist *alp, struct vnode_attr *vap,
    enum vtype obj_type, ssize_t *fixedsize, int is_64bit)
{
	int	error = 0;

	/*
	 * Parse the above tables.
	 */
	if (fixedsize) {
		*fixedsize = sizeof(uint32_t);
	}
	if (alp->commonattr) {
		error = getattrlist_parsetab(getattrlist_common_tab,
		    alp->commonattr, vap, fixedsize, NULL, is_64bit);

		if (!error) {
			/* Ignore any errrors from the bulk table */
			(void)getattrlist_parsetab(getattrlistbulk_common_tab,
			    alp->commonattr, vap, fixedsize, NULL, is_64bit);
			/*
			 * turn off va_fsid since we will be using only
			 * va_fsid64 for ATTR_CMN_FSID.
			 */
			VATTR_CLEAR_ACTIVE(vap, va_fsid);
		}
	}

	if (!error && (obj_type == VNON || obj_type == VDIR) && alp->dirattr) {
		error = getattrlist_parsetab(getattrlist_dir_tab, alp->dirattr,
	            vap, fixedsize, NULL, is_64bit);
	}

	if (!error && (obj_type != VDIR) && alp->fileattr) {
		error = getattrlist_parsetab(getattrlist_file_tab,
		    alp->fileattr, vap, fixedsize, NULL, is_64bit);

		if (!error) {
			/*Ignore any errors from the bulk table */
			(void)getattrlist_parsetab(getattrlistbulk_file_tab,
			    alp->fileattr, vap, fixedsize, NULL, is_64bit);
		}
	}

	return (error);
}

int
vfs_setup_vattr_from_attrlist(struct attrlist *alp, struct vnode_attr *vap,
    enum vtype obj_vtype, ssize_t *attrs_fixed_sizep, vfs_context_t ctx)
{
	return (getattrlist_setupvattr_all(alp, vap, obj_vtype,
	    attrs_fixed_sizep, IS_64BIT_PROCESS(vfs_context_proc(ctx))));
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
            /* 
			 * This if() statement is slightly confusing. We're trying to
			 * iterate through all of the bits listed in the array 
			 * getattr_common_tab, and see if the filesystem was expected
			 * to support it, and whether or not we need to do anything about this.
			 * 
			 * This array is full of structs that have 4 fields (attr, bits, size, action).
			 * The first is used to store the ATTR_CMN_* bit that was being requested 
			 * from userland.  The second stores the VATTR_BIT corresponding to the field
			 * filled in vnode_attr struct.  If it is 0, then we don't typically expect
			 * the filesystem to fill in this field.  The third is the size of the field,
			 * and the fourth is the type of kauth actions needed.
			 *
			 * So, for all of the ATTR_CMN bits listed in this array, we iterate through 
			 * them, and check to see if it was both passed down to the filesystem via the
			 * va_active bitfield, and whether or not we expect it to be emitted from
			 * the filesystem.  If it wasn't supported, then we un-twiddle the bit and move
			 * on.  This is done so that we can uncheck those bits and re-request
			 * a vnode_getattr from the filesystem again.
			 */
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
getvolattrlist(vfs_context_t ctx, vnode_t vp, struct attrlist *alp,
               user_addr_t attributeBuffer, size_t bufferSize, uint64_t options,
               enum uio_seg segflg, int is_64bit)
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
	pack_invalid = (options & FSOPT_PACK_INVAL_ATTRS);
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

		VFS_DEBUG(ctx, vp, "ATTRLIST -       calling to get %016llx with supported %016llx", vs.f_active, vs.f_supported);
		if ((error = vfs_getattr(mnt, &vs, ctx)) != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: filesystem returned %d", error);
			goto out;
		}
#if CONFIG_MACF
		error = mac_mount_check_getattr(ctx, mnt, &vs);
		if (error != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: MAC framework returned %d", error);
			goto out;
		}
#endif
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
#if CONFIG_MACF
		error = mac_vnode_check_getattr(ctx, NOCRED, vp, &va);
		if (error != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: MAC framework returned %d for root vnode", error);
			goto out;
		}
#endif
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
	ab.allocated = ulmin(bufferSize, fixedsize + varsize);
	if (ab.allocated > ATTR_MAX_BUFFER) {
		error = ENOMEM;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: buffer size too large (%d limit %d)", ab.allocated, ATTR_MAX_BUFFER);
		goto out;
	}
	MALLOC(ab.base, char *, ab.allocated, M_TEMP, M_ZERO | M_WAITOK);
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
#define HFS_GET_BOOT_INFO   (FCNTL_FS_SPECIFIC_BASE + 0x00004)
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
		ab.actual.volattr |= ATTR_VOL_UUID;
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
	*(uint32_t *)ab.base = (options & FSOPT_REPORT_FULLSIZE) ? ab.needed : imin(ab.allocated, ab.needed);
	
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

	if (UIO_SEG_IS_USER_SPACE(segflg))
		error = copyout(ab.base, CAST_USER_ADDR_T(attributeBuffer),
		                ab.allocated);
	else
		bcopy(ab.base, (void *)attributeBuffer, (size_t)ab.allocated);

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
 * Pack ATTR_COMMON attributes into a user buffer.
 * alp is a pointer to the bitmap of attributes required.
 * abp is the state of the attribute filling operation.
 * The attribute data (along with some other fields that are required
 * are in ad.
 */
static errno_t
attr_pack_common(vfs_context_t ctx, struct vnode *vp,  struct attrlist *alp,
    struct _attrlist_buf *abp, struct vnode_attr *vap, int proc_is64,
    const char *cnp, ssize_t cnl, const char *fullpathptr,
    ssize_t fullpathlen, int return_valid, int pack_invalid, int vtype,
    int is_bulk)
{
	uint32_t	perms = 0;
	int		error = 0;

	if ((alp->commonattr & ATTR_CMN_ERROR) &&
	    (!return_valid || pack_invalid)) {
		ATTR_PACK4((*abp), 0);
		abp->actual.commonattr |= ATTR_CMN_ERROR;
	}
	if (alp->commonattr & ATTR_CMN_NAME) {
		attrlist_pack_string(abp, cnp, cnl);
		abp->actual.commonattr |= ATTR_CMN_NAME;
	}
	if (alp->commonattr & ATTR_CMN_DEVID) {
		if (vp) {
			ATTR_PACK4((*abp),
			    vp->v_mount->mnt_vfsstat.f_fsid.val[0]);
			abp->actual.commonattr |= ATTR_CMN_DEVID;
		} else if (VATTR_IS_SUPPORTED(vap, va_devid)) {
			ATTR_PACK4((*abp), vap->va_devid);
			abp->actual.commonattr |= ATTR_CMN_DEVID;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}
	}
	if (alp->commonattr & ATTR_CMN_FSID) {
		if (vp) {
			ATTR_PACK8((*abp),
			    vp->v_mount->mnt_vfsstat.f_fsid);
			abp->actual.commonattr |= ATTR_CMN_FSID;
		} else if (VATTR_IS_SUPPORTED(vap, va_fsid64)) {
			ATTR_PACK8((*abp), vap->va_fsid64);
			abp->actual.commonattr |= ATTR_CMN_FSID;
		} else if (!return_valid || pack_invalid) {
			fsid_t fsid = {{0}};

			ATTR_PACK8((*abp), fsid);
		}
	}
	if (alp->commonattr & ATTR_CMN_OBJTYPE) {
		if (vp) {
			ATTR_PACK4((*abp), vtype);
			abp->actual.commonattr |= ATTR_CMN_OBJTYPE;
		} else if (VATTR_IS_SUPPORTED(vap, va_objtype)) {
			ATTR_PACK4((*abp), vap->va_objtype);
			abp->actual.commonattr |= ATTR_CMN_OBJTYPE;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}
	}
	if (alp->commonattr & ATTR_CMN_OBJTAG) {
		if (vp) {
			ATTR_PACK4((*abp), vp->v_tag);
			abp->actual.commonattr |= ATTR_CMN_OBJTAG;
		} else if (VATTR_IS_SUPPORTED(vap, va_objtag)) {
			ATTR_PACK4((*abp), vap->va_objtag);
			abp->actual.commonattr |= ATTR_CMN_OBJTAG;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}
	}
	if (alp->commonattr & ATTR_CMN_OBJID) {
		/*
		 * Carbon can't deal with us reporting the target ID
		 * for links.  So we ask the filesystem to give us the
		 * source ID as well, and if it gives us one, we use
		 * it instead.
		 */
		if (vap->va_vaflags & VA_64BITOBJIDS) {
			if (VATTR_IS_SUPPORTED(vap, va_linkid)) {
				ATTR_PACK8((*abp),  vap->va_linkid);
			} else {
				ATTR_PACK8((*abp),  vap->va_fileid);
			}
		} else {
			fsobj_id_t f;
			if (VATTR_IS_SUPPORTED(vap, va_linkid)) {
				f.fid_objno = (uint32_t)vap->va_linkid;
			} else {
				f.fid_objno = (uint32_t)vap->va_fileid;
			}
			f.fid_generation = 0;
			ATTR_PACK8((*abp), f);
		}
		abp->actual.commonattr |= ATTR_CMN_OBJID;
	}
	if (alp->commonattr & ATTR_CMN_OBJPERMANENTID) {
		/*
		 * Carbon can't deal with us reporting the target ID
		 * for links.  So we ask the filesystem to give us the
		 * source ID as well, and if it gives us one, we use
		 * it instead.
		 */
		if (vap->va_vaflags & VA_64BITOBJIDS) {
			if (VATTR_IS_SUPPORTED(vap, va_linkid)) {
				ATTR_PACK8((*abp),  vap->va_linkid);
			} else {
				ATTR_PACK8((*abp),  vap->va_fileid);
			}
		} else {
			fsobj_id_t f;
			if (VATTR_IS_SUPPORTED(vap, va_linkid)) {
				f.fid_objno = (uint32_t)vap->va_linkid;
			} else {
				f.fid_objno = (uint32_t)vap->va_fileid;
			}
			f.fid_generation = 0;
			ATTR_PACK8((*abp), f);
		}
		abp->actual.commonattr |= ATTR_CMN_OBJPERMANENTID;
	}
	if (alp->commonattr & ATTR_CMN_PAROBJID) {
		if (vap->va_vaflags & VA_64BITOBJIDS) {
			ATTR_PACK8((*abp), vap->va_parentid);
		} else {
			fsobj_id_t f;
			f.fid_objno = (uint32_t)vap->va_parentid;
			f.fid_generation = 0;
			ATTR_PACK8((*abp), f);
		}
		abp->actual.commonattr |= ATTR_CMN_PAROBJID;
	}
	if (alp->commonattr & ATTR_CMN_SCRIPT) {
 		if (VATTR_IS_SUPPORTED(vap, va_encoding)) {
			ATTR_PACK4((*abp), vap->va_encoding);
			abp->actual.commonattr |= ATTR_CMN_SCRIPT;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0x7e);
		}
	}
	if (alp->commonattr & ATTR_CMN_CRTIME) {
		ATTR_PACK_TIME((*abp), vap->va_create_time, proc_is64);
		abp->actual.commonattr |= ATTR_CMN_CRTIME;
	}
	if (alp->commonattr & ATTR_CMN_MODTIME) {
		ATTR_PACK_TIME((*abp), vap->va_modify_time, proc_is64);
		abp->actual.commonattr |= ATTR_CMN_MODTIME;
	}
	if (alp->commonattr & ATTR_CMN_CHGTIME) {
		ATTR_PACK_TIME((*abp), vap->va_change_time, proc_is64);
		abp->actual.commonattr |= ATTR_CMN_CHGTIME;
	}
	if (alp->commonattr & ATTR_CMN_ACCTIME) {
		ATTR_PACK_TIME((*abp), vap->va_access_time, proc_is64);
		abp->actual.commonattr |= ATTR_CMN_ACCTIME;
	}
	if (alp->commonattr & ATTR_CMN_BKUPTIME) {
		ATTR_PACK_TIME((*abp), vap->va_backup_time, proc_is64);
		abp->actual.commonattr |= ATTR_CMN_BKUPTIME;
	}
	/*
	 * They are requesting user access, we should obtain this before getting 
	 * the finder info. For some network file systems this is a performance
	 * improvement.
	 */
	if (alp->commonattr & ATTR_CMN_USERACCESS) {	/* this is expensive */
		if (vp && !is_bulk) {
			if (vtype == VDIR) {
				if (vnode_authorize(vp, NULL,
				    KAUTH_VNODE_ACCESS | KAUTH_VNODE_ADD_FILE |
				    KAUTH_VNODE_ADD_SUBDIRECTORY |
				    KAUTH_VNODE_DELETE_CHILD, ctx) == 0)
					perms |= W_OK;

				if (vnode_authorize(vp, NULL,
				    KAUTH_VNODE_ACCESS |
				    KAUTH_VNODE_LIST_DIRECTORY, ctx) == 0)
					perms |= R_OK;

				if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS |
				    KAUTH_VNODE_SEARCH, ctx) == 0)
					perms |= X_OK;
			} else {
				if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS |
				    KAUTH_VNODE_WRITE_DATA, ctx) == 0)
					perms |= W_OK;

				if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_READ_DATA, ctx) == 0)
					perms |= R_OK;
				if (vnode_authorize(vp, NULL, KAUTH_VNODE_ACCESS | KAUTH_VNODE_EXECUTE, ctx) == 0)
					perms |= X_OK;
			}
		} else if (is_bulk &&
		    VATTR_IS_SUPPORTED(vap, va_user_access)) {
			perms = vap->va_user_access;
		}
	}
	if (alp->commonattr & ATTR_CMN_FNDRINFO) {
		size_t	fisize = 32;

		error = 0; 
		if (vp && !is_bulk) {
			uio_t	auio;
			char	uio_buf[UIO_SIZEOF(1)];

			if ((auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE,
			    UIO_READ, uio_buf, sizeof(uio_buf))) == NULL) {
				error = ENOMEM;
				goto out;
			}
			uio_addiov(auio, CAST_USER_ADDR_T(abp->fixedcursor),
			    fisize);
			/* fisize may be reset to 0 after this call */
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
				bzero(abp->fixedcursor, 32);
				error = 0;
			}

			if (error == 0) {
				abp->fixedcursor += 32;
				abp->actual.commonattr |= ATTR_CMN_FNDRINFO;
			} else if (!return_valid) {
				goto out;
			} else {
				/*
				 * If we can inform the caller that we can't
				 * return this attribute, reset error and
				 * continue with the rest of the attributes.
				 */
				error = 0;
			}
		} else if (VATTR_IS_SUPPORTED(vap, va_finderinfo)) {
			bcopy(&vap->va_finderinfo[0], abp->fixedcursor, fisize);
			abp->fixedcursor += fisize;
			abp->actual.commonattr |= ATTR_CMN_FNDRINFO;
		} else if (!return_valid || pack_invalid) {
			bzero(abp->fixedcursor, fisize);
			abp->fixedcursor += fisize;
		}
	}
	if (alp->commonattr & ATTR_CMN_OWNERID) {
		ATTR_PACK4((*abp), vap->va_uid);
		abp->actual.commonattr |= ATTR_CMN_OWNERID;
	}
	if (alp->commonattr & ATTR_CMN_GRPID) {
		ATTR_PACK4((*abp), vap->va_gid);
		abp->actual.commonattr |= ATTR_CMN_GRPID;
	}
	if (alp->commonattr & ATTR_CMN_ACCESSMASK) {
		ATTR_PACK4((*abp), vap->va_mode);
		abp->actual.commonattr |= ATTR_CMN_ACCESSMASK;
	}
	if (alp->commonattr & ATTR_CMN_FLAGS) {
		ATTR_PACK4((*abp), vap->va_flags);
		abp->actual.commonattr |= ATTR_CMN_FLAGS;
	}
	if (alp->commonattr & ATTR_CMN_GEN_COUNT) {
		if (VATTR_IS_SUPPORTED(vap, va_write_gencount)) {
			ATTR_PACK4((*abp), vap->va_write_gencount);
			abp->actual.commonattr |= ATTR_CMN_GEN_COUNT;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}
	}

	if (alp->commonattr & ATTR_CMN_DOCUMENT_ID) {
		if (VATTR_IS_SUPPORTED(vap, va_document_id)) {
			ATTR_PACK4((*abp), vap->va_document_id);
			abp->actual.commonattr |= ATTR_CMN_DOCUMENT_ID;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}	
	}
	/* We already obtain the user access, so just fill in the buffer here */
	if (alp->commonattr & ATTR_CMN_USERACCESS) {
#if CONFIG_MACF
		if (!is_bulk && vp) {
			/*
			 * Rather than MAC preceding DAC, in this case we want
			 * the smallest set of permissions granted by both MAC &
			 * DAC checks.  We won't add back any permissions.
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
		}
#endif /* MAC */
		VFS_DEBUG(ctx, vp, "ATTRLIST - granting perms %d", perms);
		if (!is_bulk && vp) {
			ATTR_PACK4((*abp), perms);
			abp->actual.commonattr |= ATTR_CMN_USERACCESS;
		} else if (is_bulk && VATTR_IS_SUPPORTED(vap, va_user_access)) {
			ATTR_PACK4((*abp), perms);
			abp->actual.commonattr |= ATTR_CMN_USERACCESS;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}
	}
	if (alp->commonattr & ATTR_CMN_EXTENDED_SECURITY) {
		if (VATTR_IS_SUPPORTED(vap, va_acl) && (vap->va_acl != NULL)) {
			struct kauth_filesec fsec;
			/*
			 * We want to return a kauth_filesec (for now), but all we have is a kauth_acl.
			 */
			fsec.fsec_magic = KAUTH_FILESEC_MAGIC;
			fsec.fsec_owner = kauth_null_guid;
			fsec.fsec_group = kauth_null_guid;
			attrlist_pack_variable2(abp, &fsec, __offsetof(struct kauth_filesec, fsec_acl), vap->va_acl, KAUTH_ACL_COPYSIZE(vap->va_acl));
			abp->actual.commonattr |= ATTR_CMN_EXTENDED_SECURITY;
		} else if (!return_valid || pack_invalid) {
			attrlist_pack_variable(abp, NULL, 0);
		}
	}
	if (alp->commonattr & ATTR_CMN_UUID) {
 		if (VATTR_IS_SUPPORTED(vap, va_uuuid)) {
			ATTR_PACK(abp, vap->va_uuuid);
			abp->actual.commonattr |= ATTR_CMN_UUID;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK(abp, kauth_null_guid);
		}
	}
	if (alp->commonattr & ATTR_CMN_GRPUUID) {
		if (VATTR_IS_SUPPORTED(vap, va_guuid)) {
			ATTR_PACK(abp, vap->va_guuid);
			abp->actual.commonattr |= ATTR_CMN_GRPUUID;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK(abp, kauth_null_guid);
		}
	}
	if (alp->commonattr & ATTR_CMN_FILEID) {
		ATTR_PACK8((*abp), vap->va_fileid);
		abp->actual.commonattr |= ATTR_CMN_FILEID;
	}
	if (alp->commonattr & ATTR_CMN_PARENTID) {
		ATTR_PACK8((*abp), vap->va_parentid);
		abp->actual.commonattr |= ATTR_CMN_PARENTID;
	}
	
	if (alp->commonattr & ATTR_CMN_FULLPATH) {
		if (vp) {
			attrlist_pack_string (abp, fullpathptr, fullpathlen);
			abp->actual.commonattr |= ATTR_CMN_FULLPATH;
		}
	}
    
	if (alp->commonattr & ATTR_CMN_ADDEDTIME) {
		if (VATTR_IS_SUPPORTED(vap, va_addedtime)) {
			ATTR_PACK_TIME((*abp), vap->va_addedtime, proc_is64);
			abp->actual.commonattr |= ATTR_CMN_ADDEDTIME;
		} else if (!return_valid || pack_invalid) {
			struct timespec zerotime = {0, 0};

			ATTR_PACK_TIME((*abp), zerotime, proc_is64);
		}
	}
	if (alp->commonattr & ATTR_CMN_DATA_PROTECT_FLAGS) {
		if (VATTR_IS_SUPPORTED(vap, va_dataprotect_class)) {
			ATTR_PACK4((*abp), vap->va_dataprotect_class);
			abp->actual.commonattr |= ATTR_CMN_DATA_PROTECT_FLAGS;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}
	}
out:
	return (error);
}

static errno_t
attr_pack_dir(struct vnode *vp, struct attrlist *alp, struct _attrlist_buf *abp,
    struct vnode_attr *vap)
{
	if (alp->dirattr & ATTR_DIR_LINKCOUNT) {  /* full count of entries */
		ATTR_PACK4((*abp), (uint32_t)vap->va_dirlinkcount);
		abp->actual.dirattr |= ATTR_DIR_LINKCOUNT;
	}
	if (alp->dirattr & ATTR_DIR_ENTRYCOUNT) {
		ATTR_PACK4((*abp), (uint32_t)vap->va_nchildren);
		abp->actual.dirattr |= ATTR_DIR_ENTRYCOUNT;
	}
	if (alp->dirattr & ATTR_DIR_MOUNTSTATUS) {
		uint32_t mntstat;

		if (vp) {
			/*
			 * The vnode that is passed down may either be a
			 * top level vnode of a mount stack or a mounted
			 * on vnode. In either case, the directory should
			 * be reported as a mount point.
			 */
			if ((vp->v_flag & VROOT) ||  vnode_mountedhere(vp)) {
				mntstat = DIR_MNTSTATUS_MNTPOINT;
			} else {
				mntstat = 0;
			}
#if CONFIG_TRIGGERS
			/*
			 * Report back on active vnode triggers
			 * that can directly trigger a mount
			 */
			if (vp->v_resolve &&
			    !(vp->v_resolve->vr_flags & VNT_NO_DIRECT_MOUNT)) {
				mntstat |= DIR_MNTSTATUS_TRIGGER;
			}
#endif
		} else {
			mntstat = 0;
		}

		ATTR_PACK4((*abp), mntstat);
		abp->actual.dirattr |= ATTR_DIR_MOUNTSTATUS;
	}

	return 0;
}

/*
 * The is_bulk parameter differentiates whether the function is called from
 * getattrlist or getattrlistbulk. When coming in from getattrlistbulk,
 * the corresponding va_* values are expected to be the values filled and no
 * attempt is made to retrieve them by calling back into the filesystem.
 */
static errno_t
attr_pack_file(vfs_context_t ctx, struct vnode *vp,  struct attrlist *alp,
    struct _attrlist_buf *abp, struct vnode_attr *vap, int return_valid,
    int pack_invalid, int is_bulk)
{
	size_t	rsize = 0;
	uint64_t rlength = 0;
	uint64_t ralloc = 0;
	int error = 0;

	/*
	 * Pre-fetch the rsrc attributes now so we only get them once.
	 * Fetch the resource fork size/allocation via xattr interface
	 */
	if (vp && !is_bulk &&
	    (alp->fileattr & (ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE |
	    ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE))) {

		error = vn_getxattr(vp, XATTR_RESOURCEFORK_NAME, NULL,
		    &rsize, XATTR_NOSECURITY, ctx);
		if (error) {
			if ((error == ENOENT) || (error == ENOATTR) ||
			    (error == ENOTSUP) || (error == EPERM) ||
			    (error == EACCES)) {
				rsize = 0;
				error = 0;
			} else {
				goto out;
			}
		}
		rlength = rsize;

		if (alp->fileattr & (ATTR_FILE_RSRCALLOCSIZE |
		    ATTR_FILE_ALLOCSIZE)) {
			uint32_t  blksize;

			blksize = vp->v_mount->mnt_vfsstat.f_bsize;

			if (blksize == 0) {
				blksize = 512;
			}
			ralloc = roundup(rsize, blksize);
		}
	}

	if (alp->fileattr & ATTR_FILE_LINKCOUNT) {
		ATTR_PACK4((*abp), (uint32_t)vap->va_nlink);
		abp->actual.fileattr |= ATTR_FILE_LINKCOUNT;
	}
	/*
	 * Note the following caveats for the TOTALSIZE and ALLOCSIZE attributes:
	 * We infer that if the filesystem does not support va_data_size or va_data_alloc
	 * it must not know about alternate forks.  So when we need to gather
	 * the total size or total alloc, it's OK to substitute the total size for
	 * the data size below.  This is because it is likely a flat filesystem and we must
	 * be using AD files to store the rsrc fork and EAs.
	 *
	 * Additionally, note that getattrlist is barred from being called on
	 * resource fork paths. (Search for CN_ALLOWRSRCFORK).  So if the filesystem does
	 * support va_data_size, it is guaranteed to represent the data fork's size.  This
	 * is an important distinction to make because when we call vnode_getattr on
	 * an HFS resource fork vnode, to get the size, it will vend out the resource
	 * fork's size (it only gets the size of the passed-in vnode).
	 */
	if (alp->fileattr & ATTR_FILE_TOTALSIZE) {
		if (!is_bulk) {
			uint64_t totalsize = rlength;

			if (VATTR_IS_SUPPORTED(vap, va_data_size)) {
				totalsize += vap->va_data_size;
			} else {
				totalsize += vap->va_total_size;
			}

			ATTR_PACK8((*abp), totalsize);
			abp->actual.fileattr |= ATTR_FILE_TOTALSIZE;
		} else if (VATTR_IS_SUPPORTED(vap, va_total_size)) {
			ATTR_PACK8((*abp), vap->va_total_size);
			abp->actual.fileattr |= ATTR_FILE_TOTALSIZE;
		} else if (!return_valid || pack_invalid) {
			uint64_t zero_val = 0;

			ATTR_PACK8((*abp), zero_val);
		}
	}
	if (alp->fileattr & ATTR_FILE_ALLOCSIZE) {
		if (!is_bulk) {
			uint64_t totalalloc = ralloc;

			/*
			 * If data_alloc is supported, then it must represent the
			 * data fork size.
			 */
			if (VATTR_IS_SUPPORTED(vap, va_data_alloc)) {
				totalalloc += vap->va_data_alloc;
			} else {
				totalalloc += vap->va_total_alloc;
			}

			ATTR_PACK8((*abp), totalalloc);
			abp->actual.fileattr |= ATTR_FILE_ALLOCSIZE;
		} else if (VATTR_IS_SUPPORTED(vap, va_total_alloc)) {
			ATTR_PACK8((*abp), vap->va_total_alloc);
			abp->actual.fileattr |= ATTR_FILE_ALLOCSIZE;
		} else if (!return_valid || pack_invalid) {
			uint64_t zero_val = 0;

			ATTR_PACK8((*abp), zero_val);
		}
	}
	if (alp->fileattr & ATTR_FILE_IOBLOCKSIZE) {
		ATTR_PACK4((*abp), vap->va_iosize);
		abp->actual.fileattr |= ATTR_FILE_IOBLOCKSIZE;
	}
	if (alp->fileattr & ATTR_FILE_CLUMPSIZE) {
		if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);     /* this value is deprecated */
			abp->actual.fileattr |= ATTR_FILE_CLUMPSIZE;
		}
	}
	if (alp->fileattr & ATTR_FILE_DEVTYPE) {
		if (vp && (vp->v_type == VCHR || vp->v_type == VBLK)) {
			uint32_t dev;

			if (vp->v_specinfo != NULL) {
				dev = vp->v_specinfo->si_rdev;
			} else if (VATTR_IS_SUPPORTED(vap, va_rdev)) {
				dev = vap->va_rdev;
			} else {
				dev = 0;
			}
			ATTR_PACK4((*abp), dev);
			abp->actual.fileattr |= ATTR_FILE_DEVTYPE;
		} else if (vp) {
			ATTR_PACK4((*abp), 0);
			abp->actual.fileattr |= ATTR_FILE_DEVTYPE;
		} else if (VATTR_IS_SUPPORTED(vap, va_rdev)) {
			ATTR_PACK4((*abp), vap->va_rdev);
			abp->actual.fileattr |= ATTR_FILE_DEVTYPE;
		} else if (!return_valid || pack_invalid) {
			ATTR_PACK4((*abp), 0);
		}
	}
	/*
	 * If the filesystem does not support datalength
	 * or dataallocsize, then we infer that totalsize and
	 * totalalloc are substitutes.
	 */
	if (alp->fileattr & ATTR_FILE_DATALENGTH) {
		if (VATTR_IS_SUPPORTED(vap, va_data_size)) {
			ATTR_PACK8((*abp), vap->va_data_size);
		} else {
			ATTR_PACK8((*abp), vap->va_total_size);
		}
		abp->actual.fileattr |= ATTR_FILE_DATALENGTH;
	}
	if (alp->fileattr & ATTR_FILE_DATAALLOCSIZE) {
		if (VATTR_IS_SUPPORTED(vap, va_data_alloc)) {
			ATTR_PACK8((*abp), vap->va_data_alloc);
		} else {
			ATTR_PACK8((*abp), vap->va_total_alloc);
		}
		abp->actual.fileattr |= ATTR_FILE_DATAALLOCSIZE;
	}
	/* already got the resource fork size/allocation above */
	if (alp->fileattr & ATTR_FILE_RSRCLENGTH) {
		if (!is_bulk) {
			ATTR_PACK8((*abp), rlength);
			abp->actual.fileattr |= ATTR_FILE_RSRCLENGTH;
		} else if (VATTR_IS_SUPPORTED(vap, va_rsrc_length)) {
			ATTR_PACK8((*abp), vap->va_rsrc_length);
			abp->actual.fileattr |= ATTR_FILE_RSRCLENGTH;
		} else if (!return_valid || pack_invalid) {
			uint64_t zero_val = 0;

			ATTR_PACK8((*abp), zero_val);
		}
	}
	if (alp->fileattr & ATTR_FILE_RSRCALLOCSIZE) {
		if (!is_bulk) {
			ATTR_PACK8((*abp), ralloc);
			abp->actual.fileattr |= ATTR_FILE_RSRCALLOCSIZE;
		} else if (VATTR_IS_SUPPORTED(vap, va_rsrc_alloc)) {
			ATTR_PACK8((*abp), vap->va_rsrc_alloc);
			abp->actual.fileattr |= ATTR_FILE_RSRCALLOCSIZE;
		} else if (!return_valid || pack_invalid) {
			uint64_t zero_val = 0;

			ATTR_PACK8((*abp), zero_val);
		}
	}
out:
	return (error);
}

static void
vattr_get_alt_data(vnode_t vp, struct attrlist *alp, struct vnode_attr *vap,
    int return_valid, int is_bulk, vfs_context_t ctx)
{
	/*
	 * There are a couple of special cases.
	 * If we are after object IDs, we can make do with va_fileid.
	 */
	if ((alp->commonattr &
	    (ATTR_CMN_OBJID | ATTR_CMN_OBJPERMANENTID | ATTR_CMN_FILEID)) &&
	    !VATTR_IS_SUPPORTED(vap, va_linkid)) {
		/* forget we wanted this */
		VATTR_CLEAR_ACTIVE(vap, va_linkid);
	}
	
	/*
	 * Many filesystems don't know their parent object id.
	 * If necessary, attempt to derive it from the vnode.
	 */
	if ((alp->commonattr & (ATTR_CMN_PAROBJID | ATTR_CMN_PARENTID)) &&
	    !VATTR_IS_SUPPORTED(vap, va_parentid) && vp && !is_bulk) {
		vnode_t	dvp;

		if ((dvp = vnode_getparent(vp)) != NULLVP) {
			struct vnode_attr lva;

			VATTR_INIT(&lva);
			VATTR_WANTED(&lva, va_fileid);
			if (vnode_getattr(dvp, &lva, ctx) == 0 &&
			    VATTR_IS_SUPPORTED(vap, va_fileid)) {
				vap->va_parentid = lva.va_fileid;
				VATTR_SET_SUPPORTED(vap, va_parentid);
			}
			vnode_put(dvp);
		}
	}
	/*
	 * And we can report datasize/alloc from total.
	 */
	if ((alp->fileattr & ATTR_FILE_DATALENGTH) &&
	    !VATTR_IS_SUPPORTED(vap, va_data_size)) {
		VATTR_CLEAR_ACTIVE(vap, va_data_size);
	}

	if ((alp->fileattr & ATTR_FILE_DATAALLOCSIZE) &&
	    !VATTR_IS_SUPPORTED(vap, va_data_alloc)) {
		VATTR_CLEAR_ACTIVE(vap, va_data_alloc);
	}

	/*
	 * If we don't have an encoding, go with UTF-8
	 */
	if ((alp->commonattr & ATTR_CMN_SCRIPT) &&
	    !VATTR_IS_SUPPORTED(vap, va_encoding) && !return_valid) {
		VATTR_RETURN(vap, va_encoding,
		    0x7e /* kTextEncodingMacUnicode */);
	}

	/*
	 * If we don't have a name, we'll get one from the vnode or
	 * mount point.
	 */
	if ((alp->commonattr & ATTR_CMN_NAME) &&
	    !VATTR_IS_SUPPORTED(vap, va_name)) {
		VATTR_CLEAR_ACTIVE(vap, va_name);
	}

	/* If va_dirlinkcount isn't supported use a default of 1. */
	if ((alp->dirattr & ATTR_DIR_LINKCOUNT) &&
	    !VATTR_IS_SUPPORTED(vap, va_dirlinkcount)) {
		VATTR_RETURN(vap, va_dirlinkcount, 1);
	}
}

static errno_t
calc_varsize(vnode_t vp, struct attrlist *alp, struct vnode_attr *vap,
   ssize_t *varsizep, char *fullpathptr, ssize_t *fullpathlenp,
   const char **vnamep, const char **cnpp, ssize_t *cnlp)  
{
	int error = 0;

	*varsizep = 0; /* length count */
	/* We may need to fix up the name attribute if requested */
	if (alp->commonattr & ATTR_CMN_NAME) {
		if (VATTR_IS_SUPPORTED(vap, va_name)) {
			vap->va_name[MAXPATHLEN-1] = '\0';	/* Ensure nul-termination */
			*cnpp = vap->va_name;
			*cnlp = strlen(*cnpp);
		} else if (vp) {
			/* Filesystem did not support getting the name */
			if (vnode_isvroot(vp)) {
				if (vp->v_mount->mnt_vfsstat.f_mntonname[1] == 0x00 &&
						vp->v_mount->mnt_vfsstat.f_mntonname[0] == '/') {
					/* special case for boot volume.  Use root name when it's
					 * available (which is the volume name) or just the mount on
					 * name of "/".  we must do this for binary compatibility with
					 * pre Tiger code.  returning nothing for the boot volume name
					 * breaks installers - 3961058
					 */
					*cnpp = *vnamep = vnode_getname(vp);
					if (*cnpp == NULL) {
						/* just use "/" as name */
						*cnpp = &vp->v_mount->mnt_vfsstat.f_mntonname[0];
					}
					*cnlp = strlen(*cnpp);
				}
				else {
					getattrlist_findnamecomp(vp->v_mount->mnt_vfsstat.f_mntonname, cnpp, cnlp);
				}
			} 
			else {
				*cnpp = *vnamep = vnode_getname(vp);
				*cnlp = 0;
				if (*cnpp != NULL) {
					*cnlp = strlen(*cnpp);
				}
			}
		} else {
			*cnlp = 0;
		}
		*varsizep += roundup(*cnlp + 1, 4);
	}

	/* 
	 * Compute the full path to this vnode, if necessary. This attribute is almost certainly
	 * not supported by any filesystem, so build the path to this vnode at this time.
	 */
	if (vp && (alp->commonattr & ATTR_CMN_FULLPATH)) {
		int len = MAXPATHLEN;
		int err;

		/* call build_path making sure NOT to use the cache-only behavior */
		err = build_path(vp, fullpathptr, len, &len, 0, vfs_context_current());
		if (err) {
			error = err;
			goto out;
		}
		*fullpathlenp = 0;
		if (fullpathptr){
			*fullpathlenp = strlen(fullpathptr);
		}
		*varsizep += roundup(((*fullpathlenp) + 1), 4);
	}

	/*
	 * We have a kauth_acl_t but we will be returning a kauth_filesec_t.
	 *
	 * XXX This needs to change at some point; since the blob is opaque in
	 * user-space this is OK.
	 */
	if ((alp->commonattr & ATTR_CMN_EXTENDED_SECURITY) &&
			VATTR_IS_SUPPORTED(vap, va_acl) &&
			(vap->va_acl != NULL)) {

		/* 
		 * Since we have a kauth_acl_t (not a kauth_filesec_t), we have to check against
		 * KAUTH_FILESEC_NOACL ourselves
		 */ 
		if (vap->va_acl->acl_entrycount == KAUTH_FILESEC_NOACL) {
			*varsizep += roundup((KAUTH_FILESEC_SIZE(0)), 4);
		}
		else {
			*varsizep += roundup ((KAUTH_FILESEC_SIZE(vap->va_acl->acl_entrycount)), 4);
		}
	}

out:
	return (error);
}

static errno_t
vfs_attr_pack_internal(vnode_t vp, uio_t auio, struct attrlist *alp,
    uint64_t options, struct vnode_attr *vap, __unused void *fndesc,
    vfs_context_t ctx, int is_bulk, enum vtype vtype, ssize_t fixedsize)
{
	struct _attrlist_buf ab;
	ssize_t buf_size;
	size_t copy_size;
	ssize_t	varsize;
	const char *vname = NULL;
	const char *cnp;
	ssize_t cnl;
	char *fullpathptr;
	ssize_t	fullpathlen;
	int error;
	int proc_is64;
	int return_valid;
	int pack_invalid;
	int alloc_local_buf;

	proc_is64 = proc_is64bit(vfs_context_proc(ctx));
	ab.base = NULL;
	cnp = "unknown";
	cnl = 0;
	fullpathptr = NULL;
	fullpathlen = 0;
	error = 0;
	alloc_local_buf = 0;

	buf_size = (ssize_t)uio_resid(auio);
	if ((buf_size <= 0) || (uio_iovcnt(auio) > 1))
		return (EINVAL);

	copy_size = 0;
	/* Check for special packing semantics */
	return_valid = (alp->commonattr & ATTR_CMN_RETURNED_ATTRS) ? 1 : 0;
	pack_invalid = (options & FSOPT_PACK_INVAL_ATTRS) ? 1 : 0;

	if (pack_invalid) {
		/* Generate a valid mask for post processing */
		bcopy(&(alp->commonattr), &ab.valid, sizeof (attribute_set_t));
	}

	/* did we ask for something the filesystem doesn't support? */
	if (vap->va_active && !VATTR_ALL_SUPPORTED(vap)) {
		vattr_get_alt_data(vp, alp, vap, return_valid, is_bulk,
		    ctx);

		/* check again */
		if (!VATTR_ALL_SUPPORTED(vap)) {
			if (return_valid && pack_invalid) {
				/* Fix up valid mask for post processing */
				getattrlist_fixupattrs(&ab.valid, vap);
					
				/* Force packing of everything asked for */
				vap->va_supported = vap->va_active;
			} else if (return_valid) {
				/* Adjust the requested attributes */
				getattrlist_fixupattrs(
				    (attribute_set_t *)&(alp->commonattr), vap);
			} else {
				error = EINVAL;
			}
		}

		if (error)
			goto out;
	}

	if (vp && (alp->commonattr & (ATTR_CMN_FULLPATH))) {
		fullpathptr = (char*) kalloc(MAXPATHLEN);
		if (fullpathptr == NULL) {
			error = ENOMEM;
			VFS_DEBUG(ctx,vp, "ATTRLIST - ERROR: cannot allocate fullpath buffer");
			goto out;
		}
		bzero(fullpathptr, MAXPATHLEN);
	}

	/*
	 * Compute variable-space requirements.
	 */
	error = calc_varsize(vp, alp, vap, &varsize, fullpathptr, &fullpathlen,
	    &vname, &cnp, &cnl);
	if (error)
		goto out;

	/*
	 * Allocate a target buffer for attribute results.
	 *
	 * Note that we won't ever copy out more than the caller requested, even though
	 * we might have to allocate more than they offer so that the diagnostic checks
	 * don't result in a panic if the caller's buffer is too small..
	 */
	ab.allocated = fixedsize + varsize;
	/* Cast 'allocated' to an unsigned to verify allocation size */
	if ( ((size_t)ab.allocated) > ATTR_MAX_BUFFER) {
		error = ENOMEM;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: buffer size too large (%d limit %d)", ab.allocated, ATTR_MAX_BUFFER);
		goto out;
	}

	/*
	 * Special handling for bulk calls, align to 8 (and only if enough
	 * space left.
	 */
	if (is_bulk) {
		if (buf_size < ab.allocated) {
			goto out;
		} else {
			uint32_t newlen;

			newlen = (ab.allocated + 7) & ~0x07;
			/* Align only if enough space for alignment */
			if (newlen <= (uint32_t)buf_size)
				ab.allocated = newlen;
		}
	}

	/*
	 * See if we can reuse buffer passed in i.e. it is a kernel buffer
	 * and big enough.
	 */
	if (uio_isuserspace(auio) || (buf_size < ab.allocated)) {
		MALLOC(ab.base, char *, ab.allocated, M_TEMP,
		       M_ZERO | M_WAITOK);
		alloc_local_buf = 1;
	} else {
		/*
		 * In case this is a kernel buffer and sufficiently
		 * big, this function will try to use that buffer
		 * instead of allocating another buffer and bcopy'ing
		 * into it.
		 *
		 * The calculation below figures out where to start
		 * writing in the buffer and once all the data has been
		 * filled in, uio_resid is updated to reflect the usage
		 * of the buffer.
		 *
		 * uio_offset cannot be used here to determine the
		 * starting location as uio_offset could be set to a
		 * value which has nothing to do the location
		 * in the buffer.
		 */
		ab.base = (char *)uio_curriovbase(auio) +
		    ((ssize_t)uio_curriovlen(auio) - buf_size);
		bzero(ab.base, ab.allocated);
	}

	if (ab.base == NULL) {
		error = ENOMEM;
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: could not allocate %d for copy buffer", ab.allocated);
		goto out;
	}


	/* set the S_IFMT bits for the mode */
	if (alp->commonattr & ATTR_CMN_ACCESSMASK) {
		if (vp) {
			switch (vp->v_type) {
			case VREG:
				vap->va_mode |= S_IFREG;
				break;
			case VDIR:
				vap->va_mode |= S_IFDIR;
				break;
			case VBLK:
				vap->va_mode |= S_IFBLK;
				break;
			case VCHR:
				vap->va_mode |= S_IFCHR;
				break;
			case VLNK:
				vap->va_mode |= S_IFLNK;
				break;
			case VSOCK:
				vap->va_mode |= S_IFSOCK;
				break;
			case VFIFO:
				vap->va_mode |= S_IFIFO;
				break;
			default:
				error = EBADF;
				goto out;
			}
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

	/* common attributes ************************************************/
	error = attr_pack_common(ctx, vp, alp, &ab, vap, proc_is64, cnp, cnl,
	    fullpathptr, fullpathlen, return_valid, pack_invalid, vtype, is_bulk); 

	/* directory attributes *********************************************/
	if (!error && alp->dirattr && (vtype == VDIR)) {
		error = attr_pack_dir(vp, alp, &ab, vap);
	}

	/* file attributes **************************************************/
	if (!error && alp->fileattr && (vtype != VDIR)) {
		error = attr_pack_file(ctx, vp, alp, &ab, vap, return_valid,
		    pack_invalid, is_bulk);
	}

	if (error)
		goto out;
	
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
	*(uint32_t *)ab.base = (options & FSOPT_REPORT_FULLSIZE) ? ab.needed : imin(ab.allocated, ab.needed);

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

	copy_size = imin(buf_size, ab.allocated);

	/* Only actually copyout as much out as the user buffer can hold */
	if (alloc_local_buf) {
		error = uiomove(ab.base, copy_size, auio);
	} else {
		off_t orig_offset = uio_offset(auio);

		/*
		 * The buffer in the uio struct was used directly
		 * (i.e. it was a kernel buffer and big enough
		 * to hold the data required) in order to avoid
		 * un-needed allocation and copies.
		 *
		 * At this point, update the resid value to what it
		 * would be if this was the result of a uiomove. The
		 * offset is also incremented, though it may not
		 * mean anything to the caller but that is what
		 * uiomove does as well.
		 */
		uio_setresid(auio, buf_size - copy_size);
		uio_setoffset(auio, orig_offset + (off_t)copy_size);
	}

out:
	if (vname)
		vnode_putname(vname);
	if (fullpathptr)
		kfree(fullpathptr, MAXPATHLEN);
	if (ab.base != NULL && alloc_local_buf)
		FREE(ab.base, M_TEMP);
	return (error);
}

errno_t
vfs_attr_pack(vnode_t vp, uio_t uio, struct attrlist *alp, uint64_t options,
    struct vnode_attr *vap, __unused void *fndesc, vfs_context_t ctx)
{
	int error;
	ssize_t fixedsize;
	uint64_t orig_active;
	struct attrlist orig_al;
	enum vtype v_type;

	if (vp)
		v_type = vnode_vtype(vp);
	else
		v_type = vap->va_objtype;

	orig_al = *alp;
	orig_active = vap->va_active;
	vap->va_active = 0;

	error = getattrlist_setupvattr_all(alp, vap, v_type, &fixedsize,
	    proc_is64bit(vfs_context_proc(ctx)));

	if (error) {
		VFS_DEBUG(ctx, vp,
		    "ATTRLIST - ERROR: setup for request failed");
		goto out;
	}

	error = vfs_attr_pack_internal(vp, uio, alp, 
	    options|FSOPT_REPORT_FULLSIZE, vap, NULL, ctx, 1, v_type,
	    fixedsize);

	VATTR_CLEAR_SUPPORTED_ALL(vap);
	vap->va_active = orig_active;
	*alp = orig_al;
out:
	return (error);
}

/*
 * Obtain attribute information about a filesystem object.
 *
 * Note: The alt_name parameter can be used by the caller to pass in the vnode
 * name obtained from some authoritative source (eg. readdir vnop); where
 * filesystems' getattr vnops do not support ATTR_CMN_NAME, the alt_name will be
 * used as the ATTR_CMN_NAME attribute returned in vnode_attr.va_name.
 * 
 */
static int
getattrlist_internal(vfs_context_t ctx, vnode_t vp, struct attrlist  *alp,
    user_addr_t attributeBuffer, size_t bufferSize, uint64_t options,
    enum uio_seg segflg, char* alt_name, struct ucred *file_cred)
{
	struct vnode_attr va;
	kauth_action_t	action;
	ssize_t		fixedsize;
	char		*va_name;
	int		proc_is64;
	int		error;
	int		return_valid;
	int		pack_invalid;
	int		vtype = 0;
	uio_t		auio;
	char uio_buf[ UIO_SIZEOF(1)];

	proc_is64 = proc_is64bit(vfs_context_proc(ctx));

	if (segflg == UIO_USERSPACE) {
		if (proc_is64)
			segflg = UIO_USERSPACE64;
		else
			segflg = UIO_USERSPACE32;
	}
	auio = uio_createwithbuffer(1, 0, segflg, UIO_READ,
		    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, attributeBuffer, bufferSize);

	VATTR_INIT(&va);
	va_name = NULL;

	if (alp->bitmapcount != ATTR_BIT_MAP_COUNT) {
		error = EINVAL;
		goto out;
	}

	VFS_DEBUG(ctx, vp, "%p  ATTRLIST - %s request common %08x vol %08x file %08x dir %08x fork %08x %sfollow on '%s'",
	    vp, p->p_comm, alp->commonattr, alp->volattr, alp->fileattr, alp->dirattr, alp->forkattr,
	    (options & FSOPT_NOFOLLOW) ? "no":"", vp->v_name);

#if CONFIG_MACF
	error = mac_vnode_check_getattrlist(ctx, vp, alp);
	if (error)
		goto out;
#endif /* MAC */

	/*
	 * It is legal to request volume or file attributes,
	 * but not both.
	 */
	if (alp->volattr) {
		if (alp->fileattr || alp->dirattr || alp->forkattr) {
			error = EINVAL;
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: mixed volume/file/directory/fork attributes");
			goto out;
		}
		/* handle volume attribute request */
		error = getvolattrlist(ctx, vp, alp, attributeBuffer,
		                       bufferSize, options, segflg, proc_is64);
		goto out;
	}

	/*
	 * ATTR_CMN_GEN_COUNT and ATTR_CMN_DOCUMENT_ID reuse the bits
	 * originally allocated to ATTR_CMN_NAMEDATTRCOUNT and
	 * ATTR_CMN_NAMEDATTRLIST.
	 */
	if ((alp->commonattr & (ATTR_CMN_GEN_COUNT | ATTR_CMN_DOCUMENT_ID)) &&
	    !(options & FSOPT_ATTR_CMN_EXTENDED)) {
		error = EINVAL;
		goto out;
	}

	/* Check for special packing semantics */
	return_valid = (alp->commonattr & ATTR_CMN_RETURNED_ATTRS) ? 1 : 0;
	pack_invalid = (options & FSOPT_PACK_INVAL_ATTRS) ? 1 : 0;
	if (pack_invalid) {
		/* FSOPT_PACK_INVAL_ATTRS requires ATTR_CMN_RETURNED_ATTRS */
		if (!return_valid || alp->forkattr) {
			error = EINVAL;
			goto out;
		}
		/* Keep invalid attrs from being uninitialized */
		bzero(&va, sizeof (va));
	}

	/* Pick up the vnode type.  If the FS is bad and changes vnode types on us, we
	 * will have a valid snapshot that we can work from here.
	 */
	vtype = vp->v_type;

	/*
	 * Set up the vnode_attr structure and authorise.
	 */
	if ((error = getattrlist_setupvattr(alp, &va, &fixedsize, &action, proc_is64, (vtype == VDIR))) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: setup for request failed");
		goto out;
	}
	if ((error = vnode_authorize(vp, NULL, action, ctx)) != 0) {
		VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: authorisation failed/denied");
		goto out;
	}


	if (va.va_active != 0) {
		uint64_t va_active = va.va_active;

		/*
		 * If we're going to ask for va_name, allocate a buffer to point it at
		 */
		if (VATTR_IS_ACTIVE(&va, va_name)) {
			MALLOC_ZONE(va_name, char *, MAXPATHLEN, M_NAMEI,
			    M_WAITOK);
			if (va_name == NULL) {
				error = ENOMEM;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: cannot allocate va_name buffer");
				goto out;
			}
		}

		va.va_name = va_name;

		/*
		 * Call the filesystem.
		 */
		if ((error = vnode_getattr(vp, &va, ctx)) != 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: filesystem returned %d", error);
			goto out;
		}
#if CONFIG_MACF
		/*
		 * Give MAC polices a chance to reject or filter the
		 * attributes returned by the filesystem.  Note that MAC
		 * policies are consulted *after* calling the filesystem
		 * because filesystems can return more attributes than
		 * were requested so policies wouldn't be authoritative
		 * is consulted beforehand.  This also gives policies an
		 * opportunity to change the values of attributes
		 * retrieved.
		 */
		error = mac_vnode_check_getattr(ctx, file_cred, vp, &va);
		if (error) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: MAC framework returned %d", error);
			goto out;
		}
#else
		(void)file_cred;
#endif

		/* 
		 * If ATTR_CMN_NAME is not supported by filesystem and the
		 * caller has provided a name, use that.
		 * A (buggy) filesystem may change fields which belong
		 * to us. We try to deal with that here as well.
		 */
		va.va_active = va_active;
		if (alt_name  && va_name &&
		    !(VATTR_IS_SUPPORTED(&va, va_name))) {
			strlcpy(va_name, alt_name, MAXPATHLEN);
			VATTR_SET_SUPPORTED(&va, va_name);
		}
		va.va_name = va_name;
	}
	
	error = vfs_attr_pack_internal(vp, auio, alp, options, &va, NULL, ctx,
	    0, vtype, fixedsize);

out:
	if (va_name)
		FREE_ZONE(va_name, MAXPATHLEN, M_NAMEI);
	if (VATTR_IS_SUPPORTED(&va, va_acl) && (va.va_acl != NULL))
		kauth_acl_free(va.va_acl);

	VFS_DEBUG(ctx, vp, "ATTRLIST - returning %d", error);
	return(error);
}

int
fgetattrlist(proc_t p, struct fgetattrlist_args *uap, __unused int32_t *retval)
{
	vfs_context_t ctx;
	vnode_t vp;
	int error;
	struct attrlist al;
	struct fileproc *fp;

	ctx = vfs_context_current();
	vp = NULL;
	fp = NULL;
	error = 0;

	if ((error = file_vnode(uap->fd, &vp)) != 0)
		return (error);

	if ((error = fp_lookup(p, uap->fd, &fp, 0)) != 0 ||
	    (error = vnode_getwithref(vp)) != 0)
		goto out;

	/*
	 * Fetch the attribute request.
	 */
	error = copyin(uap->alist, &al, sizeof(al));
	if (error)
		goto out;

	/* Default to using the vnode's name. */
	error = getattrlist_internal(ctx, vp, &al, uap->attributeBuffer,
	                             uap->bufferSize, uap->options,
				     (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : \
				     UIO_USERSPACE32), NULL,
				     fp->f_fglob->fg_cred);

out:
	if (fp)
		fp_drop(p, uap->fd, fp, 0);
	if (vp)
		vnode_put(vp);
	file_drop(uap->fd);

	return error;
}

static int
getattrlistat_internal(vfs_context_t ctx, user_addr_t path,
    struct attrlist *alp, user_addr_t attributeBuffer, size_t bufferSize,
    uint64_t options, enum uio_seg segflg, enum uio_seg pathsegflg, int fd)
{
	struct nameidata nd;
	vnode_t vp;
	int32_t nameiflags;
	int error;

	nameiflags = 0;
	/*
	 * Look up the file.
	 */
	if (!(options & FSOPT_NOFOLLOW))
		nameiflags |= FOLLOW;

	nameiflags |= AUDITVNPATH1;
	NDINIT(&nd, LOOKUP, OP_GETATTR, nameiflags, pathsegflg,
	    path, ctx);

	error = nameiat(&nd, fd);

	if (error)
		return (error);

	vp = nd.ni_vp;

	error = getattrlist_internal(ctx, vp, alp, attributeBuffer,
	    bufferSize, options, segflg, NULL, NOCRED);
	
	/* Retain the namei reference until the getattrlist completes. */
	nameidone(&nd);
	vnode_put(vp);
	return (error);
}

int
getattrlist(proc_t p, struct getattrlist_args *uap, __unused int32_t *retval)
{
	enum uio_seg segflg;
	struct attrlist al;
	int error;

	segflg = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;

	/*
	 * Fetch the attribute request.
	 */
	error = copyin(uap->alist, &al, sizeof(al));
	if (error)
		return error;

	return (getattrlistat_internal(vfs_context_current(),
	    CAST_USER_ADDR_T(uap->path), &al,
	    CAST_USER_ADDR_T(uap->attributeBuffer), uap->bufferSize,
	    (uint64_t)uap->options, segflg, segflg, AT_FDCWD));
}

int
getattrlistat(proc_t p, struct getattrlistat_args *uap, __unused int32_t *retval)
{
	enum uio_seg segflg;
	struct attrlist al;
	int error;

	segflg = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;

	/*
	 * Fetch the attribute request.
	 */
	error = copyin(uap->alist, &al, sizeof(al));
	if (error)
		return error;

	return (getattrlistat_internal(vfs_context_current(),
	    CAST_USER_ADDR_T(uap->path), &al,
	    CAST_USER_ADDR_T(uap->attributeBuffer), uap->bufferSize,
	    (uint64_t)uap->options, segflg, segflg, uap->fd));
}

/*
 * This refills the per-fd direntries cache by issuing a VNOP_READDIR.
 * It attempts to try and find a size the filesystem responds to, so
 * it first tries 1 direntry sized buffer and going from 1 to 2 to 4
 * direntry sized buffers to readdir. If the filesystem does not respond
 * to 4 * direntry it returns the error by the filesystem (if any) and sets
 * EOF.
 *
 * This function also tries again if the last "refill" returned an EOF
 * to try and get any additional entries if they were added after the last
 * refill.
 */
static int
refill_fd_direntries(vfs_context_t ctx, vnode_t dvp, struct fd_vn_data *fvd,
    int *eofflagp)
{
	uio_t rdir_uio;
	char uio_buf[UIO_SIZEOF(1)];
	size_t rdirbufsiz;
	size_t rdirbufused;
	int eofflag;
	int nentries;
	int error;

	/*
	 * If the last readdir returned EOF, don't try again.
	 */
	if (fvd->fv_eofflag) {
		*eofflagp = 1;
		if (fvd->fv_buf) {
			FREE(fvd->fv_buf, M_FD_DIRBUF);
			fvd->fv_buf = NULL;
		}
		return 0;
	}

	error = 0;

	/*
	 * If there is a cached allocation size of the dirbuf that should be
	 * allocated, use that. Otherwise start with a allocation size of
	 * FV_DIRBUF_START_SIZ. This start size may need to be increased if the
	 * filesystem doesn't respond to the initial size.
	 */

	if (fvd->fv_offset && fvd->fv_bufallocsiz) {
		rdirbufsiz = fvd->fv_bufallocsiz;
	} else {
		rdirbufsiz = FV_DIRBUF_START_SIZ;
	}

	*eofflagp = 0;

	rdir_uio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ,
	    &uio_buf[0], sizeof(uio_buf));

retry_alloc:
	/*
	 * Don't explicitly zero out this buffer since this is
	 * not copied out to user space.
	 */
	if (!fvd->fv_buf) {
		MALLOC(fvd->fv_buf, caddr_t, rdirbufsiz, M_FD_DIRBUF, M_WAITOK);
		fvd->fv_bufdone = 0;
	}

	uio_reset(rdir_uio, fvd->fv_eoff, UIO_SYSSPACE, UIO_READ);
	uio_addiov(rdir_uio, CAST_USER_ADDR_T(fvd->fv_buf), rdirbufsiz);

	/*
	 * Some filesystems do not set nentries or eofflag...
	 */
	eofflag = 0;
	nentries = 0;
	error = vnode_readdir64(dvp, rdir_uio, VNODE_READDIR_EXTENDED,
	    &eofflag, &nentries, ctx);

	rdirbufused = rdirbufsiz - (size_t)uio_resid(rdir_uio);

	if (!error && (rdirbufused > 0) && (rdirbufused <= rdirbufsiz)) {
		/* Save offsets */
		fvd->fv_soff = fvd->fv_eoff;
		fvd->fv_eoff = uio_offset(rdir_uio);
		 /* Save eofflag state but don't return EOF for this time.*/
		fvd->fv_eofflag = eofflag;
		eofflag = 0;
		 /* Reset buffer parameters */
		fvd->fv_bufsiz = rdirbufused;
		fvd->fv_bufdone = 0;
		bzero(fvd->fv_buf + rdirbufused, rdirbufsiz - rdirbufused);
		/* Cache allocation size the Filesystem responded to */
		fvd->fv_bufallocsiz = rdirbufsiz;
	} else if (!eofflag && (rdirbufsiz < FV_DIRBUF_MAX_SIZ)) {
		/*
		 * Some Filesystems have higher requirements for the
		 * smallest buffer size they will respond to for a
		 * directory listing. Start (relatively) small but increase
		 * it upto FV_DIRBUF_MAX_SIZ. Most should be good with
		 * 1*direntry. Cache the size found so that this does not need
		 * need to be done every time. This also means that an error
		 * from VNOP_READDIR is ignored until at least FV_DIRBUF_MAX_SIZ
		 * has been attempted.
		 */
		FREE(fvd->fv_buf, M_FD_DIRBUF);
		fvd->fv_buf = NULL;
		rdirbufsiz = 2 * rdirbufsiz;
		fvd->fv_bufallocsiz = 0;
		goto retry_alloc;
	} else if (!error) {
		/*
		 * The Filesystem did not set eofflag but also did not
		 * return any entries (or an error). It is presumed that
		 * EOF has been reached.
		 */
		fvd->fv_eofflag = eofflag = 1;
	}

	/*
	 * If the filesystem returned an error and it had previously returned
	 * EOF, ignore the error and set EOF.
	 */
	if (error && fvd->fv_eofflag) {
		eofflag = 1;
		error = 0;
	}

	/*
	 * If either the directory has either hit EOF or an error, now is a good
	 * time to free up directory entry buffer.
	 */
	if ((error || eofflag) && fvd->fv_buf) {
		FREE(fvd->fv_buf, M_FD_DIRBUF);
		fvd->fv_buf = NULL;
	}

	*eofflagp = eofflag;

	return (error);
}

/*
 * gets the current direntry. To advance to the next direntry this has to be
 * paired with a direntry_done.
 *
 * Since directories have restrictions on where directory enumeration
 * can restart from, entries are first read into* a per fd diectory entry
 * "cache" and entries provided from that cache.
 */
static int
get_direntry(vfs_context_t ctx, vnode_t dvp, struct fd_vn_data *fvd,
    int *eofflagp, struct direntry **dpp)
{
	int eofflag;
	int error;

	*eofflagp = 0;
	*dpp = NULL;
	error = 0;
	if (!fvd->fv_bufsiz) {
		error = refill_fd_direntries(ctx, dvp, fvd, &eofflag);
		if (error) {
			return (error);
		}
		if (eofflag) {
			*eofflagp = eofflag;
			return (error);
		}
	}

	*dpp = (struct direntry *)(fvd->fv_buf + fvd->fv_bufdone);
	return (error);
}

/*
 * Advances to the next direntry.
 */
static void
direntry_done(struct fd_vn_data *fvd)
{
	struct direntry *dp;

	dp = (struct direntry *)(fvd->fv_buf + fvd->fv_bufdone);
	if (dp->d_reclen) {
		fvd->fv_bufdone += dp->d_reclen;
		if (fvd->fv_bufdone > fvd->fv_bufsiz) {
			fvd->fv_bufdone = fvd->fv_bufsiz;
		}
	} else {
		fvd->fv_bufdone = fvd->fv_bufsiz;
	}

	/*
	 * If we're at the end the fd direntries cache, reset the
	 * cache trackers.
	 */
	if (fvd->fv_bufdone == fvd->fv_bufsiz) {
		fvd->fv_bufdone = 0;
		fvd->fv_bufsiz = 0;
	}
}

/*
 *  A stripped down version of getattrlist_internal to fill in only select
 *  attributes in case of an error from getattrlist_internal.
 *
 *  It always returns at least ATTR_BULK_REQUIRED i.e. the name (but may also
 *  return some other attributes which can be obtained from the vnode).
 *
 *  It does not change the value of the passed in attrlist.
 *
 *  The objective of this function is to fill in an "error entry", i.e.
 *  an entry with ATTR_CMN_RETURNED_ATTRS & ATTR_CMN_NAME. If the caller
 *  has also asked for ATTR_CMN_ERROR, it is filled in as well.
 *
 *  Input
 *       vp - vnode pointer
 *       alp - pointer to attrlist struct.
 *       options - options passed to getattrlistbulk(2)
 *       kern_attr_buf - Kernel buffer to fill data (assumes offset 0 in
 *           buffer)
 *       kern_attr_buf_siz - Size of buffer.
 *       needs_error_attr - Whether the caller asked for ATTR_CMN_ERROR
 *       error_attr - This value is used to fill ATTR_CMN_ERROR (if the user
 *                  has requested it in the attribute list.
 *       namebuf - This is used to fill in the name.
 *       ctx - vfs context of caller.
 */
static void
get_error_attributes(vnode_t vp, struct attrlist *alp, uint64_t options,
    user_addr_t kern_attr_buf, size_t kern_attr_buf_siz, int error_attr,
    caddr_t namebuf, vfs_context_t ctx)
{
	size_t fsiz, vsiz;
	struct _attrlist_buf ab;
	int namelen;
	kauth_action_t action;
	struct attrlist al;
	int needs_error_attr = (alp->commonattr & ATTR_CMN_ERROR);

	/*
	 * To calculate fixed size required, in the FSOPT_PACK_INVAL_ATTRS case,
	 * the fixedsize should include space for all the attributes asked by
	 * the user. Only ATTR_BULK_REQUIRED (and ATTR_CMN_ERROR) will be filled
	 * and will be valid. All other attributes are zeroed out later.
	 *
	 * ATTR_CMN_RETURNED_ATTRS, ATTR_CMN_ERROR and ATTR_CMN_NAME
	 * (the only valid ones being returned from here) happen to be
	 * the first three attributes by order as well.
	 */
	al = *alp;
	if (!(options & FSOPT_PACK_INVAL_ATTRS)) {
		/*
		 * In this case the fixedsize only needs to be only for the
		 * attributes being actually returned.
		 */
		al.commonattr = ATTR_BULK_REQUIRED;
		if (needs_error_attr) {
			al.commonattr |= ATTR_CMN_ERROR;
		}
		al.fileattr = 0;
		al.dirattr = 0;
	}

	/*
	 * Passing NULL for the vnode_attr pointer is valid for
	 * getattrlist_setupvattr. All that is required is the size.
	 */
	fsiz = 0;
	(void)getattrlist_setupvattr(&al, NULL, (ssize_t *)&fsiz,
	    &action, proc_is64bit(vfs_context_proc(ctx)),
	    (vnode_vtype(vp) == VDIR));

	namelen = strlen(namebuf);
	vsiz = namelen + 1;
	vsiz = ((vsiz + 3) & ~0x03);

	bzero(&ab, sizeof(ab));
	ab.base = (char *)kern_attr_buf;
	ab.needed = fsiz + vsiz;

	/* Fill in the size needed */
	*((uint32_t *)ab.base) = ab.needed;
	if (ab.needed > (ssize_t)kern_attr_buf_siz) {
		goto out;
	}

	/*
	 * Setup to pack results into the destination buffer.
	 */
	ab.fixedcursor = ab.base + sizeof(uint32_t);
	/*
	 * Zero out buffer, ab.fixedbuffer starts after the first uint32_t
	 * which gives the length. This ensures everything that we don't
	 * fill in explicitly later is zeroed out correctly.
	 */
	bzero(ab.fixedcursor, fsiz);
	/*
	 * variable size data should start after all the fixed
	 * size data.
	 */
	ab.varcursor = ab.base + fsiz;
	/*
	 * Initialise the value for ATTR_CMN_RETURNED_ATTRS and leave space
	 * Leave space for filling in its value here at the end.
	 */
	bzero(&ab.actual, sizeof (ab.actual));
	ab.fixedcursor += sizeof (attribute_set_t);

	ab.allocated = ab.needed;

	/* Fill ATTR_CMN_ERROR (if asked for) */
	if (needs_error_attr) {
		ATTR_PACK4(ab, error_attr);
		ab.actual.commonattr |= ATTR_CMN_ERROR;
	}

	/*
	 * Fill ATTR_CMN_NAME, The attrrefrence is packed at this location
	 * but the actual string itself is packed after fixedsize which set
	 * to different lengths based on whether FSOPT_PACK_INVAL_ATTRS
	 * was passed.
	 */
	attrlist_pack_string(&ab, namebuf, namelen);

	/*
	 * Now Fill in ATTR_CMN_RETURNED_ATTR. This copies to a
	 * location after the count i.e. before ATTR_CMN_ERROR and
	 * ATTR_CMN_NAME.
	 */
	ab.actual.commonattr |= ATTR_CMN_NAME | ATTR_CMN_RETURNED_ATTRS;
	bcopy(&ab.actual, ab.base + sizeof(uint32_t), sizeof (ab.actual));
out:
	return;
}

/*
 * This is the buffer size required to return at least 1 entry. We need space
 * for the length, for ATTR_CMN_RETURNED_ATTRS and ATTR_CMN_NAME. Assuming the
 * smallest filename of a single byte we get
 */

#define MIN_BUF_SIZE_REQUIRED  (sizeof(uint32_t) + sizeof(attribute_set_t) +\
    sizeof(attrreference_t))

/*
 * Read directory entries and get attributes filled in for each directory
 */
static int
readdirattr(vnode_t dvp, struct fd_vn_data *fvd, uio_t auio,
    struct attrlist *alp, uint64_t options, int *count, int *eofflagp,
    vfs_context_t ctx)
{
	caddr_t kern_attr_buf;
	size_t kern_attr_buf_siz;
	caddr_t max_path_name_buf = NULL;
	int error = 0;

	*count = 0;
	*eofflagp = 0;

	if (uio_iovcnt(auio) > 1) {
		return (EINVAL);
	}

	/*
	 * We fill in a kernel buffer for the attributes and uiomove each
	 * entry's attributes (as returned by getattrlist_internal)
	 */
	kern_attr_buf_siz = uio_resid(auio);
	if (kern_attr_buf_siz > ATTR_MAX_BUFFER) {
		kern_attr_buf_siz = ATTR_MAX_BUFFER;
	} else if (kern_attr_buf_siz == 0) {
		/* Nothing to do */
		return (error);
	}

	MALLOC(kern_attr_buf, caddr_t, kern_attr_buf_siz, M_TEMP, M_WAITOK);

	while (uio_resid(auio) > (user_ssize_t)MIN_BUF_SIZE_REQUIRED) {
		struct direntry *dp;
		user_addr_t name_buffer;
		struct nameidata nd;
		vnode_t vp;
		struct attrlist al;
		size_t entlen;
		size_t bytes_left;
		size_t pad_bytes;
		ssize_t new_resid;

		/*
		 * get_direntry returns the current direntry and does not
		 * advance. A move to the next direntry only happens if
		 * direntry_done is called.
		 */
		error = get_direntry(ctx, dvp, fvd, eofflagp, &dp);
		if (error || (*eofflagp) || !dp) {
			break;
		}

		/*
		 * skip "." and ".." (and a bunch of other invalid conditions.)
		 */
		if (!dp->d_reclen || dp->d_ino == 0 || dp->d_namlen == 0 ||
		    (dp->d_namlen == 1 && dp->d_name[0] == '.') ||
		    (dp->d_namlen == 2 && dp->d_name[0] == '.' &&
		    dp->d_name[1] == '.')) {
			direntry_done(fvd);
			continue;
		}

		/*
		 * try to deal with not-null terminated filenames.
		 */
		if (dp->d_name[dp->d_namlen] != '\0') {
			if (!max_path_name_buf) {
				MALLOC(max_path_name_buf, caddr_t, MAXPATHLEN,
				    M_TEMP, M_WAITOK);
			}
			bcopy(dp->d_name, max_path_name_buf, dp->d_namlen);
			max_path_name_buf[dp->d_namlen] = '\0';
			name_buffer = CAST_USER_ADDR_T(max_path_name_buf);
		} else {
			name_buffer = CAST_USER_ADDR_T(&(dp->d_name));
		}

		/*
		 * We have an iocount on the directory already.
		 * 
		 * Note that we supply NOCROSSMOUNT to the namei call as we attempt to acquire
		 * a vnode for this particular entry.  This is because the native call will
		 * (likely) attempt to emit attributes based on its own metadata in order to avoid
		 * creating vnodes where posssible.  If the native call is not going to  walk
		 * up the vnode mounted-on chain in order to find the top-most mount point, then we
		 * should not either in this emulated readdir+getattrlist() approach.  We  
		 * will be responsible for setting DIR_MNTSTATUS_MNTPOINT on that directory that
		 * contains a mount point.  
		 */
		NDINIT(&nd, LOOKUP, OP_GETATTR, (AUDITVNPATH1 | USEDVP | NOCROSSMOUNT), 
		    UIO_SYSSPACE, CAST_USER_ADDR_T(name_buffer), ctx);

		nd.ni_dvp = dvp;
		error = namei(&nd);

		if (error) {
			direntry_done(fvd);
			error = 0;
			continue;
		}

		vp = nd.ni_vp;

		/*
		 * getattrlist_internal can change the values of the
		 * the required attribute list. Copy the current values
		 * and use that one instead.
		 */
		al = *alp;

		error = getattrlist_internal(ctx, vp, &al,
		    CAST_USER_ADDR_T(kern_attr_buf), kern_attr_buf_siz,
		    options | FSOPT_REPORT_FULLSIZE, UIO_SYSSPACE, 
		    CAST_DOWN_EXPLICIT(char *, name_buffer),
		    NOCRED);

		nameidone(&nd);

		if (error) {
			get_error_attributes(vp, alp, options,
			    CAST_USER_ADDR_T(kern_attr_buf),
			    kern_attr_buf_siz, error, (caddr_t)name_buffer,
			    ctx);
			error = 0;
		}

		/* Done with vnode now */
		vnode_put(vp);

		/*
		 * Because FSOPT_REPORT_FULLSIZE was set, the first 4 bytes
		 * of the buffer returned by getattrlist contains the size
		 * (even if the provided buffer isn't sufficiently big). Use
		 * that to check if we've run out of buffer space.
		 *
		 * resid is a signed type, and the size of the buffer etc
		 * are unsigned types. It is theoretically possible for
		 * resid to be < 0 and in which case we would be assigning
		 * an out of bounds value to bytes_left (which is unsigned)
		 * uiomove takes care to not ever set resid to < 0, so it
		 * is safe to do this here.
		 */
		bytes_left = (size_t)((user_size_t)uio_resid(auio));
		entlen = (size_t)(*((uint32_t *)(kern_attr_buf)));
		if (!entlen || (entlen > bytes_left)) {
			break;
		}

		/*
		 * Will the pad bytes fit as well  ? If they can't be, still use
		 * this entry but this will be the last entry returned.
		 */
		pad_bytes = ((entlen + 7) & ~0x07) - entlen;
		new_resid = 0;
		if (pad_bytes && (entlen + pad_bytes <= bytes_left)) {
			/*
			 * While entlen can never be > ATTR_MAX_BUFFER,
			 * (entlen + pad_bytes) can be, handle that and
			 * zero out the pad bytes. N.B. - Only zero
			 * out information in the kernel buffer that is
			 * going to be uiomove'ed out.
			 */
			if (entlen + pad_bytes <= kern_attr_buf_siz) {
				/* This is the normal case. */
				bzero(kern_attr_buf + entlen, pad_bytes);
			} else {
				bzero(kern_attr_buf + entlen,
				    kern_attr_buf_siz - entlen);
				/*
				 * Pad bytes left over, change the resid value
				 * manually. We only got in here because
				 * bytes_left >= entlen + pad_bytes so
				 * new_resid (which is a signed type) is
				 * always positive.
				 */
				new_resid = (ssize_t)(bytes_left -
				    (entlen + pad_bytes));
			}
			entlen += pad_bytes;
		}
		*((uint32_t *)kern_attr_buf) = (uint32_t)entlen;
		error = uiomove(kern_attr_buf, min(entlen, kern_attr_buf_siz),
		    auio);

		if (error) {
			break;
		}

		if (new_resid) {
			uio_setresid(auio, (user_ssize_t)new_resid);
		}

		/*
		 * At this point, the directory entry has been consumed, proceed
		 * to the next one.
		 */
		(*count)++;
		direntry_done(fvd);
	}

	if (max_path_name_buf) {
		FREE(max_path_name_buf, M_TEMP);
	}

	/*
	 * At this point, kern_attr_buf is always allocated
	 */
	FREE(kern_attr_buf, M_TEMP);

	/*
	 * Always set the offset to the last succesful offset
	 * returned by VNOP_READDIR.
	 */
	uio_setoffset(auio, fvd->fv_eoff);

	return (error);
}

/*
 *int getattrlistbulk(int dirfd, struct attrlist *alist, void *attributeBuffer,
 *    size_t bufferSize, uint64_t options)
 *
 * Gets directory entries alongwith their attributes in the same way
 * getattrlist does for a single file system object.
 *
 * On non error returns, retval will hold the count of entries returned.
 */
int
getattrlistbulk(proc_t p, struct getattrlistbulk_args *uap, int32_t *retval)
{
	struct attrlist al;
	vnode_t dvp;
	struct fileproc *fp;
	struct fd_vn_data *fvdata;
	vfs_context_t ctx;
	enum uio_seg segflg;
	int count;
	uio_t auio = NULL;
	char uio_buf[ UIO_SIZEOF(1) ];
	kauth_action_t action;
	int eofflag;
	uint64_t options;
	int error;

	*retval = 0;

	error = fp_getfvp(p, uap->dirfd, &fp, &dvp);
	if (error)
		return (error);

	count = 0;
	fvdata = NULL;
	eofflag = 0;
	ctx = vfs_context_current();
	segflg = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;

	if ((fp->f_fglob->fg_flag & FREAD) == 0) {
		/*
		AUDIT_ARG(vnpath_withref, dvp, ARG_VNODE1);
		*/
		error = EBADF;
		goto out;
	}

	if ((error = vnode_getwithref(dvp))) {
		dvp = NULLVP;
		goto out;
	}

	if (uap->options & FSOPT_LIST_SNAPSHOT) {
		vnode_t snapdvp;

		if (!vfs_context_issuser(ctx)) {
			error = EPERM;
			goto out;
		}

		if (!vnode_isvroot(dvp)) {
			error = EINVAL;
			goto out;
		}

		/* switch directory to snapshot directory */
		error = vnode_get_snapdir(dvp, &snapdvp, ctx);
		if (error)
			goto out;
		vnode_put(dvp);
		dvp = snapdvp;
	}

	if (dvp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

#if CONFIG_MACF
	error = mac_file_check_change_offset(vfs_context_ucred(ctx),
	                                     fp->f_fglob);
	if (error)
		goto out;
#endif
	/*
	 * XXX : Audit Support
	 *AUDIT_ARG(vnpath, dvp, ARG_VNODE1);
	 */

	options = uap->options | FSOPT_ATTR_CMN_EXTENDED;

	if ((error = copyin(CAST_USER_ADDR_T(uap->alist), &al,
	    sizeof(struct attrlist)))) {
		goto out;
	}

	if (al.volattr ||
	    ((al.commonattr & ATTR_BULK_REQUIRED) != ATTR_BULK_REQUIRED)) {
		error = EINVAL;
		goto out;
	}

#if CONFIG_MACF
	error = mac_vnode_check_readdir(ctx, dvp);
	if (error != 0) {
		goto out;
	}
#endif /* MAC */

	/*
	 * If the only item requested is file names, we can let that past with
	 * just LIST_DIRECTORY.  If they want any other attributes, that means
	 * they need SEARCH as well.
	 */
	action = KAUTH_VNODE_LIST_DIRECTORY;
	if ((al.commonattr & ~ATTR_CMN_NAME) || al.fileattr || al.dirattr)
		action |= KAUTH_VNODE_SEARCH;
	
	error = vnode_authorize(dvp, NULL, action, ctx);
	if (error) {
		goto out;
	}

	fvdata = (struct fd_vn_data *)fp->f_fglob->fg_vn_data;
	if (!fvdata) {
		panic("Directory expected to have fg_vn_data");
	}

	FV_LOCK(fvdata);

	/*
	 * getattrlistbulk(2) maintains its offset in fv_offset. However
	 * if the offset in the file glob is set (or reset) to 0, the directory
	 * traversal needs to be restarted (Any existing state in the
	 * directory buffer is removed as well).
	 */
	if (!fp->f_fglob->fg_offset) {
		fvdata->fv_offset = 0;
		if (fvdata->fv_buf)
			FREE(fvdata->fv_buf, M_FD_DIRBUF);
		fvdata->fv_buf = NULL;
		fvdata->fv_bufsiz = 0;
		fvdata->fv_bufdone = 0;
		fvdata->fv_soff = 0;
		fvdata->fv_eoff = 0;
		fvdata->fv_eofflag = 0;
	}

	auio = uio_createwithbuffer(1, fvdata->fv_offset, segflg, UIO_READ,
	    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->attributeBuffer, (user_size_t)uap->bufferSize);

	/*
	 * For "expensive" operations in which the native VNOP implementations
	 * end up having to do just as much (if not more) work than the default
	 * implementation, fall back to the default implementation.
	 * The VNOP helper functions depend on the filesystem providing the
	 * object type, if the caller has not requested ATTR_CMN_OBJTYPE, fall
	 * back to the default implementation.
	 */
	if ((al.commonattr &
	    (ATTR_CMN_UUID | ATTR_CMN_GRPUUID | ATTR_CMN_EXTENDED_SECURITY)) ||
	    !(al.commonattr & ATTR_CMN_OBJTYPE)) {
		error = ENOTSUP;
	 } else {
		struct vnode_attr va;
		char *va_name;

		if (fvdata->fv_eofflag && !fvdata->fv_buf) {
			/*
			 * If the last successful VNOP_GETATTRLISTBULK or
			 * VNOP_READDIR returned EOF, don't try again.
			 */
			eofflag = 1;
			count = 0;
			error = 0;
		} else {
			eofflag = 0;
			count = 0;

			VATTR_INIT(&va);
			MALLOC(va_name, char *, MAXPATHLEN, M_TEMP,
			    M_WAITOK | M_ZERO);
			va.va_name = va_name;

			(void)getattrlist_setupvattr_all(&al, &va, VNON, NULL,
			    IS_64BIT_PROCESS(p));

			error = VNOP_GETATTRLISTBULK(dvp, &al, &va, auio, NULL,
			    options, &eofflag, &count, ctx);

			FREE(va_name, M_TEMP);

			/*
			 * cache state of eofflag.
			 */
			if (!error) {
				fvdata->fv_eofflag = eofflag;
			}
		}
	}

	/*
	 * If the Filessytem does not natively support getattrlistbulk,
	 * do the default implementation.
	 */
	if (error == ENOTSUP) {
		eofflag = 0;
		count = 0;

		error = readdirattr(dvp, fvdata, auio, &al, options,
		    &count, &eofflag, ctx);
	}

	if (count) {
		fvdata->fv_offset = uio_offset(auio);
		fp->f_fglob->fg_offset = fvdata->fv_offset;
		*retval = count;
		error = 0;
	} else if (!error && !eofflag) {
		/*
		 * This just means the buffer was too small to fit even a
		 * single entry.
		 */
		error = ERANGE;
	}

	FV_UNLOCK(fvdata);
out:
	if (dvp) {
		vnode_put(dvp);
	}

	file_drop(uap->dirfd);

	return (error);
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
	 * If the caller's bitmaps indicate that there are no attributes to set,
	 * then exit early.  In particular, we want to avoid the MALLOC below
	 * since the caller's bufferSize could be zero, and MALLOC of zero bytes
	 * returns a NULL pointer, which would cause setattrlist to return ENOMEM.
	 */
	if (al.commonattr == 0 &&
		(al.volattr & ~ATTR_VOL_INFO) == 0 &&
		al.dirattr == 0 &&
		al.fileattr == 0 &&
		al.forkattr == 0) {
		error = 0;
		goto out;
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
		al.commonattr &= ~ATTR_CMN_CHGTIME;
		/*quietly ignore change time; advisory in man page*/
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
#if CONFIG_MACF
		if ((error = mac_vnode_check_setflags(ctx, vp, va.va_flags)) != 0)
			goto out;
#endif
	}
	if (al.commonattr & ATTR_CMN_EXTENDED_SECURITY) {

		/*
		 * We are (for now) passed a kauth_filesec_t, but all we want from
		 * it is the ACL.
		 */
		cp = cursor;
		ATTR_UNPACK(ar);
		if (ar.attr_dataoffset < 0) {
			VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: bad offset supplied", ar.attr_dataoffset);
			error = EINVAL;
			goto out;
		}

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
			/* attr_length cannot be 0! */
			if ((ar.attr_dataoffset < 0) || (ar.attr_length == 0) ||
				(ar.attr_length > uap->bufferSize) ||
				(uap->bufferSize - ar.attr_length < (unsigned)ar.attr_dataoffset)) {
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: bad offset supplied (2) ", ar.attr_dataoffset);
				error = EINVAL;
				goto out;
			}

			if (volname >= bufend - ar.attr_dataoffset - ar.attr_length) {
				error = EINVAL;
				VFS_DEBUG(ctx, vp, "ATTRLIST - ERROR: volume name too big for caller buffer");
				goto out;
			}
			volname += ar.attr_dataoffset;
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

#if CONFIG_MACF
	mac_vnode_notify_setattrlist(ctx, vp, &al);
	if (VATTR_IS_ACTIVE(&va, va_flags))
		mac_vnode_notify_setflags(ctx, vp, va.va_flags);
#endif

	/*
	 * Write the Finder Info if we have any.
	 */
	if (fndrinfo != NULL) {
		if (al.volattr & ATTR_VOL_INFO) {
			if (vp->v_tag == VT_HFS) {
#define HFS_SET_BOOT_INFO   (FCNTL_FS_SPECIFIC_BASE + 0x00005)
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
	nameiflags = AUDITVNPATH1;
	if ((uap->options & FSOPT_NOFOLLOW) == 0)
		nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, OP_SETATTR, nameiflags, UIO_USERSPACE, uap->path, ctx);
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

