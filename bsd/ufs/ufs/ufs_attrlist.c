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

/*
 * ufs_attrlist.c - UFS attribute list processing
 *
 * Copyright (c) 2002, Apple Computer, Inc.  All Rights Reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/attr.h>
#include <sys/kernel.h>

#include <architecture/byte_order.h>
#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>
#include "ufsmount.h"

/*
12345678901234567890123456789012345678901234567890123456789012345678901234567890
*/
enum {
	UFS_ATTR_CMN_NATIVE	= 0,
	UFS_ATTR_CMN_SUPPORTED	= 0,
	UFS_ATTR_VOL_NATIVE	= ATTR_VOL_NAME |
				  ATTR_VOL_CAPABILITIES |
				  ATTR_VOL_ATTRIBUTES,
	UFS_ATTR_VOL_SUPPORTED	= UFS_ATTR_VOL_NATIVE,
	UFS_ATTR_DIR_NATIVE	= 0,
	UFS_ATTR_DIR_SUPPORTED	= 0,
	UFS_ATTR_FILE_NATIVE	= 0,
	UFS_ATTR_FILE_SUPPORTED	= 0,
	UFS_ATTR_FORK_NATIVE	= 0,
	UFS_ATTR_FORK_SUPPORTED	= 0,

	UFS_ATTR_CMN_SETTABLE	= 0,
	UFS_ATTR_VOL_SETTABLE	= ATTR_VOL_NAME,
	UFS_ATTR_DIR_SETTABLE	= 0,
	UFS_ATTR_FILE_SETTABLE	= 0,
	UFS_ATTR_FORK_SETTABLE	= 0
};

static char ufs_label_magic[4] = UFS_LABEL_MAGIC;

/* Copied from diskdev_cmds/disklib/ufslabel.c */
typedef union {
	char	c[2];
	u_short	s;
} short_union_t;

/* Copied from diskdev_cmds/disklib/ufslabel.c */
typedef union {
	u_short	s[2];
	long	l;
} long_union_t;

/* Copied from diskdev_cmds/disklib/ufslabel.c */
static __inline__ void
reduce(int *sum)
{
	long_union_t l_util;

	l_util.l = *sum;
	*sum = l_util.s[0] + l_util.s[1];
	if (*sum > 65535)
		*sum -= 65535;
	return;
}

/* Copied from diskdev_cmds/disklib/ufslabel.c */
static unsigned short
in_cksum(void *data, int len)
{
	u_short	*w;
	int	 sum;

	sum = 0;
	w = (u_short *)data;
	while ((len -= 32) >= 0) {
		sum += w[0]; sum += w[1]; 
		sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5]; 
		sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9]; 
		sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13]; 
		sum += w[14]; sum += w[15];
		w += 16;
	}
	len += 32;
	while ((len -= 8) >= 0) {
		sum += w[0]; sum += w[1]; 
		sum += w[2]; sum += w[3];
		w += 4;
	}
	len += 8;
	if (len) {
		reduce(&sum);
		while ((len -= 2) >= 0) {
			sum += *w++;
		}
	}
	if (len == -1) { /* odd-length data */
		short_union_t s_util;

		s_util.s = 0;
		s_util.c[0] = *((char *)w);
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	reduce(&sum);
	return (~sum & 0xffff);
}

/* Adapted from diskdev_cmds/disklib/ufslabel.c */
static boolean_t
ufs_label_check(struct ufslabel *ul_p)
{
	u_int16_t	calc;
	u_int16_t 	checksum;

	if (bcmp(&ul_p->ul_magic, ufs_label_magic, 
	    sizeof(ul_p->ul_magic))) {
#ifdef DEBUG
		printf("ufslabel_check: label has bad magic number\n");
#endif
		return (FALSE);
	}
	if (ntohl(ul_p->ul_version) != UFS_LABEL_VERSION) {
#ifdef DEBUG
		printf("ufslabel_check: label has incorect version %d "
		    "(should be %d)\n", ntohl(ul_p->ul_version),
		    UFS_LABEL_VERSION);
#endif
		return (FALSE);
	}
	if (ntohs(ul_p->ul_namelen) > UFS_MAX_LABEL_NAME) {
#ifdef DEBUG
		printf("ufslabel_check: name length %d is too big (> %d)\n",
		    ntohs(ul_p->ul_namelen), UFS_MAX_LABEL_NAME);
#endif
		return (FALSE);
	}

	checksum = ul_p->ul_checksum;	/* Remember previous checksum. */
	ul_p->ul_checksum = 0;
	calc = in_cksum(ul_p, sizeof(*ul_p));
	if (calc != checksum) {
#ifdef DEBUG
		printf("ufslabel_check: label checksum %x (should be %x)\n",
		    checksum, calc);
#endif
		return (FALSE);
	}
	return (TRUE);
}

static void
ufs_label_init(struct ufslabel *ul_p)
{
	bzero(ul_p, sizeof(*ul_p));
	ul_p->ul_version = htonl(UFS_LABEL_VERSION);
	bcopy(ufs_label_magic, &ul_p->ul_magic, sizeof(ul_p->ul_magic));
	ul_p->ul_time = htonl(time.tv_sec);
}

static int
ufs_get_label(struct vnode *vp, struct ucred *cred, char *label,
    int *name_length)
{
	int		 error;
	int		 devBlockSize;
	struct mount	*mp;
	struct vnode	*devvp;
	struct buf	*bp;
	struct ufslabel	*ulp;

	mp = vp->v_mount;
	devvp = VFSTOUFS(mp)->um_devvp;
	VOP_DEVBLOCKSIZE(devvp, &devBlockSize);

	if (error = meta_bread(devvp, (ufs_daddr_t)(UFS_LABEL_OFFSET / devBlockSize),
	    UFS_LABEL_SIZE, cred, &bp))
		goto out;

	/*
	 * Since the disklabel is read directly by older user space code,
	 * make sure this buffer won't remain in the cache when we release it.
	 *
	 * It would be better if that user space code was modified to get
	 * at the fields of the disklabel via the filesystem (such as
	 * getattrlist).
	 */
	SET(bp->b_flags, B_NOCACHE);

	ulp = (struct ufslabel *) bp->b_data;
	if (ufs_label_check(ulp)) {
		int length;
		/* Copy the name out */
		length = ulp->ul_namelen;
#if REV_ENDIAN_FS
		if (mp->mnt_flag & MNT_REVEND)
			length = NXSwapShort(length);
#endif
		if (length > 0 && length <= UFS_MAX_LABEL_NAME) {
			bcopy(ulp->ul_name, label, length);
			*name_length = length;
		} else {
			/* Return an empty name */
			*label = '\0';
			*name_length = 0;
		}
	}

out:
	if (bp)
		brelse(bp);
	return error;
}

static int ufs_set_label(struct vnode *vp, struct ucred *cred,
    const char *label, int name_length)
{
	int		 error;
	int		 devBlockSize;
	struct mount	*mp;
	struct vnode	*devvp;
	struct buf	*bp;
	struct ufslabel *ulp;

	mp = vp->v_mount;

	/* Validate the new name's length */
	if (name_length < 0 || name_length > UFS_MAX_LABEL_NAME)
		return EINVAL;

	/* Read UFS_LABEL_SIZE bytes at UFS_LABEL_OFFSET */
	devvp = VFSTOUFS(mp)->um_devvp;
	VOP_DEVBLOCKSIZE(devvp, &devBlockSize);
	if (error = meta_bread(devvp, (ufs_daddr_t)(UFS_LABEL_OFFSET / devBlockSize),
	    UFS_LABEL_SIZE, cred, &bp))
		goto out;

	/*
	 * Since the disklabel is read directly by older user space code,
	 * make sure this buffer won't remain in the cache when we release it.
	 *
	 * It would be better if that user space code was modified to get
	 * at the fields of the disklabel via the filesystem (such as
	 * getattrlist).
	 */
	SET(bp->b_flags, B_NOCACHE);

	/* Validate the label structure; init if not valid */
	ulp = (struct ufslabel *) bp->b_data;
	if (!ufs_label_check(ulp))
		ufs_label_init(ulp);

	/* Copy new name over existing name */
	ulp->ul_namelen = name_length;
#if REV_ENDIAN_FS
	if (mp->mnt_flag & MNT_REVEND)
		ulp->ul_namelen = NXSwapShort(ulp->ul_namelen);
#endif
	bcopy(label, ulp->ul_name, name_length);

	/* Update the checksum */
	ulp->ul_checksum = 0;
	ulp->ul_checksum = in_cksum(ulp, sizeof(*ulp));

	/* Write the label back to disk */
	bwrite(bp);
	bp = NULL;

out:
	if (bp)
		brelse(bp);
	return error;
}

/*
 * Pack a C-style string into an attribute buffer.  Returns the new varptr.
 */
static void *
packstr(char *s, void *attrptr, void *varptr)
{
	struct attrreference *ref = attrptr;
	u_long	length;

	length = strlen(s) + 1;	/* String, plus terminator */

	/*
	 * In the fixed-length part of buffer, store the offset and length of
	 * the variable-length data.
	 */
	ref->attr_dataoffset = (u_int8_t *)varptr - (u_int8_t *)attrptr;
	ref->attr_length = length;

	/* Copy the string to variable-length part of buffer */
	(void) strncpy((unsigned char *)varptr, s, length);

	/* Advance pointer past string, and round up to multiple of 4 bytes */        
	return (char *)varptr + ((length + 3) & ~3);
}

/*
 * Pack an unterminated string into an attribute buffer as a C-style
 * string.  Copies the indicated number of characters followed by a
 * terminating '\0'.  Returns the new varptr.
 */
static void *
packtext(u_char *text, u_int text_len, void *attrptr, void *varptr)
{
	struct attrreference *ref = attrptr;
	u_long	length;	/* of the attribute, including terminator */

	length = text_len + 1;		/* String, plus terminator */

	/*
	 * In the fixed-length part of buffer, store the offset and length of
	 * the variable-length data.
	 */
	ref->attr_dataoffset = (u_int8_t *) varptr - (u_int8_t *) attrptr;
	ref->attr_length = length;

	/* Copy the string to variable-length part of buffer */
	bcopy(text, varptr, text_len);
	((char *) varptr)[text_len] = '\0';

	/* Advance pointer past string, and round up to multiple of 4 bytes */        
	return (char *) varptr + ((length + 3) & ~3);
}

/*
 * ufs_packvolattr
 *
 * Pack the volume-related attributes from a getattrlist call into result
 * buffers.  Fields are packed in order based on the bitmap masks.
 * Attributes with smaller masks are packed first.
 *
 * The buffer pointers are updated to point past the data that was returned.
 */
static int ufs_packvolattr(
    struct vnode	*vp,		/* The volume's vnode */
    struct ucred	*cred,
    struct attrlist	*alist,		/* Desired attributes */
    void		**attrptrptr,	/* Fixed-size attributes buffer */
    void		**varptrptr)	/* Variable-size attributes buffer */
{
	int		 error;
	attrgroup_t	 a;
	void		*attrptr = *attrptrptr;
	void		*varptr = *varptrptr;

	a = alist->volattr;
	if (a) {
		if (a & ATTR_VOL_NAME) {
			int	length;
			char	name[UFS_MAX_LABEL_NAME];

			error = ufs_get_label(vp, cred, name, &length);
			if (error)
				return error;

			varptr = packtext(name, length, attrptr, varptr);
			++((struct attrreference *)attrptr);
		}

		if (a & ATTR_VOL_CAPABILITIES) {
			vol_capabilities_attr_t *vcapattrptr;

			vcapattrptr = (vol_capabilities_attr_t *) attrptr;

			/*
			 * Capabilities this volume format has.  Note that
			 * we do not set VOL_CAP_FMT_PERSISTENTOBJECTIDS.
			 * That's because we can't resolve an inode number
			 * into a directory entry (parent and name), which
			 * Carbon would need to support PBResolveFileIDRef.
			 */
			vcapattrptr->capabilities[VOL_CAPABILITIES_FORMAT] =
			    VOL_CAP_FMT_SYMBOLICLINKS |
			    VOL_CAP_FMT_HARDLINKS |
			    VOL_CAP_FMT_SPARSE_FILES |
			    VOL_CAP_FMT_CASE_SENSITIVE |
			    VOL_CAP_FMT_CASE_PRESERVING |
			    VOL_CAP_FMT_FAST_STATFS ;
			vcapattrptr->capabilities[VOL_CAPABILITIES_INTERFACES]
			    = VOL_CAP_INT_NFSEXPORT |
			    VOL_CAP_INT_VOL_RENAME |
			    VOL_CAP_INT_ADVLOCK |
			    VOL_CAP_INT_FLOCK ;
			vcapattrptr->capabilities[VOL_CAPABILITIES_RESERVED1]
			    = 0;
			vcapattrptr->capabilities[VOL_CAPABILITIES_RESERVED2]
			    = 0;

			/* Capabilities we know about: */
			vcapattrptr->valid[VOL_CAPABILITIES_FORMAT] =
			    VOL_CAP_FMT_PERSISTENTOBJECTIDS |
			    VOL_CAP_FMT_SYMBOLICLINKS |
			    VOL_CAP_FMT_HARDLINKS |
			    VOL_CAP_FMT_JOURNAL |
			    VOL_CAP_FMT_JOURNAL_ACTIVE |
			    VOL_CAP_FMT_NO_ROOT_TIMES |
			    VOL_CAP_FMT_SPARSE_FILES |
			    VOL_CAP_FMT_ZERO_RUNS |
			    VOL_CAP_FMT_CASE_SENSITIVE |
			    VOL_CAP_FMT_CASE_PRESERVING |
			    VOL_CAP_FMT_FAST_STATFS ;
			vcapattrptr->valid[VOL_CAPABILITIES_INTERFACES] =
			    VOL_CAP_INT_SEARCHFS |
			    VOL_CAP_INT_ATTRLIST |
			    VOL_CAP_INT_NFSEXPORT |
			    VOL_CAP_INT_READDIRATTR |
			    VOL_CAP_INT_EXCHANGEDATA |
			    VOL_CAP_INT_COPYFILE |
			    VOL_CAP_INT_ALLOCATE |
			    VOL_CAP_INT_VOL_RENAME |
			    VOL_CAP_INT_ADVLOCK |
			    VOL_CAP_INT_FLOCK ;
			vcapattrptr->valid[VOL_CAPABILITIES_RESERVED1] = 0;
			vcapattrptr->valid[VOL_CAPABILITIES_RESERVED2] = 0;

			++((vol_capabilities_attr_t *)attrptr);
		}

		if (a & ATTR_VOL_ATTRIBUTES) {
			vol_attributes_attr_t *volattrptr;

			volattrptr = (vol_attributes_attr_t *)attrptr;

			volattrptr->validattr.commonattr =
			    UFS_ATTR_CMN_SUPPORTED;
			volattrptr->validattr.volattr =
			    UFS_ATTR_VOL_SUPPORTED;
			volattrptr->validattr.dirattr =
			    UFS_ATTR_DIR_SUPPORTED;
			volattrptr->validattr.fileattr =
			    UFS_ATTR_FILE_SUPPORTED;
			volattrptr->validattr.forkattr =
			    UFS_ATTR_FORK_SUPPORTED;

			volattrptr->nativeattr.commonattr =
			    UFS_ATTR_CMN_NATIVE;
			volattrptr->nativeattr.volattr =
			    UFS_ATTR_VOL_NATIVE;
			volattrptr->nativeattr.dirattr =
			    UFS_ATTR_DIR_NATIVE;
			volattrptr->nativeattr.fileattr =
			    UFS_ATTR_FILE_NATIVE;
			volattrptr->nativeattr.forkattr =
			    UFS_ATTR_FORK_NATIVE;

			++((vol_attributes_attr_t *)attrptr);
		}
	}

	/* Update the buffer pointers to point past what we just returned */
	*attrptrptr = attrptr;
	*varptrptr = varptr;

	return 0;
}

/*
 * Pack all attributes from a getattrlist or readdirattr call into
 * the result buffer.  For now, we only support volume attributes.
 */
static int
ufs_packattr(struct vnode *vp, struct ucred *cred, struct attrlist *alist,
    void **attrptr, void **varptr)
{
	int error=0;
	
	if (alist->volattr != 0)
		error = ufs_packvolattr(vp, cred, alist, attrptr, varptr);
	
	return error;
}

/*
 * Calculate the fixed-size space required to hold a set of attributes.
 * For variable-length attributes, this will be the size of the
 * attribute reference (an offset and length).
 */
static size_t
ufs_attrsize(struct attrlist *attrlist)
{
	size_t		size;
	attrgroup_t	a = 0;

#if ((ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID | ATTR_CMN_OBJTYPE	|  \
      ATTR_CMN_OBJTAG | ATTR_CMN_OBJID | ATTR_CMN_OBJPERMANENTID |         \
      ATTR_CMN_PAROBJID | ATTR_CMN_SCRIPT | ATTR_CMN_CRTIME |              \
      ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME |             \
      ATTR_CMN_BKUPTIME | ATTR_CMN_FNDRINFO | ATTR_CMN_OWNERID |           \
      ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_NAMEDATTRCOUNT |     \
      ATTR_CMN_NAMEDATTRLIST | ATTR_CMN_FLAGS | ATTR_CMN_USERACCESS)       \
      != ATTR_CMN_VALIDMASK)
#error	ufs_attrsize: Missing bits in common mask computation!
#endif

#if ((ATTR_VOL_FSTYPE | ATTR_VOL_SIGNATURE | ATTR_VOL_SIZE |                \
      ATTR_VOL_SPACEFREE | ATTR_VOL_SPACEAVAIL | ATTR_VOL_MINALLOCATION |   \
      ATTR_VOL_ALLOCATIONCLUMP | ATTR_VOL_IOBLOCKSIZE |                     \
      ATTR_VOL_OBJCOUNT | ATTR_VOL_FILECOUNT | ATTR_VOL_DIRCOUNT |          \
      ATTR_VOL_MAXOBJCOUNT | ATTR_VOL_MOUNTPOINT | ATTR_VOL_NAME |          \
      ATTR_VOL_MOUNTFLAGS | ATTR_VOL_INFO | ATTR_VOL_MOUNTEDDEVICE |        \
      ATTR_VOL_ENCODINGSUSED | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES) \
      != ATTR_VOL_VALIDMASK)
#error	ufs_attrsize: Missing bits in volume mask computation!
#endif

#if ((ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT | ATTR_DIR_MOUNTSTATUS)  \
      != ATTR_DIR_VALIDMASK)
#error	ufs_attrsize: Missing bits in directory mask computation!
#endif

#if ((ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE |	\
      ATTR_FILE_IOBLOCKSIZE | ATTR_FILE_CLUMPSIZE | ATTR_FILE_DEVTYPE |	\
      ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST |	\
      ATTR_FILE_DATALENGTH | ATTR_FILE_DATAALLOCSIZE |			\
      ATTR_FILE_DATAEXTENTS | ATTR_FILE_RSRCLENGTH |			\
      ATTR_FILE_RSRCALLOCSIZE | ATTR_FILE_RSRCEXTENTS)			\
      != ATTR_FILE_VALIDMASK)
#error	ufs_attrsize: Missing bits in file mask computation!
#endif

#if ((ATTR_FORK_TOTALSIZE | ATTR_FORK_ALLOCSIZE) != ATTR_FORK_VALIDMASK)
#error	ufs_attrsize: Missing bits in fork mask computation!
#endif

	size = 0;

	if ((a = attrlist->volattr) != 0) {
		if (a & ATTR_VOL_NAME)
			size += sizeof(struct attrreference);
		if (a & ATTR_VOL_CAPABILITIES)
			size += sizeof(vol_capabilities_attr_t);
		if (a & ATTR_VOL_ATTRIBUTES)
			size += sizeof(vol_attributes_attr_t);
	};

	/*
	 * Ignore common, dir, file, and fork attributes since we
	 * don't support those yet.
	 */

	return size;
}

/*
#
#% getattrlist	vp	= = =
#
 vop_getattrlist {
     IN struct vnode *vp;
     IN struct attrlist *alist;
     INOUT struct uio *uio;
     IN struct ucred *cred;
     IN struct proc *p;
 };

 */
__private_extern__ int 
ufs_getattrlist(struct vop_getattrlist_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	struct attrlist	*alist = ap->a_alist;
	size_t		 fixedblocksize;
	size_t		 attrblocksize;
	size_t		 attrbufsize;
	void		*attrbufptr;
	void		*attrptr;
	void		*varptr;
	int		 error;

	/*
	* Check the attrlist for valid inputs (i.e. be sure we understand what
	* caller is asking).
	*/
	if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
	    ((alist->commonattr & ~ATTR_CMN_VALIDMASK) != 0) ||
	    ((alist->volattr & ~ATTR_VOL_VALIDMASK) != 0) ||
	    ((alist->dirattr & ~ATTR_DIR_VALIDMASK) != 0) ||
	    ((alist->fileattr & ~ATTR_FILE_VALIDMASK) != 0) ||
	    ((alist->forkattr & ~ATTR_FORK_VALIDMASK) != 0))
		return EINVAL;

	/*
	* Requesting volume information requires setting the
	* ATTR_VOL_INFO bit. Also, volume info requests are
	* mutually exclusive with all other info requests.
	*/
	if ((alist->volattr != 0) &&
	    (((alist->volattr & ATTR_VOL_INFO) == 0) ||
	     (alist->dirattr != 0) || (alist->fileattr != 0) ||
	     alist->forkattr != 0))
		return EINVAL;

	/*
	* Make sure caller isn't asking for an attibute we don't support.
	*/
	if ((alist->commonattr & ~UFS_ATTR_CMN_SUPPORTED) != 0 ||
	    (alist->volattr & ~(UFS_ATTR_VOL_SUPPORTED | ATTR_VOL_INFO)) != 0 ||
	    (alist->dirattr & ~UFS_ATTR_DIR_SUPPORTED) != 0 ||
	    (alist->fileattr & ~UFS_ATTR_FILE_SUPPORTED) != 0 ||
	    (alist->forkattr & ~UFS_ATTR_FORK_SUPPORTED) != 0)
		return EOPNOTSUPP;

	/*
	 * Requesting volume information requires a vnode for the volume root.
	 */
	if (alist->volattr && (vp->v_flag & VROOT) == 0)
		return EINVAL;

	fixedblocksize = ufs_attrsize(alist);
	attrblocksize = fixedblocksize + (sizeof(u_long));
	if (alist->volattr & ATTR_VOL_NAME)
		attrblocksize += 516;	/* 512 + terminator + padding */
	attrbufsize = MIN(ap->a_uio->uio_resid, attrblocksize);
	MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);
	attrptr = attrbufptr;
	*((u_long *)attrptr) = 0;  /* Set buffer length in case of errors */
	++((u_long *)attrptr);     /* skip over length field */
	varptr = ((char *)attrptr) + fixedblocksize;

	error = ufs_packattr(vp, ap->a_cred, alist, &attrptr, &varptr);

	if (error == 0) {
		/* Don't return more data than was generated */
		attrbufsize = MIN(attrbufsize, (size_t) varptr - (size_t) attrbufptr);
	
		/* Return the actual buffer length */
		*((u_long *) attrbufptr) = attrbufsize;
	
		error = uiomove((caddr_t) attrbufptr, attrbufsize, ap->a_uio);
	}
	
	FREE(attrbufptr, M_TEMP);
	return error;
}


/*
 * Unpack the volume-related attributes from a setattrlist call into the
 * appropriate in-memory and on-disk structures.
 */
static int
ufs_unpackvolattr(
    struct vnode	*vp,
    struct ucred	*cred,
    attrgroup_t		 attrs,
    void		*attrbufptr)
{
	int		 i;
	int		 error;
	attrreference_t *attrref;

	error = 0;

	if (attrs & ATTR_VOL_NAME) {
		char	*name;
		int	 name_length;

		attrref = attrbufptr;
		name = ((char*)attrbufptr) + attrref->attr_dataoffset;
		name_length = strlen(name);
		ufs_set_label(vp, cred, name, name_length);

		/* Advance buffer pointer past attribute reference */
		attrbufptr = ++attrref;
	}

	return error;
}



/*
 * Unpack the attributes from a setattrlist call into the
 * appropriate in-memory and on-disk structures.  Right now,
 * we only support the volume name.
 */
static int
ufs_unpackattr(
    struct vnode	*vp,
    struct ucred	*cred,
    struct attrlist	*alist,
    void		*attrbufptr)
{
	int error;

	error = 0;

	if (alist->volattr != 0) {
		error = ufs_unpackvolattr(vp, cred, alist->volattr,
		    attrbufptr);
	}

	return error;
}



/*
#
#% setattrlist	vp	L L L
#
vop_setattrlist {
	IN struct vnode *vp;
	IN struct attrlist *alist;
	INOUT struct uio *uio;
	IN struct ucred *cred;
	IN struct proc *p;
};
*/
__private_extern__ int
ufs_setattrlist(struct vop_setattrlist_args *ap)
{
	struct vnode	*vp = ap->a_vp;
	struct attrlist	*alist = ap->a_alist;
	size_t		 attrblocksize;
	void		*attrbufptr;
	int		 error;

	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/*
	 * Check the attrlist for valid inputs (i.e. be sure we understand
	 * what caller is asking).
	 */
	if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
	    ((alist->commonattr & ~ATTR_CMN_SETMASK) != 0) ||
	    ((alist->volattr & ~ATTR_VOL_SETMASK) != 0) ||
	    ((alist->dirattr & ~ATTR_DIR_SETMASK) != 0) ||
	    ((alist->fileattr & ~ATTR_FILE_SETMASK) != 0) ||
	    ((alist->forkattr & ~ATTR_FORK_SETMASK) != 0))
		return EINVAL;

	/*
	 * Setting volume information requires setting the
	 * ATTR_VOL_INFO bit. Also, volume info requests are
	 * mutually exclusive with all other info requests.
	 */
	if ((alist->volattr != 0) &&
	    (((alist->volattr & ATTR_VOL_INFO) == 0) ||
	     (alist->dirattr != 0) || (alist->fileattr != 0) ||
	     alist->forkattr != 0))
		return EINVAL;

	/*
	 * Make sure caller isn't asking for an attibute we don't support.
	 * Right now, all we support is setting the volume name.
	 */
	if ((alist->commonattr & ~UFS_ATTR_CMN_SETTABLE) != 0 ||
	    (alist->volattr & ~(UFS_ATTR_VOL_SETTABLE | ATTR_VOL_INFO)) != 0 ||
	    (alist->dirattr & ~UFS_ATTR_DIR_SETTABLE) != 0 ||
	    (alist->fileattr & ~UFS_ATTR_FILE_SETTABLE) != 0 ||
	    (alist->forkattr & ~UFS_ATTR_FORK_SETTABLE) != 0)
		return EOPNOTSUPP;

	/*
	 * Setting volume information requires a vnode for the volume root.
	 */
	if (alist->volattr && (vp->v_flag & VROOT) == 0)
		return EINVAL;

	attrblocksize = ap->a_uio->uio_resid;
	if (attrblocksize < ufs_attrsize(alist))
		return EINVAL;

	MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);

	error = uiomove((caddr_t)attrbufptr, attrblocksize, ap->a_uio);
	if (error)
		goto ErrorExit;

	error = ufs_unpackattr(vp, ap->a_cred, alist, attrbufptr);

ErrorExit:
	FREE(attrbufptr, M_TEMP);
	return error;
}
