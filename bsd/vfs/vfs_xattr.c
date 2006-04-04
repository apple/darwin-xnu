/*
 * Copyright (c) 2004-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/fsevents.h>
#include <sys/kernel.h>
#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utfconv.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>

#include <sys/xattr.h>

#include <architecture/byte_order.h>
#include <vm/vm_kern.h>

/*
 * Default xattr support routines.
 */
static int default_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size,
                            int options, vfs_context_t context);

static int default_setxattr(vnode_t vp, const char *name, uio_t uio,
                            int options, vfs_context_t context);

static int default_removexattr(vnode_t vp, const char *name, int options, vfs_context_t context);

static int default_listxattr(vnode_t vp, uio_t uio, size_t *size, int options,
                             vfs_context_t context);



/*
 *  Retrieve the data of an extended attribute.
 */
int
vn_getxattr(vnode_t vp, const char *name, uio_t uio, size_t *size,
            int options, vfs_context_t context)
{
	int error;

	if (!(vp->v_type == VREG || vp->v_type == VDIR || vp->v_type == VLNK)) {
		return (EPERM);
	}
	if ((error = xattr_validatename(name))) {
		return (error);
	}
	if (!(options & XATTR_NOSECURITY) && (error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context)))
		goto out;

	/* The offset can only be non-zero for resource forks. */
	if (uio != NULL && uio_offset(uio) != 0 && 
	    bcmp(name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) != 0) {
		error = EINVAL;
		goto out;
	}

	error = VNOP_GETXATTR(vp, name, uio, size, options, context);
	if (error == ENOTSUP) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 * SMB returns ENOTSUP for finderinfo and resource forks.
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

	if (!(vp->v_type == VREG || vp->v_type == VDIR || vp->v_type == VLNK)) {
		return (EPERM);
	}
	if ((options & (XATTR_REPLACE|XATTR_CREATE)) == (XATTR_REPLACE|XATTR_CREATE)) {
		return (EINVAL);
	}
	if ((error = xattr_validatename(name))) {
		return (error);
	}
 	if (!(options & XATTR_NOSECURITY) && (error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context)))
		goto out;

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
	if (error == ENOTSUP) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 * SMB returns ENOTSUP for finderinfo and resource forks.
		 */
		error = default_setxattr(vp, name, uio, options, context);
	}
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

	if (!(vp->v_type == VREG || vp->v_type == VDIR || vp->v_type == VLNK)) {
		return (EPERM);
	}
	if ((error = xattr_validatename(name))) {
		return (error);
	}
	if (!(options & XATTR_NOSECURITY) && (error = vnode_authorize(vp, NULL, KAUTH_VNODE_WRITE_EXTATTRIBUTES, context)))
		goto out;
	error = VNOP_REMOVEXATTR(vp, name, options, context);
	if (error == ENOTSUP) {
		/*
		 * A filesystem may keep some EAs natively and return ENOTSUP for others.
		 * SMB returns ENOTSUP for finderinfo and resource forks.
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

	if (!(vp->v_type == VREG || vp->v_type == VDIR || vp->v_type == VLNK)) {
		return (EPERM);
	}
	if (!(options & XATTR_NOSECURITY) && (error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_EXTATTRIBUTES, context)))
		goto out;

	error = VNOP_LISTXATTR(vp, uio, size, options, context);
	if (error == ENOTSUP) {
		/*
		 * A filesystem may keep some but not all EAs natively, in which case
		 * the native EA names will have been uiomove-d out (or *size updated)
		 * and the default_listxattr here will finish the job.  Note SMB takes
		 * advantage of this for its finder-info and resource forks.
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
	namelen = strlen(name);
	if (namelen > XATTR_MAXNAMELEN) {
		return (ENAMETOOLONG);
	}
	if (utf8_validatestr(name, namelen) != 0) {
		return (EINVAL);
	}
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
#define ATTR_MAX_SIZE      (128*1024)  /* 128K maximum attribute data size */
#define ATTR_MAX_HDR_SIZE  65536
/*
 * Note: ATTR_MAX_HDR_SIZE is the largest attribute header
 * size supported (including the attribute entries). All of
 * the attribute entries must reside within this limit.  If
 * any of the attribute data crosses the ATTR_MAX_HDR_SIZE
 * boundry, then all of the attribute data I/O is performed
 * seperately from the attribute header I/O.
 */


#pragma options align=mac68k

#define FINDERINFOSIZE	32

typedef struct apple_double_entry {
	u_int32_t   type;     /* entry type: see list, 0 invalid */ 
	u_int32_t   offset;   /* entry data offset from the beginning of the file. */
 	u_int32_t   length;   /* entry data length in bytes. */
} apple_double_entry_t;


typedef struct apple_double_header {
	u_int32_t   magic;         /* == ADH_MAGIC */
	u_int32_t   version;       /* format version: 2 = 0x00020000 */ 
	u_int32_t   filler[4];
	u_int16_t   numEntries;	   /* number of entries which follow */ 
	apple_double_entry_t   entries[2];  /* 'finfo' & 'rsrc' always exist */
	u_int8_t    finfo[FINDERINFOSIZE];  /* Must start with Finder Info (32 bytes) */
	u_int8_t    pad[2];        /* get better alignment inside attr_header */
} apple_double_header_t;

#define ADHDRSIZE  (4+4+16+2)

/* Entries are aligned on 4 byte boundaries */
typedef struct attr_entry {
	u_int32_t   offset;     /* file offset to data */
	u_int32_t   length;     /* size of attribute data */
	u_int16_t   flags;
	u_int8_t    namelen;
	u_int8_t    name[1];    /* NULL-terminated UTF-8 name (up to 128 bytes max) */
} attr_entry_t;


/* Header + entries must fit into 64K */
typedef struct attr_header {
	apple_double_header_t  appledouble;
	u_int32_t   magic;        /* == ATTR_HDR_MAGIC */
	u_int32_t   debug_tag;    /* for debugging == file id of owning file */
	u_int32_t   total_size;   /* total size of attribute header + entries + data */ 
	u_int32_t   data_start;   /* file offset to attribute data area */
	u_int32_t   data_length;  /* length of attribute data area */
	u_int32_t   reserved[3];
	u_int16_t   flags;
	u_int16_t   num_attrs;
} attr_header_t;


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
} rsrcfork_header_t;

#define RF_FIRST_RESOURCE    256
#define RF_NULL_MAP_LENGTH    30
#define RF_EMPTY_TAG  "This resource fork intentionally left blank   "

#pragma options align=reset

/* Runtime information about the attribute file. */
typedef struct attr_info {
	vfs_context_t          context;
	vnode_t                filevp;
	size_t                 filesize;
	size_t                 iosize;
	u_int8_t               *rawdata;
	size_t                 rawsize;  /* raw size of AppleDouble file */
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


#define SWAP16(x)  NXSwapBigShortToHost((x))
#define SWAP32(x)  NXSwapBigIntToHost((x))
#define SWAP64(x)  NXSwapBigLongLongToHost((x))


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
  static void  swap_attrhdr(attr_header_t *ah);

#else
#define swap_adhdr(x)
#define swap_attrhdr(x)
#endif

static int  validate_attrhdr(attr_header_t *ah, size_t bufsize);
static int  shift_data_down(vnode_t xvp, off_t start, size_t len, off_t delta, vfs_context_t context);
static int  shift_data_up(vnode_t xvp, off_t start, size_t len, off_t delta, vfs_context_t context);


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
		if (strncmp(entry->name, name, namelen) == 0) {
			datalen = (size_t)entry->length;
			if (uio == NULL) {
				*size = datalen;
				error = 0;
				break;
			}
			if (uio_resid(uio) < datalen) {
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

	datalen = uio_resid(uio);
	namelen = strlen(name) + 1;
	entrylen = ATTR_ENTRY_LENGTH(namelen);

	if (datalen > ATTR_MAX_SIZE) {
		return (E2BIG);  /* EINVAL instead ? */
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
		if (uio_offset(uio) != 0 || datalen != FINDERINFOSIZE) {
			error = EINVAL;
			goto out;
		}
		if (ainfo.finderinfo) {
			attrdata = (u_int8_t *)ainfo.filehdr + ainfo.finderinfo->offset;
			error = uiomove((caddr_t)attrdata, datalen, uio);
			if (error)
				goto out;
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
		if (ainfo.rsrcfork && ainfo.rsrcfork->length) {
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
		if (strncmp(entry->name, name, namelen) == 0) {
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
				goto out;
			}
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
		if (strncmp(entry->name, name, namelen) == 0) {
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
		close_xattrfile(xvp, FREAD, context);
		return (error);
	}

	/* Check for Finder Info. */
	if (ainfo.finderinfo && !ainfo.emptyfinderinfo) {
		if (uio == NULL) {
			*size += sizeof(XATTR_FINDERINFO_NAME);
		} else if (uio_resid(uio) < sizeof(XATTR_FINDERINFO_NAME)) {
			error = ERANGE;
			goto out;
		} else {
			error = uiomove((caddr_t)XATTR_FINDERINFO_NAME,
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
		} else if (uio_resid(uio) < sizeof(XATTR_RESOURCEFORK_NAME)) {
			error = ERANGE;
			goto out;
		} else {
			error = uiomove((caddr_t)XATTR_RESOURCEFORK_NAME,
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
			if (xattr_protected(entry->name) ||
			    xattr_validatename(entry->name) != 0) {
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
	char *basename = NULL;
	size_t len;
	errno_t error;
	int opened = 0;
	int referenced = 0;

	if (vnode_isvroot(vp) && vnode_isdir(vp)) {
		/*
		 * For the root directory use "._." to hold the attributes.
		 */
		filename = &smallname[0];
		sprintf(filename, "%s%s", ATTR_FILE_PREFIX, ".");
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
	NDINIT(&nd, LOOKUP, LOCKLEAF | NOFOLLOW | USEDVP | DONOTAUTH, UIO_SYSSPACE,
	       CAST_USER_ADDR_T(filename), context);
   	nd.ni_dvp = dvp;

	if (fileflags & O_CREAT) {
		nd.ni_cnd.cn_nameiop = CREATE;
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

			error = vn_create(dvp, &nd.ni_vp, &nd.ni_cnd, &va,
			                  VN_CREATE_NOAUTH | VN_CREATE_NOINHERIT,
			                  context);
			if (error == 0)
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
	
	if ( (error = VNOP_OPEN(xvp, fileflags, context))) {
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
	}
out:
	if (dvp && (dvp != vp)) {
		vnode_put(dvp);
	}
	if (basename) {
		vnode_putname(basename);
	}
	if (filename && filename != &smallname[0]) {
		FREE(filename, M_TEMP);
	}
	if (error) {
		if (xvp != NULLVP) {
			if (opened) {
				(void) VNOP_CLOSE(xvp, fileflags, context);
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
	char *path;
	int pathlen;
	int error = 0;

	path = get_pathbuff();
	pathlen = MAXPATHLEN;
	vn_getpath(xvp, path, &pathlen);

	NDINIT(&nd, DELETE, LOCKPARENT | NOFOLLOW | DONOTAUTH,
	       UIO_SYSSPACE, CAST_USER_ADDR_T(path), context);
	error = namei(&nd);
	release_pathbuff(path);
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

static int
get_xattrinfo(vnode_t xvp, int setting, attr_info_t *ainfop, vfs_context_t context)
{
	uio_t auio = NULL;
	void * buffer = NULL;
	apple_double_header_t  *filehdr;
	attr_header_t *attrhdr;
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
	auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_READ);
	uio_addiov(auio, (uintptr_t)buffer, iosize);

	/* Read the file header. */
	error = VNOP_READ(xvp, auio, 0, context);
	if (error) {
		goto bail;
	}
	ainfop->rawsize = iosize - uio_resid(auio);
	ainfop->rawdata = (u_int8_t *)buffer;
	
	filehdr = (apple_double_header_t *)buffer;

	/* Check for Apple Double file. */
	if (SWAP32(filehdr->magic) != ADH_MAGIC ||
	    SWAP32(filehdr->version) != ADH_VERSION ||
	    SWAP16(filehdr->numEntries) < 1 ||
	    SWAP16(filehdr->numEntries) > 15) {
		error = ENOATTR;
		goto bail;
	}
	if (ADHDRSIZE + (SWAP16(filehdr->numEntries) * sizeof(apple_double_entry_t)) > ainfop->rawsize) {
		error = EINVAL;
		goto bail;
	}

	swap_adhdr(filehdr);
	ainfop->filehdr = filehdr;  /* valid AppleDouble header */
	/* rel_xattrinfo is responsible for freeing the header buffer */
	buffer = NULL;

	/* Check the AppleDouble entries. */
	for (i = 0; i < filehdr->numEntries; ++i) {
		if (filehdr->entries[i].type == AD_FINDERINFO &&
		    filehdr->entries[i].length > 0) {
			ainfop->finderinfo = &filehdr->entries[i];
			attrhdr = (attr_header_t *)filehdr;

	    		if (bcmp((u_int8_t*)ainfop->filehdr + ainfop->finderinfo->offset,
	    		         emptyfinfo, sizeof(emptyfinfo)) == 0) {
				ainfop->emptyfinderinfo = 1;
			}

			if (i != 0) {
				continue;
			}
			/* See if we need to convert this AppleDouble file. */
			if (filehdr->entries[0].length == FINDERINFOSIZE) {
				size_t delta;
				size_t writesize;

				if (!setting ||
				    filehdr->entries[1].type != AD_RESOURCE ||
				    filehdr->numEntries > 2) {
					continue;  /* not expected layout */
				}
				delta = ATTR_BUF_SIZE - (filehdr->entries[0].offset + FINDERINFOSIZE);
				if (filehdr->entries[1].length) {
					/* Make some room. */
					shift_data_down(xvp,
							filehdr->entries[1].offset,
							filehdr->entries[1].length,
							delta, context);
					writesize = sizeof(attr_header_t);
				} else {
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
				uio_reset(auio, 0, UIO_SYSSPACE32, UIO_WRITE);
				uio_addiov(auio, (uintptr_t)filehdr, writesize);

				swap_adhdr(filehdr);
				swap_attrhdr(attrhdr);
				error = VNOP_WRITE(xvp, auio, 0, context);
				swap_adhdr(filehdr);
				/* The attribute header gets swapped below. */
			}
			if (SWAP32 (attrhdr->magic) != ATTR_HDR_MAGIC ||
			    validate_attrhdr(attrhdr, ainfop->rawsize) != 0) {
				printf("get_xattrinfo: invalid attribute header\n");
				continue;
			}
			swap_attrhdr(attrhdr);
			ainfop->attrhdr = attrhdr;  /* valid attribute header */
			ainfop->attr_entry = (attr_entry_t *)&attrhdr[1];
			continue;
		}
		if (filehdr->entries[i].type == AD_RESOURCE &&
		    (filehdr->entries[i].length > sizeof(rsrcfork_header_t) || setting)) {
			ainfop->rsrcfork = &filehdr->entries[i];
			if (i != (filehdr->numEntries - 1)) {
				printf("get_xattrinfo: resource fork not last entry\n");
				ainfop->readonly = 1;
			}
			continue;
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
	auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_WRITE);
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
	error = VNOP_WRITE(xvp, auio, 0, context);

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

	auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_WRITE);
	uio_addiov(auio, (uintptr_t)ainfop->filehdr, ainfop->iosize);

	swap_adhdr(ainfop->filehdr);
	swap_attrhdr(ainfop->attrhdr);

	error = VNOP_WRITE(ainfop->filevp, auio, 0, ainfop->context);

	swap_adhdr(ainfop->filehdr);
	swap_attrhdr(ainfop->attrhdr);
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
swap_attrhdr(attr_header_t *ah)
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
	for (i = 0; i < count; i++, ae = ATTR_NEXT(ae)) {
		ae->offset = SWAP32 (ae->offset);
		ae->length = SWAP32 (ae->length);
		ae->flags  = SWAP16 (ae->flags);
	}
}
#endif

/*
 * Validate attributes header contents
 */
static int
validate_attrhdr(attr_header_t *ah, size_t bufsize)
{
	attr_entry_t *ae;
	u_int8_t *bufend;
	int count;
	int i;

	if (ah == NULL)
		return (EINVAL);

	bufend = (u_int8_t *)ah + bufsize;
	count = (ah->magic == ATTR_HDR_MAGIC) ? ah->num_attrs : SWAP16(ah->num_attrs);

	ae = (attr_entry_t *)(&ah[1]);
	for (i = 0; i < count && (u_int8_t *)ae < bufend; i++, ae = ATTR_NEXT(ae)) {
	}
	return (i < count ? EINVAL : 0);
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
	ucred_t ucred = vfs_context_ucred(context);
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
		ret = vn_rdwr(UIO_READ, xvp, buff, chunk, pos, UIO_SYSSPACE, IO_NODELOCKED, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error reading data @ %lld (read %d of %d) (%d)\n",
				pos, ret, chunk, ret);
			break;
		}
		
		ret = vn_rdwr(UIO_WRITE, xvp, buff, chunk, pos + delta, UIO_SYSSPACE, IO_NODELOCKED, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error writing data @ %lld (wrote %d of %d) (%d)\n",
				pos+delta, ret, chunk, ret);
			break;
		}
		
		if ((pos - chunk) < start) {
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
	ucred_t ucred = vfs_context_ucred(context);
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
		ret = vn_rdwr(UIO_READ, xvp, buff, chunk, pos, UIO_SYSSPACE, IO_NODELOCKED, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error reading data @ %lld (read %d of %d) (%d)\n",
				pos, ret, chunk, ret);
			break;
		}
		
		ret = vn_rdwr(UIO_WRITE, xvp, buff, chunk, pos - delta, UIO_SYSSPACE, IO_NODELOCKED, ucred, &iolen, p);
		if (iolen != 0) {
			printf("xattr:shift_data: error writing data @ %lld (wrote %d of %d) (%d)\n",
				pos+delta, ret, chunk, ret);
			break;
		}
		
		if ((pos + chunk) > end) {
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

	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	lf.l_type = locktype; /* F_WRLCK or F_RDLCK */
	/* Note: id is just a kernel address that's not a proc */
	return  VNOP_ADVLOCK(xvp, (caddr_t)xvp, F_SETLK, &lf, F_FLOCK, context);
}

static int
unlock_xattrfile(vnode_t xvp, vfs_context_t context)
{
	struct flock lf;

	lf.l_whence = SEEK_SET;
	lf.l_start = 0;
	lf.l_len = 0;
	lf.l_type = F_UNLCK;
	/* Note: id is just a kernel address that's not a proc */
	return  VNOP_ADVLOCK(xvp, (caddr_t)xvp, F_UNLCK, &lf, F_FLOCK, context);
}

