/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#ifndef __HFS_CATALOG__
#define __HFS_CATALOG__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/lock.h>

#include <hfs/hfs_format.h>

/* HFS Catalog */


/*
 * Catalog ADTs
 *
 * The cat_desc, cat_attr, and cat_fork structures are
 * use to import/export data to/from the Catalog file.
 * The fields in these structures are always in BSD
 * runtime format (e.g. dates and names).
 */
 
typedef u_int32_t	cnid_t;

/*
 * Catalog Node Descriptor (runtime)
 */
struct cat_desc {
	u_int8_t  cd_flags;       /* see below (8 bits) */
	u_int8_t  cd_encoding;    /* name encoding */
	int16_t   cd_namelen;     /* length of cnode name */
	char *    cd_nameptr;     /* pointer to cnode name */
	cnid_t    cd_parentcnid;  /* parent directory CNID */
	u_long    cd_hint;        /* catalog file hint */
	cnid_t    cd_cnid;        /* cnode id (for getattrlist) */
};

/* cd_flags */
#define	CD_HASBUF	0x01	/* allocated filename buffer */
#define CD_DECOMPOSED	0x02	/* name is fully decomposed */
#define	CD_ISDIR	0x80	/* describes a directory */

/*
 * Catalog Node Attributes (runtime)
 */
struct cat_attr {
	cnid_t		ca_fileid;	/* inode number (for stat) normally == cnid */
	mode_t		ca_mode;	/* file access mode and type (16 bits) */
	nlink_t		ca_nlink;	/* file link count (16 bit integer) */
	uid_t		ca_uid;		/* file owner */
	gid_t		ca_gid;		/* file group */
	dev_t		ca_rdev;	/* device a special file represents */
	time_t		ca_atime;	/* last access time */
	time_t		ca_mtime;	/* last data modification time */
	int32_t		ca_mtime_nsec;	/* last data modification time nanosec */
	time_t		ca_ctime;	/* last file status change */
	time_t		ca_itime;	/* file initialization time */
	time_t		ca_btime;	/* last backup time */
	u_long		ca_flags;	/* status flags (chflags) */
	union {
		u_int32_t  cau_blocks;	/* total file blocks used (rsrc + data) */
		u_int32_t  cau_entries;	/* total directory entries (valence) */
	} ca_union;
	u_int8_t 	ca_finderinfo[32]; /* Opaque Finder information */
};
/* Aliases for common fields */
#define	ca_blocks	ca_union.cau_blocks
#define	ca_entries	ca_union.cau_entries

/*
 * Catalog Node Fork (runtime + on disk)
 */
struct cat_fork {
	u_int64_t	cf_size;	/* fork's logical size in bytes */
	u_int32_t	cf_clump;	/* fork's clump size in bytes */
	u_int32_t	cf_blocks;	/* total blocks used by this fork */
	struct HFSPlusExtentDescriptor	cf_extents[8];	/* initial set of extents */
};


/*
 * Catalog Node Entry
 *
 * A cat_entry is used for bulk enumerations (hfs_readdirattr).
 */
struct cat_entry {
	struct cat_desc	ce_desc;
	struct cat_attr	ce_attr;
	off_t		ce_datasize;
	off_t		ce_rsrcsize;
	u_long		ce_datablks;
	u_long		ce_rsrcblks;
};

#define MAXCATENTRIES 8
/*
 * Catalog Node Entry List
 *
 * A cat_entrylist is a list of Catalog Node Entries.
 */
struct cat_entrylist {
	u_long  maxentries;    /* length of list */
	u_long  realentries;   /* valid entry count */
	struct cat_entry  entry[MAXCATENTRIES];   /* array of entries */
};

/*
 * Catalog Interface
 *
 * These functions perform a catalog transactions. The
 * catalog b-tree is abstracted through this interface.
 * (please don't go around it)
 */

struct hfsmount;

extern void cat_releasedesc(struct cat_desc *descp);

extern int cat_create (	struct hfsmount *hfsmp,
			struct cat_desc *descp,
			struct cat_attr *attrp,
			struct cat_desc *out_descp);

extern int cat_delete (	struct hfsmount *hfsmp,
			struct cat_desc *descp,
			struct cat_attr *attrp);

extern int cat_lookup (	struct hfsmount *hfsmp,
			struct cat_desc *descp,
			int wantrsrc,
			struct cat_desc *outdescp,
			struct cat_attr *attrp,
			struct cat_fork *forkp);

extern int cat_idlookup (struct hfsmount *hfsmp,
			cnid_t cnid,
			struct cat_desc *outdescp,
			struct cat_attr *attrp,
			struct cat_fork *forkp);

extern int cat_getentriesattr(
			struct hfsmount *hfsmp,
			struct cat_desc *prevdesc,
			int index,
			struct cat_entrylist *ce_list);

extern int cat_rename (	struct hfsmount * hfsmp,
			struct cat_desc * from_cdp,
			struct cat_desc * todir_cdp,
			struct cat_desc * to_cdp,
			struct cat_desc * cdp);

extern int cat_update (	struct hfsmount *hfsmp,
			struct cat_desc *descp,
			struct cat_attr *attrp,
			struct cat_fork *dataforkp,
			struct cat_fork *rsrcforkp);

extern int cat_getdirentries(
			struct hfsmount *hfsmp,
			struct cat_desc *descp,
			struct uio *uio,
			int *eofflag);

extern int cat_insertfilethread (
			struct hfsmount *hfsmp,
			struct cat_desc *descp);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __HFS_CATALOG__ */
