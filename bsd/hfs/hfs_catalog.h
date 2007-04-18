/*
 * Copyright (c) 2002-2005 Apple Computer, Inc. All rights reserved.
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
#ifndef __HFS_CATALOG__
#define __HFS_CATALOG__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/vnode.h>

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
#define	CD_ISMETA	0x40	/* describes a metadata file */
#define	CD_ISDIR	0x80	/* describes a directory */

/*
 * Catalog Node Attributes (runtime)
 */
struct cat_attr {
	cnid_t		ca_fileid;	/* inode number (for stat) normally == cnid */
	mode_t		ca_mode;	/* file access mode and type (16 bits) */
	u_int16_t	ca_recflags;	/* catalog record flags (16 bit integer) */
	u_int32_t	ca_nlink;	/* file link count */
	uid_t		ca_uid;		/* file owner */
	gid_t		ca_gid;		/* file group */
	dev_t		ca_rdev;	/* device a special file represents */
	time_t		ca_atime;	/* last access time */
	time_t		ca_atimeondisk;	/* access time value on disk */
	time_t		ca_mtime;	/* last data modification time */
	time_t		ca_ctime;	/* last file status change */
	time_t		ca_itime;	/* file initialization time */
	time_t		ca_btime;	/* last backup time */
	u_int32_t	ca_flags;	/* status flags (chflags) */
	union {
		u_int32_t  cau_blocks;	/* total file blocks used (rsrc + data) */
		u_int32_t  cau_entries;	/* total directory entries (valence) */
	} ca_union;
	u_int8_t 	ca_finderinfo[32]; /* Opaque Finder information */
	u_int32_t	ca_attrblks;    /* cached count of attribute data blocks */
};
/* Aliases for common fields */
#define	ca_blocks	ca_union.cau_blocks
#define	ca_entries	ca_union.cau_entries

/*
 * Catalog Node Fork (runtime)
 *
 * NOTE: this is not the same as a struct HFSPlusForkData
 */
struct cat_fork {
	u_int64_t      cf_size;        /* fork's logical size in bytes */
	union {
	    u_int32_t  cfu_clump;      /* fork's clump size in bytes (sys files only) */
	    u_int64_t  cfu_bytesread;  /* bytes read from this fork */
	} cf_union;
	u_int32_t      cf_vblocks;     /* virtual (unalloated) blocks */
	u_int32_t      cf_blocks;      /* total blocks used by this fork */
	struct HFSPlusExtentDescriptor  cf_extents[8];  /* initial set of extents */
};

#define cf_clump	cf_union.cfu_clump
#define cf_bytesread	cf_union.cfu_bytesread


/*
 * Directory Hint
 * Used to hold state across directory enumerations.
 *
 */
struct directoryhint {
	TAILQ_ENTRY(directoryhint) dh_link; /* chain */
	int     dh_index;                   /* index into directory (zero relative) */
	u_int32_t  dh_time;
	struct  cat_desc  dh_desc;          /* entry's descriptor */
};
typedef struct directoryhint directoryhint_t;

/* 
 * HFS_MAXDIRHINTS cannot be larger than 63 without reducing
 * HFS_INDEX_BITS, because given the 6-bit tag, at most 63 different
 * tags can exist.  When HFS_MAXDIRHINTS is larger than 63, the same
 * list may contain dirhints of the same tag, and a staled dirhint may
 * be returned.
 */
#define HFS_MAXDIRHINTS 32
#define HFS_DIRHINT_TTL 45

#define HFS_INDEX_MASK  0x03ffffff
#define HFS_INDEX_BITS  26


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
 * Catalog Operations Hint
 *
 * lower 16 bits: count of B-tree insert operations
 * upper 16 bits: count of B-tree delete operations
 *
 */
#define CAT_DELETE	0x00020000
#define CAT_CREATE	0x00000002
#define CAT_RENAME	0x00020002
#define CAT_EXCHANGE	0x00020002

typedef u_int32_t	catops_t;

/*
 * The size of cat_cookie_t much match the size of
 * the nreserve struct (in BTreeNodeReserve.c).
 */
typedef	struct cat_cookie_t {
	char	opaque[24];
} cat_cookie_t;

/* Universal catalog key */
union CatalogKey {
	HFSCatalogKey      hfs;
	HFSPlusCatalogKey  hfsPlus;
};
typedef union CatalogKey  CatalogKey;

/* Universal catalog data record */
union CatalogRecord {
	int16_t               recordType;
	HFSCatalogFolder      hfsFolder;
	HFSCatalogFile        hfsFile;
	HFSCatalogThread      hfsThread;
	HFSPlusCatalogFolder  hfsPlusFolder;
	HFSPlusCatalogFile    hfsPlusFile;
	HFSPlusCatalogThread  hfsPlusThread;
};
typedef union CatalogRecord  CatalogRecord;


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
			struct cat_fork *forkp,
    			cnid_t          *desc_cnid);

extern int cat_idlookup (struct hfsmount *hfsmp,
			cnid_t cnid,
			struct cat_desc *outdescp,
			struct cat_attr *attrp,
			struct cat_fork *forkp);

extern int cat_findname (struct hfsmount *hfsmp,
                         cnid_t cnid,
                         struct cat_desc *outdescp);

extern int cat_getentriesattr(
			struct hfsmount *hfsmp,
			directoryhint_t *dirhint,
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
			int entrycnt,
			directoryhint_t *dirhint,
			uio_t uio,
			int extended,
			int * items,
			int * eofflag);

extern int cat_insertfilethread (
			struct hfsmount *hfsmp,
			struct cat_desc *descp);

extern int cat_preflight(
			struct hfsmount *hfsmp,
			catops_t ops,
			cat_cookie_t *cookie,
			struct proc *p);

extern void cat_postflight(
			struct hfsmount *hfsmp,
			cat_cookie_t *cookie,
			struct proc *p);

extern int cat_binarykeycompare(
			HFSPlusCatalogKey *searchKey,
			HFSPlusCatalogKey *trialKey);

extern int CompareCatalogKeys(
			HFSCatalogKey *searchKey,
			HFSCatalogKey *trialKey);

extern int CompareExtendedCatalogKeys(
			HFSPlusCatalogKey *searchKey,
			HFSPlusCatalogKey *trialKey);

extern void cat_convertattr(
			struct hfsmount *hfsmp,
			CatalogRecord * recp,
			struct cat_attr *attrp,
			struct cat_fork *datafp,
			struct cat_fork *rsrcfp);

extern int cat_convertkey(
			struct hfsmount *hfsmp,
			CatalogKey *key,
			CatalogRecord * recp,
			struct cat_desc *descp);

extern int resolvelink(
			struct hfsmount *hfsmp,
			u_long linkref,
			struct HFSPlusCatalogFile *recp);

extern int cat_getkeyplusattr(
			struct hfsmount *hfsmp, 
			cnid_t cnid, 
			CatalogKey *key, 
			struct cat_attr *attrp);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __HFS_CATALOG__ */
