/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
 * attr.h - attribute data structures and interfaces
 *
 * Copyright (c) 1998, Apple Computer, Inc.  All Rights Reserved.
 */

#ifndef _SYS_ATTR_H_
#define _SYS_ATTR_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE
#ifndef _SYS_TYPES_H_
#include <sys/types.h>
#endif
#ifndef _SYS_UCRED_H
#include <sys/ucred.h>
#endif
#ifndef _SYS_MOUNT_H_
#include <sys/mount.h>
#endif
#ifndef _SYS_TIME_H_
#include <sys/time.h>
#endif

#define FSOPT_NOFOLLOW 		0x00000001
#define FSOPT_NOINMEMUPDATE 0x00000002

typedef u_int32_t text_encoding_t;

typedef u_int32_t fsobj_type_t;

typedef u_int32_t fsobj_tag_t;

typedef u_int32_t fsfile_type_t;

typedef u_int32_t fsvolid_t;

typedef struct fsobj_id {
	u_int32_t		fid_objno;
	u_int32_t		fid_generation;
} fsobj_id_t;

typedef u_int32_t attrgroup_t;

struct attrlist {
	u_short bitmapcount;			/* number of attr. bit sets in list (should be 5) */
	u_int16_t reserved;				/* (to maintain 4-byte alignment) */
	attrgroup_t commonattr;			/* common attribute group */
	attrgroup_t volattr;			/* Volume attribute group */
	attrgroup_t dirattr;			/* directory attribute group */
	attrgroup_t fileattr;			/* file attribute group */
	attrgroup_t forkattr;			/* fork attribute group */
};
#define ATTR_BIT_MAP_COUNT 5

typedef struct attribute_set {
	attrgroup_t commonattr;			/* common attribute group */
	attrgroup_t volattr;			/* Volume attribute group */
	attrgroup_t dirattr;			/* directory attribute group */
	attrgroup_t fileattr;			/* file attribute group */
	attrgroup_t forkattr;			/* fork attribute group */
} attribute_set_t;

typedef struct attrreference {
	long attr_dataoffset;
	size_t attr_length;
} attrreference_t;

/* XXX PPD This is derived from HFSVolumePriv.h and should perhaps be referenced from there? */

struct diskextent {
	u_int32_t					startblock;				/* first block allocated */
	u_int32_t					blockcount;				/* number of blocks allocated */
};

typedef struct diskextent extentrecord[8];

typedef u_int32_t vol_capabilities_set_t[4];

#define VOL_CAPABILITIES_FORMAT 0
#define VOL_CAPABILITIES_INTERFACES 1
#define VOL_CAPABILITIES_RESERVED1 2
#define VOL_CAPABILITIES_RESERVED2 3

typedef struct vol_capabilities_attr {
	vol_capabilities_set_t capabilities;
	vol_capabilities_set_t valid;
} vol_capabilities_attr_t;

#define VOL_CAP_FMT_PERSISTENTOBJECTIDS 0x00000001
#define VOL_CAP_FMT_SYMBOLICLINKS 0x00000002
#define VOL_CAP_FMT_HARDLINKS 0x00000004

#define VOL_CAP_INT_SEARCHFS 0x00000001
#define VOL_CAP_INT_ATTRLIST 0x00000002
#define VOL_CAP_INT_NFSEXPORT 0x00000004
#define VOL_CAP_INT_READDIRATTR 0x00000008

typedef struct vol_attributes_attr {
	attribute_set_t validattr;
	attribute_set_t nativeattr;
} vol_attributes_attr_t;

#define DIR_MNTSTATUS_MNTPOINT		0x00000001

#define ATTR_CMN_NAME				0x00000001
#define ATTR_CMN_DEVID				0x00000002
#define ATTR_CMN_FSID				0x00000004
#define ATTR_CMN_OBJTYPE			0x00000008
#define ATTR_CMN_OBJTAG				0x00000010
#define ATTR_CMN_OBJID				0x00000020
#define ATTR_CMN_OBJPERMANENTID		0x00000040
#define ATTR_CMN_PAROBJID			0x00000080
#define ATTR_CMN_SCRIPT				0x00000100
#define ATTR_CMN_CRTIME				0x00000200
#define ATTR_CMN_MODTIME			0x00000400
#define ATTR_CMN_CHGTIME			0x00000800
#define ATTR_CMN_ACCTIME			0x00001000
#define ATTR_CMN_BKUPTIME			0x00002000
#define ATTR_CMN_FNDRINFO			0x00004000
#define ATTR_CMN_OWNERID			0x00008000
#define ATTR_CMN_GRPID				0x00010000
#define ATTR_CMN_ACCESSMASK			0x00020000
#define ATTR_CMN_FLAGS				0x00040000
#define ATTR_CMN_NAMEDATTRCOUNT		0x00080000
#define ATTR_CMN_NAMEDATTRLIST		0x00100000
#define ATTR_CMN_USERACCESS			0x00200000

#define ATTR_CMN_VALIDMASK			0x003FFFFF
#define ATTR_CMN_SETMASK			0x0007FF00
#define ATTR_CMN_VOLSETMASK			0x00006700

#define ATTR_VOL_FSTYPE				0x00000001
#define ATTR_VOL_SIGNATURE			0x00000002
#define ATTR_VOL_SIZE				0x00000004
#define ATTR_VOL_SPACEFREE			0x00000008
#define ATTR_VOL_SPACEAVAIL			0x00000010
#define ATTR_VOL_MINALLOCATION		0x00000020
#define ATTR_VOL_ALLOCATIONCLUMP	0x00000040
#define ATTR_VOL_IOBLOCKSIZE		0x00000080
#define ATTR_VOL_OBJCOUNT			0x00000100
#define ATTR_VOL_FILECOUNT			0x00000200
#define ATTR_VOL_DIRCOUNT			0x00000400
#define ATTR_VOL_MAXOBJCOUNT		0x00000800
#define ATTR_VOL_MOUNTPOINT			0x00001000
#define ATTR_VOL_NAME				0x00002000
#define ATTR_VOL_MOUNTFLAGS			0x00004000
#define ATTR_VOL_MOUNTEDDEVICE		0x00008000
#define ATTR_VOL_ENCODINGSUSED		0x00010000
#define ATTR_VOL_CAPABILITIES		0x00020000
#define ATTR_VOL_ATTRIBUTES			0x40000000
#define ATTR_VOL_INFO				0x80000000

#define ATTR_VOL_VALIDMASK			0xC003FFFF
#define ATTR_VOL_SETMASK			0x80002000


/* File/directory attributes: */
#define ATTR_DIR_LINKCOUNT			0x00000001
#define ATTR_DIR_ENTRYCOUNT			0x00000002
#define ATTR_DIR_MOUNTSTATUS		0x00000004

#define ATTR_DIR_VALIDMASK			0x00000007
#define ATTR_DIR_SETMASK			0x00000000

#define ATTR_FILE_LINKCOUNT			0x00000001
#define ATTR_FILE_TOTALSIZE			0x00000002
#define ATTR_FILE_ALLOCSIZE			0x00000004
#define ATTR_FILE_IOBLOCKSIZE		0x00000008
#define ATTR_FILE_CLUMPSIZE			0x00000010
#define ATTR_FILE_DEVTYPE			0x00000020
#define ATTR_FILE_FILETYPE			0x00000040
#define ATTR_FILE_FORKCOUNT			0x00000080
#define ATTR_FILE_FORKLIST			0x00000100
#define ATTR_FILE_DATALENGTH		0x00000200
#define ATTR_FILE_DATAALLOCSIZE		0x00000400
#define ATTR_FILE_DATAEXTENTS		0x00000800
#define ATTR_FILE_RSRCLENGTH		0x00001000
#define ATTR_FILE_RSRCALLOCSIZE		0x00002000
#define ATTR_FILE_RSRCEXTENTS		0x00004000

#define ATTR_FILE_VALIDMASK			0x00007FFF
#define ATTR_FILE_SETMASK			0x00000020

#define ATTR_FORK_TOTALSIZE			0x00000001
#define ATTR_FORK_ALLOCSIZE			0x00000002

#define ATTR_FORK_VALIDMASK			0x00000003
#define ATTR_FORK_SETMASK			0x00000000

#define SRCHFS_START 					0x00000001
#define SRCHFS_MATCHPARTIALNAMES 		0x00000002
#define SRCHFS_MATCHDIRS 				0x00000004
#define SRCHFS_MATCHFILES 				0x00000008
#define SRCHFS_NEGATEPARAMS 			0x80000000
#define SRCHFS_VALIDOPTIONSMASK			0x8000000F

struct fssearchblock {
	struct attrlist		*returnattrs;
	void				*returnbuffer;
	size_t				returnbuffersize;
	u_long				maxmatches;
	struct timeval		timelimit;
	void				*searchparams1;
	size_t				sizeofsearchparams1;
	void				*searchparams2;
	size_t				sizeofsearchparams2;
	struct attrlist		searchattrs;
};


struct searchstate {
	u_char				reserved[556];		//	sizeof( SearchState )
};


#define FST_EOF (-1)				/* end-of-file offset */

#endif /* __APPLE_API_UNSTABLE */
#endif /* !_SYS_ATTR_H_ */
