/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1991 by NeXT Computer, Inc.
 *
 *	File:	bsd/dev/disk_label.h - NeXT disk label definition.
 *
 */

#ifndef	_BSD_DEV_DISK_LABEL_
#define	_BSD_DEV_DISK_LABEL_

#include <sys/appleapiopts.h>
#include <sys/disktab.h>

#ifdef	__APPLE_API_OBSOLETE

#define	NLABELS		4		/* # of labels on a disk */
#define	MAXLBLLEN	24		/* dl_label[] size */
#define	NBAD		1670		/* sized to make label ~= 8KB */

/*
 *  if dl_version >= DL_V3 then the bad block table is relocated
 *  to a structure separate from the disk label.
 */
typedef union {
	unsigned short	DL_v3_checksum;
	int	DL_bad[NBAD];			/* block number that is bad */
} dl_un_t;

typedef struct disk_label {
	int		dl_version;		// label version number
	int		dl_label_blkno;		// block # where this label is
	int		dl_size;		// size of media area (sectors)
	char		dl_label[MAXLBLLEN];	// media label
	unsigned	dl_flags;		// flags (see DL_xxx, below)
	unsigned	dl_tag;			// volume tag
	struct	disktab dl_dt;			// common info in disktab
	dl_un_t		dl_un;
	unsigned short	dl_checksum;		// ones complement checksum
	
	/* add things here so dl_checksum stays in a fixed place */
} disk_label_t;

/*
 * Known label versions.
 */
#define	DL_V1		0x4e655854	/* version #1: "NeXT" */
#define	DL_V2		0x646c5632	/* version #2: "dlV2" */
#define	DL_V3		0x646c5633	/* version #3: "dlV3" */
#define	DL_VERSION	DL_V3		/* default version */


/*
 * dl_flags values
 */
#define	DL_UNINIT	0x80000000	/* label is uninitialized */

/*
 * Aliases for disktab fields
 */
#define	dl_name		dl_dt.d_name
#define	dl_type		dl_dt.d_type
#define dl_part		dl_dt.d_partitions
#define	dl_front	dl_dt.d_front
#define	dl_back		dl_dt.d_back
#define	dl_ngroups	dl_dt.d_ngroups
#define	dl_ag_size	dl_dt.d_ag_size
#define	dl_ag_alts	dl_dt.d_ag_alts
#define	dl_ag_off	dl_dt.d_ag_off
#define	dl_secsize	dl_dt.d_secsize
#define	dl_ncyl		dl_dt.d_ncylinders
#define	dl_nsect	dl_dt.d_nsectors
#define	dl_ntrack	dl_dt.d_ntracks
#define	dl_rpm		dl_dt.d_rpm
#define	dl_bootfile	dl_dt.d_bootfile
#define	dl_boot0_blkno	dl_dt.d_boot0_blkno
#define	dl_hostname	dl_dt.d_hostname
#define	dl_rootpartition dl_dt.d_rootpartition
#define	dl_rwpartition	dl_dt.d_rwpartition

/*
 * Other aliases
 */
#define	dl_v3_checksum	dl_un.DL_v3_checksum
#define	dl_bad		dl_un.DL_bad

#endif	/* __APPLE_API_OBSOLETE */

#endif	/* _BSD_DEV_DISK_LABEL_ */

