/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*	@(#)disk.h	1.0	08/29/87	(c) 1987 NeXT	*/

/* 
 * HISTORY
 * 28-Mar-92  Doug Mitchell
 *  	Moved disk_label struct to <bsd/dev/disk_label.h>.
 *
 * 22-May-91  Gregg Kellogg (gk) at NeXT
 *	Split out public interface.
 *
 * 20-Jul-90  Doug Mitchell
 *	Added DKIOCSFORMAT, DKIOCGFORMAT
 *
 * 16-Apr-90  Doug Mitchell at NeXT
 *	Added DKIOCPANELPRT.
 *
 * 25-Mar-90  John Seamons (jks) at NeXT
 *	Removed obsolete DKIOCNOTIFY and DKIOCINSERT.
 *
 * 23-Mar-90  Doug Mitchell
 *	Added DKIOCEJECT.
 * 
 * 14-Feb-90  Doug Mitchell at NeXT
 *	Added DKIOCMNOTIFY.
 *
 * 16-Mar-88  John Seamons (jks) at NeXT
 *	Cleaned up to support standard disk label definitions.
 *
 * 24-Feb-88  Mike DeMoney (mike) at NeXT
 *	Added defines for dl_bootfile and dl_boot0_blkno.
 *	Reduced NBAD to allow for these entries in disktab.
 *
 * 29-Aug-87  John Seamons (jks) at NeXT
 *	Created.
 *
 */

#ifndef	_BSD_DEV_DISK_
#define	_BSD_DEV_DISK_

#include <mach/machine/vm_types.h>
#include <mach/machine/boolean.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <dev/disk_label.h>

#define	DR_CMDSIZE	32
#define	DR_ERRSIZE	32

struct disk_req {
	int	dr_bcount;		/* byte count for data transfers */
	caddr_t	dr_addr;		/* memory addr for data transfers */
	struct	timeval dr_exec_time;	/* execution time of operation */

	/* 
	 * interpretation of cmdblk and errblk is driver specific.
	 */
	char	dr_cmdblk[DR_CMDSIZE];
	char	dr_errblk[DR_ERRSIZE];
};

struct sdc_wire {
	vm_offset_t	start, end;
	boolean_t	new_pageable;
};


#define	BAD_BLK_OFF	4		/* offset of bad blk tbl from label */
#define	NBAD_BLK	(12 * 1024 / sizeof (int))

struct bad_block {			/* bad block table, sized to be 12KB */
	int	bad_blk[NBAD_BLK];
};

/* 
 * sector bitmap states (2 bits per sector) 
 */
#define	SB_UNTESTED	0		/* must be zero */
#define	SB_BAD		1
#define	SB_WRITTEN	2
#define	SB_ERASED	3

struct drive_info {			/* info about drive hardware */
	char	di_name[MAXDNMLEN];	/* drive type name */
	int	di_label_blkno[NLABELS];/* label loc'ns in DEVICE SECTORS */
	int	di_devblklen;		/* device sector size */
	int	di_maxbcount;		/* max bytes per transfer request */
};

#define	DS_STATSIZE	32

struct	disk_stats {
	int	s_ecccnt;	/* avg ECC corrections per sector */
	int	s_maxecc;	/* max ECC corrections observed */

	/* 
	 * interpretation of s_stats is driver specific 
	 */
	char	s_stats[DS_STATSIZE];
};

struct drive_location {
	char	location[ 128 ];
};

#define	DKIOCGLABEL	_IOR('d', 0,struct disk_label)	/* read label */
#define	DKIOCSLABEL	_IOW('d', 1,struct disk_label)	/* write label */
#define	DKIOCGBITMAP	_IO('d', 2)			/* read bitmap */
#define	DKIOCSBITMAP	_IO('d', 3)			/* write bitmap */
#define	DKIOCREQ	_IOWR('d', 4, struct disk_req)	/* cmd request */
#define	DKIOCINFO	_IOR('d', 5, struct drive_info)	/* get drive info */
#define	DKIOCZSTATS	_IO('d',7)			/* zero statistics */
#define	DKIOCGSTATS	_IO('d', 8)			/* get statistics */
#define	DKIOCRESET	_IO('d', 9)			/* reset disk */
#define	DKIOCGFLAGS	_IOR('d', 11, int)		/* get driver flags */
#define	DKIOCSFLAGS	_IOW('d', 12, int)		/* set driver flags */
#define	DKIOCSDCWIRE	_IOW('d', 14, struct sdc_wire)	/* sdc wire memory */
#define	DKIOCSDCLOCK	_IO('d', 15)			/* sdc lock */
#define	DKIOCSDCUNLOCK	_IO('d', 16)			/* sdc unlock */
#define	DKIOCGFREEVOL	_IOR('d', 17, int)		/* get free volume # */
#define	DKIOCGBBT	_IO('d', 18)			/* read bad blk tbl */
#define	DKIOCSBBT	_IO('d', 19)			/* write bad blk tbl */
#define	DKIOCMNOTIFY	_IOW('d', 20, int)		/* message on insert */
#define	DKIOCEJECT	_IO('d', 21)			/* eject disk */
#define	DKIOCPANELPRT	_IOW('d', 22, int)		/* register Panel */
							/* Request port */
#define DKIOCSFORMAT	_IOW('d', 23, int)		/* set 'Formatted' flag */
#define DKIOCGFORMAT	_IOR('d', 23, int)		/* get 'Formatted' flag */ 
#define DKIOCBLKSIZE	_IOR('d', 24, int)		/* device sector size */
#define	DKIOCNUMBLKS	_IOR('d', 25, int)		/* number of sectors */
#define DKIOCCHECKINSERT _IO('d',26)		/* manually poll removable */ 
						/* media drive */
#define DKIOCCANCELAUTOMOUNT _IOW('d',27, dev_t)	/* cancel automount request */
#define DKIOCGLOCATION	_IOR('d',28, struct drive_location)	/* arch dependent location descrip */
#define DKIOCSETBLOCKSIZE   _IOW('d', 24, int)  /* set media's preferred sector size */
#define DKIOCGETBLOCKSIZE   DKIOCBLKSIZE        /* get media's preferred sector size */
#define DKIOCGETBLOCKCOUNT  DKIOCNUMBLKS        /* get media's sector count */
#define DKIOCGETLOCATION    DKIOCGLOCATION      /* get media's location description */
#define DKIOCISFORMATTED    DKIOCGFORMAT        /* is media formatted? */
#define DKIOCISWRITABLE     _IOR('d', 29, int)  /* is media writable? */

#define DKIOCGETMAXBLOCKCOUNTREAD    _IOR('d', 64, u_int64_t) /* get device's maximum block count for read requests */
#define DKIOCGETMAXBLOCKCOUNTWRITE   _IOR('d', 65, u_int64_t) /* get device's maximum block count for write requests */
#define DKIOCGETMAXSEGMENTCOUNTREAD  _IOR('d', 66, u_int64_t) /* get device's maximum physical segment count for read buffers */
#define DKIOCGETMAXSEGMENTCOUNTWRITE _IOR('d', 67, u_int64_t) /* get device's maximum physical segment count for write buffers */

#endif	/* _BSD_DEV_DISK_ */
