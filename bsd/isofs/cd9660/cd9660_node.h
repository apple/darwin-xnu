/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
/*	$NetBSD: cd9660_node.h,v 1.10 1994/12/24 15:30:09 cgd Exp $	*/

/*-
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley
 * by Pace Willisson (pace@blitz.com).  The Rock Ridge Extension
 * Support code is derived from software contributed to Berkeley
 * by Atsushi Murai (amurai@spec.co.jp).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)cd9660_node.h	8.4 (Berkeley) 12/5/94
 */
#ifndef _CD9660_NODE_H_
#define _CD9660_NODE_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
/*
 * Theoretically, directories can be more than 2Gb in length,
 * however, in practice this seems unlikely. So, we define
 * the type doff_t as a long to keep down the cost of doing
 * lookup on a 32-bit machine. If you are porting to a 64-bit
 * architecture, you should make doff_t the same as off_t.
 */

#include <sys/lock.h>
#include <isofs/cd9660/iso.h>

#ifndef doff_t
#define doff_t	long
#endif

typedef	struct	{
	struct timespec	iso_atime;	/* time of last access */
	struct timespec	iso_mtime;	/* time of last modification */
	struct timespec	iso_ctime;	/* time file changed */
	uid_t		iso_uid;	/* owner user id */
	gid_t		iso_gid;	/* owner group id */
	u_short		iso_mode;	/* files access mode and type */
	short		iso_links;	/* links of file */
	dev_t		iso_rdev;	/* Major/Minor number for special */
} ISO_RRIP_INODE;

#ifdef ISODEVMAP
/*
 * FOr device# (major,minor) translation table
 */
struct iso_dnode {
	struct iso_dnode *d_next, **d_prev;	/* hash chain */
	dev_t		i_dev;		/* device where dnode resides */
	ino_t		i_number;	/* the identity of the inode */
	dev_t		d_dev;		/* device # for translation */
};
#endif

/* <ufs/inode.h> defines i_size as a macro */
#undef i_size

struct iso_node {
	struct	iso_node *i_next, **i_prev;	/* hash chain */
	struct	vnode *i_vnode;	/* vnode associated with this inode */
	struct	vnode *i_devvp;	/* vnode for block I/O */
	u_int32_t i_flag;	/* flags, see below */
	dev_t	i_dev;		/* device where inode resides */
	ino_t	i_number;	/* the identity of the inode */
				/* we use the actual starting block of the file */
	struct	iso_mnt *i_mnt;	/* filesystem associated with this inode */
	struct	lockf *i_lockf;	/* head of byte-level lock list */
	doff_t	i_endoff;	/* end of useful stuff in directory */
	doff_t	i_diroff;	/* offset in dir, where we found last entry */
	doff_t	i_offset;	/* offset of free space in directory */
	ino_t	i_ino;		/* inode number of found directory */
	struct   lock__bsd__ i_lock;    /* Inode lock. */
	long iso_extent;	/* extent of file */
	long i_size;
	long iso_start;		/* actual start of data of file (may be different */
				/* from iso_extent, if file has extended attributes) */
	ISO_RRIP_INODE  inode;
	
	ino_t	i_parent;		/* inode number of parent directory */
	u_char	*i_namep;		/* node name buffer */

	/* support Apple extensions to ISO directory rec */
	long		i_rsrcsize;	/* cached size of associated file */
	u_int32_t	i_FileType;	/* MacOS file type */
	u_int32_t	i_Creator;	/* MacOS file creator */
	u_int16_t	i_FinderFlags;	/* MacOS finder flags */

	u_int16_t	i_entries;	/* count of directory entries */
	
	struct riff_header *i_riff;
};

#define	i_forw		i_chain[0]
#define	i_back		i_chain[1]

/* These flags are kept in i_flag. */
#define	ISO_ASSOCIATED	0x0001		/* node is an associated file. */

/* <ufs/inode.h> defines VTOI and ITOV macros */
#undef VTOI
#undef ITOV

#define VTOI(vp) ((struct iso_node *)(vp)->v_data)
#define ITOV(ip) ((ip)->i_vnode)

/*
 * Prototypes for ISOFS vnode operations
 */
int cd9660_lookup __P((struct vop_lookup_args *));
int cd9660_open __P((struct vop_open_args *));
int cd9660_close __P((struct vop_close_args *));
int cd9660_access __P((struct vop_access_args *));
int cd9660_getattr __P((struct vop_getattr_args *));
int cd9660_read __P((struct vop_read_args *));
int cd9660_xa_read __P((struct vop_read_args *));
int cd9660_ioctl __P((struct vop_ioctl_args *));
int cd9660_select __P((struct vop_select_args *));
int cd9660_mmap __P((struct vop_mmap_args *));
int cd9660_seek __P((struct vop_seek_args *));
int cd9660_readdir __P((struct vop_readdir_args *));
int cd9660_readlink __P((struct vop_readlink_args *));
int cd9660_inactive __P((struct vop_inactive_args *));
int cd9660_reclaim __P((struct vop_reclaim_args *));
int cd9660_bmap __P((struct vop_bmap_args *));
int cd9660_lock __P((struct vop_lock_args *));
int cd9660_unlock __P((struct vop_unlock_args *));
int cd9660_strategy __P((struct vop_strategy_args *));
int cd9660_print __P((struct vop_print_args *));
int cd9660_islocked __P((struct vop_islocked_args *));
int cd9660_pathconf __P((struct vop_pathconf_args *));
int cd9660_blkatoff __P((struct vop_blkatoff_args *));

void cd9660_defattr __P((struct iso_directory_record *,
			struct iso_node *, struct buf *));
void cd9660_deftstamp __P((struct iso_directory_record *,
			struct iso_node *, struct buf *));
struct vnode *cd9660_ihashget __P((dev_t, ino_t, struct proc *));
void cd9660_ihashins __P((struct iso_node *));
void cd9660_ihashrem __P((struct iso_node *));
int cd9660_tstamp_conv7 __P((u_char *, struct timespec *));
int cd9660_tstamp_conv17 __P((u_char *, struct timespec *));
ino_t isodirino __P((struct iso_directory_record *, struct iso_mnt *));
#ifdef	ISODEVMAP
struct iso_dnode *iso_dmap __P((dev_t, ino_t, int));
void iso_dunmap __P((dev_t));
#endif

#endif /* __APPLE_API_PRIVATE */
#endif /* ! _CD9660_NODE_H_ */
