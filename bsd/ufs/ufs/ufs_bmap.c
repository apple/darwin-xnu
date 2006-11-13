/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)ufs_bmap.c	8.7 (Berkeley) 3/21/95
 */
/*
 * HISTORY
 * 11-July-97  Umesh Vaishampayan (umeshv@apple.com)
 *	Cleanup. Fixed compilation error when tracing is turned on.
 */
#include <rev_endian_fs.h>
#include <sys/param.h>
#include <sys/buf.h>
#include <sys/proc_internal.h>	/* for p_stats */
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/resourcevar.h>
#include <sys/trace.h>
#include <sys/quota.h>

#include <miscfs/specfs/specdev.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>
#if REV_ENDIAN_FS
#include <ufs/ufs/ufs_byte_order.h>
#include <libkern/OSByteOrder.h>
#endif /* REV_ENDIAN_FS */


/*
 * Indirect blocks are now on the vnode for the file.  They are given negative
 * logical block numbers.  Indirect blocks are addressed by the negative
 * address of the first data block to which they point.  Double indirect blocks
 * are addressed by one less than the address of the first indirect block to
 * which they point.  Triple indirect blocks are addressed by one less than
 * the address of the first double indirect block to which they point.
 *
 * ufs_bmaparray does the bmap conversion, and if requested returns the
 * array of logical blocks which must be traversed to get to a block.
 * Each entry contains the offset into that block that gets you to the
 * next block and the disk address of the block (if it is assigned).
 */

int
ufs_bmaparray(vp, bn, bnp, ap, nump, runp)
	vnode_t	    vp;
	ufs_daddr_t bn;
	ufs_daddr_t *bnp;
	struct indir *ap;
	int *nump;
	int *runp;
{
	register struct inode *ip;
	struct buf *bp;
	struct ufsmount *ump;
	struct mount *mp;
	struct vnode *devvp;
	struct indir a[NIADDR], *xap;
	ufs_daddr_t daddr;
	long metalbn;
	int error, maxrun, num;
#if REV_ENDIAN_FS
	int rev_endian=0;
#endif /* REV_ENDIAN_FS */

	ip = VTOI(vp);
	mp = vp->v_mount;
	ump = VFSTOUFS(mp);

#if REV_ENDIAN_FS
	rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

#if DIAGNOSTIC
	if (ap != NULL && nump == NULL || ap == NULL && nump != NULL)
		panic("ufs_bmaparray: invalid arguments");
#endif

	if (runp) {
		/*
		 * XXX
		 * If MAXPHYSIO is the largest transfer the disks can handle,
		 * we probably want maxrun to be 1 block less so that we
		 * don't create a block larger than the device can handle.
		 */
		*runp = 0;
		maxrun = MAXPHYSIO / mp->mnt_vfsstat.f_iosize - 1;
	}

	xap = ap == NULL ? a : ap;
	if (!nump)
		nump = &num;
	if (error = ufs_getlbns(vp, bn, xap, nump))
		return (error);

	num = *nump;
	if (num == 0) {
		*bnp = blkptrtodb(ump, ip->i_db[bn]);
		if (*bnp == 0)
			*bnp = -1;
		else if (runp)
			for (++bn; bn < NDADDR && *runp < maxrun &&
			    is_sequential(ump, ip->i_db[bn - 1], ip->i_db[bn]);
			    ++bn, ++*runp);
		return (0);
	}


	/* Get disk address out of indirect block array */
	daddr = ip->i_ib[xap->in_off];

	devvp = VFSTOUFS(vp->v_mount)->um_devvp;
	for (bp = NULL, ++xap; --num; ++xap) {
	        ufs_daddr_t *dataptr;
		int bop;

	        if ((metalbn = xap->in_lbn) == bn)
		       /*	
			* found the indirect block we were
			* looking for... exit the loop
			*/
		       break;
		
		if (daddr == 0)
		        bop = BLK_ONLYVALID | BLK_META;
		else
		        bop = BLK_META;

		if (bp)
			buf_brelse(bp);
		bp = buf_getblk(vp, (daddr64_t)((unsigned)metalbn), mp->mnt_vfsstat.f_iosize, 0, 0, bop);

		if (bp == 0) {
		        /* 
			 * Exit the loop if there is no disk address assigned yet and
			 * the indirect block isn't in the cache
			 */
			break;
		}
		/*
		 * If we get here, we've either got the block in the cache
		 * or we have a disk address for it, go fetch it.
		 */
		xap->in_exists = 1;

		if (buf_valid(bp)) {
			trace(TR_BREADHIT, pack(vp, mp->mnt_vfsstat.f_iosize), metalbn);
		}
		else {
			trace(TR_BREADMISS, pack(vp, mp->mnt_vfsstat.f_iosize), metalbn);
			buf_setblkno(bp, blkptrtodb(ump, (daddr64_t)((unsigned)daddr)));
			buf_setflags(bp, B_READ);
			VNOP_STRATEGY(bp);
			current_proc()->p_stats->p_ru.ru_inblock++;	/* XXX */
			if (error = (int)buf_biowait(bp)) {
				buf_brelse(bp);
				return (error);
			}
		}
		dataptr = (ufs_daddr_t *)buf_dataptr(bp);
		daddr = dataptr[xap->in_off];
#if REV_ENDIAN_FS
		if (rev_endian)
			daddr = OSSwapInt32(daddr);
#endif /* REV_ENDIAN_FS */
		if (num == 1 && daddr && runp) {
#if REV_ENDIAN_FS
		if (rev_endian) {
			for (bn = xap->in_off + 1;
			    bn < MNINDIR(ump) && *runp < maxrun &&
			    is_sequential(ump,
			    OSSwapInt32(dataptr[bn - 1]),
			    OSSwapInt32(dataptr[bn]));
			    ++bn, ++*runp);
		 } else {
#endif /* REV_ENDIAN_FS */
			for (bn = xap->in_off + 1;
			    bn < MNINDIR(ump) && *runp < maxrun &&
			    is_sequential(ump,
			    dataptr[bn - 1],
			    dataptr[bn]);
			    ++bn, ++*runp);
#if REV_ENDIAN_FS
		}
#endif /* REV_ENDIAN_FS */
		}
	}
	if (bp)
		buf_brelse(bp);

	daddr = blkptrtodb(ump, daddr);
	*bnp = daddr == 0 ? -1 : daddr;
	return (0);
}

/*
 * Create an array of logical block number/offset pairs which represent the
 * path of indirect blocks required to access a data block.  The first "pair"
 * contains the logical block number of the appropriate single, double or
 * triple indirect block and the offset into the inode indirect block array.
 * Note, the logical block number of the inode single/double/triple indirect
 * block appears twice in the array, once with the offset into the i_ib and
 * once with the offset into the page itself.
 */
int
ufs_getlbns(vp, bn, ap, nump)
	struct vnode *vp;
	ufs_daddr_t bn;
	struct indir *ap;
	int *nump;
{
	long metalbn, realbn;
	struct ufsmount *ump;
	int blockcnt, i, numlevels, off;

	ump = VFSTOUFS(vp->v_mount);
	if (nump)
		*nump = 0;
	numlevels = 0;
	realbn = bn;
	if ((long)bn < 0)
		bn = -(long)bn;

	/* The first NDADDR blocks are direct blocks. */
	if (bn < NDADDR)
		return (0);

	/* 
	 * Determine the number of levels of indirection.  After this loop
	 * is done, blockcnt indicates the number of data blocks possible
	 * at the given level of indirection, and NIADDR - i is the number
	 * of levels of indirection needed to locate the requested block.
	 */
	for (blockcnt = 1, i = NIADDR, bn -= NDADDR;; i--, bn -= blockcnt) {
		if (i == 0)
			return (EFBIG);
		blockcnt *= MNINDIR(ump);
		if (bn < blockcnt)
			break;
	}

	/* Calculate the address of the first meta-block. */
	if (realbn >= 0)
		metalbn = -(realbn - bn + NIADDR - i);
	else
		metalbn = -(-realbn - bn + NIADDR - i);

	/* 
	 * At each iteration, off is the offset into the bap array which is
	 * an array of disk addresses at the current level of indirection.
	 * The logical block number and the offset in that block are stored
	 * into the argument array.
	 */
	ap->in_lbn = metalbn;
	ap->in_off = off = NIADDR - i;
	ap->in_exists = 0;
	ap++;
	for (++numlevels; i <= NIADDR; i++) {
		/* If searching for a meta-data block, quit when found. */
		if (metalbn == realbn)
			break;

		blockcnt /= MNINDIR(ump);
		off = (bn / blockcnt) % MNINDIR(ump);

		++numlevels;
		ap->in_lbn = metalbn;
		ap->in_off = off;
		ap->in_exists = 0;
		++ap;

		metalbn -= -1 + off * blockcnt;
	}
	if (nump)
		*nump = numlevels;
	return (0);
}
/*
 * blockmap converts a file offsetto its physical block
 * number on the disk... it optionally returns the physically
 * contiguous size.
 */
int
ufs_blockmap(ap)
	struct vnop_blockmap_args /* {
		struct vnode *a_vp;
		off_t a_foffset;    
		size_t a_size;
		daddr64_t *a_bpn;
		size_t *a_run;
		void *a_poff;
		int a_flags;
	} */ *ap;
{
	vnode_t	    vp   = ap->a_vp;
	daddr64_t * bnp  = ap->a_bpn;
	size_t    * runp = ap->a_run;
	int	    size = ap->a_size;
	struct fs * fs;
	struct inode *ip;
	ufs_daddr_t lbn;
	ufs_daddr_t daddr = 0;
	int	devBlockSize = 0;
	int	retsize = 0;
	int	error = 0;
	int	nblks;

	ip = VTOI(vp);
	fs = ip->i_fs;
	
	lbn = (ufs_daddr_t)lblkno(fs, ap->a_foffset);
	devBlockSize = vfs_devblocksize(vnode_mount(vp));

	if (blkoff(fs, ap->a_foffset))
		panic("ufs_blockmap; allocation requested inside a block");

	if (size % devBlockSize)
		panic("ufs_blockmap: size is not multiple of device block size\n");

	if ((error = ufs_bmaparray(vp, lbn, &daddr, NULL, NULL, &nblks)))
	        return (error);

	if (bnp)
		*bnp = (daddr64_t)daddr;

	if (ap->a_poff) 
		*(int *)ap->a_poff = 0;

	if (runp) {
	        if (lbn < 0) {
		        /*
			 * we're dealing with the indirect blocks
			 * which are always fs_bsize in size
			 */
		        retsize = (nblks + 1) * fs->fs_bsize;
		} else if (daddr == -1 || nblks == 0) {
		        /*
			 * we're dealing with a 'hole'... UFS doesn't
			 * have a clean way to determine it's size
			 * or
			 * there's are no physically contiguous blocks
			 * so
			 * just return the size of the lbn we started with
			 */
		        retsize = blksize(fs, ip, lbn);
		} else {
		        /*
			 * we have 1 or more blocks that are physically contiguous
			 * to our starting block number... the orignal block + (nblks - 1)
			 * blocks must be full sized since only the last block can be 
			 * composed of fragments...
			 */
			 retsize = nblks * fs->fs_bsize;

			 /*
			  * now compute the size of the last block and add it in
			  */
			 retsize += blksize(fs, ip, (lbn + nblks));
		}
		if (retsize < size)
		        *runp = retsize;
		else
		        *runp = size;
	}
	return (0);
}
