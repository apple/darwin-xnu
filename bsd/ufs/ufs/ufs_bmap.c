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
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
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
#include <architecture/byte_order.h>
#endif /* REV_ENDIAN_FS */

/*
 * Bmap converts a the logical block number of a file to its physical block
 * number on the disk. The conversion is done by using the logical block
 * number to index into the array of block pointers described by the dinode.
 */
int
ufs_bmap(ap)
	struct vop_bmap_args /* {
		struct vnode *a_vp;
		ufs_daddr_t a_bn;
		struct vnode **a_vpp;
		ufs_daddr_t *a_bnp;
		int *a_runp;
	} */ *ap;
{
	/*
	 * Check for underlying vnode requests and ensure that logical
	 * to physical mapping is requested.
	 */
	if (ap->a_vpp != NULL)
		*ap->a_vpp = VTOI(ap->a_vp)->i_devvp;
	if (ap->a_bnp == NULL)
		return (0);

	return (ufs_bmaparray(ap->a_vp, ap->a_bn, ap->a_bnp, NULL, NULL,
	    ap->a_runp));
}

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
	struct vnode *vp;
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
		maxrun = MAXPHYSIO / mp->mnt_stat.f_iosize - 1;
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
		/* 
		 * Exit the loop if there is no disk address assigned yet and
		 * the indirect block isn't in the cache, or if we were
		 * looking for an indirect block and we've found it.
		 */

		metalbn = xap->in_lbn;
		if (daddr == 0 && !incore(vp, metalbn) || metalbn == bn)
			break;
		/*
		 * If we get here, we've either got the block in the cache
		 * or we have a disk address for it, go fetch it.
		 */
		if (bp)
			brelse(bp);

		xap->in_exists = 1;
		bp = getblk(vp, metalbn, mp->mnt_stat.f_iosize, 0, 0, BLK_META);
		if (bp->b_flags & (B_DONE | B_DELWRI)) {
			trace(TR_BREADHIT, pack(vp, mp->mnt_stat.f_iosize), metalbn);
		}
#if DIAGNOSTIC
		else if (!daddr)
			panic("ufs_bmaparry: indirect block not in cache");
#endif
		else {
			trace(TR_BREADMISS, pack(vp, mp->mnt_stat.f_iosize), metalbn);
			bp->b_blkno = blkptrtodb(ump, daddr);
			bp->b_flags |= B_READ;
			VOP_STRATEGY(bp);
			current_proc()->p_stats->p_ru.ru_inblock++;	/* XXX */
			if (error = biowait(bp)) {
				brelse(bp);
				return (error);
			}
		}

		daddr = ((ufs_daddr_t *)bp->b_data)[xap->in_off];
#if REV_ENDIAN_FS
		if (rev_endian)
			daddr = NXSwapLong(daddr);
#endif /* REV_ENDIAN_FS */
		if (num == 1 && daddr && runp) {
#if REV_ENDIAN_FS
		if (rev_endian) {
			for (bn = xap->in_off + 1;
			    bn < MNINDIR(ump) && *runp < maxrun &&
			    is_sequential(ump,
			    NXSwapLong(((ufs_daddr_t *)bp->b_data)[bn - 1]),
			    NXSwapLong(((ufs_daddr_t *)bp->b_data)[bn]));
			    ++bn, ++*runp);
		 } else {
#endif /* REV_ENDIAN_FS */
			for (bn = xap->in_off + 1;
			    bn < MNINDIR(ump) && *runp < maxrun &&
			    is_sequential(ump,
			    ((ufs_daddr_t *)bp->b_data)[bn - 1],
			    ((ufs_daddr_t *)bp->b_data)[bn]);
			    ++bn, ++*runp);
#if REV_ENDIAN_FS
		}
#endif /* REV_ENDIAN_FS */
		}
	}
	if (bp)
		brelse(bp);

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
 * Cmap converts a the file offset of a file to its physical block
 * number on the disk And returns  contiguous size for transfer.
 */
int
ufs_cmap(ap)
	struct vop_cmap_args /* {
		struct vnode *a_vp;
		off_t a_foffset;    
		size_t a_size;
		daddr_t *a_bpn;
		size_t *a_run;
		void *a_poff;
	} */ *ap;
{
	struct vnode * vp = ap->a_vp;
	ufs_daddr_t *bnp = ap->a_bpn;
	size_t *runp = ap->a_run;
	int size = ap->a_size;
	daddr_t bn;
	int nblks;
	register struct inode *ip;
	ufs_daddr_t daddr = 0;
	int devBlockSize=0;
	struct fs *fs;
	int retsize=0;
	int error=0;

	ip = VTOI(vp);
	fs = ip->i_fs;
	

	if (blkoff(fs, ap->a_foffset)) {
		panic("ufs_cmap; allocation requested inside a block");
	}

	bn = (daddr_t)lblkno(fs, ap->a_foffset);
	VOP_DEVBLOCKSIZE(ip->i_devvp, &devBlockSize);

	if (size % devBlockSize) {
		panic("ufs_cmap: size is not multiple of device block size\n");
	}

	if (error =  VOP_BMAP(vp, bn, (struct vnode **) 0, &daddr, &nblks)) {
			return(error);
	}

	retsize = nblks * fs->fs_bsize;

	if (bnp)
		*bnp = daddr;

	if (ap->a_poff) 
		*(int *)ap->a_poff = 0;

	if (daddr == -1) {
		if (size < fs->fs_bsize) {
			retsize = fragroundup(fs, size);
			if(size >= retsize)
				*runp = retsize;
			else
				*runp = size;
		} else {
			*runp = fs->fs_bsize;
		}
		return(0);
	}

	if (runp) {
		if ((size < fs->fs_bsize)) {
			*runp = size;
			return(0);
		}
		if (retsize) {
			retsize += fs->fs_bsize;
			if(size >= retsize)
				*runp = retsize;
			else
				*runp = size;
		} else {
			if (size < fs->fs_bsize) {
				retsize = fragroundup(fs, size);
				if(size >= retsize)
					*runp = retsize;
				else
					*runp = size;
			} else {
				*runp = fs->fs_bsize;
			}
		}
	}
	return (0);
}


#if NOTTOBEUSED
/*
 * Cmap converts a the file offset of a file to its physical block
 * number on the disk And returns  contiguous size for transfer.
 */
int
ufs_cmap(ap)
	struct vop_cmap_args /* {
		struct vnode *a_vp;
		off_t a_foffset;    
		size_t a_size;
		daddr_t *a_bpn;
		size_t *a_run;
		void *a_poff;
	} */ *ap;
{
	struct vnode * vp = ap->a_vp;
	ufs_daddr_t *bnp = ap->a_bpn;
	size_t *runp = ap->a_run;
	daddr_t bn;
	int nblks, blks;
	int *nump;
	register struct inode *ip;
	struct buf *bp;
	struct ufsmount *ump;
	struct mount *mp;
	struct vnode *devvp;
	struct indir a[NIADDR], *xap;
	ufs_daddr_t daddr;
	long metalbn;
	int error, maxrun, num;
	int devBlockSize=0;
	struct fs *fs;
	int size = ap->a_size;
	int block_offset=0;
	int retsize=0;
#if 1
	daddr_t orig_blkno;
	daddr_t orig_bblkno;
#endif /* 1 */	
#if REV_ENDIAN_FS
	int rev_endian=0;
#endif /* REV_ENDIAN_FS */

	ip = VTOI(vp);
	fs = ip->i_fs;
	
	mp = vp->v_mount;
	ump = VFSTOUFS(mp);

	VOP_DEVBLOCKSIZE(ip->i_devvp, &devBlockSize);
	bn = (daddr_t)lblkno(fs, ap->a_foffset);

	if (size % devBlockSize) {
		panic("ufs_cmap: size is not multiple of device block size\n");
	}

	block_offset = blkoff(fs, ap->a_foffset);
	if (block_offset) {
		panic("ufs_cmap; allocation requested inside a block");
	}

#if 1
	VOP_OFFTOBLK(vp, ap->a_foffset, & orig_blkno);
#endif /* 1 */
	/* less than block size and not block offset aligned */
	if ( (size < fs->fs_bsize) && fragoff(fs, size) && block_offset ) {
		panic("ffs_cmap: size not a mult of fragment\n");
	}
#if 0
	if (size > fs->fs_bsize && fragoff(fs, size))  {
		panic("ffs_cmap: more than bsize  & not a multiple of fragment\n");
	}
#endif /* 0 */
#if REV_ENDIAN_FS
	rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	if(runp)
		*runp = 0;

	if ( size > MAXPHYSIO)
		size = MAXPHYSIO;
	nblks = (blkroundup(fs, size))/fs->fs_bsize;

	xap = a;
	num = 0;
	if (error = ufs_getlbns(vp, bn, xap, &num))
		return (error);

	blks = 0;
	if (num == 0) {
		daddr = blkptrtodb(ump, ip->i_db[bn]);
		*bnp = ((daddr == 0) ? -1 : daddr);
		if (daddr && runp) {
			for (++bn; bn < NDADDR && blks < nblks &&
			    ip->i_db[bn] &&
			    is_sequential(ump, ip->i_db[bn - 1], ip->i_db[bn]);
			    ++bn, ++blks);

			if (blks) {
				retsize = lblktosize(fs, blks);
				if(size >= retsize)
					*runp = retsize;
				else
					*runp = size;
			} else {
				if (size < fs->fs_bsize) {
					retsize = fragroundup(fs, size);
					if(size >= retsize)
						*runp = retsize;
					else
						*runp = size;
				} else {
					*runp = fs->fs_bsize;
				}
			}
			if (ap->a_poff) 
				*(int *)ap->a_poff = 0;
		}
#if 1
		if (VOP_BMAP(vp, orig_blkno, NULL, &orig_bblkno, NULL)) {
			panic("vop_bmap failed\n");
		}
		if(daddr != orig_bblkno) {
			panic("vop_bmap and vop_cmap differ\n");
		}
#endif /* 1 */
		return (0);
	}


	/* Get disk address out of indirect block array */
	daddr = ip->i_ib[xap->in_off];

	devvp = VFSTOUFS(vp->v_mount)->um_devvp;
	for (bp = NULL, ++xap; --num; ++xap) {
		/* 
		 * Exit the loop if there is no disk address assigned yet
		 * or if we were looking for an indirect block and we've 
		 * found it.
		 */

		metalbn = xap->in_lbn;
		if (daddr == 0  || metalbn == bn)
			break;
		/*
		 * We have a disk address for it, go fetch it.
		 */
		if (bp)
			brelse(bp);

		xap->in_exists = 1;
		bp = getblk(vp, metalbn, mp->mnt_stat.f_iosize, 0, 0, BLK_META);
		if (bp->b_flags & (B_DONE | B_DELWRI)) {
			trace(TR_BREADHIT, pack(vp, mp->mnt_stat.f_iosize), metalbn);
		}
		else {
			trace(TR_BREADMISS, pack(vp, mp->mnt_stat.f_iosize), metalbn);
			bp->b_blkno = blkptrtodb(ump, daddr);
			bp->b_flags |= B_READ;
			VOP_STRATEGY(bp);
			current_proc()->p_stats->p_ru.ru_inblock++;	/* XXX */
			if (error = biowait(bp)) {
				brelse(bp);
				return (error);
			}
		}

		daddr = ((ufs_daddr_t *)bp->b_data)[xap->in_off];
#if REV_ENDIAN_FS
		if (rev_endian)
			daddr = NXSwapLong(daddr);
#endif /* REV_ENDIAN_FS */
		if (num == 1 && daddr && runp) {
			blks = 0;
#if REV_ENDIAN_FS
		if (rev_endian) {
			for (bn = xap->in_off + 1;
			    bn < MNINDIR(ump) && blks < maxrun &&
			    is_sequential(ump,
			    NXSwapLong(((ufs_daddr_t *)bp->b_data)[bn - 1]),
			    NXSwapLong(((ufs_daddr_t *)bp->b_data)[bn]));
			    ++bn, ++blks);
		 } else {
#endif /* REV_ENDIAN_FS */
			for (bn = xap->in_off + 1;
			    bn < MNINDIR(ump) && blks < maxrun &&
			    is_sequential(ump,
			    ((ufs_daddr_t *)bp->b_data)[bn - 1],
			    ((ufs_daddr_t *)bp->b_data)[bn]);
			    ++bn, ++blks);
#if REV_ENDIAN_FS
		}
#endif /* REV_ENDIAN_FS */
		}
	}
	if (bp)
		brelse(bp);

	daddr = blkptrtodb(ump, daddr);
	*bnp = ((daddr == 0) ? -1 : daddr);
	if (daddr && runp) {
		if (blks) {
			retsize = lblktosize(fs, blks);
			if(size >= retsize)
				*runp = retsize;
			else
				*runp = size;
		} else {
				if (size < fs->fs_bsize) {
					retsize = fragroundup(fs, size);
					if(size >= retsize)
						*runp = retsize;
					else
						*runp = size;
				} else {
					*runp = fs->fs_bsize;
				}
			}

	}
	if (daddr &&  ap->a_poff) 
		*(int *)ap->a_poff = 0;
#if 1
		if (VOP_BMAP(vp, orig_blkno, (struct vnode **) 0, &orig_bblkno, 0)) {
			panic("vop_bmap failed\n");
		}
		if(daddr != orig_bblkno) {
			panic("vop_bmap and vop_cmap differ\n");
		}
#endif /* 1 */
	return (0);
}
#endif /* NOTTOBEUSED */
