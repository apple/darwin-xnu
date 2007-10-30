/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)ffs_inode.c	8.13 (Berkeley) 4/21/95
 */

#include <rev_endian_fs.h>
#include <vm/vm_pager.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h>	/* for accessing p_stats */
#include <sys/file.h>
#include <sys/buf_internal.h>
#include <sys/vnode_internal.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/trace.h>
#include <sys/resourcevar.h>
#include <sys/ubc.h>
#include <sys/quota.h>

#include <sys/vm.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>

#if REV_ENDIAN_FS
#include <ufs/ufs/ufs_byte_order.h>
#include <libkern/OSByteOrder.h>
#endif /* REV_ENDIAN_FS */
#include <libkern/OSAtomic.h>

static int ffs_indirtrunc(struct inode *, ufs_daddr_t, ufs_daddr_t,
	    ufs_daddr_t, int, long *);

/*
 * Update the access, modified, and inode change times as specified by the
 * IACCESS, IUPDATE, and ICHANGE flags respectively. The IMODIFIED flag is
 * used to specify that the inode needs to be updated but that the times have
 * already been set. The access and modified times are taken from the second
 * and third parameters; the inode change time is always taken from the current
 * time. If waitfor is set, then wait for the disk write of the inode to
 * complete.
 */
int
ffs_update(struct vnode *vp, struct timeval *access, struct timeval *modify, int waitfor)
{
	register struct fs *fs;
	struct buf *bp;
	struct inode *ip;
	struct timeval tv;
	errno_t error;
#if REV_ENDIAN_FS
	struct mount *mp=(vp)->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	ip = VTOI(vp);
	if (vp->v_mount->mnt_flag & MNT_RDONLY) {
		ip->i_flag &=
		    ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);
		return (0);
	}
	if ((ip->i_flag &
	    (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) == 0)
		return (0);
	if (ip->i_flag & IN_ACCESS)
		ip->i_atime = access->tv_sec;
	if (ip->i_flag & IN_UPDATE) {
		ip->i_mtime = modify->tv_sec;
		ip->i_modrev++;
	}
	if (ip->i_flag & IN_CHANGE) {
		microtime(&tv);
		ip->i_ctime = tv.tv_sec;
	}
	ip->i_flag &= ~(IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE);
	fs = ip->i_fs;
	/*
	 * Ensure that uid and gid are correct. This is a temporary
	 * fix until fsck has been changed to do the update.
	 */
	if (fs->fs_inodefmt < FS_44INODEFMT) {		/* XXX */
		ip->i_din.di_ouid = ip->i_uid;		/* XXX */
		ip->i_din.di_ogid = ip->i_gid;		/* XXX */
	}						/* XXX */
	if (error = buf_bread(ip->i_devvp,
			      (daddr64_t)((unsigned)fsbtodb(fs, ino_to_fsba(fs, ip->i_number))),
		(int)fs->fs_bsize, NOCRED, &bp)) {
		buf_brelse(bp);
		return ((int)error);
	}
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_inode_out(ip, ((struct dinode *)buf_dataptr(bp) + ino_to_fsbo(fs, ip->i_number)));
	else {
#endif /* REV_ENDIAN_FS */
	*((struct dinode *)buf_dataptr(bp) + ino_to_fsbo(fs, ip->i_number)) = ip->i_din;
#if REV_ENDIAN_FS
	}
#endif /* REV_ENDIAN_FS */

	if (waitfor && (vp->v_mount->mnt_flag & MNT_ASYNC) == 0)
		return ((int)buf_bwrite(bp));
	else {
		buf_bdwrite(bp);
		return (0);
	}
}


#define	SINGLE	0	/* index of single indirect block */
#define	DOUBLE	1	/* index of double indirect block */
#define	TRIPLE	2	/* index of triple indirect block */

int
ffs_truncate_internal(vnode_t ovp, off_t length, int flags, ucred_t cred)
{
	struct inode	*oip;
	struct fs	*fs;
	ufs_daddr_t lastblock;
	ufs_daddr_t bn, lbn, lastiblock[NIADDR], indir_lbn[NIADDR];
	ufs_daddr_t oldblks[NDADDR + NIADDR], newblks[NDADDR + NIADDR];
	buf_t	bp;
	int	offset, size, level, i;
	long	count, nblocks, vflags, blocksreleased = 0;
	struct	timeval tv;
	int	aflags, error, allerror;
	off_t	osize;
	int	devBlockSize=0;
#if QUOTA
	int64_t change;   /* in bytes */
#endif /* QUOTA */

	if (length < 0)
		return (EINVAL);

	oip = VTOI(ovp);
	fs = oip->i_fs;

	if (length > fs->fs_maxfilesize)
	        return (EFBIG);

	microtime(&tv);
	if (ovp->v_type == VLNK &&
	    oip->i_size < ovp->v_mount->mnt_maxsymlinklen) {
#if DIAGNOSTIC
		if (length != 0)
			panic("ffs_truncate: partial truncate of symlink");
#endif
		bzero((char *)&oip->i_shortlink, (u_int)oip->i_size);
		oip->i_size = 0;
		oip->i_flag |= IN_CHANGE | IN_UPDATE;
		return (ffs_update(ovp, &tv, &tv, 1));
	}

	if (oip->i_size == length) {
		oip->i_flag |= IN_CHANGE | IN_UPDATE;
		return (ffs_update(ovp, &tv, &tv, 0));
	}
#if QUOTA
	if (error = getinoquota(oip))
		return (error);
#endif
	osize = oip->i_size;

	/*
	 * Lengthen the size of the file. We must ensure that the
	 * last byte of the file is allocated. Since the smallest
	 * value of osize is 0, length will be at least 1.
	 */
	if (osize < length) {
		offset = blkoff(fs, length - 1);
		lbn = lblkno(fs, length - 1);
		aflags = B_CLRBUF;
		if (flags & IO_SYNC)
			aflags |= B_SYNC;
		if (error = ffs_balloc(oip, lbn, offset + 1, cred, &bp, aflags, 0))
			return (error);
		oip->i_size = length;
		
		if (UBCINFOEXISTS(ovp)) {
			buf_markinvalid(bp);
			buf_bwrite(bp);
			ubc_setsize(ovp, (off_t)length); 
		} else {
			if (aflags & B_SYNC)
				buf_bwrite(bp);
			else
				buf_bawrite(bp);
		}
		oip->i_flag |= IN_CHANGE | IN_UPDATE;
		return (ffs_update(ovp, &tv, &tv, 1));
	}
	/*
	 * Shorten the size of the file. If the file is not being
	 * truncated to a block boundry, the contents of the
	 * partial block following the end of the file must be
	 * zero'ed in case it ever become accessable again because
	 * of subsequent file growth.
	 */
	if (UBCINFOEXISTS(ovp))
		ubc_setsize(ovp, (off_t)length); 

	vflags = ((length > 0) ? BUF_WRITE_DATA : 0) | BUF_SKIP_META;

	if (vflags & BUF_WRITE_DATA)
	        ffs_fsync_internal(ovp, MNT_WAIT);
	allerror = buf_invalidateblks(ovp, vflags, 0, 0);
                
	offset = blkoff(fs, length);
	if (offset == 0) {
		oip->i_size = length;
	} else {
		lbn = lblkno(fs, length);
		aflags = B_CLRBUF;
		if (flags & IO_SYNC)
			aflags |= B_SYNC;
		if (error = ffs_balloc(oip, lbn, offset, cred, &bp, aflags, 0))
			return (error);
		oip->i_size = length;
		size = blksize(fs, oip, lbn);
		bzero((char *)buf_dataptr(bp) + offset, (u_int)(size - offset));
		allocbuf(bp, size);
		if (UBCINFOEXISTS(ovp)) {
			buf_markinvalid(bp);
			buf_bwrite(bp);
		} else {
			if (aflags & B_SYNC)
				buf_bwrite(bp);
			else
				buf_bawrite(bp);
		}
	}
	/*
	 * Calculate index into inode's block list of
	 * last direct and indirect blocks (if any)
	 * which we want to keep.  Lastblock is -1 when
	 * the file is truncated to 0.
	 */
	lastblock = lblkno(fs, length + fs->fs_bsize - 1) - 1;
	lastiblock[SINGLE] = lastblock - NDADDR;
	lastiblock[DOUBLE] = lastiblock[SINGLE] - NINDIR(fs);
	lastiblock[TRIPLE] = lastiblock[DOUBLE] - NINDIR(fs) * NINDIR(fs);

	devBlockSize = vfs_devblocksize(vnode_mount(ovp));
	nblocks = btodb(fs->fs_bsize, devBlockSize);

	/*
	 * Update file and block pointers on disk before we start freeing
	 * blocks.  If we crash before free'ing blocks below, the blocks
	 * will be returned to the free list.  lastiblock values are also
	 * normalized to -1 for calls to ffs_indirtrunc below.
	 */
	bcopy((caddr_t)&oip->i_db[0], (caddr_t)oldblks, sizeof oldblks);
	for (level = TRIPLE; level >= SINGLE; level--)
		if (lastiblock[level] < 0) {
			oip->i_ib[level] = 0;
			lastiblock[level] = -1;
		}
	for (i = NDADDR - 1; i > lastblock; i--)
		oip->i_db[i] = 0;
	oip->i_flag |= IN_CHANGE | IN_UPDATE;
	if (error = ffs_update(ovp, &tv, &tv, MNT_WAIT))
		allerror = error;
	/*
	 * Having written the new inode to disk, save its new configuration
	 * and put back the old block pointers long enough to process them.
	 * Note that we save the new block configuration so we can check it
	 * when we are done.
	 */
	bcopy((caddr_t)&oip->i_db[0], (caddr_t)newblks, sizeof newblks);
	bcopy((caddr_t)oldblks, (caddr_t)&oip->i_db[0], sizeof oldblks);
	oip->i_size = osize;

	vflags = ((length > 0) ? BUF_WRITE_DATA : 0) | BUF_SKIP_META;

	if (vflags & BUF_WRITE_DATA)
	        ffs_fsync_internal(ovp, MNT_WAIT);
	allerror = buf_invalidateblks(ovp, vflags, 0, 0);

	/*
	 * Indirect blocks first.
	 */
	indir_lbn[SINGLE] = -NDADDR;
	indir_lbn[DOUBLE] = indir_lbn[SINGLE] - NINDIR(fs) - 1;
	indir_lbn[TRIPLE] = indir_lbn[DOUBLE] - NINDIR(fs) * NINDIR(fs) - 1;
	for (level = TRIPLE; level >= SINGLE; level--) {
		bn = oip->i_ib[level];
		if (bn != 0) {
			error = ffs_indirtrunc(oip, indir_lbn[level],
			    fsbtodb(fs, bn), lastiblock[level], level, &count);
			if (error)
				allerror = error;
			blocksreleased += count;
			if (lastiblock[level] < 0) {
				oip->i_ib[level] = 0;
				ffs_blkfree(oip, bn, fs->fs_bsize);
				blocksreleased += nblocks;
			}
		}
		if (lastiblock[level] >= 0)
			goto done;
	}

	/*
	 * All whole direct blocks or frags.
	 */
	for (i = NDADDR - 1; i > lastblock; i--) {
		register long bsize;

		bn = oip->i_db[i];
		if (bn == 0)
			continue;
		oip->i_db[i] = 0;
		bsize = blksize(fs, oip, i);
		ffs_blkfree(oip, bn, bsize);
		blocksreleased += btodb(bsize, devBlockSize);
	}
	if (lastblock < 0)
		goto done;

	/*
	 * Finally, look for a change in size of the
	 * last direct block; release any frags.
	 */
	bn = oip->i_db[lastblock];
	if (bn != 0) {
		long oldspace, newspace;

		/*
		 * Calculate amount of space we're giving
		 * back as old block size minus new block size.
		 */
		oldspace = blksize(fs, oip, lastblock);
		oip->i_size = length;
		newspace = blksize(fs, oip, lastblock);
		if (newspace == 0)
			panic("itrunc: newspace");
		if (oldspace - newspace > 0) {
			/*
			 * Block number of space to be free'd is
			 * the old block # plus the number of frags
			 * required for the storage we're keeping.
			 */
			bn += numfrags(fs, newspace);
			ffs_blkfree(oip, bn, oldspace - newspace);
			blocksreleased += btodb(oldspace - newspace, devBlockSize);
		}
	}
done:
#if DIAGNOSTIC
	for (level = SINGLE; level <= TRIPLE; level++)
		if (newblks[NDADDR + level] != oip->i_ib[level])
			panic("itrunc1");
	for (i = 0; i < NDADDR; i++)
		if (newblks[i] != oip->i_db[i])
			panic("itrunc2");
	if (length == 0 &&
	    (vnode_hasdirtyblks(ovp) || vnode_hascleanblks(ovp)))
		panic("itrunc3");
#endif /* DIAGNOSTIC */
	/*
	 * Put back the real size.
	 */
	oip->i_size = length;
	oip->i_blocks -= blocksreleased;
	if (oip->i_blocks < 0)			/* sanity */
		oip->i_blocks = 0;
	oip->i_flag |= IN_CHANGE;
#if QUOTA
	change = dbtob((int64_t)blocksreleased,devBlockSize);
	(void) chkdq(oip, -change, NOCRED, 0);
#endif
	return (allerror);
}

/*
 * Release blocks associated with the inode ip and stored in the indirect
 * block bn.  Blocks are free'd in LIFO order up to (but not including)
 * lastbn.  If level is greater than SINGLE, the block is an indirect block
 * and recursive calls to indirtrunc must be used to cleanse other indirect
 * blocks.
 *
 * NB: triple indirect blocks are untested.
 */
static int
ffs_indirtrunc(ip, lbn, dbn, lastbn, level, countp)
	register struct inode *ip;
	ufs_daddr_t lbn, lastbn;
	ufs_daddr_t dbn;
	int level;
	long *countp;
{
	register int i;
	struct buf *bp;
	struct buf *tbp;
	register struct fs *fs = ip->i_fs;
	register ufs_daddr_t *bap;
	struct vnode *vp=ITOV(ip);
	ufs_daddr_t *copy, nb, nlbn, last;
	long blkcount, factor;
	int nblocks, blocksreleased = 0;
	errno_t error = 0, allerror = 0;
	int devBlockSize=0;
	struct mount *mp=vp->v_mount;
#if REV_ENDIAN_FS
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	/*
	 * Calculate index in current block of last
	 * block to be kept.  -1 indicates the entire
	 * block so we need not calculate the index.
	 */
	factor = 1;
	for (i = SINGLE; i < level; i++)
		factor *= NINDIR(fs);
	last = lastbn;
	if (lastbn > 0)
		last /= factor;

	devBlockSize = vfs_devblocksize(mp);
	nblocks = btodb(fs->fs_bsize, devBlockSize);

	/* Doing a MALLOC here is asking for trouble. We can still
	 * deadlock on pagerfile lock, in case we are running
	 * low on memory and block in MALLOC
	 */

	tbp = buf_geteblk(fs->fs_bsize);
	copy = (ufs_daddr_t *)buf_dataptr(tbp);

	/*
	 * Get buffer of block pointers, zero those entries corresponding
	 * to blocks to be free'd, and update on disk copy first.  Since
	 * double(triple) indirect before single(double) indirect, calls
	 * to bmap on these blocks will fail.  However, we already have
	 * the on disk address, so we have to set the blkno field
	 * explicitly instead of letting buf_bread do everything for us.
	 */

	vp = ITOV(ip);
	bp = buf_getblk(vp, (daddr64_t)((unsigned)lbn), (int)fs->fs_bsize, 0, 0, BLK_META);

	if (buf_valid(bp)) {
		/* Braces must be here in case trace evaluates to nothing. */
		trace(TR_BREADHIT, pack(vp, fs->fs_bsize), lbn);
	} else {
		trace(TR_BREADMISS, pack(vp, fs->fs_bsize), lbn);
		OSIncrementAtomic(&current_proc()->p_stats->p_ru.ru_inblock);	/* pay for read */
		buf_setflags(bp,  B_READ);
		if (buf_count(bp) > buf_size(bp))
			panic("ffs_indirtrunc: bad buffer size");
		buf_setblkno(bp, (daddr64_t)((unsigned)dbn));
		VNOP_STRATEGY(bp);
		error = buf_biowait(bp);
	}
	if (error) {
		buf_brelse(bp);
		*countp = 0;
		buf_brelse(tbp);
		return ((int)error);
	}

	bap = (ufs_daddr_t *)buf_dataptr(bp);
	bcopy((caddr_t)bap, (caddr_t)copy, (u_int)fs->fs_bsize);
	bzero((caddr_t)&bap[last + 1],
	  (u_int)(NINDIR(fs) - (last + 1)) * sizeof (ufs_daddr_t));
	if (last == -1)
		buf_markinvalid(bp);
	if (last != -1 && (vp)->v_mount->mnt_flag & MNT_ASYNC) {
		error = 0;
		buf_bdwrite(bp);
	} else {
		error = buf_bwrite(bp);
		if (error)
			allerror = error;
	}
	bap = copy;

	/*
	 * Recursively free totally unused blocks.
	 */
	for (i = NINDIR(fs) - 1, nlbn = lbn + 1 - i * factor; i > last;
	    i--, nlbn += factor) {
#if	REV_ENDIAN_FS
		if (rev_endian)
			nb = OSSwapInt32(bap[i]);
		else {
#endif	/* REV_ENDIAN_FS */
			nb = bap[i];
#if	REV_ENDIAN_FS
		}
#endif	/* REV_ENDIAN_FS */
		if (nb == 0)
			continue;
		if (level > SINGLE) {
			if (error = ffs_indirtrunc(ip, nlbn, fsbtodb(fs, nb),
			    (ufs_daddr_t)-1, level - 1, &blkcount))
				allerror = error;
			blocksreleased += blkcount;
		}
		ffs_blkfree(ip, nb, fs->fs_bsize);
		blocksreleased += nblocks;
	}

	/*
	 * Recursively free last partial block.
	 */
	if (level > SINGLE && lastbn >= 0) {
		last = lastbn % factor;
#if	REV_ENDIAN_FS
		if (rev_endian)
			nb = OSSwapInt32(bap[i]);
		else {
#endif	/* REV_ENDIAN_FS */
			nb = bap[i];
#if	REV_ENDIAN_FS
		}
#endif	/* REV_ENDIAN_FS */
		if (nb != 0) {
			if (error = ffs_indirtrunc(ip, nlbn, fsbtodb(fs, nb),
			    last, level - 1, &blkcount))
				allerror = error;
			blocksreleased += blkcount;
		}
	}
	buf_brelse(tbp);
	*countp = blocksreleased;
	return ((int)allerror);
}

