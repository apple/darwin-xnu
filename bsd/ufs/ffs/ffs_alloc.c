/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
 *	@(#)ffs_alloc.c	8.18 (Berkeley) 5/26/95
 */
#include <rev_endian_fs.h>
#include <vm/vm_pager.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/quota.h>

#include <sys/vm.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>

#if REV_ENDIAN_FS
#include <ufs/ufs/ufs_byte_order.h>
#include <libkern/OSByteOrder.h>
#endif /* REV_ENDIAN_FS */

extern u_long nextgennumber;

static ufs_daddr_t ffs_alloccg(struct inode *, int, ufs_daddr_t, int);
static ufs_daddr_t ffs_alloccgblk(struct fs *, struct cg *, ufs_daddr_t);
static ufs_daddr_t ffs_clusteralloc(struct inode *, int, ufs_daddr_t, int);
static ino_t	ffs_dirpref(struct inode *);
static ufs_daddr_t ffs_fragextend(struct inode *, int, long, int, int);
static void	ffs_fserr(struct fs *, u_int, char *);
static u_long	ffs_hashalloc
		   (struct inode *, int, long, int, u_int32_t (*)());
static ino_t	ffs_nodealloccg(struct inode *, int, ufs_daddr_t, int);
static ufs_daddr_t ffs_mapsearch(struct fs *, struct cg *, ufs_daddr_t, int);
static void ffs_clusteracct
		(struct fs *fs, struct cg *cgp, ufs_daddr_t blkno, int cnt);

/*
 * Allocate a block in the file system.
 * 
 * The size of the requested block is given, which must be some
 * multiple of fs_fsize and <= fs_bsize.
 * A preference may be optionally specified. If a preference is given
 * the following hierarchy is used to allocate a block:
 *   1) allocate the requested block.
 *   2) allocate a rotationally optimal block in the same cylinder.
 *   3) allocate a block in the same cylinder group.
 *   4) quadradically rehash into other cylinder groups, until an
 *      available block is located.
 * If no block preference is given the following heirarchy is used
 * to allocate a block:
 *   1) allocate a block in the cylinder group that contains the
 *      inode for the file.
 *   2) quadradically rehash into other cylinder groups, until an
 *      available block is located.
 */
ffs_alloc(ip, lbn, bpref, size, cred, bnp)
	register struct inode *ip;
	ufs_daddr_t lbn, bpref;
	int size;
	kauth_cred_t cred;
	ufs_daddr_t *bnp;
{
	register struct fs *fs;
	ufs_daddr_t bno;
	int cg, error;
	int devBlockSize=0;
	*bnp = 0;
	fs = ip->i_fs;
#if DIAGNOSTIC
	if ((u_int)size > fs->fs_bsize || fragoff(fs, size) != 0) {
		printf("dev = 0x%x, bsize = %d, size = %d, fs = %s\n",
		    ip->i_dev, fs->fs_bsize, size, fs->fs_fsmnt);
		panic("ffs_alloc: bad size");
	}
	if (cred == NOCRED)
		panic("ffs_alloc: missing credential\n");
#endif /* DIAGNOSTIC */
	if (size == fs->fs_bsize && fs->fs_cstotal.cs_nbfree == 0)
		goto nospace;
	if (suser(cred, NULL) && freespace(fs, fs->fs_minfree) <= 0)
		goto nospace;
	devBlockSize = vfs_devblocksize(vnode_mount(ITOV(ip)));
#if QUOTA
	if (error = chkdq(ip, (int64_t)size, cred, 0))
		return (error);
#endif /* QUOTA */
	if (bpref >= fs->fs_size)
		bpref = 0;
	if (bpref == 0)
		cg = ino_to_cg(fs, ip->i_number);
	else
		cg = dtog(fs, bpref);
	bno = (ufs_daddr_t)ffs_hashalloc(ip, cg, (long)bpref, size,
	    (u_int32_t (*)())ffs_alloccg);
	if (bno > 0) {
		ip->i_blocks += btodb(size, devBlockSize);
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
		*bnp = bno;
		return (0);
	}
#if QUOTA
	/*
	 * Restore user's disk quota because allocation failed.
	 */
	(void) chkdq(ip, (int64_t)-size, cred, FORCE);
#endif /* QUOTA */
nospace:
	ffs_fserr(fs, kauth_cred_getuid(cred), "file system full");
	uprintf("\n%s: write failed, file system is full\n", fs->fs_fsmnt);
	return (ENOSPC);
}

/*
 * Reallocate a fragment to a bigger size
 *
 * The number and size of the old block is given, and a preference
 * and new size is also specified. The allocator attempts to extend
 * the original block. Failing that, the regular block allocator is
 * invoked to get an appropriate block.
 */
ffs_realloccg(ip, lbprev, bpref, osize, nsize, cred, bpp)
	register struct inode *ip;
	ufs_daddr_t lbprev;
	ufs_daddr_t bpref;
	int osize, nsize;
	kauth_cred_t cred;
	struct buf **bpp;
{
	register struct fs *fs;
	struct buf *bp;
	int cg, request, error;
	ufs_daddr_t bprev, bno;
	int devBlockSize=0;
	
	*bpp = 0;
	fs = ip->i_fs;
#if DIAGNOSTIC
	if ((u_int)osize > fs->fs_bsize || fragoff(fs, osize) != 0 ||
	    (u_int)nsize > fs->fs_bsize || fragoff(fs, nsize) != 0) {
		printf(
		    "dev = 0x%x, bsize = %d, osize = %d, nsize = %d, fs = %s\n",
		    ip->i_dev, fs->fs_bsize, osize, nsize, fs->fs_fsmnt);
		panic("ffs_realloccg: bad size");
	}
	if (cred == NOCRED)
		panic("ffs_realloccg: missing credential\n");
#endif /* DIAGNOSTIC */
	if (suser(cred, NULL) != 0 && freespace(fs, fs->fs_minfree) <= 0)
		goto nospace;
	if ((bprev = ip->i_db[lbprev]) == 0) {
		printf("dev = 0x%x, bsize = %d, bprev = %d, fs = %s\n",
		    ip->i_dev, fs->fs_bsize, bprev, fs->fs_fsmnt);
		panic("ffs_realloccg: bad bprev");
	}
	/*
	 * Allocate the extra space in the buffer.
	 */
	if (error = (int)buf_bread(ITOV(ip), (daddr64_t)((unsigned)lbprev), osize, NOCRED, &bp)) {
		buf_brelse(bp);
		return (error);
	}
	devBlockSize = vfs_devblocksize(vnode_mount(ITOV(ip)));

#if QUOTA
	if (error = chkdq(ip, (int64_t)(nsize - osize), cred, 0))
	{
		buf_brelse(bp);
		return (error);
	}
#endif /* QUOTA */
	/*
	 * Check for extension in the existing location.
	 */
	cg = dtog(fs, bprev);
	if (bno = ffs_fragextend(ip, cg, (long)bprev, osize, nsize)) {
		if ((ufs_daddr_t)buf_blkno(bp) != fsbtodb(fs, bno))
			panic("bad blockno");
		ip->i_blocks += btodb(nsize - osize, devBlockSize);
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
		allocbuf(bp, nsize);
		buf_setflags(bp, B_DONE);
		bzero((char *)buf_dataptr(bp) + osize, (u_int)buf_size(bp) - osize);
		*bpp = bp;
		return (0);
	}
	/*
	 * Allocate a new disk location.
	 */
	if (bpref >= fs->fs_size)
		bpref = 0;
	switch ((int)fs->fs_optim) {
	case FS_OPTSPACE:
		/*
		 * Allocate an exact sized fragment. Although this makes 
		 * best use of space, we will waste time relocating it if 
		 * the file continues to grow. If the fragmentation is
		 * less than half of the minimum free reserve, we choose
		 * to begin optimizing for time.
		 */
		request = nsize;
		if (fs->fs_minfree < 5 ||
		    fs->fs_cstotal.cs_nffree >
		    fs->fs_dsize * fs->fs_minfree / (2 * 100))
			break;
		log(LOG_NOTICE, "%s: optimization changed from SPACE to TIME\n",
			fs->fs_fsmnt);
		fs->fs_optim = FS_OPTTIME;
		break;
	case FS_OPTTIME:
		/*
		 * At this point we have discovered a file that is trying to
		 * grow a small fragment to a larger fragment. To save time,
		 * we allocate a full sized block, then free the unused portion.
		 * If the file continues to grow, the `ffs_fragextend' call
		 * above will be able to grow it in place without further
		 * copying. If aberrant programs cause disk fragmentation to
		 * grow within 2% of the free reserve, we choose to begin
		 * optimizing for space.
		 */
		request = fs->fs_bsize;
		if (fs->fs_cstotal.cs_nffree <
		    fs->fs_dsize * (fs->fs_minfree - 2) / 100)
			break;
		log(LOG_NOTICE, "%s: optimization changed from TIME to SPACE\n",
			fs->fs_fsmnt);
		fs->fs_optim = FS_OPTSPACE;
		break;
	default:
		printf("dev = 0x%x, optim = %d, fs = %s\n",
		    ip->i_dev, fs->fs_optim, fs->fs_fsmnt);
		panic("ffs_realloccg: bad optim");
		/* NOTREACHED */
	}
	bno = (ufs_daddr_t)ffs_hashalloc(ip, cg, (long)bpref, request,
	    (u_int32_t (*)())ffs_alloccg);
	if (bno > 0) {
	        buf_setblkno(bp, (daddr64_t)((unsigned)fsbtodb(fs, bno)));
		ffs_blkfree(ip, bprev, (long)osize);
		if (nsize < request)
			ffs_blkfree(ip, bno + numfrags(fs, nsize),
			    (long)(request - nsize));
		ip->i_blocks += btodb(nsize - osize, devBlockSize);
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
		allocbuf(bp, nsize);
		buf_setflags(bp, B_DONE);
		bzero((char *)buf_dataptr(bp) + osize, (u_int)buf_size(bp) - osize);
		*bpp = bp;
		return (0);
	}
#if QUOTA
	/*
	 * Restore user's disk quota because allocation failed.
	 */
	(void) chkdq(ip, (int64_t)-(nsize - osize), cred, FORCE);
#endif /* QUOTA */
	buf_brelse(bp);
nospace:
	/*
	 * no space available
	 */
	ffs_fserr(fs, kauth_cred_getuid(cred), "file system full");
	uprintf("\n%s: write failed, file system is full\n", fs->fs_fsmnt);
	return (ENOSPC);
}

/*
 * Reallocate a sequence of blocks into a contiguous sequence of blocks.
 *
 * The vnode and an array of buffer pointers for a range of sequential
 * logical blocks to be made contiguous is given. The allocator attempts
 * to find a range of sequential blocks starting as close as possible to
 * an fs_rotdelay offset from the end of the allocation for the logical
 * block immediately preceeding the current range. If successful, the
 * physical block numbers in the buffer pointers and in the inode are
 * changed to reflect the new allocation. If unsuccessful, the allocation
 * is left unchanged. The success in doing the reallocation is returned.
 * Note that the error return is not reflected back to the user. Rather
 * the previous block allocation will be used.
 */
/* Note: This routine is unused in UBC cluster I/O */

int doasyncfree = 1;
int doreallocblks = 1;


/*
 * Allocate an inode in the file system.
 * 
 * If allocating a directory, use ffs_dirpref to select the inode.
 * If allocating in a directory, the following hierarchy is followed:
 *   1) allocate the preferred inode.
 *   2) allocate an inode in the same cylinder group.
 *   3) quadradically rehash into other cylinder groups, until an
 *      available inode is located.
 * If no inode preference is given the following heirarchy is used
 * to allocate an inode:
 *   1) allocate an inode in cylinder group 0.
 *   2) quadradically rehash into other cylinder groups, until an
 *      available inode is located.
 */
int
ffs_valloc(
		struct vnode *pvp,
		mode_t mode,
		kauth_cred_t cred,
		struct vnode **vpp)

{
	register struct inode *pip;
	register struct fs *fs;
	register struct inode *ip;
	struct timeval tv;
	ino_t ino, ipref;
	int cg, error;
	
	*vpp = NULL;
	pip = VTOI(pvp);
	fs = pip->i_fs;
	if (fs->fs_cstotal.cs_nifree == 0)
		goto noinodes;

	if ((mode & IFMT) == IFDIR)
		ipref = ffs_dirpref(pip);
	else
		ipref = pip->i_number;
	if (ipref >= fs->fs_ncg * fs->fs_ipg)
		ipref = 0;
	cg = ino_to_cg(fs, ipref);
	/*
	 * Track the number of dirs created one after another
	 * in a cg without intervening files.
	 */
	if ((mode & IFMT) == IFDIR) {
		if (fs->fs_contigdirs[cg] < 255)
			fs->fs_contigdirs[cg]++;
	} else {
		if (fs->fs_contigdirs[cg] > 0)
			fs->fs_contigdirs[cg]--;
	}
	ino = (ino_t)ffs_hashalloc(pip, cg, (long)ipref, mode, ffs_nodealloccg);
	if (ino == 0)
		goto noinodes;

        error = ffs_vget_internal(pvp->v_mount, ino, vpp, NULL, NULL, mode, 0);
	if (error) {
		ffs_vfree(pvp, ino, mode);
		return (error);
	}
	ip = VTOI(*vpp);

	if (ip->i_mode) {
		printf("mode = 0%o, inum = %d, fs = %s\n",
		    ip->i_mode, ip->i_number, fs->fs_fsmnt);
		panic("ffs_valloc: dup alloc");
	}
	if (ip->i_blocks) {				/* XXX */
		printf("free inode %s/%d had %d blocks\n",
		    fs->fs_fsmnt, ino, ip->i_blocks);
		ip->i_blocks = 0;
	}
	ip->i_flags = 0;
	/*
	 * Set up a new generation number for this inode.
	 */
	microtime(&tv);
	if (++nextgennumber < (u_long)tv.tv_sec)
		nextgennumber = tv.tv_sec;
	ip->i_gen = nextgennumber;
	return (0);
noinodes:
	ffs_fserr(fs, kauth_cred_getuid(cred), "out of inodes");
	uprintf("\n%s: create/symlink failed, no inodes free\n", fs->fs_fsmnt);
	return (ENOSPC);
}

/*
 * Find a cylinder group to place a directory.
 *
 * The policy implemented by this algorithm is to allocate a
 * directory inode in the same cylinder group as its parent
 * directory, but also to reserve space for its files inodes
 * and data. Restrict the number of directories which may be
 * allocated one after another in the same cylinder group
 * without intervening allocation of files.
 */
static ino_t
ffs_dirpref(pip)
	struct inode *pip;
{
	register struct fs *fs;
	int cg, prefcg, dirsize, cgsize;
	int avgifree, avgbfree, avgndir, curdirsize;
	int minifree, minbfree, maxndir;
	int mincg, minndir;
	int maxcontigdirs;

	fs = pip->i_fs;
	avgifree = fs->fs_cstotal.cs_nifree / fs->fs_ncg;
	avgbfree = fs->fs_cstotal.cs_nbfree / fs->fs_ncg;
	avgndir = fs->fs_cstotal.cs_ndir / fs->fs_ncg;

	/*
	 * Force allocation in another cg if creating a first level dir.
	 */
	if (ITOV(pip)->v_flag & VROOT) {
#ifdef __APPLE__
		prefcg = random() % fs->fs_ncg;
#else
		prefcg = arc4random() % fs->fs_ncg;
#endif
		mincg = prefcg;
		minndir = fs->fs_ipg;
		for (cg = prefcg; cg < fs->fs_ncg; cg++)
			if (fs->fs_cs(fs, cg).cs_ndir < minndir &&
			    fs->fs_cs(fs, cg).cs_nifree >= avgifree &&
			    fs->fs_cs(fs, cg).cs_nbfree >= avgbfree) {
				mincg = cg;
				minndir = fs->fs_cs(fs, cg).cs_ndir;
			}
		for (cg = 0; cg < prefcg; cg++)
			if (fs->fs_cs(fs, cg).cs_ndir < minndir &&
			    fs->fs_cs(fs, cg).cs_nifree >= avgifree &&
			    fs->fs_cs(fs, cg).cs_nbfree >= avgbfree) {
				mincg = cg;
				minndir = fs->fs_cs(fs, cg).cs_ndir;
			}
		return ((ino_t)(fs->fs_ipg * mincg));
	}

	/*
	 * Count various limits which used for
	 * optimal allocation of a directory inode.
	 */
	maxndir = min(avgndir + fs->fs_ipg / 16, fs->fs_ipg);
	minifree = avgifree - fs->fs_ipg / 4;
	if (minifree < 0)
		minifree = 0;
	minbfree = avgbfree - fs->fs_fpg / fs->fs_frag / 4;
	if (minbfree < 0)
		minbfree = 0;
	cgsize = fs->fs_fsize * fs->fs_fpg;
	dirsize = fs->fs_avgfilesize * fs->fs_avgfpdir;
	curdirsize = avgndir ? (cgsize - avgbfree * fs->fs_bsize) / avgndir : 0;
	if (dirsize < curdirsize)
		dirsize = curdirsize;
	maxcontigdirs = min(cgsize / dirsize, 255);
	if (fs->fs_avgfpdir > 0)
		maxcontigdirs = min(maxcontigdirs,
		    fs->fs_ipg / fs->fs_avgfpdir);
	if (maxcontigdirs == 0)
		maxcontigdirs = 1;

	/*
	 * Limit number of dirs in one cg and reserve space for
	 * regular files, but only if we have no deficit in
	 * inodes or space.
	 */
	prefcg = ino_to_cg(fs, pip->i_number);
	for (cg = prefcg; cg < fs->fs_ncg; cg++)
		if (fs->fs_cs(fs, cg).cs_ndir < maxndir &&
		    fs->fs_cs(fs, cg).cs_nifree >= minifree &&
		    fs->fs_cs(fs, cg).cs_nbfree >= minbfree) {
			if (fs->fs_contigdirs[cg] < maxcontigdirs)
				return ((ino_t)(fs->fs_ipg * cg));
		}
	for (cg = 0; cg < prefcg; cg++)
		if (fs->fs_cs(fs, cg).cs_ndir < maxndir &&
		    fs->fs_cs(fs, cg).cs_nifree >= minifree &&
		    fs->fs_cs(fs, cg).cs_nbfree >= minbfree) {
			if (fs->fs_contigdirs[cg] < maxcontigdirs)
				return ((ino_t)(fs->fs_ipg * cg));
		}
	/*
	 * This is a backstop when we have deficit in space.
	 */
	for (cg = prefcg; cg < fs->fs_ncg; cg++)
		if (fs->fs_cs(fs, cg).cs_nifree >= avgifree)
			return ((ino_t)(fs->fs_ipg * cg));
	for (cg = 0; cg < prefcg; cg++)
		if (fs->fs_cs(fs, cg).cs_nifree >= avgifree)
			break;
	return ((ino_t)(fs->fs_ipg * cg));
}

/*
 * Select the desired position for the next block in a file.  The file is
 * logically divided into sections. The first section is composed of the
 * direct blocks. Each additional section contains fs_maxbpg blocks.
 * 
 * If no blocks have been allocated in the first section, the policy is to
 * request a block in the same cylinder group as the inode that describes
 * the file. If no blocks have been allocated in any other section, the
 * policy is to place the section in a cylinder group with a greater than
 * average number of free blocks.  An appropriate cylinder group is found
 * by using a rotor that sweeps the cylinder groups. When a new group of
 * blocks is needed, the sweep begins in the cylinder group following the
 * cylinder group from which the previous allocation was made. The sweep
 * continues until a cylinder group with greater than the average number
 * of free blocks is found. If the allocation is for the first block in an
 * indirect block, the information on the previous allocation is unavailable;
 * here a best guess is made based upon the logical block number being
 * allocated.
 * 
 * If a section is already partially allocated, the policy is to
 * contiguously allocate fs_maxcontig blocks.  The end of one of these
 * contiguous blocks and the beginning of the next is physically separated
 * so that the disk head will be in transit between them for at least
 * fs_rotdelay milliseconds.  This is to allow time for the processor to
 * schedule another I/O transfer.
 */
ufs_daddr_t
ffs_blkpref(ip, lbn, indx, bap)
	struct inode *ip;
	ufs_daddr_t lbn;
	int indx;
	ufs_daddr_t *bap;
{
	register struct fs *fs;
	register int cg;
	int avgbfree, startcg;
	ufs_daddr_t nextblk;
#if	REV_ENDIAN_FS
	daddr_t prev=0;
	struct vnode *vp=ITOV(ip);
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif	/* REV_ENDIAN_FS */

	fs = ip->i_fs;
#if	REV_ENDIAN_FS
	if (indx && bap) {
	if (rev_endian) {
		if (bap != &ip->i_db[0])
			prev = OSSwapInt32(bap[indx - 1]);
		else
			prev = bap[indx - 1];
	} else prev = bap[indx - 1];
	}
	if (indx % fs->fs_maxbpg == 0 || prev == 0)
#else	/* REV_ENDIAN_FS */
	if (indx % fs->fs_maxbpg == 0 || bap[indx - 1] == 0) 
#endif /* REV_ENDIAN_FS */
	{
		if (lbn < NDADDR) {
			cg = ino_to_cg(fs, ip->i_number);
			return (fs->fs_fpg * cg + fs->fs_frag);
		}
		/*
		 * Find a cylinder with greater than average number of
		 * unused data blocks.
		 */
#if	REV_ENDIAN_FS
		if (indx == 0 || prev == 0)
#else	/* REV_ENDIAN_FS */
		if (indx == 0 || bap[indx - 1] == 0)
#endif /* REV_ENDIAN_FS */
			startcg =
			    ino_to_cg(fs, ip->i_number) + lbn / fs->fs_maxbpg;
		else
#if	REV_ENDIAN_FS
			startcg = dtog(fs, prev) + 1;
#else	/* REV_ENDIAN_FS */
			startcg = dtog(fs, bap[indx - 1]) + 1;
#endif	/* REV_ENDIAN_FS */
		startcg %= fs->fs_ncg;
		avgbfree = fs->fs_cstotal.cs_nbfree / fs->fs_ncg;
		for (cg = startcg; cg < fs->fs_ncg; cg++)
			if (fs->fs_cs(fs, cg).cs_nbfree >= avgbfree) {
				fs->fs_cgrotor = cg;
				return (fs->fs_fpg * cg + fs->fs_frag);
			}
		for (cg = 0; cg <= startcg; cg++)
			if (fs->fs_cs(fs, cg).cs_nbfree >= avgbfree) {
				fs->fs_cgrotor = cg;
				return (fs->fs_fpg * cg + fs->fs_frag);
			}
		return (NULL);
	}
	/*
	 * One or more previous blocks have been laid out. If less
	 * than fs_maxcontig previous blocks are contiguous, the
	 * next block is requested contiguously, otherwise it is
	 * requested rotationally delayed by fs_rotdelay milliseconds.
	 */
#if	REV_ENDIAN_FS
	if (rev_endian) {
		nextblk = prev + fs->fs_frag;
		if (indx < fs->fs_maxcontig) {
			return (nextblk);
		}
		if (bap != &ip->i_db[0])
			prev = OSSwapInt32(bap[indx - fs->fs_maxcontig]);
		else
			prev = bap[indx - fs->fs_maxcontig];
		if (prev + blkstofrags(fs, fs->fs_maxcontig) != nextblk)
			return (nextblk);
	} else {
#endif	/* REV_ENDIAN_FS */
	nextblk = bap[indx - 1] + fs->fs_frag;
	if (indx < fs->fs_maxcontig || bap[indx - fs->fs_maxcontig] +
	    blkstofrags(fs, fs->fs_maxcontig) != nextblk)
		return (nextblk);
#if REV_ENDIAN_FS
	}
#endif	/* REV_ENDIAN_FS */
	if (fs->fs_rotdelay != 0)
		/*
		 * Here we convert ms of delay to frags as:
		 * (frags) = (ms) * (rev/sec) * (sect/rev) /
		 *	((sect/frag) * (ms/sec))
		 * then round up to the next block.
		 */
		nextblk += roundup(fs->fs_rotdelay * fs->fs_rps * fs->fs_nsect /
		    (NSPF(fs) * 1000), fs->fs_frag);
	return (nextblk);
}

/*
 * Implement the cylinder overflow algorithm.
 *
 * The policy implemented by this algorithm is:
 *   1) allocate the block in its requested cylinder group.
 *   2) quadradically rehash on the cylinder group number.
 *   3) brute force search for a free block.
 */
/*VARARGS5*/
static u_long
ffs_hashalloc(ip, cg, pref, size, allocator)
	struct inode *ip;
	int cg;
	long pref;
	int size;	/* size for data blocks, mode for inodes */
	u_int32_t (*allocator)();
{
	register struct fs *fs;
	long result;
	int i, icg = cg;

	fs = ip->i_fs;
	/*
	 * 1: preferred cylinder group
	 */
	result = (*allocator)(ip, cg, pref, size);
	if (result)
		return (result);
	/*
	 * 2: quadratic rehash
	 */
	for (i = 1; i < fs->fs_ncg; i *= 2) {
		cg += i;
		if (cg >= fs->fs_ncg)
			cg -= fs->fs_ncg;
		result = (*allocator)(ip, cg, 0, size);
		if (result)
			return (result);
	}
	/*
	 * 3: brute force search
	 * Note that we start at i == 2, since 0 was checked initially,
	 * and 1 is always checked in the quadratic rehash.
	 */
	cg = (icg + 2) % fs->fs_ncg;
	for (i = 2; i < fs->fs_ncg; i++) {
		result = (*allocator)(ip, cg, 0, size);
		if (result)
			return (result);
		cg++;
		if (cg == fs->fs_ncg)
			cg = 0;
	}
	return (NULL);
}

/*
 * Determine whether a fragment can be extended.
 *
 * Check to see if the necessary fragments are available, and 
 * if they are, allocate them.
 */
static ufs_daddr_t
ffs_fragextend(ip, cg, bprev, osize, nsize)
	struct inode *ip;
	int cg;
	long bprev;
	int osize, nsize;
{
	register struct fs *fs;
	register struct cg *cgp;
	struct buf *bp;
	struct timeval tv;
	long bno;
	int frags, bbase;
	int i, error;
#if REV_ENDIAN_FS
	struct vnode *vp=ITOV(ip);
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	fs = ip->i_fs;
	if (fs->fs_cs(fs, cg).cs_nffree < numfrags(fs, nsize - osize))
		return (NULL);
	frags = numfrags(fs, nsize); /* number of fragments needed */
	bbase = fragnum(fs, bprev); /* 	offset in a frag (it is mod fragsize */
	if (bbase > fragnum(fs, (bprev + frags - 1))) {
		/* cannot extend across a block boundary */
		return (NULL);
	}
	/* read corresponding cylinder group info */
	error = (int)buf_bread(ip->i_devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, cg))),
			       (int)fs->fs_cgsize, NOCRED, &bp);
	if (error) {
		buf_brelse(bp);
		return (NULL);
	}
	cgp = (struct cg *)buf_dataptr(bp);
#if REV_ENDIAN_FS
	if (rev_endian) {
		byte_swap_cgin(cgp, fs);
	}
#endif /* REV_ENDIAN_FS */

	if (!cg_chkmagic(cgp)) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		buf_brelse(bp);
		return (NULL);
	}
	microtime(&tv);
	cgp->cg_time = tv.tv_sec;
	bno = dtogd(fs, bprev);
	for (i = numfrags(fs, osize); i < frags; i++)
		if (isclr(cg_blksfree(cgp), bno + i)) {
#if REV_ENDIAN_FS
			if (rev_endian)
				byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
			buf_brelse(bp);
			return (NULL);
		}
	/*
	 * the current fragment can be extended
	 * deduct the count on fragment being extended into
	 * increase the count on the remaining fragment (if any)
	 * allocate the extended piece
	 */
	for (i = frags; i < fs->fs_frag - bbase; i++)
		if (isclr(cg_blksfree(cgp), bno + i))
			break;
	cgp->cg_frsum[i - numfrags(fs, osize)]--;
	if (i != frags)
		cgp->cg_frsum[i - frags]++;
	for (i = numfrags(fs, osize); i < frags; i++) {
		clrbit(cg_blksfree(cgp), bno + i);
		cgp->cg_cs.cs_nffree--;
		fs->fs_cstotal.cs_nffree--;
		fs->fs_cs(fs, cg).cs_nffree--;
	}
	fs->fs_fmod = 1;
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
	buf_bdwrite(bp);
	return (bprev);
}

/*
 * Determine whether a block can be allocated.
 *
 * Check to see if a block of the appropriate size is available,
 * and if it is, allocate it.
 */
static ufs_daddr_t
ffs_alloccg(ip, cg, bpref, size)
	struct inode *ip;
	int cg;
	ufs_daddr_t bpref;
	int size;
{
	register struct fs *fs;
	register struct cg *cgp;
	struct buf *bp;
	struct timeval tv;
	register int i;
	int error, bno, frags, allocsiz;
#if REV_ENDIAN_FS
	struct vnode *vp=ITOV(ip);
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	fs = ip->i_fs;
	if (fs->fs_cs(fs, cg).cs_nbfree == 0 && size == fs->fs_bsize)
		return (NULL);
	error = (int)buf_bread(ip->i_devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, cg))),
			       (int)fs->fs_cgsize, NOCRED, &bp);
	if (error) {
		buf_brelse(bp);
		return (NULL);
	}
	cgp = (struct cg *)buf_dataptr(bp);
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgin(cgp,fs);
#endif /* REV_ENDIAN_FS */
	if (!cg_chkmagic(cgp) ||
	    (cgp->cg_cs.cs_nbfree == 0 && size == fs->fs_bsize)) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		buf_brelse(bp);
		return (NULL);
	}
	microtime(&tv);
	cgp->cg_time = tv.tv_sec;
	if (size == fs->fs_bsize) {
		bno = ffs_alloccgblk(fs, cgp, bpref);
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		buf_bdwrite(bp);
		return (bno);
	}
	/*
	 * check to see if any fragments are already available
	 * allocsiz is the size which will be allocated, hacking
	 * it down to a smaller size if necessary
	 */
	frags = numfrags(fs, size);
	for (allocsiz = frags; allocsiz < fs->fs_frag; allocsiz++)
		if (cgp->cg_frsum[allocsiz] != 0)
			break;
	if (allocsiz == fs->fs_frag) {
		/*
		 * no fragments were available, so a block will be 
		 * allocated, and hacked up
		 */
		if (cgp->cg_cs.cs_nbfree == 0) {
#if	REV_ENDIAN_FS
			if (rev_endian)
				byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
			buf_brelse(bp);
			return (NULL);
		}
		bno = ffs_alloccgblk(fs, cgp, bpref);
		bpref = dtogd(fs, bno);
		for (i = frags; i < fs->fs_frag; i++)
			setbit(cg_blksfree(cgp), bpref + i);
		i = fs->fs_frag - frags;
		cgp->cg_cs.cs_nffree += i;
		fs->fs_cstotal.cs_nffree += i;
		fs->fs_cs(fs, cg).cs_nffree += i;
		fs->fs_fmod = 1;
		cgp->cg_frsum[i]++;
#if	REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
		buf_bdwrite(bp);
		return (bno);
	}
	bno = ffs_mapsearch(fs, cgp, bpref, allocsiz);
	if (bno < 0) {
#if	REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
		buf_brelse(bp);
		return (NULL);
	}
	for (i = 0; i < frags; i++)
		clrbit(cg_blksfree(cgp), bno + i);
	cgp->cg_cs.cs_nffree -= frags;
	fs->fs_cstotal.cs_nffree -= frags;
	fs->fs_cs(fs, cg).cs_nffree -= frags;
	fs->fs_fmod = 1;
	cgp->cg_frsum[allocsiz]--;
	if (frags != allocsiz)
		cgp->cg_frsum[allocsiz - frags]++;
#if	REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
	buf_bdwrite(bp);
	return (cg * fs->fs_fpg + bno);
}

/*
 * Allocate a block in a cylinder group.
 *
 * This algorithm implements the following policy:
 *   1) allocate the requested block.
 *   2) allocate a rotationally optimal block in the same cylinder.
 *   3) allocate the next available block on the block rotor for the
 *      specified cylinder group.
 * Note that this routine only allocates fs_bsize blocks; these
 * blocks may be fragmented by the routine that allocates them.
 */
static ufs_daddr_t
ffs_alloccgblk(fs, cgp, bpref)
	register struct fs *fs;
	register struct cg *cgp;
	ufs_daddr_t bpref;
{
	ufs_daddr_t bno, blkno;
	int cylno, pos, delta;
	short *cylbp;
	register int i;

	if (bpref == 0 || dtog(fs, bpref) != cgp->cg_cgx) {
		bpref = cgp->cg_rotor;
		goto norot;
	}
	bpref = blknum(fs, bpref);
	bpref = dtogd(fs, bpref);
	/*
	 * if the requested block is available, use it
	 */
	if (ffs_isblock(fs, cg_blksfree(cgp), fragstoblks(fs, bpref))) {
		bno = bpref;
		goto gotit;
	}
	if (fs->fs_nrpos <= 1 || fs->fs_cpc == 0) {
		/*
		 * Block layout information is not available.
		 * Leaving bpref unchanged means we take the
		 * next available free block following the one 
		 * we just allocated. Hopefully this will at
		 * least hit a track cache on drives of unknown
		 * geometry (e.g. SCSI).
		 */
		goto norot;
	}
	/*
	 * check for a block available on the same cylinder
	 */
	cylno = cbtocylno(fs, bpref);
	if (cg_blktot(cgp)[cylno] == 0)
		goto norot;
	/*
	 * check the summary information to see if a block is 
	 * available in the requested cylinder starting at the
	 * requested rotational position and proceeding around.
	 */
	cylbp = cg_blks(fs, cgp, cylno);
	pos = cbtorpos(fs, bpref);
	for (i = pos; i < fs->fs_nrpos; i++)
		if (cylbp[i] > 0)
			break;
	if (i == fs->fs_nrpos)
		for (i = 0; i < pos; i++)
			if (cylbp[i] > 0)
				break;
	if (cylbp[i] > 0) {
		/*
		 * found a rotational position, now find the actual
		 * block. A panic if none is actually there.
		 */
		pos = cylno % fs->fs_cpc;
		bno = (cylno - pos) * fs->fs_spc / NSPB(fs);
		if (fs_postbl(fs, pos)[i] == -1) {
			printf("pos = %d, i = %d, fs = %s\n",
			    pos, i, fs->fs_fsmnt);
			panic("ffs_alloccgblk: cyl groups corrupted");
		}
		for (i = fs_postbl(fs, pos)[i];; ) {
			if (ffs_isblock(fs, cg_blksfree(cgp), bno + i)) {
				bno = blkstofrags(fs, (bno + i));
				goto gotit;
			}
			delta = fs_rotbl(fs)[i];
			if (delta <= 0 ||
			    delta + i > fragstoblks(fs, fs->fs_fpg))
				break;
			i += delta;
		}
		printf("pos = %d, i = %d, fs = %s\n", pos, i, fs->fs_fsmnt);
		panic("ffs_alloccgblk: can't find blk in cyl");
	}
norot:
	/*
	 * no blocks in the requested cylinder, so take next
	 * available one in this cylinder group.
	 */
	bno = ffs_mapsearch(fs, cgp, bpref, (int)fs->fs_frag);
	if (bno < 0)
		return (NULL);
	cgp->cg_rotor = bno;
gotit:
	blkno = fragstoblks(fs, bno);
	ffs_clrblock(fs, cg_blksfree(cgp), (long)blkno);
	ffs_clusteracct(fs, cgp, blkno, -1);
	cgp->cg_cs.cs_nbfree--;
	fs->fs_cstotal.cs_nbfree--;
	fs->fs_cs(fs, cgp->cg_cgx).cs_nbfree--;
	cylno = cbtocylno(fs, bno);
	cg_blks(fs, cgp, cylno)[cbtorpos(fs, bno)]--;
	cg_blktot(cgp)[cylno]--;
	fs->fs_fmod = 1;
	return (cgp->cg_cgx * fs->fs_fpg + bno);
}

/*
 * Determine whether a cluster can be allocated.
 *
 * We do not currently check for optimal rotational layout if there
 * are multiple choices in the same cylinder group. Instead we just
 * take the first one that we find following bpref.
 */
static ufs_daddr_t
ffs_clusteralloc(ip, cg, bpref, len)
	struct inode *ip;
	int cg;
	ufs_daddr_t bpref;
	int len;
{
	register struct fs *fs;
	register struct cg *cgp;
	struct buf *bp;
	int i, got, run, bno, bit, map;
	u_char *mapp;
	int32_t *lp;
#if REV_ENDIAN_FS
	struct vnode *vp=ITOV(ip);
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	fs = ip->i_fs;
	if (fs->fs_maxcluster[cg] < len)
		return (NULL);
	if (buf_bread(ip->i_devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, cg))), (int)fs->fs_cgsize,
		      NOCRED, &bp))
		goto fail;
	cgp = (struct cg *)buf_dataptr(bp);
#if	REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgin(cgp,fs);
#endif	/* REV_ENDIAN_FS */
	if (!cg_chkmagic(cgp)) {
#if	REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
		goto fail;
	}
	/*
	 * Check to see if a cluster of the needed size (or bigger) is
	 * available in this cylinder group.
	 */
	lp = &cg_clustersum(cgp)[len];
	for (i = len; i <= fs->fs_contigsumsize; i++)
		if (*lp++ > 0)
			break;
	if (i > fs->fs_contigsumsize) {
		/*
		 * This is the first time looking for a cluster in this
		 * cylinder group. Update the cluster summary information
		 * to reflect the true maximum sized cluster so that
		 * future cluster allocation requests can avoid reading
		 * the cylinder group map only to find no clusters.
		 */
		lp = &cg_clustersum(cgp)[len - 1];
		for (i = len - 1; i > 0; i--)
			if (*lp-- > 0)
				break;
		fs->fs_maxcluster[cg] = i;
#if	REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
		goto fail;
	}
	/*
	 * Search the cluster map to find a big enough cluster.
	 * We take the first one that we find, even if it is larger
	 * than we need as we prefer to get one close to the previous
	 * block allocation. We do not search before the current
	 * preference point as we do not want to allocate a block
	 * that is allocated before the previous one (as we will
	 * then have to wait for another pass of the elevator
	 * algorithm before it will be read). We prefer to fail and
	 * be recalled to try an allocation in the next cylinder group.
	 */
	if (dtog(fs, bpref) != cg)
		bpref = 0;
	else
		bpref = fragstoblks(fs, dtogd(fs, blknum(fs, bpref)));
	mapp = &cg_clustersfree(cgp)[bpref / NBBY];
	map = *mapp++;
	bit = 1 << (bpref % NBBY);
	for (run = 0, got = bpref; got < cgp->cg_nclusterblks; got++) {
		if ((map & bit) == 0) {
			run = 0;
		} else {
			run++;
			if (run == len)
				break;
		}
		if ((got & (NBBY - 1)) != (NBBY - 1)) {
			bit <<= 1;
		} else {
			map = *mapp++;
			bit = 1;
		}
	}
	if (got == cgp->cg_nclusterblks) {
#if	REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
		goto fail;
	}
	/*
	 * Allocate the cluster that we have found.
	 */
	for (i = 1; i <= len; i++)
		if (!ffs_isblock(fs, cg_blksfree(cgp), got - run + i))
			panic("ffs_clusteralloc: map mismatch");
	bno = cg * fs->fs_fpg + blkstofrags(fs, got - run + 1);
	if (dtog(fs, bno) != cg)
		panic("ffs_clusteralloc: allocated out of group");
	len = blkstofrags(fs, len);
	for (i = 0; i < len; i += fs->fs_frag)
		if ((got = ffs_alloccgblk(fs, cgp, bno + i)) != bno + i)
			panic("ffs_clusteralloc: lost block");
#if	REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgout(cgp,fs);
#endif	/* REV_ENDIAN_FS */
	buf_bdwrite(bp);
	return (bno);

fail:
	buf_brelse(bp);
	return (0);
}

/*
 * Determine whether an inode can be allocated.
 *
 * Check to see if an inode is available, and if it is,
 * allocate it using the following policy:
 *   1) allocate the requested inode.
 *   2) allocate the next available inode after the requested
 *      inode in the specified cylinder group.
 */
static ino_t
ffs_nodealloccg(ip, cg, ipref, mode)
	struct inode *ip;
	int cg;
	ufs_daddr_t ipref;
	int mode;
{
	register struct fs *fs;
	register struct cg *cgp;
	struct buf *bp;
	struct timeval tv;
	int error, start, len, loc, map, i;
#if REV_ENDIAN_FS
	struct vnode *vp=ITOV(ip);
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	fs = ip->i_fs;
	if (fs->fs_cs(fs, cg).cs_nifree == 0)
		return (NULL);
	error = (int)buf_bread(ip->i_devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, cg))),
			       (int)fs->fs_cgsize, NOCRED, &bp);
	if (error) {
		buf_brelse(bp);
		return (NULL);
	}
	cgp = (struct cg *)buf_dataptr(bp);
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgin(cgp,fs);
#endif /* REV_ENDIAN_FS */
	if (!cg_chkmagic(cgp) || cgp->cg_cs.cs_nifree == 0) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		buf_brelse(bp);
		return (NULL);
	}

	microtime(&tv);
	cgp->cg_time = tv.tv_sec;
	if (ipref) {
		ipref %= fs->fs_ipg;
		if (isclr(cg_inosused(cgp), ipref))
			goto gotit;
	}
	start = cgp->cg_irotor / NBBY;
	len = howmany(fs->fs_ipg - cgp->cg_irotor, NBBY);
	loc = skpc(0xff, len, &cg_inosused(cgp)[start]);
	if (loc == 0) {
		len = start + 1;
		start = 0;
		loc = skpc(0xff, len, &cg_inosused(cgp)[0]);
		if (loc == 0) {
			printf("cg = %d, irotor = %d, fs = %s\n",
			    cg, cgp->cg_irotor, fs->fs_fsmnt);
			panic("ffs_nodealloccg: map corrupted");
			/* NOTREACHED */
		}
	}
	i = start + len - loc;
	map = cg_inosused(cgp)[i];
	ipref = i * NBBY;
	for (i = 1; i < (1 << NBBY); i <<= 1, ipref++) {
		if ((map & i) == 0) {
			cgp->cg_irotor = ipref;
			goto gotit;
		}
	}
	printf("fs = %s\n", fs->fs_fsmnt);
	panic("ffs_nodealloccg: block not in map");
	/* NOTREACHED */
gotit:
	setbit(cg_inosused(cgp), ipref);
	cgp->cg_cs.cs_nifree--;
	fs->fs_cstotal.cs_nifree--;
	fs->fs_cs(fs, cg).cs_nifree--;
	fs->fs_fmod = 1;
	if ((mode & IFMT) == IFDIR) {
		cgp->cg_cs.cs_ndir++;
		fs->fs_cstotal.cs_ndir++;
		fs->fs_cs(fs, cg).cs_ndir++;
	}
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
	buf_bdwrite(bp);
	return (cg * fs->fs_ipg + ipref);
}

/*
 * Free a block or fragment.
 *
 * The specified block or fragment is placed back in the
 * free map. If a fragment is deallocated, a possible 
 * block reassembly is checked.
 */
void
ffs_blkfree(ip, bno, size)
	register struct inode *ip;
	ufs_daddr_t bno;
	long size;
{
	register struct fs *fs;
	register struct cg *cgp;
	struct buf *bp;
	struct timeval tv;
	ufs_daddr_t blkno;
	int i, error, cg, blk, frags, bbase;
#if REV_ENDIAN_FS
	struct vnode *vp=ITOV(ip);
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	fs = ip->i_fs;
	if ((u_int)size > fs->fs_bsize || fragoff(fs, size) != 0) {
		printf("dev = 0x%x, bsize = %d, size = %d, fs = %s\n",
		    ip->i_dev, fs->fs_bsize, size, fs->fs_fsmnt);
		panic("blkfree: bad size");
	}
	cg = dtog(fs, bno);
	if ((u_int)bno >= fs->fs_size) {
		printf("bad block %d, ino %d\n", bno, ip->i_number);
		ffs_fserr(fs, ip->i_uid, "bad block");
		return;
	}
	error = (int)buf_bread(ip->i_devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, cg))),
			       (int)fs->fs_cgsize, NOCRED, &bp);
	if (error) {
		buf_brelse(bp);
		return;
	}
	cgp = (struct cg *)buf_dataptr(bp);
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgin(cgp,fs);
#endif /* REV_ENDIAN_FS */
	if (!cg_chkmagic(cgp)) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		buf_brelse(bp);
		return;
	}
	microtime(&tv);
	cgp->cg_time = tv.tv_sec;
	bno = dtogd(fs, bno);
	if (size == fs->fs_bsize) {
		blkno = fragstoblks(fs, bno);
		if (ffs_isblock(fs, cg_blksfree(cgp), blkno)) {
			printf("dev = 0x%x, block = %d, fs = %s\n",
			    ip->i_dev, bno, fs->fs_fsmnt);
			panic("blkfree: freeing free block");
		}
		ffs_setblock(fs, cg_blksfree(cgp), blkno);
		ffs_clusteracct(fs, cgp, blkno, 1);
		cgp->cg_cs.cs_nbfree++;
		fs->fs_cstotal.cs_nbfree++;
		fs->fs_cs(fs, cg).cs_nbfree++;
		i = cbtocylno(fs, bno);
		cg_blks(fs, cgp, i)[cbtorpos(fs, bno)]++;
		cg_blktot(cgp)[i]++;
	} else {
		bbase = bno - fragnum(fs, bno);
		/*
		 * decrement the counts associated with the old frags
		 */
		blk = blkmap(fs, cg_blksfree(cgp), bbase);
		ffs_fragacct(fs, blk, cgp->cg_frsum, -1);
		/*
		 * deallocate the fragment
		 */
		frags = numfrags(fs, size);
		for (i = 0; i < frags; i++) {
			if (isset(cg_blksfree(cgp), bno + i)) {
				printf("dev = 0x%x, block = %d, fs = %s\n",
				    ip->i_dev, bno + i, fs->fs_fsmnt);
				panic("blkfree: freeing free frag");
			}
			setbit(cg_blksfree(cgp), bno + i);
		}
		cgp->cg_cs.cs_nffree += i;
		fs->fs_cstotal.cs_nffree += i;
		fs->fs_cs(fs, cg).cs_nffree += i;
		/*
		 * add back in counts associated with the new frags
		 */
		blk = blkmap(fs, cg_blksfree(cgp), bbase);
		ffs_fragacct(fs, blk, cgp->cg_frsum, 1);
		/*
		 * if a complete block has been reassembled, account for it
		 */
		blkno = fragstoblks(fs, bbase);
		if (ffs_isblock(fs, cg_blksfree(cgp), blkno)) {
			cgp->cg_cs.cs_nffree -= fs->fs_frag;
			fs->fs_cstotal.cs_nffree -= fs->fs_frag;
			fs->fs_cs(fs, cg).cs_nffree -= fs->fs_frag;
			ffs_clusteracct(fs, cgp, blkno, 1);
			cgp->cg_cs.cs_nbfree++;
			fs->fs_cstotal.cs_nbfree++;
			fs->fs_cs(fs, cg).cs_nbfree++;
			i = cbtocylno(fs, bbase);
			cg_blks(fs, cgp, i)[cbtorpos(fs, bbase)]++;
			cg_blktot(cgp)[i]++;
		}
	}
	fs->fs_fmod = 1;
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
	buf_bdwrite(bp);
}

#if DIAGNOSTIC
/*
 * Verify allocation of a block or fragment. Returns true if block or
 * fragment is allocated, false if it is free.
 */
ffs_checkblk(ip, bno, size)
	struct inode *ip;
	ufs_daddr_t bno;
	long size;
{
	struct fs *fs;
	struct cg *cgp;
	struct buf *bp;
	int i, error, frags, free;
#if REV_ENDIAN_FS
	struct vnode *vp=ITOV(ip);
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	fs = ip->i_fs;
	if ((u_int)size > fs->fs_bsize || fragoff(fs, size) != 0) {
		printf("bsize = %d, size = %d, fs = %s\n",
		    fs->fs_bsize, size, fs->fs_fsmnt);
		panic("checkblk: bad size");
	}
	if ((u_int)bno >= fs->fs_size)
		panic("checkblk: bad block %d", bno);
	error = (int)buf_bread(ip->i_devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, dtog(fs, bno)))),
			       (int)fs->fs_cgsize, NOCRED, &bp);
	if (error) {
		buf_brelse(bp);
		return;
	}
	cgp = (struct cg *)buf_dataptr(bp);
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgin(cgp,fs);
#endif /* REV_ENDIAN_FS */
	if (!cg_chkmagic(cgp)) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		buf_brelse(bp);
		return;
	}
	bno = dtogd(fs, bno);
	if (size == fs->fs_bsize) {
		free = ffs_isblock(fs, cg_blksfree(cgp), fragstoblks(fs, bno));
	} else {
		frags = numfrags(fs, size);
		for (free = 0, i = 0; i < frags; i++)
			if (isset(cg_blksfree(cgp), bno + i))
				free++;
		if (free != 0 && free != frags)
			panic("checkblk: partially free fragment");
	}
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
	buf_brelse(bp);
	return (!free);
}
#endif /* DIAGNOSTIC */

/*
 * Free an inode.
 *
 * The specified inode is placed back in the free map.
 */
int
ffs_vfree(struct vnode *vp, ino_t ino, int mode)
{
	register struct fs *fs;
	register struct cg *cgp;
	register struct inode *pip;
	struct buf *bp;
	struct timeval tv;
	int error, cg;
#if REV_ENDIAN_FS
	struct mount *mp=vp->v_mount;
	int rev_endian=(mp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	pip = VTOI(vp);
	fs = pip->i_fs;
	if ((u_int)ino >= fs->fs_ipg * fs->fs_ncg)
		panic("ifree: range: dev = 0x%x, ino = %d, fs = %s\n",
		    pip->i_dev, ino, fs->fs_fsmnt);
	cg = ino_to_cg(fs, ino);
	error = (int)buf_bread(pip->i_devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, cg))),
			       (int)fs->fs_cgsize, NOCRED, &bp);
	if (error) {
		buf_brelse(bp);
		return (0);
	}
	cgp = (struct cg *)buf_dataptr(bp);
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgin(cgp,fs);
#endif /* REV_ENDIAN_FS */
	if (!cg_chkmagic(cgp)) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		buf_brelse(bp);
		return (0);
	}
	microtime(&tv);
	cgp->cg_time = tv.tv_sec;
	ino %= fs->fs_ipg;
	if (isclr(cg_inosused(cgp), ino)) {
		printf("dev = 0x%x, ino = %d, fs = %s\n",
		    pip->i_dev, ino, fs->fs_fsmnt);
		if (fs->fs_ronly == 0)
			panic("ifree: freeing free inode");
	}
	clrbit(cg_inosused(cgp), ino);
	if (ino < cgp->cg_irotor)
		cgp->cg_irotor = ino;
	cgp->cg_cs.cs_nifree++;
	fs->fs_cstotal.cs_nifree++;
	fs->fs_cs(fs, cg).cs_nifree++;
	if ((mode & IFMT) == IFDIR) {
		cgp->cg_cs.cs_ndir--;
		fs->fs_cstotal.cs_ndir--;
		fs->fs_cs(fs, cg).cs_ndir--;
	}
	fs->fs_fmod = 1;
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
	buf_bdwrite(bp);
	return (0);
}

/*
 * Find a block of the specified size in the specified cylinder group.
 *
 * It is a panic if a request is made to find a block if none are
 * available.
 */
static ufs_daddr_t
ffs_mapsearch(fs, cgp, bpref, allocsiz)
	register struct fs *fs;
	register struct cg *cgp;
	ufs_daddr_t bpref;
	int allocsiz;
{
	ufs_daddr_t bno;
	int start, len, loc, i;
	int blk, field, subfield, pos;

	/*
	 * find the fragment by searching through the free block
	 * map for an appropriate bit pattern
	 */
	if (bpref)
		start = dtogd(fs, bpref) / NBBY;
	else
		start = cgp->cg_frotor / NBBY;
	len = howmany(fs->fs_fpg, NBBY) - start;
	loc = scanc((u_int)len, (u_char *)&cg_blksfree(cgp)[start],
		(u_char *)fragtbl[fs->fs_frag],
		(u_char)(1 << (allocsiz - 1 + (fs->fs_frag % NBBY))));
	if (loc == 0) {
		len = start + 1;
		start = 0;
		loc = scanc((u_int)len, (u_char *)&cg_blksfree(cgp)[0],
			(u_char *)fragtbl[fs->fs_frag],
			(u_char)(1 << (allocsiz - 1 + (fs->fs_frag % NBBY))));
		if (loc == 0) {
			printf("start = %d, len = %d, fs = %s\n",
			    start, len, fs->fs_fsmnt);
			panic("ffs_alloccg: map corrupted");
			/* NOTREACHED */
		}
	}
	bno = (start + len - loc) * NBBY;
	cgp->cg_frotor = bno;
	/*
	 * found the byte in the map
	 * sift through the bits to find the selected frag
	 */
	for (i = bno + NBBY; bno < i; bno += fs->fs_frag) {
		blk = blkmap(fs, cg_blksfree(cgp), bno);
		blk <<= 1;
		field = around[allocsiz];
		subfield = inside[allocsiz];
		for (pos = 0; pos <= fs->fs_frag - allocsiz; pos++) {
			if ((blk & field) == subfield)
				return (bno + pos);
			field <<= 1;
			subfield <<= 1;
		}
	}
	printf("bno = %d, fs = %s\n", bno, fs->fs_fsmnt);
	panic("ffs_alloccg: block not in map");
	return (-1);
}

/*
 * Update the cluster map because of an allocation or free.
 *
 * Cnt == 1 means free; cnt == -1 means allocating.
 */
static void
ffs_clusteracct(struct fs *fs, struct cg *cgp, ufs_daddr_t blkno, int cnt)
{
	int32_t *sump;
	int32_t *lp;
	u_char *freemapp, *mapp;
	int i, start, end, forw, back, map, bit;

	if (fs->fs_contigsumsize <= 0)
		return;
	freemapp = cg_clustersfree(cgp);
	sump = cg_clustersum(cgp);
	/*
	 * Allocate or clear the actual block.
	 */
	if (cnt > 0)
		setbit(freemapp, blkno);
	else
		clrbit(freemapp, blkno);
	/*
	 * Find the size of the cluster going forward.
	 */
	start = blkno + 1;
	end = start + fs->fs_contigsumsize;
	if (end >= cgp->cg_nclusterblks)
		end = cgp->cg_nclusterblks;
	mapp = &freemapp[start / NBBY];
	map = *mapp++;
	bit = 1 << (start % NBBY);
	for (i = start; i < end; i++) {
		if ((map & bit) == 0)
			break;
		if ((i & (NBBY - 1)) != (NBBY - 1)) {
			bit <<= 1;
		} else {
			map = *mapp++;
			bit = 1;
		}
	}
	forw = i - start;
	/*
	 * Find the size of the cluster going backward.
	 */
	start = blkno - 1;
	end = start - fs->fs_contigsumsize;
	if (end < 0)
		end = -1;
	mapp = &freemapp[start / NBBY];
	map = *mapp--;
	bit = 1 << (start % NBBY);
	for (i = start; i > end; i--) {
		if ((map & bit) == 0)
			break;
		if ((i & (NBBY - 1)) != 0) {
			bit >>= 1;
		} else {
			map = *mapp--;
			bit = 1 << (NBBY - 1);
		}
	}
	back = start - i;
	/*
	 * Account for old cluster and the possibly new forward and
	 * back clusters.
	 */
	i = back + forw + 1;
	if (i > fs->fs_contigsumsize)
		i = fs->fs_contigsumsize;
	sump[i] += cnt;
	if (back > 0)
		sump[back] -= cnt;
	if (forw > 0)
		sump[forw] -= cnt;
	/*
	 * Update cluster summary information.
	 */
	lp = &sump[fs->fs_contigsumsize];
	for (i = fs->fs_contigsumsize; i > 0; i--)
		if (*lp-- > 0)
			break;
	fs->fs_maxcluster[cgp->cg_cgx] = i;
}

/*
 * Fserr prints the name of a file system with an error diagnostic.
 * 
 * The form of the error message is:
 *	fs: error message
 */
static void
ffs_fserr(fs, uid, cp)
	struct fs *fs;
	u_int uid;
	char *cp;
{

	log(LOG_ERR, "uid %d on %s: %s\n", uid, fs->fs_fsmnt, cp);
}
