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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)fs.h	8.13 (Berkeley) 3/21/95
 */
#ifndef _FFS_FS_H_
#define _FFS_FS_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE
/*
 * Each disk drive contains some number of file systems.
 * A file system consists of a number of cylinder groups.
 * Each cylinder group has inodes and data.
 *
 * A file system is described by its super-block, which in turn
 * describes the cylinder groups.  The super-block is critical
 * data and is replicated in each cylinder group to protect against
 * catastrophic loss.  This is done at `newfs' time and the critical
 * super-block data does not change, so the copies need not be
 * referenced further unless disaster strikes.
 *
 * For file system fs, the offsets of the various blocks of interest
 * are given in the super block as:
 *	[fs->fs_sblkno]		Super-block
 *	[fs->fs_cblkno]		Cylinder group block
 *	[fs->fs_iblkno]		Inode blocks
 *	[fs->fs_dblkno]		Data blocks
 * The beginning of cylinder group cg in fs, is given by
 * the ``cgbase(fs, cg)'' macro.
 *
 * The first boot and super blocks are given in absolute disk addresses.
 * The byte-offset forms are preferred, as they don't imply a sector size.
 */
#define BBSIZE		8192
#define SBSIZE		8192
#define	BBOFF		((off_t)(0))
#define	SBOFF		((off_t)(BBOFF + BBSIZE))
#define	BBLOCK		((ufs_daddr_t)(0))
#define	SBLOCK		((ufs_daddr_t)(BBLOCK + BBSIZE / DEV_BSIZE))

/*
 * Addresses stored in inodes are capable of addressing fragments
 * of `blocks'. File system blocks of at most size MAXBSIZE can 
 * be optionally broken into 2, 4, or 8 pieces, each of which is
 * addressible; these pieces may be DEV_BSIZE, or some multiple of
 * a DEV_BSIZE unit.
 *
 * Large files consist of exclusively large data blocks.  To avoid
 * undue wasted disk space, the last data block of a small file may be
 * allocated as only as many fragments of a large block as are
 * necessary.  The file system format retains only a single pointer
 * to such a fragment, which is a piece of a single large block that
 * has been divided.  The size of such a fragment is determinable from
 * information in the inode, using the ``blksize(fs, ip, lbn)'' macro.
 *
 * The file system records space availability at the fragment level;
 * to determine block availability, aligned fragments are examined.
 */

/*
 * MINBSIZE is the smallest allowable block size.
 * In order to insure that it is possible to create files of size
 * 2^32 with only two levels of indirection, MINBSIZE is set to 4096.
 * MINBSIZE must be big enough to hold a cylinder group block,
 * thus changes to (struct cg) must keep its size within MINBSIZE.
 * Note that super blocks are always of size SBSIZE,
 * and that both SBSIZE and MAXBSIZE must be >= MINBSIZE.
 */
#define MINBSIZE	4096

/*
 * The path name on which the file system is mounted is maintained
 * in fs_fsmnt. MAXMNTLEN defines the amount of space allocated in 
 * the super block for this name.
 */
#define MAXMNTLEN	512

/*
 * The limit on the amount of summary information per file system
 * is defined by MAXCSBUFS. It is currently parameterized for a
 * size of 128 bytes (2 million cylinder groups on machines with
 * 32-bit pointers, and 1 million on 64-bit machines). One pointer
 * is taken away to point to an array of cluster sizes that is
 * computed as cylinder groups are inspected.
 * There is a 128-byte region in the superblock reserved for in-core
 * pointers to summary information. Originally this included an array
 * of pointers to blocks of struct csum; now there are just two
 * pointers and the remaining space is padded with fs_ocsp[].
 *
 * NOCSPTRS determines the size of this padding. One pointer (fs_csp)
 * is taken away to point to a contiguous array of struct csum for
 * all cylinder groups; a second (fs_maxcluster) points to an array
 * of cluster sizes that is computed as cylinder groups are inspected.
 */
#define NOCSPTRS ((128 / sizeof(void *)) - 2)


/*
 * A summary of contiguous blocks of various sizes is maintained
 * in each cylinder group. Normally this is set by the initial
 * value of fs_maxcontig. To conserve space, a maximum summary size
 * is set by FS_MAXCONTIG.
 */
#define FS_MAXCONTIG	16

/*
 * MINFREE gives the minimum acceptable percentage of file system
 * blocks which may be free. If the freelist drops below this level
 * only the superuser may continue to allocate blocks. This may
 * be set to 0 if no reserve of free blocks is deemed necessary,
 * however throughput drops by fifty percent if the file system
 * is run at between 95% and 100% full; thus the minimum default
 * value of fs_minfree is 5%. However, to get good clustering
 * performance, 10% is a better choice. hence we use 10% as our
 * default value. With 10% free space, fragmentation is not a
 * problem, so we choose to optimize for time.
 */
#define MINFREE		5
#define DEFAULTOPT	FS_OPTTIME

/*
 * Per cylinder group information; summarized in blocks allocated
 * from first cylinder group data blocks.  These blocks have to be
 * read in from fs_csaddr (size fs_cssize) in addition to the
 * super block.
 */
struct csum {
	int32_t	cs_ndir;		/* number of directories */
	int32_t	cs_nbfree;		/* number of free blocks */
	int32_t	cs_nifree;		/* number of free inodes */
	int32_t	cs_nffree;		/* number of free frags */
};

/*
 * Super block for an FFS file system.
 */
struct fs {
	int32_t	 fs_firstfield;		/* historic file system linked list, */
	int32_t	 fs_unused_1;		/*     used for incore super blocks */
	ufs_daddr_t fs_sblkno;		/* addr of super-block in filesys */
	ufs_daddr_t fs_cblkno;		/* offset of cyl-block in filesys */
	ufs_daddr_t fs_iblkno;		/* offset of inode-blocks in filesys */
	ufs_daddr_t fs_dblkno;		/* offset of first data after cg */
	int32_t	 fs_cgoffset;		/* cylinder group offset in cylinder */
	int32_t	 fs_cgmask;		/* used to calc mod fs_ntrak */
	time_t 	 fs_time;		/* last time written */
	int32_t	 fs_size;		/* number of blocks in fs */
	int32_t	 fs_dsize;		/* number of data blocks in fs */
	int32_t	 fs_ncg;		/* number of cylinder groups */
	int32_t	 fs_bsize;		/* size of basic blocks in fs */
	int32_t	 fs_fsize;		/* size of frag blocks in fs */
	int32_t	 fs_frag;		/* number of frags in a block in fs */
/* these are configuration parameters */
	int32_t	 fs_minfree;		/* minimum percentage of free blocks */
	int32_t	 fs_rotdelay;		/* num of ms for optimal next block */
	int32_t	 fs_rps;		/* disk revolutions per second */
/* these fields can be computed from the others */
	int32_t	 fs_bmask;		/* ``blkoff'' calc of blk offsets */
	int32_t	 fs_fmask;		/* ``fragoff'' calc of frag offsets */
	int32_t	 fs_bshift;		/* ``lblkno'' calc of logical blkno */
	int32_t	 fs_fshift;		/* ``numfrags'' calc number of frags */
/* these are configuration parameters */
	int32_t	 fs_maxcontig;		/* max number of contiguous blks */
	int32_t	 fs_maxbpg;		/* max number of blks per cyl group */
/* these fields can be computed from the others */
	int32_t	 fs_fragshift;		/* block to frag shift */
	int32_t	 fs_fsbtodb;		/* fsbtodb and dbtofsb shift constant */
	int32_t	 fs_sbsize;		/* actual size of super block */
	int32_t	 fs_csmask;		/* csum block offset (now unused) */
	int32_t	 fs_csshift;		/* csum block number (now unused) */
	int32_t	 fs_nindir;		/* value of NINDIR */
	int32_t	 fs_inopb;		/* value of INOPB */
	int32_t	 fs_nspf;		/* value of NSPF */
/* yet another configuration parameter */
	int32_t	 fs_optim;		/* optimization preference, see below */
/* these fields are derived from the hardware */
	int32_t	 fs_npsect;		/* # sectors/track including spares */
	int32_t	 fs_interleave;		/* hardware sector interleave */
	int32_t	 fs_trackskew;		/* sector 0 skew, per track */
	int32_t	 fs_headswitch;		/* head switch time, usec */
	int32_t	 fs_trkseek;		/* track-to-track seek, usec */
/* sizes determined by number of cylinder groups and their sizes */
	ufs_daddr_t fs_csaddr;		/* blk addr of cyl grp summary area */
	int32_t	 fs_cssize;		/* size of cyl grp summary area */
	int32_t	 fs_cgsize;		/* cylinder group size */
/* these fields are derived from the hardware */
	int32_t	 fs_ntrak;		/* tracks per cylinder */
	int32_t	 fs_nsect;		/* sectors per track */
	int32_t  fs_spc;			/* sectors per cylinder */
/* this comes from the disk driver partitioning */
	int32_t	 fs_ncyl;		/* cylinders in file system */
/* these fields can be computed from the others */
	int32_t	 fs_cpg;			/* cylinders per group */
	int32_t	 fs_ipg;			/* inodes per group */
	int32_t	 fs_fpg;			/* blocks per group * fs_frag */
/* this data must be re-computed after crashes */
	struct	csum fs_cstotal;	/* cylinder summary information */
/* these fields are cleared at mount time */
	int8_t   fs_fmod;		/* super block modified flag */
	int8_t   fs_clean;		/* file system is clean flag */
	int8_t 	 fs_ronly;		/* mounted read-only flag */
	int8_t   fs_flags;		/* currently unused flag */
	u_char	 fs_fsmnt[MAXMNTLEN];	/* name mounted on */
/* these fields retain the current block allocation info */
	int32_t	 fs_cgrotor;		/* last cg searched */
	void    *fs_ocsp[NOCSPTRS];	/* list of fs_cs info buffers */
	struct	csum *fs_csp;		/* list of fs_cs info buffers */
	int32_t	 *fs_maxcluster;	/* max cluster in each cyl group */
	int32_t	 fs_cpc;		/* cyl per cycle in postbl */
	int16_t	 fs_opostbl[16][8];	/* old rotation block list head */
	int32_t	 fs_sparecon[50];	/* reserved for future constants */
	int32_t	 fs_contigsumsize;	/* size of cluster summary array */ 
	int32_t	 fs_maxsymlinklen;	/* max length of an internal symlink */
	int32_t	 fs_inodefmt;		/* format of on-disk inodes */
	u_int64_t fs_maxfilesize;	/* maximum representable file size */
	int64_t	 fs_qbmask;		/* ~fs_bmask for use with 64-bit size */
	int64_t	 fs_qfmask;		/* ~fs_fmask for use with 64-bit size */
	int32_t	 fs_state;		/* validate fs_clean field */
	int32_t	 fs_postblformat;	/* format of positional layout tables */
	int32_t	 fs_nrpos;		/* number of rotational positions */
	int32_t	 fs_postbloff;		/* (u_int16) rotation block list head */
	int32_t	 fs_rotbloff;		/* (u_int8) blocks for each rotation */
	int32_t	 fs_magic;		/* magic number */
	u_int8_t fs_space[1];		/* list of blocks for each rotation */
/* actually longer */
};

/*
 * Filesystem identification
 */
#define	FS_MAGIC	0x011954	/* the fast filesystem magic number */
#define	FS_OKAY		0x7c269d38	/* superblock checksum */
#define FS_42INODEFMT	-1		/* 4.2BSD inode format */
#define FS_44INODEFMT	2		/* 4.4BSD inode format */
/*
 * Preference for optimization.
 */
#define FS_OPTTIME	0	/* minimize allocation time */
#define FS_OPTSPACE	1	/* minimize disk fragmentation */

/*
 * Rotational layout table format types
 */
#define FS_42POSTBLFMT		-1	/* 4.2BSD rotational table format */
#define FS_DYNAMICPOSTBLFMT	1	/* dynamic rotational table format */
/*
 * Macros for access to superblock array structures
 */
#define fs_postbl(fs, cylno) \
    (((fs)->fs_postblformat == FS_42POSTBLFMT) \
    ? ((fs)->fs_opostbl[cylno]) \
    : ((int16_t *)((u_int8_t *)(fs) + \
	(fs)->fs_postbloff) + (cylno) * (fs)->fs_nrpos))
#define fs_rotbl(fs) \
    (((fs)->fs_postblformat == FS_42POSTBLFMT) \
    ? ((fs)->fs_space) \
    : ((u_int8_t *)((u_int8_t *)(fs) + (fs)->fs_rotbloff)))

/*
 * The size of a cylinder group is calculated by CGSIZE. The maximum size
 * is limited by the fact that cylinder groups are at most one block.
 * Its size is derived from the size of the maps maintained in the 
 * cylinder group and the (struct cg) size.
 */
#define CGSIZE(fs) \
    /* base cg */	(sizeof(struct cg) + sizeof(int32_t) + \
    /* blktot size */	(fs)->fs_cpg * sizeof(int32_t) + \
    /* blks size */	(fs)->fs_cpg * (fs)->fs_nrpos * sizeof(int16_t) + \
    /* inode map */	howmany((fs)->fs_ipg, NBBY) + \
    /* block map */	howmany((fs)->fs_cpg * (fs)->fs_spc / NSPF(fs), NBBY) +\
    /* if present */	((fs)->fs_contigsumsize <= 0 ? 0 : \
    /* cluster sum */	(fs)->fs_contigsumsize * sizeof(int32_t) + \
    /* cluster map */	howmany((fs)->fs_cpg * (fs)->fs_spc / NSPB(fs), NBBY)))

/*
 * Convert cylinder group to base address of its global summary info.
 *
 * N.B. This macro assumes that sizeof(struct csum) is a power of two.
 */
#define fs_cs(fs, indx) fs_csp[indx]

/*
 * Cylinder group block for a file system.
 */
#define	CG_MAGIC	0x090255
struct cg {
	int32_t	 cg_firstfield;		/* historic cyl groups linked list */
	int32_t	 cg_magic;		/* magic number */
	time_t	 cg_time;		/* time last written */
	int32_t	 cg_cgx;		/* we are the cgx'th cylinder group */
	int16_t	 cg_ncyl;		/* number of cyl's this cg */
	int16_t	 cg_niblk;		/* number of inode blocks this cg */
	int32_t	 cg_ndblk;		/* number of data blocks this cg */
	struct	csum cg_cs;		/* cylinder summary information */
	int32_t	 cg_rotor;		/* position of last used block */
	int32_t	 cg_frotor;		/* position of last used frag */
	int32_t	 cg_irotor;		/* position of last used inode */
	int32_t	 cg_frsum[MAXFRAG];	/* counts of available frags */
	int32_t	 cg_btotoff;		/* (int32) block totals per cylinder */
	int32_t	 cg_boff;		/* (u_int16) free block positions */
	int32_t	 cg_iusedoff;		/* (u_int8) used inode map */
	int32_t	 cg_freeoff;		/* (u_int8) free block map */
	int32_t	 cg_nextfreeoff;	/* (u_int8) next available space */
	int32_t	 cg_clustersumoff;	/* (u_int32) counts of avail clusters */
	int32_t	 cg_clusteroff;		/* (u_int8) free cluster map */
	int32_t	 cg_nclusterblks;	/* number of clusters this cg */
	int32_t	 cg_sparecon[13];	/* reserved for future use */
	u_int8_t cg_space[1];		/* space for cylinder group maps */
/* actually longer */
};

/*
 * Macros for access to cylinder group array structures
 */
#define cg_blktot(cgp) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_btot) \
    : ((int32_t *)((u_int8_t *)(cgp) + (cgp)->cg_btotoff)))
#define cg_blks(fs, cgp, cylno) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_b[cylno]) \
    : ((int16_t *)((u_int8_t *)(cgp) + \
	(cgp)->cg_boff) + (cylno) * (fs)->fs_nrpos))
#define cg_inosused(cgp) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_iused) \
    : ((u_int8_t *)((u_int8_t *)(cgp) + (cgp)->cg_iusedoff)))
#define cg_blksfree(cgp) \
    (((cgp)->cg_magic != CG_MAGIC) \
    ? (((struct ocg *)(cgp))->cg_free) \
    : ((u_int8_t *)((u_int8_t *)(cgp) + (cgp)->cg_freeoff)))
#define cg_chkmagic(cgp) \
    ((cgp)->cg_magic == CG_MAGIC || ((struct ocg *)(cgp))->cg_magic == CG_MAGIC)
#define cg_clustersfree(cgp) \
    ((u_int8_t *)((u_int8_t *)(cgp) + (cgp)->cg_clusteroff))
#define cg_clustersum(cgp) \
    ((int32_t *)((u_int8_t *)(cgp) + (cgp)->cg_clustersumoff))

/*
 * The following structure is defined
 * for compatibility with old file systems.
 */
struct ocg {
	int32_t	 cg_firstfield;		/* historic linked list of cyl groups */
	int32_t	 cg_unused_1;		/*     used for incore cyl groups */
	time_t	 cg_time;		/* time last written */
	int32_t	 cg_cgx;		/* we are the cgx'th cylinder group */
	int16_t	 cg_ncyl;		/* number of cyl's this cg */
	int16_t	 cg_niblk;		/* number of inode blocks this cg */
	int32_t	 cg_ndblk;		/* number of data blocks this cg */
	struct	csum cg_cs;		/* cylinder summary information */
	int32_t	 cg_rotor;		/* position of last used block */
	int32_t	 cg_frotor;		/* position of last used frag */
	int32_t	 cg_irotor;		/* position of last used inode */
	int32_t	 cg_frsum[8];		/* counts of available frags */
	int32_t	 cg_btot[32];		/* block totals per cylinder */
	int16_t	 cg_b[32][8];		/* positions of free blocks */
	u_int8_t cg_iused[256];		/* used inode map */
	int32_t	 cg_magic;		/* magic number */
	u_int8_t cg_free[1];		/* free block map */
/* actually longer */
};

/*
 * Turn file system block numbers into disk block addresses.
 * This maps file system blocks to device size blocks.
 */
#define fsbtodb(fs, b)	((b) << (fs)->fs_fsbtodb)
#define	dbtofsb(fs, b)	((b) >> (fs)->fs_fsbtodb)

/*
 * Cylinder group macros to locate things in cylinder groups.
 * They calc file system addresses of cylinder group data structures.
 */
#define	cgbase(fs, c)	((ufs_daddr_t)((fs)->fs_fpg * (c)))
#define	cgdmin(fs, c)	(cgstart(fs, c) + (fs)->fs_dblkno)	/* 1st data */
#define	cgimin(fs, c)	(cgstart(fs, c) + (fs)->fs_iblkno)	/* inode blk */
#define	cgsblock(fs, c)	(cgstart(fs, c) + (fs)->fs_sblkno)	/* super blk */
#define	cgtod(fs, c)	(cgstart(fs, c) + (fs)->fs_cblkno)	/* cg block */
#define cgstart(fs, c)							\
	(cgbase(fs, c) + (fs)->fs_cgoffset * ((c) & ~((fs)->fs_cgmask)))

/*
 * Macros for handling inode numbers:
 *     inode number to file system block offset.
 *     inode number to cylinder group number.
 *     inode number to file system block address.
 */
#define	ino_to_cg(fs, x)	((x) / (fs)->fs_ipg)
#define	ino_to_fsba(fs, x)						\
	((ufs_daddr_t)(cgimin(fs, ino_to_cg(fs, x)) +			\
	    (blkstofrags((fs), (((x) % (fs)->fs_ipg) / INOPB(fs))))))
#define	ino_to_fsbo(fs, x)	((x) % INOPB(fs))

/*
 * Give cylinder group number for a file system block.
 * Give cylinder group block number for a file system block.
 */
#define	dtog(fs, d)	((d) / (fs)->fs_fpg)
#define	dtogd(fs, d)	((d) % (fs)->fs_fpg)

/*
 * Extract the bits for a block from a map.
 * Compute the cylinder and rotational position of a cyl block addr.
 */
#define blkmap(fs, map, loc) \
    (((map)[(loc) / NBBY] >> ((loc) % NBBY)) & (0xff >> (NBBY - (fs)->fs_frag)))
#define cbtocylno(fs, bno) \
    ((bno) * NSPF(fs) / (fs)->fs_spc)
#define cbtorpos(fs, bno) \
    (((bno) * NSPF(fs) % (fs)->fs_spc / (fs)->fs_nsect * (fs)->fs_trackskew + \
     (bno) * NSPF(fs) % (fs)->fs_spc % (fs)->fs_nsect * (fs)->fs_interleave) % \
     (fs)->fs_nsect * (fs)->fs_nrpos / (fs)->fs_npsect)

/*
 * The following macros optimize certain frequently calculated
 * quantities by using shifts and masks in place of divisions
 * modulos and multiplications.
 */
#define blkoff(fs, loc)		/* calculates (loc % fs->fs_bsize) */ \
	((loc) & (fs)->fs_qbmask)
#define fragoff(fs, loc)	/* calculates (loc % fs->fs_fsize) */ \
	((loc) & (fs)->fs_qfmask)
#define lblktosize(fs, blk)	/* calculates (blk * fs->fs_bsize) */ \
	((blk) << (fs)->fs_bshift)
#define lblkno(fs, loc)		/* calculates (loc / fs->fs_bsize) */ \
	((loc) >> (fs)->fs_bshift)
#define numfrags(fs, loc)	/* calculates (loc / fs->fs_fsize) */ \
	((loc) >> (fs)->fs_fshift)
#define blkroundup(fs, size)	/* calculates roundup(size, fs->fs_bsize) */ \
	(((size) + (fs)->fs_qbmask) & (fs)->fs_bmask)
#define fragroundup(fs, size)	/* calculates roundup(size, fs->fs_fsize) */ \
	(((size) + (fs)->fs_qfmask) & (fs)->fs_fmask)
#define fragstoblks(fs, frags)	/* calculates (frags / fs->fs_frag) */ \
	((frags) >> (fs)->fs_fragshift)
#define blkstofrags(fs, blks)	/* calculates (blks * fs->fs_frag) */ \
	((blks) << (fs)->fs_fragshift)
#define fragnum(fs, fsb)	/* calculates (fsb % fs->fs_frag) */ \
	((fsb) & ((fs)->fs_frag - 1))
#define blknum(fs, fsb)		/* calculates rounddown(fsb, fs->fs_frag) */ \
	((fsb) &~ ((fs)->fs_frag - 1))

/*
 * Determine the number of available frags given a
 * percentage to hold in reserve.
 */
#define freespace(fs, percentreserved) \
	(blkstofrags((fs), (fs)->fs_cstotal.cs_nbfree) + \
	(fs)->fs_cstotal.cs_nffree - ((fs)->fs_dsize * (percentreserved) / 100))

/*
 * Determining the size of a file block in the file system.
 */
#define blksize(fs, ip, lbn) \
	(((lbn) >= NDADDR || (ip)->i_size >= ((lbn) + 1) << (fs)->fs_bshift) \
	    ? (fs)->fs_bsize \
	    : (fragroundup(fs, blkoff(fs, (ip)->i_size))))
#define dblksize(fs, dip, lbn) \
	(((lbn) >= NDADDR || (dip)->di_size >= ((lbn) + 1) << (fs)->fs_bshift) \
	    ? (fs)->fs_bsize \
	    : (fragroundup(fs, blkoff(fs, (dip)->di_size))))

/*
 * Number of disk sectors per block/fragment; assumes DEV_BSIZE byte
 * sector size.
 */
#define	NSPB(fs)	((fs)->fs_nspf << (fs)->fs_fragshift)
#define	NSPF(fs)	((fs)->fs_nspf)

/*
 * Number of inodes in a secondary storage block/fragment.
 */
#define	INOPB(fs)	((fs)->fs_inopb)
#define	INOPF(fs)	((fs)->fs_inopb >> (fs)->fs_fragshift)

/*
 * Number of indirects in a file system block.
 */
#define	NINDIR(fs)	((fs)->fs_nindir)

/*
 * This macro controls whether the file system format is byte swapped or not.
 * At NeXT, all little endian machines read and write big endian file systems.
 */
#define	BIG_ENDIAN_FS	(__LITTLE_ENDIAN__)

#ifdef __APPLE_API_PRIVATE
extern int inside[], around[];
extern u_char *fragtbl[];
#endif /* __APPLE_API_PRIVATE */


/*
 * UFS Label:
 *   The purpose of this label is to name a UFS/FFS filesystem.  The label
 *   is located at offset 7K (BBSIZE=8K - UFS_LABEL_SIZE=1K = 7K) of the 
 *   partition.  The first 7K is still available for boot blocks.
 */

#define UFS_LABEL_MAGIC		{ 'L', 'A', 'B', 'L' }
#define UFS_LABEL_SIZE		1024
#define UFS_LABEL_OFFSET	(BBSIZE - UFS_LABEL_SIZE) /* top 1K */
#define UFS_LABEL_VERSION	1
#define UFS_MAX_LABEL_NAME	512

struct ufslabel {
    u_int32_t		ul_magic;
    u_int16_t		ul_checksum;	/* checksum over entire label*/
    u_int32_t		ul_version;	/* label version */
    u_int32_t		ul_time;	/* creation time */
    u_int16_t		ul_namelen;	/* filesystem name length */
    u_char		ul_name[UFS_MAX_LABEL_NAME]; /* filesystem name */
    u_int64_t		ul_uuid;	/* filesystem uuid */
    u_char		ul_reserved[24];/* reserved for future use */
    u_char		ul_unused[460];	/* pad out to 1K */
};

#endif /* __APPLE_API_UNSTABLE */
#endif /* ! _FFS_FS_H_ */
