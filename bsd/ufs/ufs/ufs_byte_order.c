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
/* Copyright 1998 Apple Computer, Inc.
 *
 * UFS byte swapping routines to make a big endian file system useful on a
 * little endian machine.
 *
 * HISTORY
 *
 * 16 Feb 1998 A. Ramesh at Apple
 *      MacOSX version created.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/quota.h>
#include <ufs/ufs/ufs_byte_order.h>
#include <architecture/byte_order.h>

#define	byte_swap_longlong(thing) ((thing) = NXSwapLongLong(thing))
#define	byte_swap_int(thing) ((thing) = NXSwapLong(thing))
#define	byte_swap_short(thing) ((thing) = NXSwapShort(thing))

void
byte_swap_longlongs(unsigned long long *array, int count)
{
	register unsigned long long	i;

	for (i = 0;  i < count;  i++)
		byte_swap_longlong(array[i]);
}

void
byte_swap_ints(int *array, int count)
{
	register int	i;

	for (i = 0;  i < count;  i++)
		byte_swap_int(array[i]);
}

void
byte_swap_shorts(short *array, int count)
{
	register int	i;

	for (i = 0;  i < count;  i++)
		byte_swap_short(array[i]);
}

void
byte_swap_sbin(struct fs *sb)
{
	u_int16_t *usptr;
	unsigned long size;

	byte_swap_ints(((int32_t *)&sb->fs_firstfield), 52);
	byte_swap_int(sb->fs_cgrotor);
	byte_swap_int(sb->fs_cpc);
	byte_swap_shorts((int16_t *)sb->fs_opostbl, 16 * 8); 
	byte_swap_ints((int32_t *)sb->fs_sparecon, 50);
	byte_swap_ints((int32_t *)&sb->fs_contigsumsize, 3);
	byte_swap_longlongs((u_int64_t *)&sb->fs_maxfilesize,3);
	byte_swap_ints((int32_t *)&sb->fs_state, 6);

	/* Got these magic numbers from mkfs.c in newfs */
	if (sb->fs_nrpos != 8 || sb->fs_cpc > 16) {
		usptr = (u_int16_t *)((u_int8_t *)(sb) + (sb)->fs_postbloff);
		size = sb->fs_cpc * sb->fs_nrpos;
		byte_swap_shorts(usptr,size);	/* fs_postbloff */
	}
}

void
byte_swap_sbout(struct fs *sb)
{
	u_int16_t *usptr;
	unsigned long size;
	/* Got these magic numbers from mkfs.c in newfs */
	if (sb->fs_nrpos != 8 || sb->fs_cpc > 16) {
		usptr = (u_int16_t *)((u_int8_t *)(sb) + (sb)->fs_postbloff);
		size = sb->fs_cpc * sb->fs_nrpos;
		byte_swap_shorts(usptr,size);	/* fs_postbloff */
	}

	byte_swap_ints(((int32_t *)&sb->fs_firstfield), 52);
	byte_swap_int(sb->fs_cgrotor);
	byte_swap_int(sb->fs_cpc);
	byte_swap_shorts((int16_t *)sb->fs_opostbl, 16 * 8); 
	byte_swap_ints((int32_t *)sb->fs_sparecon, 50);
	byte_swap_ints((int32_t *)&sb->fs_contigsumsize, 3);
	byte_swap_longlongs((u_int64_t *)&sb->fs_maxfilesize,3);
	byte_swap_ints((int32_t *)&sb->fs_state, 6);
}

void
byte_swap_csum(struct csum *cs)
{
	byte_swap_ints((int *) cs, sizeof(struct csum) / sizeof(int32_t));
}

/* This is for the new 4.4 cylinder group block */
void
byte_swap_cgin(struct cg *cg, struct fs * fs)
{
	int32_t * ulptr;
	int16_t * usptr;
	int size;

	byte_swap_int(cg->cg_firstfield);
	byte_swap_int(cg->cg_magic);
	byte_swap_int(cg->cg_time);
	byte_swap_int(cg->cg_cgx);
	byte_swap_short(cg->cg_ncyl);
	byte_swap_short(cg->cg_niblk);
	byte_swap_int(cg->cg_ndblk);
	byte_swap_csum(&cg->cg_cs);
	byte_swap_int(cg->cg_rotor);
	byte_swap_int(cg->cg_frotor);
	byte_swap_int(cg->cg_irotor);
	byte_swap_ints(cg->cg_frsum, MAXFRAG);
	byte_swap_int(cg->cg_iusedoff);
	byte_swap_int(cg->cg_freeoff);
	byte_swap_int(cg->cg_nextfreeoff);
	byte_swap_int(cg->cg_clusteroff);
	byte_swap_int(cg->cg_nclusterblks);
	byte_swap_ints(&cg->cg_sparecon, 13);

	byte_swap_int(cg->cg_btotoff);
	ulptr = ((int32_t *)((u_int8_t *)(cg) + (cg)->cg_btotoff));
	size = fs->fs_cpg;
	byte_swap_ints(ulptr, size);	/*cg_btotoff*/

	byte_swap_int(cg->cg_boff);
	usptr = ((int16_t *)((u_int8_t *)(cg) + (cg)->cg_boff));
	size = fs->fs_cpg * fs->fs_nrpos;
	byte_swap_shorts(usptr,size);	/*cg_boff*/

	byte_swap_int(cg->cg_clustersumoff);

	if ((unsigned int)fs->fs_contigsumsize > 0) {

	ulptr = ((int32_t *)((u_int8_t *)(cg) + (cg)->cg_clustersumoff));
		size = (fs->fs_contigsumsize + 1);
		byte_swap_ints(ulptr, size);	/*cg_clustersumoff*/
	}

}

/* This is for the new 4.4 cylinder group block */
void
byte_swap_cgout(struct cg *cg, struct fs * fs)
{
	int32_t * ulptr;
	int16_t * usptr;
	int size;

	byte_swap_int(cg->cg_firstfield);
	byte_swap_int(cg->cg_magic);
	byte_swap_int(cg->cg_time);
	byte_swap_int(cg->cg_cgx);
	byte_swap_short(cg->cg_ncyl);
	byte_swap_short(cg->cg_niblk);
	byte_swap_int(cg->cg_ndblk);
	byte_swap_csum(&cg->cg_cs);
	byte_swap_int(cg->cg_rotor);
	byte_swap_int(cg->cg_frotor);
	byte_swap_int(cg->cg_irotor);
	byte_swap_ints(cg->cg_frsum, MAXFRAG);
	byte_swap_int(cg->cg_freeoff);
	byte_swap_int(cg->cg_nextfreeoff);
	byte_swap_int(cg->cg_nclusterblks);
	byte_swap_ints(&cg->cg_sparecon, 13);

	byte_swap_int(cg->cg_iusedoff);
	byte_swap_int(cg->cg_clusteroff);
	ulptr = ((int32_t *)((u_int8_t *)(cg) + (cg)->cg_btotoff));
	size = fs->fs_cpg;
	byte_swap_ints(ulptr, size);	/*cg_btotoff*/
	byte_swap_int(cg->cg_btotoff);

	usptr = ((int16_t *)((u_int8_t *)(cg) + (cg)->cg_boff));
	size = fs->fs_cpg * fs->fs_nrpos;
	byte_swap_shorts(usptr,size);	/*cg_boff*/
	byte_swap_int(cg->cg_boff);

	if ((unsigned int)fs->fs_contigsumsize > 0) {
	ulptr = ((int32_t *)((u_int8_t *)(cg) + (cg)->cg_clustersumoff));
		size = (fs->fs_contigsumsize + 1);
		byte_swap_ints(ulptr, size);	/*cg_clustersumoff*/

	}
	byte_swap_int(cg->cg_clustersumoff);

}

/* This value MUST correspond to the value set in the ffs_mounts */

#define RESYMLNKLEN 60

void
byte_swap_inode_in(struct dinode *di, struct inode *ip)
{
	int		i;

	ip->i_mode = NXSwapShort(di->di_mode);
	ip->i_nlink = NXSwapShort(di->di_nlink);
	ip->i_oldids[0] = NXSwapShort(di->di_u.oldids[0]);
	ip->i_oldids[1] = NXSwapShort(di->di_u.oldids[1]);
	ip->i_size = NXSwapLongLong(di->di_size);
	ip->i_atime = NXSwapLong(di->di_atime);
	ip->i_atimensec = NXSwapLong(di->di_atimensec);
	ip->i_mtime = NXSwapLong(di->di_mtime);
	ip->i_mtimensec = NXSwapLong(di->di_mtimensec);
	ip->i_ctime = NXSwapLong(di->di_ctime);
	ip->i_ctimensec = NXSwapLong(di->di_ctimensec);
	if (((ip->i_mode & IFMT) == IFLNK ) && (ip->i_size <= RESYMLNKLEN)) {
		bcopy(&di->di_shortlink,  &ip->i_shortlink, RESYMLNKLEN);
	} else {
		for (i=0; i < NDADDR; i++)	/* direct blocks */
			ip->i_db[i] = NXSwapLong(di->di_db[i]);
		for (i=0; i < NIADDR; i++)	/* indirect blocks */
			ip->i_ib[i] = NXSwapLong(di->di_ib[i]);
	} 
	ip->i_flags = NXSwapLong(di->di_flags);
	ip->i_blocks = NXSwapLong(di->di_blocks);
	ip->i_gen = NXSwapLong(di->di_gen);
	ip->i_uid = NXSwapLong(di->di_uid);
	ip->i_gid = NXSwapLong(di->di_gid);
	ip->i_spare[0] = NXSwapLong(di->di_spare[0]);
	ip->i_spare[1] = NXSwapLong(di->di_spare[1]);
}

void
byte_swap_inode_out(struct inode *ip, struct dinode *di)
{
	int		i;
	int mode, inosize;

	mode = (ip->i_mode & IFMT);
	inosize = ip->i_size;
 
	di->di_mode = NXSwapShort(ip->i_mode);
	di->di_nlink = NXSwapShort(ip->i_nlink);
	di->di_u.oldids[0] = NXSwapShort(ip->i_oldids[0]);
	di->di_u.oldids[1] = NXSwapShort(ip->i_oldids[1]);
	di->di_size = NXSwapLongLong(ip->i_size);
	di->di_atime = NXSwapLong(ip->i_atime);
	di->di_atimensec = NXSwapLong(ip->i_atimensec);
	di->di_mtime = NXSwapLong(ip->i_mtime);
	di->di_mtimensec = NXSwapLong(ip->i_mtimensec);
	di->di_ctime = NXSwapLong(ip->i_ctime);
	di->di_ctimensec = NXSwapLong(ip->i_ctimensec);
	if ((mode == IFLNK) && (inosize <= RESYMLNKLEN)) {
		bcopy( &ip->i_shortlink, &di->di_shortlink, RESYMLNKLEN);
	} else {
		for (i=0; i < NDADDR; i++)	/* direct blocks */
			di->di_db[i] = NXSwapLong(ip->i_db[i]);
		for (i=0; i < NIADDR; i++)	/* indirect blocks */
			di->di_ib[i] = NXSwapLong(ip->i_ib[i]);
	}
	di->di_flags = NXSwapLong(ip->i_flags);
	di->di_blocks = NXSwapLong(ip->i_blocks);
	di->di_gen = NXSwapLong(ip->i_gen);
	di->di_uid = NXSwapLong(ip->i_uid);
	di->di_gid = NXSwapLong(ip->i_gid);
	di->di_spare[0] = NXSwapLong(ip->i_spare[0]);
	di->di_spare[1] = NXSwapLong(ip->i_spare[1]);
}

void
byte_swap_direct(struct direct *dirp)
{
	byte_swap_int(dirp->d_ino);
	byte_swap_short(dirp->d_reclen);
}

void
byte_swap_dir_block_in(char *addr, int count)
{
	struct direct	*ep = (struct direct *) addr;
	int		entryoffsetinblk = 0;

	while (entryoffsetinblk < count) {
		ep = (struct direct *) (entryoffsetinblk + addr);
		byte_swap_int(ep->d_ino);
		byte_swap_short(ep->d_reclen);
		entryoffsetinblk += ep->d_reclen;
		if (ep->d_reclen < 12)		/* handle garbage in dirs */
			break;
	}
}

void
byte_swap_dir_out(char *addr, int count)
{
	struct direct	*ep = (struct direct *) addr;
	int		entryoffsetinblk = 0;
	int		reclen;

	while (entryoffsetinblk < count) {
		ep = (struct direct *) (entryoffsetinblk + addr);
		reclen = ep->d_reclen;
		entryoffsetinblk += reclen;
		byte_swap_int(ep->d_ino);
		byte_swap_short(ep->d_reclen);
		if (reclen < 12)
			break;
	}
}

void
byte_swap_dir_block_out(struct buf *bp)
{
	struct direct	*ep = (struct direct *) bp->b_data;
	int		reclen, entryoffsetinblk = 0;

	while (entryoffsetinblk < bp->b_bcount) {
		ep = (struct direct *) (entryoffsetinblk + bp->b_data);
		reclen = ep->d_reclen;
		entryoffsetinblk += reclen;
		byte_swap_int(ep->d_ino);
		byte_swap_short(ep->d_reclen);
		if (reclen < 12)
			break;
	}
}

void
byte_swap_dirtemplate_in(struct dirtemplate *dirt)
{
	byte_swap_int(dirt->dot_ino);
	byte_swap_short(dirt->dot_reclen);
	byte_swap_int(dirt->dotdot_ino);
	byte_swap_short(dirt->dotdot_reclen);
}

void
byte_swap_minidir_in(struct direct *dirp)
{
	byte_swap_int(dirp->d_ino);
	byte_swap_short(dirp->d_reclen);
}

#if 0
/* This is for the compatability (old) cylinder group block */
void
byte_swap_ocylgroup(struct cg *cg)
{
	byte_swap_int(cg->cg_time);
	byte_swap_int(cg->cg_cgx);
	byte_swap_short(cg->cg_ncyl);
	byte_swap_short(cg->cg_niblk);
	byte_swap_int(cg->cg_ndblk);
	byte_swap_csum(&cg->cg_cs);
	byte_swap_int(cg->cg_rotor);
	byte_swap_int(cg->cg_frotor);
	byte_swap_int(cg->cg_irotor);
	byte_swap_ints(&cg->cg_frsum, 8);
	byte_swap_ints(&cg->cg_btot, 32);
	byte_swap_shorts((short *)&cg->cg_b, 32 * 8);
	byte_swap_int(cg->cg_magic);
}
#endif /* 0 */
