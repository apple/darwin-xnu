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
/*	$NetBSD: cd9660_vfsops.c,v 1.18 1995/03/09 12:05:36 mycroft Exp $	*/

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
 *	@(#)cd9660_vfsops.c	8.9 (Berkeley) 12/5/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <miscfs/specfs/specdev.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <sys/utfconv.h>
#include <architecture/byte_order.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/iso_rrip.h>
#include <isofs/cd9660/cd9660_node.h>
#include <isofs/cd9660/cd9660_mount.h>

/*
 * Minutes, Seconds, Frames (M:S:F)
 */
struct CDMSF {
	u_char   minute;
	u_char   second;
	u_char   frame;
};

/*
 * Table Of Contents
 */
struct CDTOC_Desc {
	u_char        session;
	u_char        ctrl_adr;  /* typed to be machine and compiler independent */
	u_char        tno;
	u_char        point;
	struct CDMSF  address;
	u_char        zero;
	struct CDMSF  p;
};

struct CDTOC {
	u_short            length;  /* in native cpu endian */
	u_char             first_session;
	u_char             last_session;
	struct CDTOC_Desc  trackdesc[1];
};

#define MSF_TO_LBA(msf)		\
	(((((msf).minute * 60UL) + (msf).second) * 75UL) + (msf).frame - 150)

u_char isonullname[] = "\0";

extern int enodev ();

struct vfsops cd9660_vfsops = {
	cd9660_mount,
	cd9660_start,
	cd9660_unmount,
	cd9660_root,
	cd9660_quotactl,
	cd9660_statfs,
	cd9660_sync,
	cd9660_vget,
	cd9660_fhtovp,
	cd9660_vptofh,
	cd9660_init,
	cd9660_sysctl
};

/*
 * Called by vfs_mountroot when iso is going to be mounted as root.
 *
 * Name is updated by mount(8) after booting.
 */
#define ROOTNAME	"root_device"

static int iso_mountfs __P((struct vnode *devvp, struct mount *mp,
		struct proc *p, struct iso_args *argp));

static void DRGetTypeCreatorAndFlags(
				struct iso_mnt * theMountPointPtr,
				struct iso_directory_record * theDirRecPtr, 
				u_int32_t * theTypePtr, 
				u_int32_t * theCreatorPtr, 
				u_int16_t * theFlagsPtr);

int	cd9660_vget_internal(
		struct mount *mp, 
		ino_t ino, 
		struct vnode **vpp, 
		int relocated, 
		struct iso_directory_record *isodir, 
		struct proc *p);

int
cd9660_mountroot()
{
	register struct mount *mp;
	extern struct vnode *rootvp;
	struct proc *p = current_proc();	/* XXX */
	struct iso_mnt *imp;
	size_t size;
	int error;
	struct iso_args args;
	
	/*
	 * Get vnodes for swapdev and rootdev.
	 */
	if ( bdevvp(rootdev, &rootvp))
		panic("cd9660_mountroot: can't setup bdevvp's");

	MALLOC_ZONE(mp, struct mount *,
			sizeof(struct mount), M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));

    /* Initialize the default IO constraints */
    mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
    mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

	mp->mnt_op = &cd9660_vfsops;
	mp->mnt_flag = MNT_RDONLY;
	LIST_INIT(&mp->mnt_vnodelist);
	args.flags = ISOFSMNT_ROOT;
	args.ssector = 0;
	args.fspec = 0;
	args.toc_length = 0;
	args.toc = 0;
	if ((error = iso_mountfs(rootvp, mp, p, &args))) {
		vrele(rootvp); /* release the reference from bdevvp() */

		if (mp->mnt_kern_flag & MNTK_IO_XINFO)
		        FREE(mp->mnt_xinfo_ptr, M_TEMP);
		FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		return (error);
	}
	simple_lock(&mountlist_slock);
	CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	simple_unlock(&mountlist_slock);
	mp->mnt_vnodecovered = NULLVP;
	imp = VFSTOISOFS(mp);
	(void) copystr("/", mp->mnt_stat.f_mntonname, MNAMELEN - 1,
		&size);
	bzero(mp->mnt_stat.f_mntonname + size, MNAMELEN - size);
	(void) copystr(ROOTNAME, mp->mnt_stat.f_mntfromname, MNAMELEN - 1,
		&size);
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
	(void)cd9660_statfs(mp, &mp->mnt_stat, p);
	return (0);
}

/*
 * VFS Operations.
 *
 * mount system call
 */
int
cd9660_mount(mp, path, data, ndp, p)
	register struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	struct vnode *devvp;
	struct iso_args args;
	size_t size;
	int error;
	struct iso_mnt *imp = NULL;
	
	if ((error = copyin(data, (caddr_t)&args, sizeof (struct iso_args))))
		return (error);
	
	if ((mp->mnt_flag & MNT_RDONLY) == 0)
		return (EROFS);

	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		imp = VFSTOISOFS(mp);
		if (args.fspec == 0)
			return (vfs_export(mp, &imp->im_export, &args.export));
	}
	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible block device.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW, UIO_USERSPACE, args.fspec, p);
	if ((error = namei(ndp)))
		return (error);
	devvp = ndp->ni_vp;

	if (devvp->v_type != VBLK) {
		vrele(devvp);
		return (ENOTBLK);
	}
	if (major(devvp->v_rdev) >= nblkdev) {
		vrele(devvp);
		return (ENXIO);
	}
	if ((mp->mnt_flag & MNT_UPDATE) == 0)
		error = iso_mountfs(devvp, mp, p, &args);
	else {
		if (devvp != imp->im_devvp)
			error = EINVAL;	/* needs translation */
		else
			vrele(devvp);
	}
	if (error) {
		vrele(devvp);
		return (error);
	}

	/* Indicate that we don't support volfs */
	mp->mnt_flag &= ~MNT_DOVOLFS;

	(void) copyinstr(path, mp->mnt_stat.f_mntonname, MNAMELEN - 1, &size);
	bzero(mp->mnt_stat.f_mntonname + size, MNAMELEN - size);
	(void) copyinstr(args.fspec, mp->mnt_stat.f_mntfromname, MNAMELEN - 1,
		&size);
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
	return (0);
}

/*
 * Find the BSD device for the physical disk corresponding to the
 * mount point's device.  We use this physical device to read whole
 * (2352 byte) sectors from the CD to get the content for the video
 * files (tracks).
 *
 * The "path" argument is the path to the block device that the volume
 * is being mounted on (args.fspec).  It should be of the form:
 *	/dev/disk1s0
 * where the last "s0" part is stripped off to determine the physical
 * device's path.  It is assumed to be in user memory.
 */
static struct vnode *
cd9660_phys_device(char *path, struct proc *p)
{
	int err;
	char *whole_path = NULL;	// path to "whole" device
	char *s, *saved;
	struct nameidata nd;
	struct vnode *result;
	size_t actual_size;
	
	if (path == NULL)
		return NULL;

	result = NULL;

	/* Make a copy of the mount from name, then remove trailing "s...". */
	MALLOC(whole_path, char *, MNAMELEN, M_ISOFSMNT, M_WAITOK);
	copyinstr(path, whole_path, MNAMELEN-1, &actual_size);
	
	/*
	 * I would use strrchr or rindex here, but those are declared __private_extern__,
	 * and can't be used across component boundaries at this time.
	 */
	for (s=whole_path, saved=NULL; *s; ++s)
		if (*s == 's')
			saved = s;
	*saved = '\0';

	/* Lookup the "whole" device. */
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, whole_path, p);
	err = namei(&nd);
	if (err) {
		printf("isofs: Cannot find physical device: %s\n", whole_path);
		goto done;
	}
	
	/* Open the "whole" device. */
	err = VOP_OPEN(nd.ni_vp, FREAD, FSCRED, p);
	if (err) {
		vrele(nd.ni_vp);
		printf("isofs: Cannot open physical device: %s\n", whole_path);
		goto done;
	}

	result = nd.ni_vp;

done:
	FREE(whole_path, M_ISOFSMNT);
	return result;
}


/*
 * See if the given CD-ROM XA disc appears to be a Video CD
 * (version < 2.0; so, not SVCD).  If so, fill in the extent
 * information for the MPEGAV directory, set the VCD flag,
 * and return true.
 */
static int
cd9660_find_video_dir(struct iso_mnt *isomp)
{
	int result, err;
	struct vnode *rootvp = NULL;
	struct vnode *videovp = NULL;
	struct componentname cn;
	char dirname[] = "MPEGAV";
	
	result = 0;		/* Assume not a video CD */
	
	err = cd9660_root(isomp->im_mountp, &rootvp);
	if (err) {
		printf("cd9660_find_video_dir: cd9660_root failed (%d)\n", err);
		return 0;	/* couldn't find video dir */
	}
	
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = LOCKPARENT|ISLASTCN;
	cn.cn_proc = current_proc();
	cn.cn_cred = cn.cn_proc->p_ucred;
	cn.cn_pnbuf = dirname;
	cn.cn_pnlen = sizeof(dirname)-1;
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = cn.cn_pnlen;
	
	err = VOP_LOOKUP(rootvp, &videovp, &cn);
	if (err == 0) {
		struct iso_node *ip = VTOI(videovp);
		result = 1;		/* Looks like video CD */
		isomp->video_dir_start = ip->iso_start;
		isomp->video_dir_end = ip->iso_start + (ip->i_size >> isomp->im_bshift);
		isomp->im_flags2 |= IMF2_IS_VCD;
	}

	if (videovp != NULL)
		vput(videovp);
	if (rootvp != NULL)
		vput(rootvp);
	
	return result;
}

/*
 * Common code for mount and mountroot
 */
static int
iso_mountfs(devvp, mp, p, argp)
	register struct vnode *devvp;
	struct mount *mp;
	struct proc *p;
	struct iso_args *argp;
{
	register struct iso_mnt *isomp = (struct iso_mnt *)0;
	struct buf *bp = NULL;
	struct buf *pribp = NULL, *supbp = NULL;
	dev_t dev = devvp->v_rdev;
	int error = EINVAL;
	int breaderr = 0;
	int needclose = 0;
	extern struct vnode *rootvp;
	u_long iso_bsize;
	int iso_blknum;
	int joliet_level;
	struct iso_volume_descriptor *vdp = NULL;
	struct iso_primary_descriptor *pri = NULL;
	struct iso_primary_descriptor *sup = NULL;
	struct iso_directory_record *rootp;
	int logical_block_size;
	u_int8_t vdtype;
	int blkoff = argp->ssector;
	
	if (!(mp->mnt_flag & MNT_RDONLY))
		return (EROFS);

	/*
	 * Disallow multiple mounts of the same device.
	 * Disallow mounting of a device that is currently in use
	 * (except for root, which might share swap device for miniroot).
	 * Flush out any old buffers remaining from a previous use.
	 */
	if ((error = vfs_mountedon(devvp)))
		return (error);
	if (vcount(devvp) > 1 && devvp != rootvp)
		return (EBUSY);
	if ((error = vinvalbuf(devvp, V_SAVE, p->p_ucred, p, 0, 0)))
		return (error);

	if ((error = VOP_OPEN(devvp, FREAD, FSCRED, p)))
		return (error);
	needclose = 1;
	
	/* This is the "logical sector size".  The standard says this
	 * should be 2048 or the physical sector size on the device,
	 * whichever is greater.  For now, we'll just use a constant.
	 */
	iso_bsize = ISO_DEFAULT_BLOCK_SIZE;

	/* tell IOKit that we're assuming 2K sectors */
	if ((error = VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE,
	     (caddr_t)&iso_bsize, FWRITE, p->p_ucred, p)))
		return (error);
	devvp->v_specsize = iso_bsize;
	joliet_level = 0;
	for (iso_blknum = 16 + blkoff; iso_blknum < (100 + blkoff); iso_blknum++) {
		if ((error = bread(devvp, iso_blknum, iso_bsize, NOCRED, &bp))) {
			if (bp) {
				bp->b_flags |= B_AGE;
				brelse(bp);
				bp = NULL;
			}
			breaderr = error;
			printf("iso_mountfs: bread error %d reading block %d\n", error, iso_blknum);
			continue;
		}

		vdp = (struct iso_volume_descriptor *)bp->b_data;
		if (bcmp (vdp->volume_desc_id, ISO_STANDARD_ID, sizeof(vdp->volume_desc_id)) != 0) {
#ifdef DEBUG
		        printf("cd9660_vfsops.c: iso_mountfs: "
					"Invalid ID in volume desciptor.\n");
#endif
			/* There should be a primary volume descriptor followed by any
			 * secondary volume descriptors, then an end volume descriptor.
			 * Some discs are mastered without an end volume descriptor or
			 * they have the type field set and the volume descriptor ID is
			 * not set. If we at least found a primary volume descriptor,
			 * mount the disc.
			 */
			if (pri != NULL)
				break;
			
			error = EINVAL;
			goto out;
		}
		
		vdtype = isonum_711 (vdp->type);
		if (vdtype == ISO_VD_END) 
			break;

		if (vdtype == ISO_VD_PRIMARY) {
			if (pribp == NULL) {
				pribp = bp;
				bp = NULL;
				pri = (struct iso_primary_descriptor *)vdp;
			}
		} else if(vdtype == ISO_VD_SUPPLEMENTARY) {
			if (supbp == NULL) {
				supbp = bp;
				bp = NULL;
				sup = (struct iso_primary_descriptor *)vdp;

				if ((argp->flags & ISOFSMNT_NOJOLIET) == 0) {
					/*
					 * some Joliet CDs are "out-of-spec and don't correctly
					 * set the SVD flags. We ignore the flags and rely soely
					 * on the escape_seq
					 */
					if (bcmp(sup->escape_seq, ISO_UCS2_Level_1, 3) == 0)
						joliet_level = 1;
					else if (bcmp(sup->escape_seq, ISO_UCS2_Level_2, 3) == 0)
						joliet_level = 2;
					else if (bcmp(sup->escape_seq, ISO_UCS2_Level_3, 3) == 0)
						joliet_level = 3;
				}
			}
		}

		if (bp) {
			bp->b_flags |= B_AGE;
			brelse(bp);
			bp = NULL;
		}
	}

	if (bp) {
		bp->b_flags |= B_AGE;
		brelse(bp);
		bp = NULL;
	}
	
	if (pri == NULL) {
		if (breaderr)
			error = breaderr;
		else
			error = EINVAL;
		goto out;
	}
	
	logical_block_size = isonum_723 (pri->logical_block_size);
	
	if (logical_block_size < DEV_BSIZE || logical_block_size > MAXBSIZE
	    || (logical_block_size & (logical_block_size - 1)) != 0) {
		error = EINVAL;
		goto out;
	}
	
	rootp = (struct iso_directory_record *)pri->root_directory_record;
	
	MALLOC(isomp, struct iso_mnt *, sizeof *isomp, M_ISOFSMNT, M_WAITOK);
	bzero((caddr_t)isomp, sizeof *isomp);
	isomp->im_sector_size = ISO_DEFAULT_BLOCK_SIZE;
	isomp->logical_block_size = logical_block_size;
	isomp->volume_space_size = isonum_733 (pri->volume_space_size);
	/*
	 * Since an ISO9660 multi-session CD can also access previous
	 * sessions, we have to include them into the space consider-
	 * ations.  This doesn't yield a very accurate number since
	 * parts of the old sessions might be inaccessible now, but we
	 * can't do much better.  This is also important for the NFS
	 * filehandle validation.
	 */
	isomp->volume_space_size += blkoff;
	bcopy (rootp, isomp->root, sizeof isomp->root);
	isomp->root_extent = isonum_733 (rootp->extent);
	isomp->root_size = isonum_733 (rootp->size);

	/*
	 * getattrlist wants the volume name, create date and modify date
	 */

	/* Remove any trailing white space */
	if ( strlen(pri->volume_id) ) {
		char    	*myPtr;

		myPtr = pri->volume_id + strlen( pri->volume_id ) - 1;
		while ( *myPtr == ' ' && myPtr >= pri->volume_id ) {
			*myPtr = 0x00;
			myPtr--;
		}
	}

	if (pri->volume_id[0] == 0)
		strcpy(isomp->volume_id, ISO_DFLT_VOLUME_ID);
	else
		bcopy(pri->volume_id, isomp->volume_id, sizeof(isomp->volume_id));
	cd9660_tstamp_conv17(pri->creation_date, &isomp->creation_date);
	cd9660_tstamp_conv17(pri->modification_date, &isomp->modification_date);

	/* See if this is a CD-XA volume */
	if (bcmp( pri->CDXASignature, ISO_XA_ID,
			sizeof(pri->CDXASignature) ) == 0 ) {
		isomp->im_flags2 |= IMF2_IS_CDXA;
	}

	isomp->im_bmask = logical_block_size - 1;
	isomp->im_bshift = 0;
	while ((1 << isomp->im_bshift) < isomp->logical_block_size)
		isomp->im_bshift++;

	pribp->b_flags |= B_AGE;
	brelse(pribp);
	pribp = NULL;

	mp->mnt_data = (qaddr_t)isomp;
	mp->mnt_stat.f_fsid.val[0] = (long)dev;
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	mp->mnt_maxsymlinklen = 0;
	mp->mnt_flag |= MNT_LOCAL;

	isomp->im_mountp = mp;
	isomp->im_dev = dev;
	isomp->im_devvp = devvp;	

	devvp->v_specflags |= SI_MOUNTEDON;

	/*
	 * If the logical block size is not 2K then we must
	 * set the block device's physical block size to this
	 * disc's logical block size.
	 *
	 */
	if (logical_block_size != iso_bsize) {
		iso_bsize = logical_block_size;
		if ((error = VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE,
		     (caddr_t)&iso_bsize, FWRITE, p->p_ucred, p)))
			goto out;
		devvp->v_specsize = iso_bsize;
	}
	
	/* Check the Rock Ridge Extention support */
	if (!(argp->flags & ISOFSMNT_NORRIP)) {
		if ( (error = bread(isomp->im_devvp,
				  (isomp->root_extent + isonum_711(rootp->ext_attr_length)),
				  isomp->logical_block_size, NOCRED, &bp)) ) {

			printf("iso_mountfs: bread error %d reading block %d\n",
			   error, isomp->root_extent + isonum_711(rootp->ext_attr_length));
			argp->flags |= ISOFSMNT_NORRIP;
			goto skipRRIP;
		}
		rootp = (struct iso_directory_record *)bp->b_data;
		
		if ((isomp->rr_skip = cd9660_rrip_offset(rootp,isomp)) < 0) {
			argp->flags  |= ISOFSMNT_NORRIP;
		} else {
			argp->flags  &= ~ISOFSMNT_GENS;
		}
		
		/*
		 * The contents are valid,
		 * but they will get reread as part of another vnode, so...
		 */
		bp->b_flags |= B_AGE;
		brelse(bp);
		bp = NULL;
	}
skipRRIP:

	isomp->im_flags = argp->flags & (ISOFSMNT_NORRIP | ISOFSMNT_GENS |
					 ISOFSMNT_EXTATT | ISOFSMNT_NOJOLIET);

	switch (isomp->im_flags&(ISOFSMNT_NORRIP|ISOFSMNT_GENS)) {
	default:
		isomp->iso_ftype = ISO_FTYPE_DEFAULT;
		break;
	case ISOFSMNT_GENS|ISOFSMNT_NORRIP:
		isomp->iso_ftype = ISO_FTYPE_9660;
		break;
	case 0:
		isomp->iso_ftype = ISO_FTYPE_RRIP;
		break;
	}
	
	/* Decide whether to use the Joliet descriptor */

	if (isomp->iso_ftype != ISO_FTYPE_RRIP && joliet_level != 0) {
		char vol_id[32];
		int i, convflags;
		size_t convbytes;
		u_int16_t *uchp;
		
		/*
		 * On Joliet CDs use the UCS-2 volume identifier.
		 *
		 * This name can have up to 16 UCS-2 chars.
		 */
		convflags = UTF_DECOMPOSED;
		if (BYTE_ORDER != BIG_ENDIAN)
			convflags |= UTF_REVERSE_ENDIAN;
		uchp = (u_int16_t *)sup->volume_id;
		for (i = 0; i < 16 && uchp[i]; ++i);
		if ((utf8_encodestr((u_int16_t *)sup->volume_id, (i * 2), vol_id,
			&convbytes, sizeof(vol_id), 0, convflags) == 0)
			&& convbytes && (vol_id[0] != ' ')) {
			char * strp;

			/* Remove trailing spaces */
			strp = vol_id + convbytes - 1;
			while (strp > vol_id && *strp == ' ')
				*strp-- = '\0';
			bcopy(vol_id, isomp->volume_id, convbytes + 1);
		}

		rootp = (struct iso_directory_record *)
			sup->root_directory_record;
		bcopy (rootp, isomp->root, sizeof isomp->root);
		isomp->root_extent = isonum_733 (rootp->extent);
		isomp->root_size = isonum_733 (rootp->size);
		supbp->b_flags |= B_AGE;
		isomp->iso_ftype = ISO_FTYPE_JOLIET;
	}

	if (supbp) {
		brelse(supbp);
		supbp = NULL;
	}

	/* If there was a TOC in the arguments, copy it in. */
	if (argp->flags & ISOFSMNT_TOC) {
		MALLOC(isomp->toc, struct CDTOC *, argp->toc_length, M_ISOFSMNT, M_WAITOK);
		if ((error = copyin(argp->toc, isomp->toc, argp->toc_length)))
			goto out;
	}

	/* See if this could be a Video CD */
	if ((isomp->im_flags2 & IMF2_IS_CDXA) && cd9660_find_video_dir(isomp)) {
		/* Get the 2352-bytes-per-block device. */
		isomp->phys_devvp = cd9660_phys_device(argp->fspec, p);
	}

	return (0);
out:
	if (bp)
		brelse(bp);
	if (pribp)
		brelse(pribp);
	if (supbp)
		brelse(supbp);
	if (needclose)
		(void)VOP_CLOSE(devvp, FREAD, NOCRED, p);
	if (isomp) {
		if (isomp->toc)
			FREE((caddr_t)isomp->toc, M_ISOFSMNT);
		FREE((caddr_t)isomp, M_ISOFSMNT);
		mp->mnt_data = (qaddr_t)0;
	}

	/* Clear the mounted on bit in the devvp If it 	 */
	/* not set, this is a nop and there is no way to */
	/* get here with it set unless we did it.  If you*/
	/* are making code changes which makes the above */
	/* assumption not true, change this code.        */

	devvp->v_specflags &= ~SI_MOUNTEDON;

	return (error);
}

/*
 * Make a filesystem operational.
 * Nothing to do at the moment.
 */
/* ARGSUSED */
int
cd9660_start(mp, flags, p)
	struct mount *mp;
	int flags;
	struct proc *p;
{
	return (0);
}

/*
 * unmount system call
 */
int
cd9660_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
{
	register struct iso_mnt *isomp;
	int error, flags = 0;
	int force = 0;
	
	if ( (mntflags & MNT_FORCE) ) {
		flags |= FORCECLOSE;
		force = 1;
	}

	if ( (error = vflush(mp, NULLVP, flags)) && !force )
		return (error);

	isomp = VFSTOISOFS(mp);

#ifdef	ISODEVMAP
	if (isomp->iso_ftype == ISO_FTYPE_RRIP)
		iso_dunmap(isomp->im_dev);
#endif
	
	isomp->im_devvp->v_specflags &= ~SI_MOUNTEDON;
	error = VOP_CLOSE(isomp->im_devvp, FREAD, NOCRED, p);
	if (error && !force )
		return(error);

	vrele(isomp->im_devvp);
	
	if (isomp->phys_devvp) {
		error = VOP_CLOSE(isomp->phys_devvp, FREAD, FSCRED, p);
		if (error && !force)
			return error;
		vrele(isomp->phys_devvp);
	}

	if (isomp->toc)
		FREE((caddr_t)isomp->toc, M_ISOFSMNT);

	FREE((caddr_t)isomp, M_ISOFSMNT);
	mp->mnt_data = (qaddr_t)0;
	mp->mnt_flag &= ~MNT_LOCAL;
	return (0);
}

/*
 * Return root of a filesystem
 */
int
cd9660_root(mp, vpp)
	struct mount *mp;
	struct vnode **vpp;
{
	struct iso_mnt *imp = VFSTOISOFS(mp);
	struct iso_directory_record *dp =
		(struct iso_directory_record *)imp->root;
	ino_t ino = isodirino(dp, imp);

	/*
	 * With RRIP we must use the `.' entry of the root directory.
	 * Simply tell vget, that it's a relocated directory.
	 */
	return (cd9660_vget_internal(mp, ino, vpp,
		imp->iso_ftype == ISO_FTYPE_RRIP, dp, current_proc()));
}

/*
 * Do operations associated with quotas, not supported
 */
/* ARGSUSED */
int
cd9660_quotactl(mp, cmd, uid, arg, p)
	struct mount *mp;
	int cmd;
	uid_t uid;
	caddr_t arg;
	struct proc *p;
{

	return (EOPNOTSUPP);
}

/*
 * Get file system statistics.
 */
int
cd9660_statfs(mp, sbp, p)
	struct mount *mp;
	register struct statfs *sbp;
	struct proc *p;
{
	register struct iso_mnt *isomp;
	
	isomp = VFSTOISOFS(mp);

#ifdef COMPAT_09
	sbp->f_type = 5;
#else
	sbp->f_type = 0;
#endif
	sbp->f_bsize = isomp->logical_block_size;
	sbp->f_iosize = sbp->f_bsize;	/* XXX */
	sbp->f_blocks = isomp->volume_space_size;
	sbp->f_bfree = 0; /* total free blocks */
	sbp->f_bavail = 0; /* blocks free for non superuser */
	sbp->f_files =  0; /* total files */
	sbp->f_ffree = 0; /* free file nodes */
	if (sbp != &mp->mnt_stat) {
		bcopy(mp->mnt_stat.f_mntonname, sbp->f_mntonname, MNAMELEN);
		bcopy(mp->mnt_stat.f_mntfromname, sbp->f_mntfromname, MNAMELEN);
	}

	strncpy( sbp->f_fstypename, mp->mnt_vfc->vfc_name, (MFSNAMELEN - 1) );
	sbp->f_fstypename[(MFSNAMELEN - 1)] = '\0';

	/* DO NOT use the first spare for flags; it's been reassigned for another use: */
	/* sbp->f_spare[0] = isomp->im_flags; */

	return (0);
}

/* ARGSUSED */
int
cd9660_sync(mp, waitfor, cred, p)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct proc *p;
{

	return (0);
}

/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the inode number is in range
 * - call iget() to get the locked inode
 * - check for an unallocated inode (i_mode == 0)
 * - check that the generation number matches
 */

struct ifid {
	ushort	ifid_len;
	ushort	ifid_pad;
	int	ifid_ino;
	long	ifid_start;
};

/* ARGSUSED */
int
cd9660_fhtovp(mp, fhp, nam, vpp, exflagsp, credanonp)
	register struct mount *mp;
	struct fid *fhp;
	struct mbuf *nam;
	struct vnode **vpp;
	int *exflagsp;
	struct ucred **credanonp;
{
	struct ifid *ifhp = (struct ifid *)fhp;
	register struct iso_node *ip;
	register struct netcred *np;
	register struct iso_mnt *imp = VFSTOISOFS(mp);
	struct vnode *nvp;
	int error;
	
#ifdef	ISOFS_DBG
	printf("fhtovp: ino %d, start %ld\n",
	       ifhp->ifid_ino, ifhp->ifid_start);
#endif
	
	/*
	 * Get the export permission structure for this <mp, client> tuple.
	 */
	np = vfs_export_lookup(mp, &imp->im_export, nam);
	if (nam && (np == NULL))
		return (EACCES);

	if ( (error = VFS_VGET(mp, &ifhp->ifid_ino, &nvp)) ) {
		*vpp = NULLVP;
		return (error);
	}
	ip = VTOI(nvp);
	if (ip->inode.iso_mode == 0) {
		vput(nvp);
		*vpp = NULLVP;
		return (ESTALE);
	}
	*vpp = nvp;
	if (np) {
		*exflagsp = np->netc_exflags;
		*credanonp = &np->netc_anon;
	}
	return (0);
}

/*
 * Scan the TOC for the track which contains the given sector.
 *
 * If there is no matching track, or no TOC, then return -1.
 */
static int
cd9660_track_for_sector(struct CDTOC *toc, u_int sector)
{
	int i, tracks, result;
	
	if (toc == NULL)
		return -1;

	tracks = toc->length / sizeof(struct CDTOC_Desc);
	
	result = -1;		/* Sentinel in case we don't find the right track. */
	for (i=0; i<tracks; ++i) {
		if (toc->trackdesc[i].point < 100 && MSF_TO_LBA(toc->trackdesc[i].p) <= sector) {
			result = toc->trackdesc[i].point;
		}
	}
	
	return result;
}

/*
 * Determine whether the given node is really a video CD video
 * file.  Return non-zero if it appears to be a video file.
 */
static int
cd9660_is_video_file(struct iso_node *ip, struct iso_mnt *imp)
{
	int lbn;
	int track;
	
	/* Check whether this could really be a Video CD at all */
	if (((imp->im_flags2 & IMF2_IS_VCD) == 0) ||
		imp->phys_devvp == NULL ||
		imp->toc == NULL)
	{
		return 0;	/* Doesn't even look like VCD... */
	}

	/* Make sure it is a file */
	if ((ip->inode.iso_mode & S_IFMT) != S_IFREG)
		return 0;	/* Not even a file... */

	/*
	 * And in the right directory.  This assumes the same inode
	 * number convention that cd9660_vget_internal uses (that
	 * part of the inode number is the block containing the
	 * file's directory entry).
	 */
	lbn = lblkno(imp, ip->i_number);
	if (lbn < imp->video_dir_start || lbn >= imp->video_dir_end)
		return 0;	/* Not in the correct directory */
	
	/*
	 * If we get here, the file should be a video file, but
	 * do a couple of extra sanity checks just to be sure.
	 * First, verify the form of the name
	 */
	if (strlen(ip->i_namep) != 11 ||		/* Wrong length? */
		bcmp(ip->i_namep+7, ".DAT", 4) ||	/* Wrong extension? */
		(bcmp(ip->i_namep, "AVSEQ", 5) &&	/* Wrong beginning? */
		 bcmp(ip->i_namep, "MUSIC", 5)))
	{
		return 0;	/* Invalid name format */
	}
	
	/*
	 * Verify that AVSEQnn.DAT is in track #(nn+1).  This would
	 * not be appropriate for Super Video CD, which allows
	 * multiple sessions, so the track numbers might not
	 * match up like this. 
	 */
	track = (ip->i_namep[5] - '0') * 10 + ip->i_namep[6] - '0';
	if (track != (cd9660_track_for_sector(imp->toc, ip->iso_start) - 1))
	{
		return 0;	/* Wrong number in name */
	}

	/* It must be a video file if we got here. */
	return 1;
}

int
cd9660_vget(mp, ino, vpp)
	struct mount *mp;
	void *ino;
	struct vnode **vpp;
{
	/*
	 * XXXX
	 * It would be nice if we didn't always set the `relocated' flag
	 * and force the extra read, but I don't want to think about fixing
	 * that right now.
	 */

	return ( cd9660_vget_internal( mp, *(ino_t*)ino, vpp, 0, 
								   (struct iso_directory_record *) 0,
								   current_proc()) );
}

int
cd9660_vget_internal(mp, ino, vpp, relocated, isodir, p)
	struct mount *mp;
	ino_t ino;
	struct vnode **vpp;
	int relocated;
	struct iso_directory_record *isodir;
    struct proc *p;
{
	register struct iso_mnt *imp;
	struct iso_node *ip;
	struct buf *bp;
	struct vnode *vp, *nvp;
	dev_t dev;
	int error;

	imp = VFSTOISOFS(mp);
	dev = imp->im_dev;

	/* Check for unmount in progress */
    if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
        *vpp = NULLVP;
        return (EPERM);
    }

	if ((*vpp = cd9660_ihashget(dev, ino, p)) != NULLVP)
		return (0);

	MALLOC_ZONE(ip, struct iso_node *, sizeof(struct iso_node),
	    M_ISOFSNODE, M_WAITOK);
	/* Allocate a new vnode/iso_node. */
	if ( (error = getnewvnode(VT_ISOFS, mp, cd9660_vnodeop_p, &vp)) ) {
		FREE_ZONE(ip,sizeof(struct iso_node), M_ISOFSNODE);
		*vpp = NULLVP;
		return (error);
	}
	bzero((caddr_t)ip, sizeof(struct iso_node));
	lockinit(&ip->i_lock, PINOD,"isonode",0,0);
	vp->v_data = ip;
	ip->i_vnode = vp;
	ip->i_dev = dev;
	ip->i_number = ino;
	ip->i_namep = &isonullname[0];

	/*
	 * Put it onto its hash chain and lock it so that other requests for
	 * this inode will block if they arrive while we are sleeping waiting
	 * for old data structures to be purged or for the contents of the
	 * disk portion of this inode to be read.
	 */
	cd9660_ihashins(ip);

	if (isodir == 0) {
		int lbn, off;

		lbn = lblkno(imp, ino);
		if (lbn >= imp->volume_space_size) {
			vput(vp);
			printf("fhtovp: lbn exceed volume space %d\n", lbn);
			return (ESTALE);
		}
	
		off = blkoff(imp, ino);
		if (off + ISO_DIRECTORY_RECORD_SIZE > imp->logical_block_size) {
			vput(vp);
			printf("fhtovp: crosses block boundary %d\n",
				off + ISO_DIRECTORY_RECORD_SIZE);
			return (ESTALE);
		}
	
		error = bread(imp->im_devvp, lbn,
					imp->logical_block_size, NOCRED, &bp);
		if (error) {
			vput(vp);
			brelse(bp);
			printf("fhtovp: bread error %d\n",error);
			return (error);
		}
		isodir = (struct iso_directory_record *)(bp->b_data + off);

		if (off + isonum_711(isodir->length) >
			imp->logical_block_size) {
			vput(vp);
			if (bp != 0)
				brelse(bp);
			printf("fhtovp: directory crosses block boundary "
				"%d[off=%d/len=%d]\n",
				off +isonum_711(isodir->length), off,
				isonum_711(isodir->length));
			return (ESTALE);
		}

		/*
		 * for directories we can get parentID from adjacent 
		 * parent directory record
		 */
		if ((isonum_711(isodir->flags) & directoryBit)
				&& (isodir->name[0] == 0)) {
			struct iso_directory_record *pdp;

			pdp = (struct iso_directory_record *)
					((char *)bp->b_data + isonum_711(isodir->length));
			if ((isonum_711(pdp->flags) & directoryBit)
					&& (pdp->name[0] == 1))
				ip->i_parent = isodirino(pdp, imp);
		}
	} else
		bp = 0;

	ip->i_mnt = imp;
	ip->i_devvp = imp->im_devvp;
	VREF(ip->i_devvp);

	if (relocated) {
		/*
		 * On relocated directories we must
		 * read the `.' entry out of a dir.
		 */
		ip->iso_start = ino >> imp->im_bshift;
		if (bp != 0)
			brelse(bp);
		if ( (error = VOP_BLKATOFF(vp, (off_t)0, NULL, &bp)) ) {
			vput(vp);
			return (error);
		}
		isodir = (struct iso_directory_record *)bp->b_data;
	}

	/*
	 * go get apple extensions to ISO directory record or use
	 * defaults when there are no apple extensions.
	 */
	if ( ((isonum_711( isodir->flags ) & directoryBit) == 0) &&
	     (imp->iso_ftype != ISO_FTYPE_RRIP) ) {
		/* This is an ISO directory record for a file */
		DRGetTypeCreatorAndFlags(imp, isodir, &ip->i_FileType, 
		                         &ip->i_Creator, &ip->i_FinderFlags);

		if (isonum_711(isodir->flags) & associatedBit)
			ip->i_flag |= ISO_ASSOCIATED;
	}

	/*
	 * Shadow the ISO 9660 invisible state to the FinderInfo
	 */
	if (isonum_711(isodir->flags) & existenceBit) {
		ip->i_FinderFlags |= fInvisibleBit;
	}

	ip->iso_extent = isonum_733(isodir->extent);
	ip->i_size = isonum_733(isodir->size);
	ip->iso_start = isonum_711(isodir->ext_attr_length) + ip->iso_extent;
	/*
	 * account for AppleDouble header
	 */
	if (ip->i_flag & ISO_ASSOCIATED)
		ip->i_size += ADH_SIZE;

	/*
	 * if we have a valid name, fill in i_namep with UTF-8 name
	 */
	if (isonum_711(isodir->name_len) != 0) {
		u_char *utf8namep;
		u_short namelen;
		ino_t inump = 0;

		MALLOC(utf8namep, u_char *, ISO_RRIP_NAMEMAX + 1, M_TEMP, M_WAITOK);
		namelen = isonum_711(isodir->name_len);

		switch (imp->iso_ftype) {
		case ISO_FTYPE_RRIP:
			cd9660_rrip_getname(isodir, utf8namep, &namelen, &inump, imp);
			break;

		case ISO_FTYPE_JOLIET:
			ucsfntrans((u_int16_t *)isodir->name, namelen,
				   utf8namep, &namelen,
				   isonum_711(isodir->flags) & directoryBit, ip->i_flag & ISO_ASSOCIATED);
			break;

		default:
			isofntrans (isodir->name, namelen,
					utf8namep, &namelen,
					imp->iso_ftype == ISO_FTYPE_9660, ip->i_flag & ISO_ASSOCIATED);
		}

		utf8namep[namelen] = '\0';
		MALLOC(ip->i_namep, u_char *, namelen + 1, M_TEMP, M_WAITOK);
		bcopy(utf8namep, ip->i_namep, namelen + 1);
		FREE(utf8namep, M_TEMP);
	}

	/*
	 * Setup time stamp, attribute
	 */
	vp->v_type = VNON;
	switch (imp->iso_ftype) {
	default:	/* ISO_FTYPE_9660 */
		{
		struct buf *bp2;
		int off;
		if ((imp->im_flags & ISOFSMNT_EXTATT)
				&& (off = isonum_711(isodir->ext_attr_length)))
			VOP_BLKATOFF(vp, (off_t)-(off << imp->im_bshift), NULL, &bp2);
		else
			bp2 = NULL;
		cd9660_defattr(isodir, ip, bp2);
		cd9660_deftstamp(isodir, ip, bp2);
		if (bp2)
			brelse(bp2);
		break;
		}
	case ISO_FTYPE_RRIP:
		cd9660_rrip_analyze(isodir, ip, imp);
		break;
	}

	/*
	 * See if this is a Video CD file.  If so, we must adjust the
	 * length to account for larger sectors plus the RIFF header.
	 * We also must substitute the VOP_READ and VOP_PAGEIN functions.
	 *
	 * The cd9660_is_video_file routine assumes that the inode has
	 * been completely set up; it refers to several fields.
	 *
	 * This must be done before we release bp, because isodir
	 * points into bp's data.
	 */
	if (cd9660_is_video_file(ip, imp))
	{
		cd9660_xa_init(vp, isodir);
	}

	if (bp != 0)
		brelse(bp);

	/*
	 * Initialize the associated vnode
	 */
	 
	if (ip->iso_extent == imp->root_extent) {
		vp->v_flag |= VROOT;
		ip->i_parent = 1;	/* root's parent is always 1 by convention */
		/* mode type must be S_IFDIR */
		ip->inode.iso_mode = (ip->inode.iso_mode & ~S_IFMT) | S_IFDIR;
	}

	switch (vp->v_type = IFTOVT(ip->inode.iso_mode)) {
	case VFIFO:
#if	FIFO
		vp->v_op = cd9660_fifoop_p;
		break;
#else
		vput(vp);
		return (EOPNOTSUPP);
#endif	/* FIFO */
	case VCHR:
	case VBLK:
		/*
		 * if device, look at device number table for translation
		 */
#ifdef	ISODEVMAP
		if (dp = iso_dmap(dev, ino, 0))
			ip->inode.iso_rdev = dp->d_dev;
#endif
		vp->v_op = cd9660_specop_p;
		if ( (nvp = checkalias(vp, ip->inode.iso_rdev, mp)) ) {
			/*
			 * Discard unneeded vnode, but save its iso_node.
			 */
			cd9660_ihashrem(ip);
			VOP_UNLOCK(vp, 0, p);
			nvp->v_data = vp->v_data;
			vp->v_data = NULL;
			vp->v_op = spec_vnodeop_p;
			vrele(vp);
			vgone(vp);
			/*
			 * Reinitialize aliased inode.
			 */
			vp = nvp;
			ip->i_vnode = vp;
			cd9660_ihashins(ip);
		}
		break;
	case VREG:
		ubc_info_init(vp);
		break;
	default:
		break;
	}
	
	/*
	 * XXX need generation number?
	 */

	*vpp = vp;

	return (0);
}


/************************************************************************
 *
 *  Function:	DRGetTypeCreatorAndFlags
 *
 *  Purpose:	Set up the fileType, fileCreator and fileFlags
 *
 *  Returns:	none
 *
 *  Side Effects:	sets *theTypePtr, *theCreatorPtr, and *theFlagsPtr
 *
 *  Description:
 *
 *  Revision History:
 *	28 Jul 88	BL¡B	Added a new extension type of 6, which allows
 *						the specification of four of the finder flags.
 *						We let the creator of the disk just copy over
 *						the finder flags, but we only look at always
 *						switch launch, system, bundle, and locked bits.
 *	15 Aug 88	BL¡B	The Apple extensions to ISO 9660 implemented the
 *						padding field at the end of a directory record
 *						incorrectly.
 *	19 Jul 89	BG		Rewrote routine to handle the "new" Apple
 *						Extensions definition, as well as take into
 *						account the possibility of "other" definitions.
 *	02 Nov 89	BG		Corrected the 'AA' SystemUseID processing to
 *						check for SystemUseID == 2 (HFS).  Was incorrectly
 *						checking for SystemUseID == 1 (ProDOS) before.
 *	18 Mar 92	CMP		Fixed the check for whether len_fi was odd or even.
 *						Before it would always assume even for an XA record.
 *	26 Dec 97	jwc		Swiped from MacOS implementation of ISO 9660 CD-ROM
 *						support and modified to work in MacOSX file system.
 *
 *********************************************************************** */
 
static void
DRGetTypeCreatorAndFlags(	struct iso_mnt * theMountPointPtr,
							struct iso_directory_record * theDirRecPtr, 
							u_int32_t * theTypePtr, 
							u_int32_t * theCreatorPtr, 
							u_int16_t * theFlagsPtr )
{
	int					foundStuff;
	u_int32_t			myType;
	u_int32_t			myCreator;
	AppleExtension		*myAppleExtPtr;
	NewAppleExtension	*myNewAppleExtPtr;
	u_int16_t			myFinderFlags;
	char				*myPtr;

	foundStuff = 1;
	myType = 0x3f3f3f3f;
	myCreator = 0x3f3f3f3f;
	myFinderFlags = 0;
	*theFlagsPtr = 0x0000;

	/*
	 * handle the fact that our original apple extensions didn't take
	 * into account the padding byte on a file name
	 */

	myPtr = &theDirRecPtr->name[ (isonum_711(theDirRecPtr->name_len)) ];
	
	/* if string length is even, bump myPtr for padding byte */
	if ( ((isonum_711(theDirRecPtr->name_len)) & 0x01) == 0 )
		myPtr++;
	myAppleExtPtr = (AppleExtension *) myPtr;

	/*
	 * checking for whether or not the new 'AA' code is being 
	 * called (and if so, correctly)
	 */
	if ( (isonum_711(theDirRecPtr->length)) <= 
		 ISO_DIRECTORY_RECORD_SIZE + (isonum_711(theDirRecPtr->name_len)) ) {
		foundStuff = 0;
		goto DoneLooking;
	}

	foundStuff = 0;	/* now we default to *false* until we find a good one */
	myPtr = (char *) myAppleExtPtr;

	if ( (theMountPointPtr->im_flags2 & IMF2_IS_CDXA) != 0 )
		myPtr += 14;/* add in CD-XA fixed record offset (tnx, Phillips) */
	myNewAppleExtPtr = (NewAppleExtension *) myPtr;

	/*
	 * Calculate the "real" end of the directory record information.
	 *
	 * Note: We always read the first 4 bytes of the System-Use data, so
	 * adjust myPtr down so we don't read off the end of the directory!
	 */
	myPtr = ((char *) theDirRecPtr) + (isonum_711(theDirRecPtr->length));
	myPtr -= sizeof(NewAppleExtension) - 1;
	while( (char *) myNewAppleExtPtr < myPtr ) 	/* end of directory buffer */
	{
		/*
		 *	If we get here, we can assume that ALL further entries in this
		 *	directory record are of the form:
		 *
		 *		struct OptionalSystemUse
		 *		{
		 *			byte	Signature[2];
		 *			byte	OSULength;
		 *			byte	systemUseID;
		 *			byte	fileType[4];		# only if HFS
		 *			byte	fileCreator[4];		# only if HFS
		 *			byte	finderFlags[2];		# only if HFS
		 *		};
		 *
		 *	This means that we can examine the Signature bytes to see
		 *	if they are 'AA' (the NEW Apple extension signature).
		 *	If they are, deal with them.  If they aren't,
		 *	the OSULength field will tell us how long this extension
		 *	info is (including the signature and length bytes) and that
		 *	will allow us to walk the OptionalSystemUse records until
		 *	we hit the end of them or run off the end of the 
		 *	directory record.
		 */
		u_char				*myFromPtr, *myToPtr;
		union
		{
			u_int32_t		fourchars;
			u_char			chars[4];
		} myChars;

		if ( (myNewAppleExtPtr->signature[0] == 'A') &&
			(myNewAppleExtPtr->signature[1] == 'A') ) {
			if ( isonum_711(myNewAppleExtPtr->systemUseID) == 2 ) {
				/* HFS */
				foundStuff = 1;			/* we got one! */

				myFromPtr = &myNewAppleExtPtr->fileType[0]; 
				myToPtr = &myChars.chars[0];
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr = *myFromPtr;
				myType = myChars.fourchars;	/* copy file type to user var */

				myFromPtr = &myNewAppleExtPtr->fileCreator[0]; 
				myToPtr = &myChars.chars[0];
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr = *myFromPtr;
				myCreator = myChars.fourchars;	/* copy creator to user var */

				myFromPtr = &myNewAppleExtPtr->finderFlags[0]; 
				myToPtr = &myChars.chars[2];	/* *flags* is a short */
				myChars.fourchars = 0; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr = *myFromPtr;
				myFinderFlags = myChars.fourchars;
				myFinderFlags &=
					( fAlwaysBit | fSystemBit | fHasBundleBit | fLockedBit );
				/* return Finder flags to user var */
				*theFlagsPtr = (myFinderFlags | fInitedBit);

				break;		/* exit the loop */
			}
		}

		/*
		 *	Check to see if we have a reasonable OSULength value.
		 *	ZERO is not an acceptable value.  Nor is any value less than 4.
		 */

		if ( (isonum_711(myNewAppleExtPtr->OSULength)) < 4 ) 
			break;	/* not acceptable - get out! */

		/* otherwise, step past this SystemUse record */
		(char *)myNewAppleExtPtr += (isonum_711(myNewAppleExtPtr->OSULength));
		
	} /* end of while loop */

DoneLooking:
	if ( foundStuff != 0 ) {
		*theTypePtr    = myType;
		*theCreatorPtr = myCreator;
	} else {
		*theTypePtr = 0;
		*theCreatorPtr = 0;
	}
	
	return;
	
} /* DRGetTypeCreatorAndFlags */


/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
cd9660_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	register struct iso_node *ip = VTOI(vp);
	register struct ifid *ifhp;
	
	ifhp = (struct ifid *)fhp;
	ifhp->ifid_len = sizeof(struct ifid);
	
	ifhp->ifid_ino = ip->i_number;
	ifhp->ifid_start = ip->iso_start;
	
#ifdef	ISOFS_DBG
	printf("vptofh: ino %d, start %ld\n",
	       ifhp->ifid_ino,ifhp->ifid_start);
#endif
	return (0);
}

/*
 * Fast-FileSystem only?
 */
int
cd9660_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
     int * name;
     u_int namelen;
     void* oldp;
     size_t * oldlenp;
     void * newp;
     size_t newlen;
     struct proc * p;
{
     return (EOPNOTSUPP);
}

